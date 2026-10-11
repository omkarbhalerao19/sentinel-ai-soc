import sqlite3
from datetime import datetime
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from ml_engine import ml_engine
from secops_agent import generate_incident_report

app = FastAPI(title="SentinelAI - Threat Intelligence & Anomaly Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")

def init_db():
    conn = sqlite3.connect("incidents.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            endpoint TEXT,
            risk_index INTEGER,
            threat_type TEXT,
            mitre_id TEXT,
            severity TEXT,
            explanation TEXT,
            mitigation_command TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class NetworkLog(BaseModel):
    source_ip: str
    endpoint: str = "/api/v1/login"
    request_rate: float
    failed_logins: int
    avg_payload_kb: float
    ports_scanned: int
    syn_flag_ratio: float

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()
stats = {"total_packets": 0, "anomalies_blocked": 0}

@app.get("/")
async def serve_dashboard():
    return FileResponse("static/index.html")

@app.post("/api/ingest")
async def ingest_network_log(log: NetworkLog):
    stats["total_packets"] += 1
    log_dict = log.model_dump()
    ml_result = ml_engine.evaluate_packet(log_dict)

    event_payload = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source_ip": log.source_ip,
        "endpoint": log.endpoint,
        "request_rate": log.request_rate,
        "risk_index": ml_result["risk_index"],
        "is_anomaly": ml_result["is_anomaly"],
        "total_packets": stats["total_packets"],
        "anomalies_blocked": stats["anomalies_blocked"]
    }

    if ml_result["is_anomaly"]:
        stats["anomalies_blocked"] += 1
        event_payload["anomalies_blocked"] = stats["anomalies_blocked"]
        report = generate_incident_report(log_dict, ml_result)
        event_payload["report"] = report

        conn = sqlite3.connect("incidents.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (timestamp, source_ip, endpoint, risk_index, threat_type, mitre_id, severity, explanation, mitigation_command)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_payload["timestamp"], log.source_ip, log.endpoint,
            ml_result["risk_index"], report["threat_type"], report["mitre_id"],
            report["severity"], report["explanation"], report["mitigation_command"]
        ))
        conn.commit()
        conn.close()

    await manager.broadcast(event_payload)
    return event_payload

@app.get("/api/incidents")
async def get_recent_incidents():
    conn = sqlite3.connect("incidents.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 20")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)