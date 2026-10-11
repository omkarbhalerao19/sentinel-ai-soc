import time
import random
import requests

API_URL = "http://127.0.0.1:8000/api/ingest"

TEST_ANOMALY_PROFILES = [
    {"source_ip": "198.51.100.10", "endpoint": "/api/v1/login", "request_rate": 45.0, "failed_logins": 28, "avg_payload_kb": 2.1, "ports_scanned": 1, "syn_flag_ratio": 0.20},
    {"source_ip": "198.51.100.25", "endpoint": "/api/v1/search", "request_rate": 240.0, "failed_logins": 0, "avg_payload_kb": 1.2, "ports_scanned": 2, "syn_flag_ratio": 0.88},
    {"source_ip": "203.0.113.45", "endpoint": "/admin/config", "request_rate": 60.0, "failed_logins": 2, "avg_payload_kb": 0.8, "ports_scanned": 35, "syn_flag_ratio": 0.55},
    {"source_ip": "203.0.113.88", "endpoint": "/api/v1/query", "request_rate": 18.0, "failed_logins": 0, "avg_payload_kb": 42.5, "ports_scanned": 1, "syn_flag_ratio": 0.15}
]

def generate_normal_packet():
    return {
        "source_ip": f"192.0.2.{random.randint(10, 250)}",
        "endpoint": random.choice(["/home", "/products", "/api/v1/status", "/profile"]),
        "request_rate": round(random.uniform(5.0, 22.0), 1),
        "failed_logins": random.choices([0, 1], weights=[0.92, 0.08])[0],
        "avg_payload_kb": round(random.uniform(1.5, 6.5), 2),
        "ports_scanned": 1,
        "syn_flag_ratio": round(random.uniform(0.08, 0.22), 2)
    }

if __name__ == "__main__":
    print("Starting SentinelAI Live Traffic Simulator... Press Ctrl+C to stop.")
    while True:
        payload = generate_normal_packet() if random.random() < 0.75 else random.choice(TEST_ANOMALY_PROFILES)
        try:
            res = requests.post(API_URL, json=payload, timeout=5).json()
            status = "ANOMALY" if res["is_anomaly"] else "NORMAL"
            print(f"[{res['timestamp']}] {status} | IP: {payload['source_ip']} | Risk: {res['risk_index']}/100")
        except Exception as e:
            print(f"Connection error: {e}")
        time.sleep(1.5)