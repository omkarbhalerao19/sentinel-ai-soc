import os
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rag_engine import rag_engine

load_dotenv()

class ThreatReport(BaseModel):
    threat_type: str = Field(description="Specific anomaly classification")
    mitre_id: str = Field(description="MITRE ATT&CK Technique ID, e.g., T1110")
    severity: str = Field(description="Medium, High, or Critical")
    explanation: str = Field(description="Concise technical root-cause analysis")
    mitigation_command: str = Field(description="Recommended firewall rule")

def generate_incident_report(log_data: dict, ml_result: dict) -> dict:
    rag_match = rag_engine.retrieve_context(log_data)
    api_key = os.getenv("OPENAI_API_KEY", "")

    if api_key and api_key != "your_api_key_here":
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            prompt = f"""
            Analyze this flagged network anomaly and generate a structured SecOps incident response:
            - Source IP: {log_data['source_ip']}
            - Endpoint: {log_data['endpoint']}
            - Telemetry: {log_data}
            - ML Risk Index: {ml_result['risk_index']}/100
            - Retrieved Threat Intel: {rag_match['context']}
            """
            completion = client.beta.chat.completions.parse(
                model=os.getenv("MODEL_NAME", "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": "You are an elite Principal SecOps AI Agent."},
                    {"role": "user", "content": prompt}
                ],
                response_format=ThreatReport
            )
            return completion.choices[0].message.parsed.model_dump()
        except Exception as e:
            print(f"[Agent Warning] LLM call failed ({e}), using heuristic fallback.")

    ip = log_data["source_ip"]
    if log_data["failed_logins"] >= 10:
        return {
            "threat_type": "Auth Brute Force",
            "mitre_id": "T1110",
            "severity": "High",
            "explanation": f"Detected {log_data['failed_logins']} failed authentication attempts from {ip} targeting {log_data['endpoint']}.",
            "mitigation_command": f"ufw deny from {ip} to any port 443"
        }
    elif log_data["syn_flag_ratio"] >= 0.65 or log_data["request_rate"] >= 120:
        return {
            "threat_type": "High-Rate Traffic Flood",
            "mitre_id": "T1498",
            "severity": "Critical",
            "explanation": f"High packet velocity ({log_data['request_rate']} req/s) with {int(log_data['syn_flag_ratio']*100)}% SYN ratio.",
            "mitigation_command": f"ufw limit from {ip}"
        }
    elif log_data["ports_scanned"] >= 12:
        return {
            "threat_type": "Port Sweep Discovery",
            "mitre_id": "T1046",
            "severity": "Medium",
            "explanation": f"Host {ip} probed {log_data['ports_scanned']} distinct ports in a single window.",
            "mitigation_command": f"ufw deny from {ip}"
        }
    else:
        return {
            "threat_type": "Payload Size Anomaly",
            "mitre_id": "T1190",
            "severity": "Critical",
            "explanation": f"Anomalous payload size ({log_data['avg_payload_kb']} KB) sent to {log_data['endpoint']}.",
            "mitigation_command": f"ufw reject from {ip}"
        }