import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class ThreatIntelRAG:
    def __init__(self, persist_dir: str = "./chroma_db"):
        self.documents = [
            "MITRE T1110 (Credential Guessing): High failed login attempts (>10) from a single client targeting authentication endpoints.",
            "MITRE T1046 (Network Service Discovery): Rapid probing across many destination ports (ports_scanned >15) with low payload size.",
            "MITRE T1498 (Network Denial of Service): High request_rate (>150 req/sec) combined with high syn_flag_ratio (>0.70).",
            "MITRE T1190 (Application Layer Anomaly): Abnormally large HTTP payload sizes (avg_payload_kb >25 KB) sent to query endpoints.",
            "MITRE T1041 (Data Transfer Anomaly): Sustained high outbound payload size with moderate request rate."
        ]
        self.metadatas = [
            {"mitre_id": "T1110", "category": "Brute Force", "default_severity": "High"},
            {"mitre_id": "T1046", "category": "Port Scanning", "default_severity": "Medium"},
            {"mitre_id": "T1498", "category": "DDoS / SYN Flood", "default_severity": "Critical"},
            {"mitre_id": "T1190", "category": "Web Payload Anomaly", "default_severity": "Critical"},
            {"mitre_id": "T1041", "category": "Data Exfiltration", "default_severity": "High"}
        ]
        self.vectorizer = TfidfVectorizer()
        self.doc_vectors = self.vectorizer.fit_transform(self.documents)

    def retrieve_context(self, log_data: dict) -> dict:
        # Rule-assisted semantic query construction for accurate MITRE mapping
        terms = [
            f"request_rate {log_data['request_rate']}",
            f"failed_logins {log_data['failed_logins']}",
            f"avg_payload_kb {log_data['avg_payload_kb']}",
            f"ports_scanned {log_data['ports_scanned']}",
            f"syn_flag_ratio {log_data['syn_flag_ratio']}"
        ]
        if log_data.get("failed_logins", 0) > 10:
            terms.append("Credential Guessing failed login attempts authentication")
        if log_data.get("ports_scanned", 0) > 15:
            terms.append("Network Service Discovery probing destination ports_scanned")
        if log_data.get("request_rate", 0) > 150 or log_data.get("syn_flag_ratio", 0) > 0.70:
            terms.append("Network Denial of Service High request_rate syn_flag_ratio")
        if log_data.get("avg_payload_kb", 0) > 25:
            terms.append("Application Layer Anomaly large HTTP payload avg_payload_kb")

        query = " ".join(terms)
        query_vec = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vec, self.doc_vectors).flatten()
        best_idx = int(np.argmax(similarities))

        return {
            "context": self.documents[best_idx],
            "mitre_id": self.metadatas[best_idx]["mitre_id"],
            "category": self.metadatas[best_idx]["category"]
        }

rag_engine = ThreatIntelRAG()