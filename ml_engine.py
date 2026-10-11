import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

MODEL_PATH = "models/anomaly_pipeline.joblib"
FEATURE_COLUMNS = [
    "request_rate",
    "failed_logins",
    "avg_payload_kb",
    "ports_scanned",
    "syn_flag_ratio"
]

class AnomalyDetectionEngine:
    def __init__(self):
        os.makedirs("models", exist_ok=True)
        if os.path.exists(MODEL_PATH):
            self.pipeline = joblib.load(MODEL_PATH)
        else:
            self.pipeline = self._train_initial_model()

    def _train_initial_model(self) -> Pipeline:
        np.random.seed(42)
        n_normal = 2000
        normal_data = pd.DataFrame({
            "request_rate": np.random.normal(loc=15.0, scale=5.0, size=n_normal).clip(1, 40),
            "failed_logins": np.random.choice([0, 1, 2], size=n_normal, p=[0.85, 0.12, 0.03]),
            "avg_payload_kb": np.random.normal(loc=4.5, scale=1.5, size=n_normal).clip(0.5, 12),
            "ports_scanned": np.random.choice([1, 2, 3], size=n_normal, p=[0.90, 0.08, 0.02]),
            "syn_flag_ratio": np.random.normal(loc=0.15, scale=0.05, size=n_normal).clip(0.01, 0.35)
        })

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("iforest", IsolationForest(
                n_estimators=150,
                contamination=0.04,
                random_state=42,
                n_jobs=-1
            ))
        ])

        pipeline.fit(normal_data[FEATURE_COLUMNS])
        joblib.dump(pipeline, MODEL_PATH)
        print(f"[ML Engine] Trained and saved IsolationForest model to {MODEL_PATH}")
        return pipeline

    def evaluate_packet(self, log_data: dict) -> dict:
        df = pd.DataFrame([[
            log_data["request_rate"],
            log_data["failed_logins"],
            log_data["avg_payload_kb"],
            log_data["ports_scanned"],
            log_data["syn_flag_ratio"]
        ]], columns=FEATURE_COLUMNS)

        prediction = int(self.pipeline.predict(df)[0])
        raw_score = float(self.pipeline.decision_function(df)[0])
        risk_index = int(np.clip((0.15 - raw_score) * 220, 0, 100))

        return {
            "is_anomaly": bool(prediction == -1 or risk_index >= 60),
            "anomaly_score": round(raw_score, 4),
            "risk_index": risk_index
        }

ml_engine = AnomalyDetectionEngine()