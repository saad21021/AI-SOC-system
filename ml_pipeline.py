import joblib
import pandas as pd
import numpy as np
import os
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load models
scaler = joblib.load(os.path.join(BASE_DIR, 'scaler.pkl'))
iso_forest = joblib.load(os.path.join(BASE_DIR, 'isolation_forest.pkl'))
random_forest = joblib.load(os.path.join(BASE_DIR, 'random_forest.pkl'))
cluster_map = joblib.load(os.path.join(BASE_DIR, 'cluster_map.pkl'))

FEATURE_COLUMNS = scaler.feature_names_in_

def analyze_traffic(df_batch):
    # Safe column alignment
    X = df_batch.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    # Scale
    X_scaled = scaler.transform(X)

    # Isolation Forest
    iso_preds = iso_forest.predict(X_scaled)
    iso_scores = iso_forest.decision_function(X_scaled)

    results = []

    for idx in range(len(df_batch)):
        timestamp = str(datetime.datetime.now())

        if iso_preds[idx] == 1:
            results.append({
                "timestamp": timestamp,
                "status": "✅ Normal",
                "severity": 0.0,
                "is_anomaly": False,
                "score": float(iso_scores[idx])
            })
        else:
            x_input = X_scaled[idx].reshape(1, -1)

            rf_pred = random_forest.predict(x_input)[0]
            confidence = np.max(random_forest.predict_proba(x_input))

            raw_attack = cluster_map.get(rf_pred, "Unknown")
            attack_lower = str(raw_attack).lower()

            if rf_pred == -1:
                final_alert = "⚠️ Unknown Threat (Noise)"
            elif "ddos" in attack_lower or "dos" in attack_lower:
                final_alert = "🚨 DDoS Attack"
            elif raw_attack == "Unknown":
                final_alert = "⚠️ Suspicious Activity"
            elif "port" in attack_lower:
                final_alert = "🔍 Port Scan"
            elif "bot" in attack_lower:
                final_alert = "🤖 Bot Activity"
            else:
                final_alert = f"⚠️ {raw_attack} Activity"

            # Combined severity
            sev = 0.7 * abs(iso_scores[idx]) + 0.3 * confidence

            if "ddos" in attack_lower:
                sev += 0.3

            sev = float(min(1.0, sev))

            results.append({
                "timestamp": timestamp,
                "status": final_alert,
                "severity": sev,
                "confidence": float(confidence),
                "is_anomaly": True,
                "cluster_predicted": int(rf_pred),
                "score": float(iso_scores[idx])
            })

    return results, X_scaled
