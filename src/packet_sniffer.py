import numpy as np
import pandas as pd
import time
import random
from joblib import load
import os
import datetime
from incident_handler import respond_to_threat

print("🔍 Live packet sniffing started...")

# Setup
MODEL_FEATURES = [" Flow Duration", " Bwd Packet Length Mean", " Packet Length Std"]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "mlp_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
REALTIME_LOG = os.path.join(BASE_DIR, "incidents", "realtime_incidents.csv")

MODEL = load(MODEL_PATH)
SCALER = load(SCALER_PATH)

while True:
    # Simulate a more 'malicious' packet
    duration = np.random.normal(120000, 30000)
    bwd_len = np.random.normal(1200, 200)
    pkt_std = np.random.normal(150, 30)

    # X = np.array([[duration, bwd_len, pkt_std]])
    # X_scaled = SCALER.transform(X)
    X = pd.DataFrame([[duration, bwd_len, pkt_std]], columns=MODEL_FEATURES)
    X_scaled = SCALER.transform(X)
    prediction = MODEL.predict(X_scaled)[0]
    confidence = MODEL.predict_proba(X_scaled)[0][1]

    print(f"[DEBUG] Prediction={prediction} | Confidence={confidence:.4f}")

    # Only log threats
    if prediction == 1 and confidence > 0.4:
        ip = f"192.168.1.{random.randint(1, 255)}"
        respond_to_threat("Live Threat", ip, confidence, source="sniffer")

        # Log to realtime incidents CSV
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lat, lon = 28.61 + random.uniform(-0.2, 0.2), 77.20 + random.uniform(-0.2, 0.2)
        with open(REALTIME_LOG, "a", encoding='utf-8') as f:
            f.write(f"{timestamp},Live Threat,{ip},{confidence:.4f},sniffer,1,Logged from sniffer,{lat:.5f},{lon:.5f}\n")
            print(f"[LIVE] {ip} → Confidence: {confidence:.4f} | Logged to realtime_incidents.csv")

    time.sleep(2)