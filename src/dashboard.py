import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

# --- SETUP ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCIDENT_DIR = os.path.join(BASE_DIR, "incidents")
DEFAULT_CSV = os.path.join(INCIDENT_DIR, "incident_log.csv")
MODEL_FEATURES = ["Flow Duration", "Bwd Packet Length Mean", "Packet Length Std"]

MODEL = None
SCALER = None

# --- PAGE CONFIG ---
st.set_page_config(page_title="🛡️ Cyber Threat Dashboard", layout="wide")
st.title("🛡️ AI-Powered Cyber Threat Dashboard with Prediction")

# --- SIDEBAR: FILE UPLOAD ---
st.sidebar.header("📁 Upload Data")
upload_mode = st.sidebar.radio("Choose input type:", ["🔍 Pre-Detected Log", "🤖 Raw Feature Data"])
uploaded_file = st.sidebar.file_uploader("Upload a CSV file", type=["csv"])

# --- LOAD UNIFIED MODEL ---
def load_mlp_model():
    global MODEL, SCALER
    import joblib
    model_path = os.path.join(BASE_DIR, "mlp_model.pkl")
    scaler_path = os.path.join(BASE_DIR, "scaler.pkl")

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        st.error("❌ Trained model or scaler file not found.")
        return

    MODEL = joblib.load(model_path)
    SCALER = joblib.load(scaler_path)

# --- PREDICT THREATS ON RAW FEATURE DATA ---
def predict_threats(raw_df):
    global MODEL, SCALER
    if MODEL is None:
        load_mlp_model()

    # Check required features
    if not all(f in raw_df.columns for f in MODEL_FEATURES):
        st.error(f"❌ Missing one or more required features: {MODEL_FEATURES}")
        return None

    # Prepare input
    X_raw = raw_df[MODEL_FEATURES].astype("float32")
    X_scaled = SCALER.transform(X_raw)

    preds = MODEL.predict(X_scaled)
    probs = MODEL.predict_proba(X_scaled)

    # Build incidents-like dataframe
    incidents = []
    for i in range(len(preds)):
        if preds[i] == 1:  # Threat
            confidence = round(max(probs[i]), 4)
            ip = f"192.168.1.{(i+1)%255}"
            action = "Alerted and Logged"
            if confidence > 0.95:
                action += " + Quarantined"
            action += " + Simulated IP Block"

            incidents.append({
                "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": "Predicted Threat",
                "ip_address": ip,
                "confidence": confidence,
                "detection_source": "dashboard-MLP",
                "threat_score": 1,
                "action_taken": action
            })

    if not incidents:
        st.info("✅ No threats detected in uploaded data.")
        return None

    return pd.DataFrame(incidents)

# --- LOAD DATA ---
df = None
if uploaded_file:
    if upload_mode == "🔍 Pre-Detected Log":
        df = pd.read_csv(uploaded_file)
    elif upload_mode == "🤖 Raw Feature Data":
        raw_df = pd.read_csv(uploaded_file)
        df = predict_threats(raw_df)

# Fallback to default incident log
if df is None and os.path.exists(DEFAULT_CSV):
    df = pd.read_csv(DEFAULT_CSV)
elif df is None:
    st.warning("⚠️ No data available to display.")
    st.stop()

# Parse timestamps
if "timestamp" in df.columns:
    df["timestamp"] = pd.to_datetime(df["timestamp"])
else:
    st.error("❌ Missing 'timestamp' column.")
    st.stop()

# Default threat score
if "threat_score" not in df.columns:
    df["threat_score"] = 0

# --- FILTERS ---
st.sidebar.header("🔍 Filters")
attack_types = df["attack_type"].dropna().unique().tolist()
selected_attack_types = st.sidebar.multiselect("Attack Types", attack_types, default=attack_types)

ip_addresses = df["ip_address"].dropna().unique().tolist()
selected_ips = st.sidebar.multiselect("IP Addresses", ip_addresses, default=ip_addresses[:10])

filtered_df = df[df["attack_type"].isin(selected_attack_types)]
filtered_df = filtered_df[filtered_df["ip_address"].isin(selected_ips)]

# --- SUMMARY METRICS ---
st.subheader("📊 Summary")
col1, col2, col3 = st.columns(3)
col1.metric("Total Incidents", len(filtered_df))
col2.metric("Unique IPs", filtered_df["ip_address"].nunique())
col3.metric("Attack Types", filtered_df["attack_type"].nunique())

# --- FREQUENCY CHART ---
st.subheader("⚠️ Attack Type Frequency")
st.bar_chart(filtered_df["attack_type"].value_counts())

# --- TIMELINE ---
st.subheader("📈 Threats Over Time")
df_time = filtered_df.set_index("timestamp").resample("1min").count()["attack_type"]
st.line_chart(df_time)

# --- TOP IPs ---
st.subheader("🌐 Top IPs by Detections")
top_ips = filtered_df["ip_address"].value_counts().head(10)
st.dataframe(top_ips.reset_index().rename(columns={"index": "IP Address", "ip_address": "Detections"}))

# --- HIGH THREAT SCORE ---
st.subheader("🔥 High Threat Score IPs")
high_threats = filtered_df.groupby("ip_address")["threat_score"].max().sort_values(ascending=False).head(10)
st.dataframe(high_threats.reset_index().rename(columns={"ip_address": "IP Address", "threat_score": "Max Threat Score"}))

# --- RAW LOG VIEW ---
with st.expander("🗂 Raw Incident Log"):
    st.dataframe(filtered_df)
