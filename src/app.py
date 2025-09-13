from flask import Flask, render_template, request, redirect
import pandas as pd
import os
import joblib
import datetime
from werkzeug.utils import secure_filename
from incident_handler import respond_to_threat
import random
import numpy as np
import csv
import folium
import threading
from folium.plugins import MarkerCluster
# from packet_sniffer import start_sniffing

from flask import send_file
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
from flask import session
from flask import flash
from flask import session, url_for


def generate_simulated_traffic(n=5):
    data = []
    for _ in range(n):
        duration = np.random.normal(80000, 15000)
        bwd_len = np.random.normal(700, 100)
        pkt_std = np.random.normal(60, 10)
        data.append([duration, bwd_len, pkt_std])
    df = pd.DataFrame(data, columns=MODEL_FEATURES)
    return df

# --- CONFIG ---
app = Flask(__name__)
app.secret_key = "supersecret123"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv"}
MODEL_FEATURES = [" Flow Duration", " Bwd Packet Length Mean", " Packet Length Std"]
MODEL = None
SCALER = None

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "mlp_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
INCIDENT_DIR = os.path.join(BASE_DIR, "incidents")
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(INCIDENT_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- Load model and scaler once ---
def load_model():
    global MODEL, SCALER
    MODEL = joblib.load(MODEL_PATH)
    SCALER = joblib.load(SCALER_PATH)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_ip_and_attack_stats():
    csv_path = os.path.join("incidents", "incident_log.csv")
    if not os.path.exists(csv_path):
        return {}, {}
    df = pd.read_csv(csv_path)
    top_ips = df["ip_address"].value_counts().head(5).to_dict()
    attack_counts = df["attack_type"].value_counts().to_dict()
    return top_ips, attack_counts

def get_recent_threats(n=10, attack_filter=None):
    path = os.path.join("incidents", "incident_log.csv")
    if not os.path.exists(path):
        return []

    df = pd.read_csv(path)

    if attack_filter and attack_filter != "All Attacks":
        df = df[df["attack_type"] == attack_filter]

    return df.sort_values("timestamp", ascending=False).head(n).to_dict(orient="records")

def get_isolated_ips():
    path = os.path.join(INCIDENT_DIR, "isolated_ips.txt")
    if not os.path.exists(path):
        return []
    
    updated_lines = []
    valid_ips = []
    now = datetime.datetime.now()

    with open(path, "r") as f:
        lines = f.readlines()

    for line in lines:
        parts = line.strip().split(",")
        if len(parts) == 2:
            ip, timestamp_str = parts
            try:
                timestamp = datetime.datetime.fromisoformat(timestamp_str)
                if (now - timestamp).total_seconds() <= 3600:  # 1 hour
                    valid_ips.append(ip)
                    updated_lines.append(line)
            except:
                continue

    # Overwrite the file with only valid entries
    with open(path, "w") as f:
        f.writelines(updated_lines)

    return valid_ips

def compute_kpis():
    path = os.path.join(INCIDENT_DIR, "realtime_incidents.csv")
    if not os.path.exists(path):
        return {
            "total_threats": 0,
            "active_ips": 0,
            "last_threat_time": "N/A"
        }

    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    return {
        "total_threats": len(df),
        "active_ips": df["ip_address"].nunique(),
        "last_threat_time": df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S") if not df.empty else "N/A"
    }



@app.route("/", methods=["GET", "POST"])
def index():
    df = None
    results = []
    df_preview = None

    # kpis = {
    # "total_threats": 248,
    # "detection_rate": "92.3",
    # "active_ips": 11,
    # "last_threat_time": "2025-07-12 01:21:20"
    # }

    kpis = compute_kpis()

    # Load logs for filtering regardless of request method
    top_ips, attack_stats = get_ip_and_attack_stats()
    attack_filter = request.form.get("attack_filter", None)
    recent_threats = get_recent_threats(attack_filter=attack_filter)

    # Filter dropdown clicked
    if request.method == "POST" and attack_filter is not None and 'simulate' not in request.form and 'file' not in request.files:
        if attack_filter != "All Attacks":
            recent_threats = [t for t in recent_threats if t["attack_type"] == attack_filter]

        return render_template("index.html", results=[], uploaded=False,
                               df_preview=df_preview, top_ips=top_ips,
                               attack_stats=attack_stats, recent_threats=recent_threats,
                               performance=None, attack_filter=attack_filter)

    # Regular Upload or Simulate
    if request.method == "POST":
        if 'simulate' in request.form:
            df = generate_simulated_traffic()
        elif 'file' in request.files:
            uploaded_file = request.files['file']
            if uploaded_file and allowed_file(uploaded_file.filename):
                df = pd.read_csv(uploaded_file)
            else:
                return redirect(request.url)
        else:
            return redirect(request.url)

        # Validate columns
        if not all(col in df.columns for col in MODEL_FEATURES):
            return render_template("index.html", error=f"❌ CSV must contain: {MODEL_FEATURES}",
                                   uploaded=False, top_ips=top_ips, attack_stats=attack_stats,
                                   recent_threats=recent_threats, performance=None, attack_filter="All Attacks", isolated_ips = isolated_ips, kpis=kpis)

        # Predict
        X = df[MODEL_FEATURES].astype("float32")
        X_scaled = SCALER.transform(X)
        preds = MODEL.predict(X_scaled)
        probs = MODEL.predict_proba(X_scaled)

        for i in range(len(preds)):
            if preds[i] == 1:
                ip = f"192.168.1.{random.randint(1, 255)}"
                confidence = float(np.round(probs[i][1], 4))
                severity = "High" if confidence > 0.9 else "Medium" if confidence > 0.6 else "Low"
                respond_to_threat("Predicted Threat", ip, confidence)
                results.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attack": "Predicted Threat",
                    "ip": ip,
                    "confidence": confidence,
                    "severity": severity
                })

        df.columns = df.columns.str.strip()
        df_preview = df.head().to_html(classes="table table-sm", index=False)

        top_ips, attack_stats = get_ip_and_attack_stats()
        recent_threats = get_recent_threats(attack_filter=attack_filter)
        isolated_ips = get_isolated_ips()

        return render_template("index.html", results=results, uploaded=True,
                               df_preview=df_preview, top_ips=top_ips,
                               attack_stats=attack_stats, recent_threats=recent_threats,
                               performance=None, attack_filter="All Attacks", isolated_ips = isolated_ips, kpis=kpis)
    
    isolated_ips = get_isolated_ips()

    # GET request (first load)
    return render_template("index.html", results=[], uploaded=False,
                           df_preview=None, top_ips=top_ips, attack_stats=attack_stats,
                           recent_threats=recent_threats, performance=None, attack_filter="All Attacks", isolated_ips = isolated_ips, kpis=kpis)


@app.route("/plot/threats")
def plot_threats():
    csv_path = os.path.join(INCIDENT_DIR, "realtime_incidents.csv")
    if not os.path.exists(csv_path):
        return "No data", 404

    # df = pd.read_csv(csv_path)
    df = pd.read_csv(csv_path)
    if df.empty or "timestamp" not in df.columns:
        return "Invalid data", 400

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        return "No valid timestamp data to plot", 400
    
    df = df.set_index("timestamp")
    df = df.sort_index()
    print(df.index.min(), "to", df.index.max())

    # Plot setup
    fig, ax = plt.subplots(figsize=(10, 4))
    df["attack_type"].resample("1min").count().plot(ax=ax, color="crimson")

    ax.set_title("Threats Detected Over Time", fontsize=14)
    ax.set_xlabel("Time")
    ax.set_ylabel("Detections per Minute")
    ax.grid(True)
    plt.tight_layout()

    # Return plot as image
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)
    return send_file(buf, mimetype='image/png')

@app.route("/export")
def export_logs():
    csv_path = os.path.join(INCIDENT_DIR, "incident_log.csv")
    if os.path.exists(csv_path):
        return send_file(csv_path, as_attachment=True)
    return "❌ No log file to export", 404

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Replace with secure DB/auth in future
        if username == "admin" and password == "admin123":
            session["user"] = username
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.before_request
def require_login():
    if request.endpoint not in ("login", "static") and "user" not in session:
        return redirect(url_for("login"))


@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    ip_to_unblock = request.form.get("ip")
    path = os.path.join(INCIDENT_DIR, "isolated_ips.txt")

    if os.path.exists(path):
        with open(path, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            if not line.strip().startswith(ip_to_unblock + ","):
                new_lines.append(line)

        with open(path, "w") as f:
            f.writelines(new_lines)

        print(f"✅ Unblocked IP: {ip_to_unblock}")
    else:
        print("⚠️ No isolated_ips.txt found.")

    return redirect("/")


@app.route("/download_isolated_ips")
def download_isolated_ips():
    path = os.path.join(INCIDENT_DIR, "isolated_ips.txt")
    if not os.path.exists(path):
        return "No isolated IPs found.", 404

    # Convert to CSV
    csv_path = os.path.join(INCIDENT_DIR, "isolated_ips.csv")
    with open(path, "r") as f, open(csv_path, "w", newline='') as out:
        writer = csv.writer(out)
        writer.writerow(["IP Address", "Isolated At"])
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                writer.writerow(parts)

    return send_file(csv_path, as_attachment=True)

@app.route("/map")
def threat_map():
    path = os.path.join(INCIDENT_DIR, "realtime_incidents.csv")
    if not os.path.exists(path):
        return "No threat data found", 404

    df = pd.read_csv(path)
    if "latitude" not in df.columns or "longitude" not in df.columns:
        return "No geolocation data available to plot.", 400
    df = df.dropna(subset=["latitude", "longitude"])

    threat_map = folium.Map(location=[28.6139, 77.2090], zoom_start=6)

    marker_cluster = MarkerCluster().add_to(threat_map)

    print("🧭 Total threats to plot:", len(df))
    print(df[["latitude", "longitude"]].drop_duplicates())

    for _, row in df.iterrows():
        popup_text = f"""
        <strong>{row['attack_type']}</strong><br>
        IP: {row['ip_address']}<br>
        Confidence: {row['confidence']}<br>
        Timestamp: {row['timestamp']}<br>
        Action: {row['action_taken']}
        """
        folium.CircleMarker(
            location=[row["latitude"], row["longitude"]],
            radius=6,
            popup=popup_text,
            color="red" if row["confidence"] > 0.8 else "orange",
            fill=True,
            fill_opacity=0.7
        ).add_to(marker_cluster)  # ✅ Add to cluster now

    map_path = os.path.join(STATIC_DIR, "threat_map.html")
    threat_map.save(map_path)

    return render_template("map_embed.html")


# sniffer_thread = None
# sniffer_running = False

# @app.route("/start_sniffer", methods=["POST"])
# def start_sniffer():
#     global sniffer_thread, sniffer_running
#     if not sniffer_running:
#         sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
#         sniffer_thread.start()
#         sniffer_running = True
#         flash("🛰️ Packet Sniffer Started!", "success")
#     else:
#         flash("Packet sniffer is already running.", "info")
#     return redirect("/")



if __name__ == "__main__":
    load_model()
    print("✅ Model and scaler loaded")
    print("Model classes:", MODEL.classes_)
    # Start packet sniffer thread
    # threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(debug=True)