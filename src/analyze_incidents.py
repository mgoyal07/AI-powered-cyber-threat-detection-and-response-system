import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Absolute path setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCIDENT_DIR = os.path.join(BASE_DIR, "incidents")
CSV_PATH = os.path.join(INCIDENT_DIR, "incident_log.csv")
PLOT_PATH = os.path.join(INCIDENT_DIR, "threats_over_time.png")

# Load incident log CSV
if not os.path.exists(CSV_PATH):
    print(f"❌ No incident log found at: {CSV_PATH}")
    exit()

df = pd.read_csv(CSV_PATH)

# Print the first few entries
print("\n🔍 Sample Incidents:")
print(df.head())

# Total incidents
print(f"\n📊 Total incidents logged: {len(df)}")

# Attack type count
attack_counts = df["attack_type"].value_counts()
print("\n⚠️ Attack types frequency:")
print(attack_counts)

# Top IPs
ip_counts = df["ip_address"].value_counts().head(5)
print("\n🌐 Top 5 IPs involved in attacks:")
print(ip_counts)

# Plot attacks over time
df["timestamp"] = pd.to_datetime(df["timestamp"])
df.set_index("timestamp", inplace=True)

plt.figure(figsize=(10, 5))
df["attack_type"].resample("1min").count().plot()
plt.title("🚨 Threats Detected Over Time")
plt.xlabel("Time")
plt.ylabel("Detections per Minute")
plt.tight_layout()
plt.savefig(PLOT_PATH)
print(f"\n📈 Saved plot: {PLOT_PATH}")

# Reset index for further analysis
df.reset_index(inplace=True)
