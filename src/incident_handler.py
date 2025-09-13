import os
import csv
import json
import datetime
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from twilio.rest import Client
import random

SENDER_EMAIL = "m49991847@gmail.com"
SENDER_PASSWORD = ""  # Preferably use an App Password
RECEIVER_EMAIL = "goyal.mridul.07@gmail.com"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCIDENT_DIR = os.path.join(BASE_DIR, "incidents")
os.makedirs(INCIDENT_DIR, exist_ok=True)

collected_incidents = []
ip_threat_count = {}

WEBHOOK_URL = "https://discord.com/api/webhooks/1392833415493193788/cI4kJziLfqWLcfFNsLkhrPF_dZqqOfKpppWC3eenQKMzF-lMPLAKMaD0zQOkoB1lFVYS"  # Replace this

def respond_to_threat(attack_type, ip_address, confidence, source="flask"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_threat_count[ip_address] = ip_threat_count.get(ip_address, 0) + 1
    threat_score = ip_threat_count[ip_address]

    actions = ["Alerted and Logged"]
    
    if confidence > 0.85:
        actions.append("Quarantined")
        isolate_ip(ip_address)
    
    if confidence > 0.65:
        actions.append("Firewall Rule Applied")
        apply_firewall_rule(ip_address)

    if confidence > 0.5:
        actions.append("SMS/API Alert Sent")
        send_sms_alert(ip_address, attack_type, confidence)
    
    actions.append("Simulated IP Block")

    latitude = round(random.uniform(28.4, 28.7), 5)     # near Delhi
    longitude = round(random.uniform(77.0, 77.4), 5)

    incident = {
        "timestamp": timestamp,
        "attack_type": attack_type,
        "ip_address": ip_address,
        "confidence": confidence,
        "detection_source": source,
        "threat_score": threat_score,
        "action_taken": " + ".join(actions),
        "latitude": latitude,
        "longitude": longitude
    }

    print(f"[ALERT] {attack_type} from {ip_address} (Confidence: {confidence})")
    send_webhook_alert(incident)
    # send_sms_alert(ip_address, attack_type, confidence)
    save_to_csv(os.path.join(INCIDENT_DIR, "incident_log.csv"), incident)
    save_to_csv(os.path.join(INCIDENT_DIR, "realtime_incidents.csv"), incident)

def save_to_csv(csv_path, incident):
    exists = os.path.isfile(csv_path)
    with open(csv_path, "a", newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=incident.keys())
        if not exists:
            writer.writeheader()
        writer.writerow(incident)

def send_webhook_alert(incident):
    try:
        message = (
            f"🚨 {incident['attack_type']} detected from {incident['ip_address']}\n"
            f"Confidence: {incident['confidence']} | Score: {incident.get('threat_score', 1)}\n"
            f"Action: {incident['action_taken']}"
        )
        r = requests.post(WEBHOOK_URL, json={"content": message})
        if r.status_code in [200, 204]:
            print("🔔 Webhook sent.")
    except Exception as e:
        print(f"Webhook error: {e}")

def apply_firewall_rule(ip):
    print(f"🛡️ Simulated firewall rule applied to block {ip}")

# def send_sms_alert(ip, attack, confidence):
#     print(f"📲 SMS Alert: {attack} from {ip} (Confidence: {confidence}) [Simulated]")

def send_sms_alert(ip, attack_type, confidence):
    from twilio.rest import Client

    account_sid = ""
    auth_token = ""
    from_number = ""  # Your Twilio number
    to_number = ""  # Your verified personal number

    message = f"🚨 {attack_type} detected from {ip}. Confidence: {confidence}"

    try:
        client = Client(account_sid, auth_token)
        msg = client.messages.create(
            body=message,
            from_=from_number,
            to=to_number
        )
        print(f"📲 SMS sent: {msg.sid}")
    except Exception as e:
        print(f"❌ SMS failed: {e}")


def isolate_ip(ip):
    quarantine_file = os.path.join(INCIDENT_DIR, "isolated_ips.txt")
    timestamp = datetime.datetime.now().isoformat()
    with open(quarantine_file, "a") as file:
        file.write(f"{ip},{timestamp}\n")
    print(f"🚫 IP {ip} added to isolation list (isolated_ips.txt)")










