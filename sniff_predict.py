from scapy.all import sniff, IP, TCP
import time
import pandas as pd
import joblib

# Load your trained model and scaler
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

# Define expected features
feature_cols = ['Destination Port', 'Flow Duration',
                'Total Fwd Packets', 'Flow Packets/s']

# Cache to track flows
flows = {}

# Set to track alerted flows
alerted_flows = set()


def extract_features(pkt):
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]
        flow_id = (ip.src, ip.dst, tcp.sport, tcp.dport)

        now = time.time()

        if flow_id not in flows:
            flows[flow_id] = {
                'start_time': now,
                'packets': 1
            }
            return flow_id, None
        else:
            flows[flow_id]['packets'] += 1

        duration = now - flows[flow_id]['start_time']
        packets = flows[flow_id]['packets']
        pps = packets / duration if duration > 0 else 0

        # Prepare input for model
        new_data = {
            'Destination Port': tcp.dport,
            'Flow Duration': duration * 1e6,  # convert to microseconds to match dataset scale
            'Total Fwd Packets': packets,
            'Flow Packets/s': pps
        }

        return flow_id, new_data
    return None, None


def predict_and_alert(flow_id, flow_data):
    if flow_id in alerted_flows:
        return

    # Skip flows that are too short or sparse
    if flow_data['Flow Duration'] < 100000 or flow_data['Total Fwd Packets'] < 3:
        return

    df = pd.DataFrame([flow_data])[feature_cols]

    X_scaled = scaler.transform(df)

    proba = model.predict_proba(X_scaled)[0]

    prediction = model.predict(X_scaled)[0]
    if prediction == 1:
        print(f"🚨 Portscan Detected! Flow: {flow_data}")
        alerted_flows.add(flow_id)
    else:
        print("✅ Normal traffic.")


def packet_callback(pkt):
    flow_id, flow_data = extract_features(pkt)
    if flow_data:
        predict_and_alert(flow_id, flow_data)


# Start sniffing (can be run as root for full capture)
print("🔍 Sniffing traffic... Press Ctrl+C to stop.")
sniff(filter="tcp", prn=packet_callback, store=0)
print("🔎 Model classes:", model.classes_)
