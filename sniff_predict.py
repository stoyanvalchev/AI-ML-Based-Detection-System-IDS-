# Import necessary libraries
from scapy.all import sniff, IP, TCP  # For packet sniffing and parsing
import time                           # To track timing information for flows
import pandas as pd                   # For handling feature data
import joblib                         # To load the pre-trained ML model and scaler

# Load the trained machine learning model and the associated scaler for preprocessing
model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")

# Define the expected feature columns used by the model
feature_cols = ['Destination Port', 'Flow Duration',
                'Total Fwd Packets', 'Flow Packets/s']

# Dictionary to keep track of active flows and their metadata
flows = {}

# Set to store flow IDs that have already triggered an alert
alerted_flows = set()

# Function to extract flow-level features from each packet


def extract_features(pkt):
    # Only process packets that are both IP and TCP
    if IP in pkt and TCP in pkt:
        ip = pkt[IP]
        tcp = pkt[TCP]

        # Identify a flow by its 4-tuple: source IP, destination IP, source port, destination port
        flow_id = (ip.src, ip.dst, tcp.sport, tcp.dport)
        now = time.time()  # Current timestamp

        # If this is a new flow, initialize its metadata
        if flow_id not in flows:
            flows[flow_id] = {
                'start_time': now,
                'packets': 1
            }
            return flow_id, None  # No features yet for a new flow

        # Otherwise, update the existing flow's packet count
        flows[flow_id]['packets'] += 1

        # Calculate flow duration and packets per second
        duration = now - flows[flow_id]['start_time']
        packets = flows[flow_id]['packets']
        pps = packets / duration if duration > 0 else 0

        # Create a feature dictionary to feed into the ML model
        new_data = {
            'Destination Port': tcp.dport,
            # Convert to microseconds for consistency with training data
            'Flow Duration': duration * 1e6,
            'Total Fwd Packets': packets,
            'Flow Packets/s': pps
        }

        return flow_id, new_data
    return None, None  # Return nothing if packet is not IP/TCP

# Function to make a prediction using the ML model and raise an alert if suspicious


def predict_and_alert(flow_id, flow_data):
    # Avoid duplicate alerts for the same flow
    if flow_id in alerted_flows:
        return

    # Skip very short or sparse flows (likely noise)
    if flow_data['Flow Duration'] < 100000 or flow_data['Total Fwd Packets'] < 3:
        return

    # Convert the flow data to a DataFrame with the correct feature order
    df = pd.DataFrame([flow_data])[feature_cols]

    # Scale the data using the loaded scaler
    X_scaled = scaler.transform(df)

    # Get prediction probabilities and the final class prediction
    proba = model.predict_proba(X_scaled)[0]
    prediction = model.predict(X_scaled)[0]

    # If the model predicts an attack (class 1), raise an alert
    if prediction == 1:
        print(f"🚨 Portscan Detected! Flow: {flow_data}")
        alerted_flows.add(flow_id)
    else:
        print("✅ Normal traffic.")

# Callback function that gets triggered for each sniffed packet


def packet_callback(pkt):
    flow_id, flow_data = extract_features(pkt)
    if flow_data:  # Only predict if enough data has been collected
        predict_and_alert(flow_id, flow_data)


# Start sniffing for TCP packets and process each packet with packet_callback
print("🔍 Sniffing traffic... Press Ctrl+C to stop.")
sniff(filter="tcp", prn=packet_callback, store=0)

# Print the model’s class labels (e.g., [0: Normal, 1: Portscan])
print("🔎 Model classes:", model.classes_)
