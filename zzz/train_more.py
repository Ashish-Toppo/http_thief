import pandas as pd
from scapy.all import sniff, TCP, IP
from sklearn.pipeline import Pipeline
import joblib

# Function to capture TCP packets and extract features using Scapy
def capture_packets_and_extract_features(packet_count=100):
    packets = sniff(count=packet_count, filter="tcp")  # Capture TCP packets (adjust count as needed)

    # Extract features from captured packets
    features = []
    for packet in packets:
        if TCP in packet and IP in packet:  # Check if packet is TCP and IP
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            protocol = "HTTP" if packet[TCP].dport == 80 else "HTTPS" if packet[TCP].dport == 443 else "Other"
            features.append({"source_ip": source_ip, "destination_ip": destination_ip, "protocol": protocol})

    return pd.DataFrame(features)

# Function to load trained model and continue training with new data
def load_and_train_more(model_filename='trained_model.pkl', packet_count=100):
    # Load the trained model and the preprocessor from file
    try:
        pipeline = joblib.load(model_filename)
        print(f"Loaded model and preprocessor from '{model_filename}'")
    except FileNotFoundError:
        print(f"Error: '{model_filename}' not found.")
        return

    # Capture packets and extract features
    df = capture_packets_and_extract_features(packet_count=packet_count)

    # Prepare data for training
    X = df.drop(columns=['protocol'])  # Features
    y = df['protocol']  # Target variable

    # Continue training the model with new data
    pipeline.fit(X, y)

    # Save the updated model and preprocessor
    joblib.dump(pipeline, model_filename)
    print(f"Updated model and preprocessor saved as '{model_filename}'.")

# Main function
if __name__ == "__main__":
    load_and_train_more(model_filename='trained_model.pkl', packet_count=5000)
