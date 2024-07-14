import joblib
from scapy.all import sniff, TCP, IP
import pandas as pd

# Function to capture TCP packets and extract features
def capture_packets_and_extract_features(packet_count=1000):
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

# Function to load trained model and predict
def load_and_predict(features):
     # Load the trained model and the preprocessor from file
    try:
        pipeline = joblib.load(model_filename)
        print(f"Loaded model and preprocessor from '{model_filename}'")
    except FileNotFoundError:
        print(f"Error: '{model_filename}' not found.")
        return

    # Capture packets and extract features
    df = capture_packets_and_extract_features(packet_count=packet_count)

    # Prepare data for prediction
    X = df.drop(columns=['protocol'])  # Features

    # Make predictions
    predictions = pipeline.predict(X)
    df['predicted_protocol'] = predictions

    print(df)

# def main():
#     # Capture packets and extract features
#     captured_data_packets = capture_packets_and_extract_features()

#     # prepare data for prediction
#     X = captured_data_packets.drop(columns=['protocol'])  # Features
#     X = pd.get_dummies(X, columns=['source_ip', 'destination_ip'])

#     # Predict using the trained model
#     predict_with_model(X)
    

if __name__ == "__main__":
    load_and_predict(model_filename='trained_model.pkl', packet_count=100)
