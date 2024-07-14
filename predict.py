import pandas as pd
from scapy.all import sniff, TCP, IP
from sklearn.pipeline import Pipeline
import joblib
import sys

# function to print result in a file
def print_dataframe_to_file(filename, df):
    with open(filename, 'w') as file:
        file.write(df.to_string(index=False) + '\n')

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

# Function to load trained model and make predictions on new data
def load_and_predict(model_filename='trained_model.pkl', packet_count=100):
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

    #print data frame to file
    print_dataframe_to_file('predictions.csv', df)
    
    print("The predictions are printed in the predictions.csv file")


# Main function
if __name__ == "__main__":
    load_and_predict(model_filename='trained_model.pkl', packet_count=100)
