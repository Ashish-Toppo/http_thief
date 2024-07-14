import pandas as pd
from scapy.all import sniff, TCP, IP
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
import joblib

# Function to capture TCP packets and extract features (replace with actual implementation)
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

# Function to train machine learning model
def train_model(df):
   # Prepare data for training
    X = df.drop(columns=['protocol'])  # Features
    y = df['protocol']  # Target variable

    # Preprocessing and model pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), ['source_ip', 'destination_ip'])
        ]
    )

    model = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', DecisionTreeClassifier(max_depth=5, random_state=42))
    ])

    # Train model
    model.fit(X, y)

    # Save the trained model to a file
    model_filename = 'trained_model.pkl'
    joblib.dump(model, model_filename)
    print(f"Trained model saved as '{model_filename}'.")

    # Evaluate model performance on training set
    y_pred_train = model.predict(X)
    train_accuracy = accuracy_score(y, y_pred_train)
    print(f"Training accuracy: {train_accuracy}")

def main():
    # Capture packets and extract features
    df = capture_packets_and_extract_features()

    # print the captured data
    print(df)

    # Train machine learning model
    train_model(df)

if __name__ == "__main__":
    main()
