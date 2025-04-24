# AI/ML-Based Detection System (IDS)

This repository contains an AI/ML-based Intrusion Detection System (IDS) designed to detect network intrusions using machine learning algorithms. It uses preprocessed network traffic data, extracts relevant features, trains a classifier, and performs real-time or batch predictions.

## Features

- 📦 Preprocessing and feature extraction from raw network traffic.
- 🧠 Machine Learning model training and serialization.
- 🔍 Real-time packet sniffing and attack prediction.
- 📊 Utilizes CICIDS2017 dataset for training/testing.

## Repository Structure

├── extract_features.py # Script for feature extraction from raw data ├── train_model.py # Trains ML model on network data ├── sniff_predict.py # Sniffs network packets and predicts intrusions ├── model.pkl # Pre-trained ML model ├── scaler.pkl # Scaler used to normalize input features ├── top_features_portscan.csv # Selected top features for detection ├── Friday-WorkingHours...csv # Sample dataset used for training/testing ├── LICENSE └── README.md # This file

## Requirements

- Python 3.x
- scikit-learn
- pandas
- numpy
- scapy

Install dependencies with:

```bash
pip install -r requirements.txt
```

Usage

1. Extract Features
```bash
python extract_features.py Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

2. Train a Model
```bash
python train_model.py
```

3. Predict with Real-Time Traffic
```bash
sudo python sniff_predict.py
```

Dataset

This project uses the CICIDS2017 dataset. You can download it from:
https://www.unb.ca/cic/datasets/ids-2017.html

License

This project is licensed under the MIT License. See the LICENSE file for more details.