"""DDoS and Traffic Anomaly Machine Learning Training Pipeline for CyberShield AI.

Workflow:
1. Load dataset from app/ml/datasets/ddos_dataset.csv or generate synthetic network flow dataset
   (1000 normal baseline flows and 1000 DDoS/volumetric attack flows).
2. Extract standardized network features via NETWORK_FEATURE_NAMES.
3. Scale features via StandardScaler.
4. Train RandomForestClassifier (supervised) and IsolationForest (unsupervised anomaly detector).
5. Evaluate classification metrics on holdout test set.
6. Serialize models and scaler to app/ml/trained_models/.
"""

import os
import sys
import random
import csv
from datetime import datetime

# Add project root to sys.path so app modules import cleanly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from app.ml.feature_extractors import NETWORK_FEATURE_NAMES


def generate_synthetic_ddos_dataset() -> tuple:
    """Generate 1,000 benign normal traffic flows and 1,000 DDoS attack flows.
    
    NOTE: This synthetic dataset models empirical distributions from standard network
    benchmarks (e.g. CIC-IDS-2017 / CAIDA) for training demonstration purposes.
    """
    random.seed(42)

    data_rows = []
    labels = []

    # 1. Normal / Benign Traffic Flows (1,000 samples)
    for _ in range(1000):
        packet_count = random.randint(10, 500)
        duration = random.uniform(2.0, 180.0)
        unique_src_ips = random.randint(1, min(25, packet_count))
        unique_dst_ips = random.randint(1, 5)
        unique_dst_ports = random.randint(4, 50)
        avg_pkt_size = random.uniform(300.0, 1400.0)
        src_ip_concentration = random.uniform(0.04, 0.35)
        port_diversity = unique_dst_ports
        syn_ratio = random.uniform(0.01, 0.15)
        packet_rate = packet_count / duration
        byte_rate = (packet_count * avg_pkt_size) / duration

        data_rows.append([
            packet_count, duration, unique_src_ips, unique_dst_ips,
            unique_dst_ports, avg_pkt_size, src_ip_concentration,
            port_diversity, syn_ratio, packet_rate, byte_rate
        ])
        labels.append(0)  # Normal

    # 2. DDoS Attack Flows (1,000 samples)
    # Types: SYN Flood, Volumetric UDP Flood, Distributed Botnet Flood
    for _ in range(1000):
        attack_type = random.choice(['syn_flood', 'volumetric_flood', 'botnet_ddos'])

        if attack_type == 'syn_flood':
            packet_count = random.randint(1500, 30000)
            duration = random.uniform(0.5, 15.0)
            unique_src_ips = random.randint(1, 10)
            unique_dst_ips = 1
            unique_dst_ports = random.randint(1, 2)  # Target port 80/443
            avg_pkt_size = random.uniform(40.0, 80.0)  # Small TCP SYN packets
            src_ip_concentration = random.uniform(0.75, 0.98)
            port_diversity = unique_dst_ports
            syn_ratio = random.uniform(0.85, 1.0)  # Almost all SYN
        elif attack_type == 'volumetric_flood':
            packet_count = random.randint(5000, 100000)
            duration = random.uniform(0.2, 5.0)
            unique_src_ips = random.randint(50, 400)
            unique_dst_ips = 1
            unique_dst_ports = 1
            avg_pkt_size = random.uniform(1000.0, 1480.0)  # Large UDP datagrams
            src_ip_concentration = random.uniform(0.25, 0.60)
            port_diversity = 1
            syn_ratio = 0.0
        else:  # botnet_ddos
            packet_count = random.randint(10000, 80000)
            duration = random.uniform(5.0, 60.0)
            unique_src_ips = random.randint(1200, 8000)  # Massive distributed botnet
            unique_dst_ips = 1
            unique_dst_ports = random.randint(1, 3)
            avg_pkt_size = random.uniform(200.0, 900.0)
            src_ip_concentration = random.uniform(0.01, 0.05)
            port_diversity = unique_dst_ports
            syn_ratio = random.uniform(0.4, 0.7)

        packet_rate = packet_count / duration
        byte_rate = (packet_count * avg_pkt_size) / duration

        data_rows.append([
            packet_count, duration, unique_src_ips, unique_dst_ips,
            unique_dst_ports, avg_pkt_size, src_ip_concentration,
            port_diversity, syn_ratio, packet_rate, byte_rate
        ])
        labels.append(1)  # DDoS / Malicious

    return data_rows, labels


def train_ddos_pipeline():
    """Execute complete dataset handling, feature scaling, model training and serialization."""
    print("=" * 70)
    print("CyberShield AI - DDoS & Traffic Anomaly Model Training Pipeline")
    print("=" * 70)

    if not SKLEARN_AVAILABLE:
        print("[ERROR] scikit-learn, pandas, or numpy is not installed in the environment.")
        return False

    base_dir = os.path.dirname(os.path.abspath(__file__))
    datasets_dir = os.path.join(base_dir, 'datasets')
    models_dir = os.path.join(base_dir, 'trained_models')
    os.makedirs(datasets_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    dataset_path = os.path.join(datasets_dir, 'ddos_dataset.csv')

    # Step 1: Load or Generate Dataset
    if os.path.exists(dataset_path):
        print(f"[*] Loading existing dataset from: {dataset_path}")
        df = pd.read_csv(dataset_path)
        X_raw = df[NETWORK_FEATURE_NAMES].values
        labels = df['label'].tolist()
    else:
        print("[*] Dataset not found at app/ml/datasets/ddos_dataset.csv.")
        print("[*] Generating synthetic DDoS telemetry dataset (1,000 Normal, 1,000 Attack flows)...")
        X_raw, labels = generate_synthetic_ddos_dataset()

        # Save synthetic dataset to disk for provenance
        with open(dataset_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(NETWORK_FEATURE_NAMES + ['label', 'notes'])
            for row, l in zip(X_raw, labels):
                writer.writerow(row + [l, 'Synthetic DDoS telemetry generated by CyberShield AI'])
        print(f"[+] Saved synthetic dataset to: {dataset_path}")

    X = np.array(X_raw, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    print(f"[*] Total flow records: {len(y)} (Normal: {list(y).count(0)}, DDoS Attack: {list(y).count(1)})")

    # Step 2: Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Split complete: Training set = {X_train.shape[0]}, Test set = {X_test.shape[0]}")

    # Step 3: Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Step 4: Supervised Classifier (RandomForest)
    print("\n[*] Training Supervised Model: RandomForestClassifier (n_estimators=100)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    # Step 5: Unsupervised Anomaly Detector (IsolationForest)
    print("[*] Training Unsupervised Model: IsolationForest (contamination=0.1)...")
    iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso_forest.fit(X_train_scaled[y_train == 0])  # Fit on benign baseline

    # Step 6: Evaluation
    y_pred_rf = rf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred_rf)
    prec = precision_score(y_test, y_pred_rf, zero_division=0)
    rec = recall_score(y_test, y_pred_rf, zero_division=0)
    f1 = f1_score(y_test, y_pred_rf, zero_division=0)
    cm = confusion_matrix(y_test, y_pred_rf)

    print("\n" + "=" * 70)
    print("DDoS DETECTION MODEL EVALUATION (Test Set)")
    print("=" * 70)
    print(f"  Accuracy  : {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print(f"  Confusion Matrix (TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}):")
    print(f"    [[{cm[0,0]:3d}, {cm[0,1]:3d}],")
    print(f"     [{cm[1,0]:3d}, {cm[1,1]:3d}]]")

    # Step 7: Serialize Models and Scaler
    model_dest = os.path.join(models_dir, 'ddos_model.pkl')
    scaler_dest = os.path.join(models_dir, 'ddos_scaler.pkl')
    iso_dest = os.path.join(models_dir, 'ddos_iso_forest.pkl')

    joblib.dump(rf, model_dest)
    joblib.dump(scaler, scaler_dest)
    joblib.dump(iso_forest, iso_dest)

    print("\n" + "=" * 70)
    print(f"[+] Serialized DDoS model saved to       : {model_dest}")
    print(f"[+] Feature scaler saved to             : {scaler_dest}")
    print(f"[+] IsolationForest detector saved to   : {iso_dest}")
    print("=" * 70)
    print("[SUCCESS] DDoS model training pipeline completed successfully!\n")
    return True


if __name__ == '__main__':
    train_ddos_pipeline()
