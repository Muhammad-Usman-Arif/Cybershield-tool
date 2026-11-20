"""Model Evaluation and Benchmark Suite for CyberShield AI.

Features:
- Loads serialized ML models and scalers from app/ml/trained_models/
- Executes holdout evaluation on benchmark datasets
- Computes comprehensive classification metrics (Accuracy, Precision, Recall, F1, Confusion Matrix)
- Runs real-world sample URL and network flow inference validations
- Formats and exports results to app/ml/evaluation_results.json
"""

import os
import sys
import json
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import numpy as np
    import pandas as pd
    import joblib
    from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from app.ml.feature_extractors import FEATURE_NAMES, NETWORK_FEATURE_NAMES, extract_url_features_dict


def evaluate_phishing_model() -> dict:
    """Evaluate serialized Phishing URL detection model."""
    print("\n" + "=" * 70)
    print("EVALUATING PHISHING DETECTION MODEL")
    print("=" * 70)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'trained_models', 'phishing_model.pkl')
    scaler_path = os.path.join(base_dir, 'trained_models', 'phishing_scaler.pkl')
    dataset_path = os.path.join(base_dir, 'datasets', 'phishing_dataset.csv')

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print(f"[!] Phishing model or scaler not found in {os.path.join(base_dir, 'trained_models')}")
        return {'status': 'Model not trained yet'}

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    # Load dataset if available
    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        urls = df['url'].tolist()
        y_true = df['label'].tolist()

        X_raw = []
        for u in urls:
            f_dict = extract_url_features_dict(u)
            X_raw.append([f_dict[fname] for fname in FEATURE_NAMES])

        X = np.array(X_raw, dtype=np.float32)
        X_scaled = scaler.transform(X)

        y_pred = model.predict(X_scaled)
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred).tolist()

        report = classification_report(y_true, y_pred, target_names=['Legitimate', 'Phishing'], output_dict=True)
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=['Legitimate', 'Phishing']))
    else:
        acc, prec, rec, f1, cm, report = None, None, None, None, None, {}

    # Real-world URL Sample Inferences
    sample_urls = [
        ("https://www.google.com/search?q=cybersecurity", 0, "Legitimate Google Search"),
        ("https://github.com/torvalds/linux/releases", 0, "Legitimate GitHub Repo"),
        ("http://192.168.1.100/paypal/login.php?update=account", 1, "Phishing IP + Keyword"),
        ("http://secure-login.bank-update.verification.xyz/auth", 1, "Phishing Deceptive TLD + Subdomains"),
        ("http://bit.ly/fake-amazon-security-update-2026", 1, "Phishing Shortener")
    ]

    print("\nReal-World Sample Inferences:")
    sample_results = []
    for test_url, expected_label, description in sample_urls:
        f_dict = extract_url_features_dict(test_url)
        vec = np.array([[f_dict[fn] for fn in FEATURE_NAMES]], dtype=np.float32)
        vec_scaled = scaler.transform(vec)
        pred = int(model.predict(vec_scaled)[0])
        prob = float(model.predict_proba(vec_scaled)[0][1]) if hasattr(model, 'predict_proba') else (1.0 if pred == 1 else 0.0)

        label_str = "Phishing" if pred == 1 else "Legitimate"
        correct = (pred == expected_label)
        status_sym = "[PASS]" if correct else "[FAIL]"
        print(f"  {status_sym} URL: {test_url[:48]}... -> {label_str} (Risk Score: {int(prob*100)}%)")

        sample_results.append({
            'url': test_url,
            'description': description,
            'predicted_class': label_str,
            'probability_phishing': round(prob, 4),
            'correct': correct
        })

    return {
        'model_type': type(model).__name__,
        'dataset_evaluated': dataset_path if os.path.exists(dataset_path) else 'N/A',
        'metrics': {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1_score': f1,
            'confusion_matrix': cm
        },
        'classification_report': report,
        'sample_validations': sample_results
    }


def evaluate_ddos_model() -> dict:
    """Evaluate serialized DDoS detection model."""
    print("\n" + "=" * 70)
    print("EVALUATING DDOS DETECTION MODEL")
    print("=" * 70)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'trained_models', 'ddos_model.pkl')
    scaler_path = os.path.join(base_dir, 'trained_models', 'ddos_scaler.pkl')
    dataset_path = os.path.join(base_dir, 'datasets', 'ddos_dataset.csv')

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):
        print(f"[!] DDoS model or scaler not found in {os.path.join(base_dir, 'trained_models')}")
        return {'status': 'Model not trained yet'}

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        X_raw = df[NETWORK_FEATURE_NAMES].values
        y_true = df['label'].values

        X_scaled = scaler.transform(X_raw)
        y_pred = model.predict(X_scaled)

        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred).tolist()

        report = classification_report(y_true, y_pred, target_names=['Normal', 'DDoS Attack'], output_dict=True)
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=['Normal', 'DDoS Attack']))
    else:
        acc, prec, rec, f1, cm, report = None, None, None, None, None, {}

    # Real-world traffic scenario validations
    sample_flows = [
        ({
            'packet_count': 50, 'duration': 30.0, 'unique_src_ips': 1, 'unique_dst_ips': 2,
            'unique_dst_ports': 12, 'avg_pkt_size': 850.0, 'src_ip_concentration': 0.15,
            'port_diversity': 12, 'syn_ratio': 0.05, 'packet_rate': 1.67, 'byte_rate': 1419.5
        }, 0, "Normal Web Browsing Session"),
        ({
            'packet_count': 15000, 'duration': 1.2, 'unique_src_ips': 1, 'unique_dst_ips': 1,
            'unique_dst_ports': 1, 'avg_pkt_size': 64.0, 'src_ip_concentration': 0.99,
            'port_diversity': 1, 'syn_ratio': 0.98, 'packet_rate': 12500.0, 'byte_rate': 800000.0
        }, 1, "Aggressive TCP SYN Flood Attack"),
        ({
            'packet_count': 50000, 'duration': 10.0, 'unique_src_ips': 4500, 'unique_dst_ips': 1,
            'unique_dst_ports': 2, 'avg_pkt_size': 512.0, 'src_ip_concentration': 0.02,
            'port_diversity': 2, 'syn_ratio': 0.55, 'packet_rate': 5000.0, 'byte_rate': 2560000.0
        }, 1, "Distributed Botnet Volumetric Attack")
    ]

    print("\nSample Flow Inferences:")
    sample_results = []
    for flow_dict, expected_label, description in sample_flows:
        vals = [flow_dict[fn] for fn in NETWORK_FEATURE_NAMES]
        vec = np.array([vals], dtype=np.float32)
        vec_scaled = scaler.transform(vec)
        pred = int(model.predict(vec_scaled)[0])
        prob = float(model.predict_proba(vec_scaled)[0][1]) if hasattr(model, 'predict_proba') else (1.0 if pred == 1 else 0.0)

        label_str = "DDoS Attack" if pred == 1 else "Normal Traffic"
        correct = (pred == expected_label)
        status_sym = "[PASS]" if correct else "[FAIL]"
        print(f"  {status_sym} Scenario: {description} -> {label_str} (Confidence: {int(prob*100)}%)")

        sample_results.append({
            'scenario': description,
            'predicted_class': label_str,
            'probability_attack': round(prob, 4),
            'correct': correct
        })

    return {
        'model_type': type(model).__name__,
        'dataset_evaluated': dataset_path if os.path.exists(dataset_path) else 'N/A',
        'metrics': {
            'accuracy': acc,
            'precision': prec,
            'recall': rec,
            'f1_score': f1,
            'confusion_matrix': cm
        },
        'classification_report': report,
        'sample_validations': sample_results
    }


def run_evaluation():
    """Execute complete model evaluation and write summary report to JSON."""
    if not SKLEARN_AVAILABLE:
        print("[ERROR] scikit-learn and pandas are required for model evaluation.")
        return False

    summary = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'platform': 'CyberShield AI Detection Engines',
        'phishing_model': evaluate_phishing_model(),
        'ddos_model': evaluate_ddos_model()
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_json = os.path.join(base_dir, 'evaluation_results.json')

    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print(f"[+] Evaluation results exported successfully to:\n    {output_json}")
    print("=" * 70)
    return True


if __name__ == '__main__':
    run_evaluation()
