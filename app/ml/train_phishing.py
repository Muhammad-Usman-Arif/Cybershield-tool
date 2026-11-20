"""Phishing URL Machine Learning Model Training Pipeline for CyberShield AI.

Workflow:
1. Load dataset from app/ml/datasets/phishing_dataset.csv or generate synthetic dataset
   (1000 legitimate and 1000 phishing URLs with documented synthetic origin).
2. Extract lexical and structural features via feature_extractors.
3. Standardize features with StandardScaler.
4. Perform 80/20 train/test split.
5. Train and evaluate RandomForestClassifier and LogisticRegression.
6. Select the superior model by F1 score and serialize to app/ml/trained_models/.
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
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from app.ml.feature_extractors import FEATURE_NAMES, extract_url_features_dict, extract_url_features


def generate_synthetic_phishing_dataset() -> tuple:
    """Generate 1,000 legitimate and 1,000 phishing URLs for research/demonstration.
    
    NOTE: This synthetic dataset is generated programmatically using known empirical
    phishing heuristics and standard alexa/tranco top-domain structures for training
    and offline model demonstration.
    """
    random.seed(42)

    legit_domains = [
        'google.com', 'youtube.com', 'github.com', 'wikipedia.org',
        'amazon.com', 'microsoft.com', 'linkedin.com', 'reddit.com',
        'apple.com', 'stackoverflow.com', 'netflix.com', 'cnn.com',
        'bbc.co.uk', 'twitter.com', 'nytimes.com', 'cloudflare.com',
        'mozilla.org', 'wordpress.org', 'adobe.com', 'spotify.com',
        'dropbox.com', 'zoom.us', 'slack.com', 'salesforce.com',
        'medium.com', 'quora.com', 'nih.gov', 'mit.edu', 'stanford.edu'
    ]

    legit_paths = [
        '', '/', '/about', '/contact', '/docs/api/v2', '/articles/2026/cybersecurity',
        '/products/software/enterprise', '/search?q=network+security&category=tech',
        '/help/center/faq', '/wiki/Machine_learning', '/user/profile/overview',
        '/pricing/plans', '/blog/latest-updates', '/download/release-notes'
    ]

    legitimate_urls = []
    for _ in range(1000):
        dom = random.choice(legit_domains)
        path = random.choice(legit_paths)
        scheme = 'https://' if random.random() > 0.05 else 'http://'
        sub = 'www.' if random.random() > 0.5 else ('api.' if random.random() > 0.8 else '')
        legitimate_urls.append(f"{scheme}{sub}{dom}{path}")

    # Known phishing patterns
    phish_targets = ['paypal', 'amazon', 'microsoft', 'apple', 'chase', 'wellsfargo', 'netflix', 'binance', 'google']
    phish_keywords = ['login', 'verify', 'update', 'confirm', 'account', 'secure', 'banking', 'recovery', 'signin', 'wallet']
    tlds = ['.xyz', '.top', '.club', '.online', '.site', '.ru', '.cn', '.info', '.biz', '.cc']
    shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 'shorturl.at', 't.co']

    phishing_urls = []
    for _ in range(1000):
        pattern_type = random.randint(1, 8)
        target = random.choice(phish_targets)
        kw = random.choice(phish_keywords)
        tld = random.choice(tlds)

        if pattern_type == 1:
            # IP address in domain
            ip = f"{random.randint(40, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            phishing_urls.append(f"http://{ip}:{random.choice([8080, 8443, 80])}/{target}/{kw}-account.php?id={random.randint(1000, 9999)}")
        elif pattern_type == 2:
            # Excessive subdomains with target brand impersonation
            phishing_urls.append(f"http://{kw}.{target}.account-verification.secure-portal{tld}/index.html")
        elif pattern_type == 3:
            # Hyphenated deceptive domain
            phishing_urls.append(f"http://{target}-{kw}-security-center-update{tld}/auth/login.aspx?ref=session")
        elif pattern_type == 4:
            # Insecure HTTP with credential action keywords and TLD in path
            phishing_urls.append(f"http://security-check-portal{tld}/{target}.com/login/verify.html")
        elif pattern_type == 5:
            # High entropy randomized domain
            entropy_str = "".join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(14, 22)))
            phishing_urls.append(f"http://{entropy_str}{tld}/{target}/{kw}")
        elif pattern_type == 6:
            # URL shortener hiding target
            short = random.choice(shorteners)
            phishing_urls.append(f"http://{short}/{target}-{random.randint(1000, 9999)}")
        elif pattern_type == 7:
            # @ symbol spoofing / double slashes
            phishing_urls.append(f"http://{target}.com@phish-gateway{tld}//login.php?user={kw}")
        else:
            # Long URL with numerous parameters and dots
            phishing_urls.append(f"http://www.{target}.com.{kw}.portal.access-verification{tld}/signin?redirect=true&token={random.randint(100000, 999999)}&auth=false")

    urls = legitimate_urls + phishing_urls
    labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

    return urls, labels


def train_phishing_pipeline():
    """Execute complete dataset loading/generation, feature extraction, training and serialization."""
    print("=" * 70)
    print("CyberShield AI - Phishing Detection Model Training Pipeline")
    print("=" * 70)

    if not SKLEARN_AVAILABLE:
        print("[ERROR] scikit-learn, pandas, or numpy is not installed in the environment.")
        return False

    base_dir = os.path.dirname(os.path.abspath(__file__))
    datasets_dir = os.path.join(base_dir, 'datasets')
    models_dir = os.path.join(base_dir, 'trained_models')
    os.makedirs(datasets_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    dataset_path = os.path.join(datasets_dir, 'phishing_dataset.csv')

    # Step 1: Load or Generate Dataset
    if os.path.exists(dataset_path):
        print(f"[*] Loading existing dataset from: {dataset_path}")
        df = pd.read_csv(dataset_path)
        urls = df['url'].tolist()
        labels = df['label'].tolist()
    else:
        print("[*] Dataset not found at app/ml/datasets/phishing_dataset.csv.")
        print("[*] Generating synthetic training dataset (1,000 Legitimate, 1,000 Phishing)...")
        urls, labels = generate_synthetic_phishing_dataset()

        # Save synthetic dataset to disk for provenance
        with open(dataset_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label', 'notes'])
            for u, l in zip(urls, labels):
                writer.writerow([u, l, 'Synthetic demonstration URL generated by CyberShield AI'])
        print(f"[+] Saved synthetic dataset to: {dataset_path}")

    print(f"[*] Total samples: {len(urls)} (Legitimate: {labels.count(0)}, Phishing: {labels.count(1)})")

    # Step 2: Feature Extraction
    print(f"[*] Extracting {len(FEATURE_NAMES)} features per URL...")
    X_raw = []
    for u in urls:
        f_dict = extract_url_features_dict(u)
        X_raw.append([f_dict[fname] for fname in FEATURE_NAMES])

    X = np.array(X_raw, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    # Step 3: Train / Test Split (80 / 20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Split complete: Training set = {X_train.shape[0]} samples, Test set = {X_test.shape[0]} samples")

    # Step 4: Feature Normalization (StandardScaler)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Step 5: Train Models
    print("\n[*] Training Model 1: RandomForestClassifier (n_estimators=100)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    print("[*] Training Model 2: LogisticRegression...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train_scaled, y_train)

    # Step 6: Evaluation
    models = {
        'RandomForestClassifier': rf,
        'LogisticRegression': lr
    }

    best_model_name = None
    best_f1 = -1.0
    best_model = None
    eval_reports = {}

    print("\n" + "=" * 70)
    print("EVALUATION RESULTS ON TEST SET (20% Holdout)")
    print("=" * 70)

    for name, model in models.items():
        y_pred = model.predict(X_test_scaled)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        eval_reports[name] = {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist()
        }

        print(f"\n--- {name} ---")
        print(f"  Accuracy  : {acc:.4f} ({acc*100:.2f}%)")
        print(f"  Precision : {prec:.4f}")
        print(f"  Recall    : {rec:.4f}")
        print(f"  F1 Score  : {f1:.4f}")
        print(f"  Confusion Matrix (TN={cm[0,0]}, FP={cm[0,1]}, FN={cm[1,0]}, TP={cm[1,1]}):")
        print(f"    [[{cm[0,0]:3d}, {cm[0,1]:3d}],")
        print(f"     [{cm[1,0]:3d}, {cm[1,1]:3d}]]")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = model

    # Step 7: Serialize Best Model and Scaler
    print("\n" + "=" * 70)
    print(f"[*] Best model: {best_model_name} with F1-Score of {best_f1:.4f}")

    model_dest = os.path.join(models_dir, 'phishing_model.pkl')
    scaler_dest = os.path.join(models_dir, 'phishing_scaler.pkl')

    joblib.dump(best_model, model_dest)
    joblib.dump(scaler, scaler_dest)

    print(f"[+] Serialized model saved to : {model_dest}")
    print(f"[+] Feature scaler saved to   : {scaler_dest}")
    print("=" * 70)
    print("[SUCCESS] Phishing model training pipeline completed successfully!\n")
    return True


if __name__ == '__main__':
    train_phishing_pipeline()
