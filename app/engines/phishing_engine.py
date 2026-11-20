"""Phishing URL Detection Engine for CyberShield AI.

Features:
- Deterministic URL lexical and structural feature extraction
- Machine Learning inference using trained Random Forest classifier
- Heuristic fallback with weighted security indicator rules
- Full compliance with shared CyberShield AI engine format
"""

import os
import re
import math
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, Any, List, Optional

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

from app.engines.risk_engine import calculate_risk_level


SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'update', 'confirm', 'account',
    'banking', 'verify', 'paypal', 'amazon', 'microsoft'
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'shorturl.at',
    'rb.gy', 'cutt.ly', 'tiny.cc'
}

COMMON_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.biz',
    '.info', '.xyz', '.top', '.club', '.online', '.site',
    '.shop', '.vip', '.tech', '.work', '.pro', '.ru', '.cn'
]

FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_hyphens', 'num_at', 'num_question',
    'num_equal', 'num_slash', 'num_percent', 'has_ip', 'uses_https',
    'domain_length', 'subdomain_count', 'has_suspicious_keywords',
    'url_entropy', 'digit_count', 'letter_count', 'special_char_count',
    'tld_in_path', 'double_slash_in_path', 'port_in_url', 'url_shortener'
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features(url: str) -> Dict[str, Any]:
    """Extract lexical and structural features from a URL string."""
    if not url:
        url = ''
    raw_url = str(url).strip()
    clean_url = raw_url.lower()

    parse_url = raw_url
    if not (parse_url.startswith('http://') or parse_url.startswith('https://')):
        parse_url = 'http://' + parse_url

    parsed = urlparse(parse_url)
    netloc = parsed.netloc or ''
    path = parsed.path or ''

    # Port extraction
    port_in_url = False
    domain = netloc
    if ':' in netloc:
        domain = netloc.split(':')[0]
        port_in_url = True
    elif parsed.port is not None:
        port_in_url = True

    # Subdomains
    domain_segments = domain.split('.')
    if len(domain_segments) > 2:
        subdomain_count = len(domain_segments) - 2
    else:
        subdomain_count = 0

    # IP check in domain
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    has_ip = bool(ip_pattern.match(domain)) or bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain))

    # TLD in path check
    path_lower = path.lower()
    tld_in_path = any(tld in path_lower for tld in COMMON_TLDS)

    # Double slash in path check
    double_slash_in_path = '//' in path

    # URL shortener check
    domain_lower = domain.lower()
    url_shortener = any(short in domain_lower for short in URL_SHORTENERS)

    # Suspicious keywords
    has_suspicious_keywords = any(kw in clean_url for kw in SUSPICIOUS_KEYWORDS)

    return {
        'url_length': len(raw_url),
        'num_dots': raw_url.count('.'),
        'num_hyphens': raw_url.count('-'),
        'num_at': raw_url.count('@'),
        'num_question': raw_url.count('?'),
        'num_equal': raw_url.count('='),
        'num_slash': raw_url.count('/'),
        'num_percent': raw_url.count('%'),
        'has_ip': has_ip,
        'uses_https': clean_url.startswith('https://'),
        'domain_length': len(domain),
        'subdomain_count': subdomain_count,
        'has_suspicious_keywords': has_suspicious_keywords,
        'url_entropy': round(calculate_entropy(raw_url), 4),
        'digit_count': sum(1 for c in raw_url if c.isdigit()),
        'letter_count': sum(1 for c in raw_url if c.isalpha()),
        'special_char_count': sum(1 for c in raw_url if not c.isalnum()),
        'tld_in_path': tld_in_path,
        'double_slash_in_path': double_slash_in_path,
        'port_in_url': port_in_url,
        'url_shortener': url_shortener
    }


class PhishingEngine:
    """Production-grade Phishing URL Detection Engine."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_loaded = False
        self.model_path = None
        self.scaler_path = None
        self._load_model()

    def _load_model(self):
        """Attempt to load trained ML model and feature scaler."""
        # Search relative to file and project root
        current_dir = os.path.dirname(os.path.abspath(__file__))
        app_dir = os.path.abspath(os.path.join(current_dir, '..'))
        models_dir = os.path.join(app_dir, 'ml', 'trained_models')

        model_file = os.path.join(models_dir, 'phishing_model.pkl')
        scaler_file = os.path.join(models_dir, 'phishing_scaler.pkl')

        self.model_path = model_file
        self.scaler_path = scaler_file

        if joblib and os.path.exists(model_file):
            try:
                self.model = joblib.load(model_file)
                if os.path.exists(scaler_file):
                    self.scaler = joblib.load(scaler_file)
                self.model_loaded = True
            except Exception as e:
                self.model_loaded = False
                self.model = None
                self.scaler = None
        else:
            self.model_loaded = False

    def reload_model(self):
        """Force reloading model from disk."""
        self._load_model()
        return self.model_loaded

    def get_model_info(self) -> Dict[str, Any]:
        """Return information about the active detection model."""
        return {
            'engine': 'PhishingEngine',
            'model_loaded': self.model_loaded,
            'model_type': type(self.model).__name__ if self.model else 'Heuristic Rule-Based Engine',
            'model_path': self.model_path if os.path.exists(self.model_path or '') else None,
            'scaler_loaded': self.scaler is not None,
            'feature_count': len(FEATURE_NAMES),
            'features': FEATURE_NAMES
        }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a URL for phishing characteristics using ML or rule-based heuristics."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if not url or not isinstance(url, str) or not url.strip():
            return {
                'success': False,
                'result': 'Invalid Input',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.0,
                'indicators': ['Empty or missing URL string provided'],
                'model_used': 'Input Validator',
                'details': {'error': 'No URL provided for analysis'},
                'timestamp': timestamp
            }

        url_str = url.strip()
        features = extract_url_features(url_str)
        indicators = []
        is_phishing_indicator = False

        # Evaluate heuristic indicator triggers
        if features['has_ip']:
            indicators.append("Host contains direct IP address instead of domain name")
            is_phishing_indicator = True

        if features['url_shortener']:
            indicators.append("URL uses URL shortening service to conceal true destination")

        if features['has_suspicious_keywords'] and not features['uses_https']:
            indicators.append("Insecure HTTP protocol used with credential/banking target keywords")
        elif features['has_suspicious_keywords']:
            indicators.append("Sensitive target keywords (login/account/verify/banking) present in URL")

        if features['subdomain_count'] > 3:
            indicators.append(f"Excessive subdomain depth detected ({features['subdomain_count']} subdomains)")

        if features['num_hyphens'] > 3:
            indicators.append(f"High number of hyphens ({features['num_hyphens']}) indicating deceptive naming")

        if features['url_length'] > 100:
            indicators.append(f"Abnormally long URL string ({features['url_length']} characters)")

        if features['num_dots'] > 5:
            indicators.append(f"Excessive dots ({features['num_dots']}) in URL structure")

        if features['num_at'] > 0:
            indicators.append("URL contains '@' symbol, which may truncate target authority in browsers")

        if features['tld_in_path']:
            indicators.append("Common top-level domain extension embedded within path segment")

        if features['double_slash_in_path']:
            indicators.append("Suspicious double slash redirection sequence '//' in URL path")

        if features['port_in_url']:
            indicators.append("Non-standard port specified directly in URL host")

        if features['url_entropy'] > 4.5:
            indicators.append(f"High Shannon entropy ({features['url_entropy']}) indicating randomized or obfuscated characters")

        # Decision mechanism: Machine Learning or Heuristic Rules
        if self.model_loaded and self.model is not None and np is not None:
            try:
                # Prepare feature vector in exact order
                feature_vector = [
                    float(1 if features[f] is True else (0 if features[f] is False else features[f]))
                    for f in FEATURE_NAMES
                ]
                X = np.array([feature_vector], dtype=np.float32)

                if self.scaler is not None:
                    X = self.scaler.transform(X)

                prediction = self.model.predict(X)[0]
                if hasattr(self.model, 'predict_proba'):
                    probabilities = self.model.predict_proba(X)[0]
                    # Index 1 is Phishing
                    prob_phishing = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
                else:
                    prob_phishing = 1.0 if prediction == 1 else 0.0

                risk_score = int(round(prob_phishing * 100))
                confidence = round(float(max(prob_phishing, 1.0 - prob_phishing)), 2)
                model_used = f"RandomForestClassifier (ML) v1.0"
            except Exception as e:
                # Fallback to heuristics if ML inference encounters unexpected error
                risk_score, confidence, model_used = self._compute_heuristic_score(features)
                indicators.append(f"Notice: ML inference fallback engaged ({str(e)})")
        else:
            risk_score, confidence, model_used = self._compute_heuristic_score(features)

        # Normalize to 0-100 range
        risk_score = max(0, min(100, risk_score))
        risk_level = calculate_risk_level(risk_score)

        # Determine categorical result
        if risk_score >= 60:
            result = 'Phishing'
        elif risk_score >= 35:
            result = 'Suspicious'
        else:
            result = 'Legitimate'

        # Ensure at least one indicator if classified suspicious/phishing
        if (result in ('Phishing', 'Suspicious')) and not indicators:
            indicators.append("Accumulated structural anomalies exceed legitimate baseline threshold")
        elif result == 'Legitimate' and not indicators:
            indicators.append("Standard domain topology and clean lexical structure verified")

        return {
            'success': True,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'indicators': indicators,
            'model_used': model_used,
            'details': {
                'url': url_str,
                'features': features,
                'is_phishing_indicator': is_phishing_indicator,
                'heuristic_score': risk_score
            },
            'timestamp': timestamp
        }

    def _compute_heuristic_score(self, features: Dict[str, Any]) -> tuple:
        """Compute rule-based heuristic risk score strictly following specification."""
        score = 0

        # has_ip: +30 points
        if features['has_ip']:
            score += 30

        # url_shortener: +20 points
        if features['url_shortener']:
            score += 20

        # has_suspicious_keywords AND not uses_https: +25 points
        if features['has_suspicious_keywords'] and not features['uses_https']:
            score += 25
        elif features['has_suspicious_keywords']:
            score += 15

        # subdomain_count > 3: +15 points
        if features['subdomain_count'] > 3:
            score += 15

        # num_hyphens > 3: +10 points
        if features['num_hyphens'] > 3:
            score += 10

        # url_length > 100: +10 points
        if features['url_length'] > 100:
            score += 10

        # num_dots > 5: +10 points
        if features['num_dots'] > 5:
            score += 10

        # has_at: +20 points
        if features['num_at'] > 0:
            score += 20

        # tld_in_path: +15 points
        if features['tld_in_path']:
            score += 15

        # Additional structural penalties
        if features['double_slash_in_path']:
            score += 15
        if features['port_in_url']:
            score += 10
        if features['url_entropy'] > 4.6:
            score += 10

        # If clean domain and HTTPS without any flags, low score
        if not features['uses_https'] and score == 0:
            score += 10

        normalized_score = max(0, min(100, score))
        confidence = 0.85 if score > 30 or score == 0 else 0.75
        model_used = "Rule-Based Heuristic Scoring Engine"
        return normalized_score, confidence, model_used


# Singleton instance
phishing_engine = PhishingEngine()
