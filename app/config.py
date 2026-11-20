"""
CyberShield AI - Application Configuration Profiles
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Ensure environment variables are loaded
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
env_file = os.path.join(basedir, '.env')
if os.path.exists(env_file):
    load_dotenv(env_file)
else:
    load_dotenv()


class Config:
    """Base Configuration with default cybersecurity platform parameters."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'cybershield-insecure-dev-secret-key-change-in-production')

    # Database Configuration
    if os.getenv('VERCEL'):
        SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:////tmp/cybershield.db')
        UPLOAD_FOLDER = '/tmp/uploads'
        REPORTS_FOLDER = '/tmp/reports'
    else:
        SQLALCHEMY_DATABASE_URI = os.getenv(
            'DATABASE_URL',
            f"sqlite:///{os.path.join(basedir, 'cybershield.db')}"
        )
        UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
        if not UPLOAD_FOLDER:
            UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
        elif not os.path.isabs(UPLOAD_FOLDER):
            UPLOAD_FOLDER = os.path.join(basedir, UPLOAD_FOLDER)

        REPORTS_FOLDER = os.getenv('REPORTS_FOLDER')
        if not REPORTS_FOLDER:
            REPORTS_FOLDER = os.path.join(basedir, 'reports')
        elif not os.path.isabs(REPORTS_FOLDER):
            REPORTS_FOLDER = os.path.join(basedir, REPORTS_FOLDER)

    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))

    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Allowed extensions for threat telemetry and artifact uploads
    ALLOWED_EXTENSIONS = {
        'pcap', 'pcapng', 'cap',
        'log', 'txt', 'csv', 'json',
        'exe', 'dll', 'bin',
        'pdf', 'zip'
    }

    # Modular Detection & Risk Thresholds
    DETECTION_THRESHOLDS = {
        'phishing_confidence': float(os.getenv('THRESH_PHISHING_CONF', 0.75)),
        'ddos_anomaly_score': float(os.getenv('THRESH_DDOS_ANOMALY', 0.70)),
        'brute_force_failed_attempts': int(os.getenv('THRESH_BF_ATTEMPTS', 5)),
        'brute_force_window_seconds': int(os.getenv('THRESH_BF_WINDOW', 300)),
        'dns_entropy_threshold': float(os.getenv('THRESH_DNS_ENTROPY', 3.5)),
        'ip_spoofing_ttl_variance': float(os.getenv('THRESH_TTL_VARIANCE', 15.0)),
        'risk_levels': {
            'critical': 85,
            'high': 70,
            'medium': 40,
            'low': 20
        }
    }


class DevelopmentConfig(Config):
    """Development Environment Configuration."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Hardened Production Environment Configuration."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True


class TestingConfig(Config):
    """Automated Testing Configuration."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
