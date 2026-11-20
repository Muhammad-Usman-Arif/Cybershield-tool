# CyberShield AI — Enterprise Security Operations & Threat Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%202.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Theme](https://img.shields.io/badge/Theme-Black%20SOC%20%23050505-cyan.svg)](#)

CyberShield AI is an enterprise-grade cybersecurity detection, analysis, and threat intelligence web application designed for Security Operations Centers (SOC). The platform combines machine learning models, heuristic protocol analysis, and real-time telemetry parsers to investigate multiple attack surfaces.

---

## 🛡️ Core Detection Modules

1. **Phishing URL Detection (`/phishing`)**
   - 28 lexical and structural URL feature extraction.
   - Machine Learning (Random Forest) classifier with fallback rule heuristics.
   - Detects raw IP URLs, homoglyph characters, subdomain nesting depth, and brand impersonation.

2. **IP Spoofing Detection (`/ip-spoofing`)**
   - Ingress filtering (BCP 38 / RFC 2827 compliance).
   - TTL (Time-To-Live) variance and anomaly detection.
   - PCAP network capture file and manual packet inspection.

3. **DNS Spoofing & Tunneling Detection (`/dns-spoofing`)**
   - Domain Generation Algorithm (DGA) detection via Shannon entropy scoring.
   - Internationalized Domain Name (IDN / Punycode) homograph attack identification.
   - Recursive public DNS resolver comparison (Google, Cloudflare, Quad9) to flag cache poisoning.
   - PCAP DNS flow analysis for Fast-Flux and tunneling exfiltration.

4. **DDoS Traffic Detection (`/ddos`)**
   - Volumetric flow rate analytics (PPS, BPS).
   - TCP handshake starvation (SYN ratio) and source IP concentration metrics.
   - NetFlow/CICIDS flow CSV parser and manual metric evaluation.

5. **Brute Force Detection (`/brute-force`)**
   - Sliding-window frequency analysis for authentication events.
   - Multi-format log parser supporting OpenSSH, syslog, PAM, Apache/Nginx 401/403, and Windows Event Logs.
   - Attacking IP extraction and targeted username auditing.

6. **Static Malware Analysis (`/malware`)**
   - 100% non-execution sandbox byte inspection.
   - Cryptographic SHA-256 fingerprinting.
   - Magic bytes format validation and extension threat tiering.
   - Section Shannon entropy scoring for packer / cryptor identification.
   - YARA detection rule integration.

---

## ⚡ Key Features

- **Beginner Mode vs. Advanced Mode**: Toggle between guided beginner walkthroughs with attack flow diagrams and advanced raw telemetry/entropy views.
- **SOC Analyst Command Library**: Instant 1-click clipboard copy for diagnostic CLI commands (`curl`, `whois`, `dig`, `tcpdump`, `ss`, `netstat`, `certutil`).
- **Enterprise Excel Export (`.xlsx`)**: Formatted 4-sheet forensic workbooks generated with `openpyxl` including KPI summary cards and embedded Pie and Bar charts.
- **Executive PDF Incident Reports**: Branded, print-ready PDF reports generated via `ReportLab`.
- **Consent-Based Geolocation Auditing**: Secure analyst session tracking with city/region resolution.
- **Admin Management Console**: Role-based access control (Admin vs. Analyst), user provisioning, and threat alert management.
- **SOC Black Theme**: Custom CSS palette (`#050505` main, `#151515` cards, `#00D9FF` accent, `#292929` borders).

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Git

### 2. Clone Repository
```bash
git clone https://github.com/Muhammad-Usman-Arif/Cybershield-tool.git
cd Cybershield-tool
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
Copy the example environment file:
```bash
copy .env.example .env
```

### 5. Launch Application
```bash
python run.py
```

The application will start on:
👉 **`http://127.0.0.1:5000`**

---

## 🔐 Default Administrative Credentials

- **Username**: `admin`
- **Password**: `CyberShield2026!`

*(You can modify these or provision new analysts under Settings -> User Management).*

---

## 🧪 Automated Testing & Verification

Run the master verification test suite:
```bash
python tests/test_master_verification.py
```
And verify the Excel export engine:
```bash
python tests/test_excel_export.py
```

---

## 📂 Project Architecture

```
CyberShieldAI/
├── app/
│   ├── config.py              # Environment configurations (Dev, Prod, Test)
│   ├── extensions.py          # Flask extensions (DB, Login, CSRF, Bcrypt)
│   ├── engines/               # Security and risk assessment engines
│   │   ├── phishing_engine.py
│   │   ├── ip_spoofing_engine.py
│   │   ├── dns_engine.py
│   │   ├── ddos_engine.py
│   │   ├── brute_force_engine.py
│   │   ├── malware_engine.py
│   │   └── risk_engine.py
│   ├── models/                # SQLAlchemy database models
│   ├── routes/                # Blueprint controller endpoints
│   ├── services/              # Export services (Excel / PDF)
│   ├── static/                # CSS, JS, SOC theme styling
│   └── templates/             # Jinja2 HTML templates
├── tests/                     # Automated QA test suites
├── requirements.txt           # Python dependencies
├── run.py                     # Entry point & DB auto-initializer
└── README.md                  # Project documentation
```

---

## 📜 License
This project is licensed under the MIT License.
