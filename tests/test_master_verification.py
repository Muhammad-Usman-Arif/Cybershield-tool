import sys
import os

sys.path.insert(0, r'C:\Users\DELL\Desktop\cybertool\CyberShieldAI')

from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app('development')
client = app.test_client()

print("=" * 70)
print("CYBERSHIELD AI — MASTER SYSTEM VERIFICATION TEST")
print("=" * 70)

with app.app_context():
    # 1. Test Health Endpoint
    res = client.get('/api/health')
    print(f"1. Health Check Endpoint: Status {res.status_code} | Data: {res.get_json()}")
    assert res.status_code == 200
    assert res.get_json().get('status') == 'healthy'

    # 2. Test CSRF Protection returning JSON for API calls
    res = client.post('/phishing/api/analyze', 
                      json={'url': 'http://evil.com'},
                      headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"2. Phase 1 Fix - CSRF Validation API Response: {res.status_code}")
    print(f"   Content-Type: {res.headers.get('Content-Type')}")
    print(f"   Response Body: {res.get_json()}")
    assert res.status_code == 400
    assert 'application/json' in res.headers.get('Content-Type', '')
    assert res.get_json().get('code') == 'CSRF_ERROR'
    print("   ✓ SUCCESS: CSRF error returns clean JSON, not '<!doctype' HTML!")

    # 3. Test Unauthorized Access returning JSON for API calls
    app.config['WTF_CSRF_ENABLED'] = False
    res = client.post('/phishing/api/analyze', 
                      json={'url': 'http://evil.com'},
                      headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"3. Phase 1 Fix - Unauthorized API Response: {res.status_code}")
    print(f"   Response Body: {res.get_json()}")
    assert res.status_code == 401
    assert 'application/json' in res.headers.get('Content-Type', '')
    assert res.get_json().get('code') == 'UNAUTHORIZED'
    print("   ✓ SUCCESS: Unauthorized API returns clean JSON, not login HTML!")

    # 4. Test 404 Error Handler for API
    res = client.get('/api/non-existent-endpoint', headers={'Accept': 'application/json'})
    print(f"4. API 404 Handler: Status {res.status_code} | JSON: {res.get_json()}")
    assert res.status_code == 404
    assert res.get_json().get('code') == 'NOT_FOUND'
    print("   ✓ SUCCESS: API 404 returns clean JSON error!")

    # 5. Authenticate as Admin via form login
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@cybershield.local', role='admin', is_active=True)
        admin.set_password('CyberShield2026!')
        db.session.add(admin)
        db.session.commit()

    login_res = client.post('/auth/login', data={'username': 'admin', 'password': 'CyberShield2026!'})
    assert login_res.status_code == 302, f"Login failed: {login_res.status_code}"
    print(f"\n4. Authenticated session established for user: {admin.username} (Role: {admin.role})")

    # 6. Verify All 18 UI Routes Render 200 OK
    routes_to_test = [
        ('/', 'Dashboard Overview'),
        ('/phishing/', 'Phishing Detection Module'),
        ('/ip-spoofing/', 'IP Spoofing Module'),
        ('/dns-spoofing/', 'DNS Spoofing Module'),
        ('/ddos/', 'DDoS Detection Module'),
        ('/brute-force/', 'Brute Force Module'),
        ('/malware/', 'Malware Analysis Module'),
        ('/monitoring/', 'Live Monitoring'),
        ('/monitoring/threat-intel', 'Threat Intelligence'),
        ('/monitoring/alerts', 'Security Alerts'),
        ('/history/', 'Detection History'),
        ('/reports/', 'Reports & Export'),
        ('/location/history', 'Location History'),
        ('/sessions/', 'Working Sessions'),
        ('/settings/', 'Settings & Profile'),
        ('/settings/users', 'User Management (Admin)'),
        ('/location/admin', 'Global Locations (Admin)'),
        ('/help/', 'Help & SOC Playbook')
    ]

    print("\n5. Testing All 18 UI Route Pages:")
    for route, label in routes_to_test:
        r = client.get(route)
        print(f"   [{r.status_code}] {label:35} -> {route}")
        assert r.status_code == 200, f"Route {route} failed with status {r.status_code}"

    # 7. Test Authenticated Phishing API
    print("\n6. Testing Authenticated Phishing Detection API:")
    res_phish = client.post('/phishing/api/analyze',
                            json={'url': 'http://192.168.1.100/secure-login/paypal/update.php'},
                            headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"   API Status: {res_phish.status_code} | Result: {res_phish.get_json().get('result')}")
    assert res_phish.status_code == 200
    assert res_phish.get_json().get('success') is True

    # 8. Test Authenticated IP Spoofing API
    print("\n7. Testing Authenticated IP Spoofing API:")
    res_ip = client.post('/ip-spoofing/api/analyze',
                         json={'src_ip': '10.0.0.1', 'dst_ip': '192.168.1.1', 'ttl': 5, 'protocol': 'TCP'},
                         headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"   API Status: {res_ip.status_code} | Result: {res_ip.get_json().get('result')}")
    assert res_ip.status_code == 200
    assert res_ip.get_json().get('success') is True

    # 9. Test Authenticated DNS Spoofing API
    print("\n8. Testing Authenticated DNS Spoofing API:")
    res_dns = client.post('/dns-spoofing/api/analyze',
                          json={'domain': 'evil-tracker-phish.com'},
                          headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"   API Status: {res_dns.status_code} | Result: {res_dns.get_json().get('result')}")
    assert res_dns.status_code == 200
    assert res_dns.get_json().get('success') is True

    # 10. Test Authenticated DDoS API
    print("\n9. Testing Authenticated DDoS API:")
    res_ddos = client.post('/ddos/api/analyze',
                           json={'packet_count': 10000, 'duration_seconds': 2, 'unique_src_ips': 1, 'unique_dst_ports': 1, 'src_concentration': 0.95, 'syn_ratio': 0.9},
                           headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"   API Status: {res_ddos.status_code} | Result: {res_ddos.get_json().get('result')}")
    assert res_ddos.status_code == 200
    assert res_ddos.get_json().get('success') is True

    # 11. Test Authenticated Brute Force API
    print("\n10. Testing Authenticated Brute Force API:")
    sample_log = "Nov  5 10:21:33 server sshd[1234]: Failed password for root from 192.168.1.50 port 45212 ssh2\n" * 6
    res_bf = client.post('/brute-force/api/analyze',
                         json={'log_text': sample_log, 'threshold': 5},
                         headers={'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    print(f"   API Status: {res_bf.status_code} | Result: {res_bf.get_json().get('result')}")
    assert res_bf.status_code == 200
    assert res_bf.get_json().get('success') is True

    # 12. Test Enterprise Excel Export (.xlsx)
    print("\n11. Testing Enterprise Excel Export (.xlsx):")
    res_excel = client.get('/reports/export/excel')
    print(f"   Excel Status: {res_excel.status_code} | Size: {len(res_excel.data)} bytes")
    assert res_excel.status_code == 200
    assert len(res_excel.data) > 5000

print("\n" + "=" * 70)
print("ALL 12 TEST CATEGORIES PASSED WITH 100% SUCCESS!")
print("=" * 70)
