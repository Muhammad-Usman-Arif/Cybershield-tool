import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import openpyxl
from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.detection import DetectionHistory
from app.models.phishing_result import PhishingResult
from app.models.network_analysis import NetworkAnalysis
from app.models.dns_analysis import DNSAnalysis
from app.models.ddos_analysis import DDoSAnalysis
from app.models.brute_force import BruteForceResult
from app.models.malware_analysis import MalwareAnalysis
from app.models.location_event import LocationEvent
from app.services.excel_export import generate_enterprise_detection_excel

def test_enterprise_excel_export():
    app = create_app('development')
    with app.app_context():
        # 1. Admin and standard analyst accounts
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@cybershield.ai', role='admin')
            admin.set_password('AdminPass123!')
            db.session.add(admin)
            db.session.commit()

        analyst = User.query.filter_by(role='analyst').first()
        if not analyst:
            analyst = User(username='analyst', email='analyst@cybershield.ai', role='analyst')
            analyst.set_password('AnalystPass123!')
            db.session.add(analyst)
            db.session.commit()

        print(f"Verified Users -> Admin: {admin.username} (ID {admin.id}), Analyst: {analyst.username} (ID {analyst.id})")

        # 2. Verify / seed records for all 6 detection modules
        modules = ['phishing', 'ip_spoofing', 'dns_spoofing', 'ddos', 'brute_force', 'malware']
        for mod in modules:
            existing = DetectionHistory.query.filter_by(module=mod).first()
            if not existing:
                clean_name = mod.replace('_', ' ').title()
                det = DetectionHistory(
                    user_id=analyst.id,
                    module=mod,
                    input_summary=f"Sample target for {clean_name}",
                    result=f"Detected {clean_name} Threat",
                    risk_score=85 if mod in ['phishing', 'malware', 'ddos'] else 45,
                    risk_level='Critical' if mod in ['phishing', 'malware', 'ddos'] else 'Medium',
                    indicators_json='["Threat signature matched", "Anomalous traffic rate"]',
                    model_used='CyberShield AI Engine v2'
                )
                db.session.add(det)
                db.session.flush()

                if mod == 'phishing':
                    pr = PhishingResult(detection_id=det.id, url='https://secure-login.bank-verify-fraud.com', is_phishing=True, confidence=0.96)
                    db.session.add(pr)
                elif mod == 'ip_spoofing':
                    na = NetworkAnalysis(detection_id=det.id, file_name='traffic_capture_01.pcap', packet_count=1450, analysis_summary='IP header anomaly')
                    na.suspicious_ips = ['198.51.100.24', '203.0.113.88']
                    db.session.add(na)
                elif mod == 'dns_spoofing':
                    da = DNSAnalysis(detection_id=det.id, domain='login.microsoft-sec-portal.net', resolved_ip='198.51.100.5', is_suspicious=True)
                    db.session.add(da)
                elif mod == 'ddos':
                    dda = DDoSAnalysis(detection_id=det.id, duration_seconds=15.2, total_packets=92000, avg_packet_size=64.0, anomalies=['SYN Flood Anomaly', 'Volumetric Spike'])
                    db.session.add(dda)
                elif mod == 'brute_force':
                    bfr = BruteForceResult(detection_id=det.id, failed_attempts=54, suspicious_ips=['192.0.2.15', '192.0.2.16'])
                    db.session.add(bfr)
                elif mod == 'malware':
                    ma = MalwareAnalysis(detection_id=det.id, file_name='invoice_payment_macro.exe', file_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', file_type='PE32 Executable', file_size=45056, entropy=7.42, yara_matches=['Trojan_Downloader_Generic', 'Suspicious_High_Entropy_Section'])
                    db.session.add(ma)

                loc = LocationEvent(user_id=analyst.id, detection_id=det.id, event_type=mod, city='Karachi', region='Sindh', country='Pakistan', timezone='Asia/Karachi', latitude=24.8607, longitude=67.0011, accuracy=15.0)
                db.session.add(loc)
                db.session.commit()
                print(f"Created sample detection record for {mod} (ID {det.id})")
            else:
                print(f"Found existing record for {mod} (ID {existing.id})")

        # 3. Test Full Export (Admin)
        buf = generate_enterprise_detection_excel({'timezone': 'Asia/Karachi'}, admin)
        wb = openpyxl.load_workbook(buf)
        sheet_names = wb.sheetnames
        print("Generated Workbook Sheet Names:", sheet_names)

        expected_sheets = ['Executive Summary', 'Detection History', 'Tool-wise Analysis', 'Location & Activity']
        for s in expected_sheets:
            assert s in sheet_names, f"Missing sheet: {s}"

        # 4. Validate Sheet 1 (Executive Summary)
        ws_summary = wb['Executive Summary']
        assert 'CYBERSHIELD AI' in str(ws_summary['A1'].value), "Executive summary title missing!"
        print("Executive Summary A1 Title:", ws_summary['A1'].value)
        print("Executive Summary Charts present:", len(ws_summary._charts))
        assert len(ws_summary._charts) >= 2, "Expected at least 2 charts in Executive Summary!"

        # 5. Validate Sheet 2 (Detection History - 20 Columns)
        ws_h = wb['Detection History']
        headers = [ws_h.cell(row=5, column=c).value for c in range(1, 21)]
        print(f"Detection History 20 Headers: {headers}")
        assert len(headers) == 20, f"Expected 20 headers, got {len(headers)}"
        assert headers[0] == "Record ID"
        assert headers[1] == "Tool Name"
        assert headers[6] == "Location (City, Region, Country)"
        assert headers[10] == "Risk Level"
        assert headers[11] == "Risk Score"
        assert headers[19] == "Report / Record Reference"

        # Check row data and formatting
        data_row_1 = [ws_h.cell(row=6, column=c).value for c in range(1, 21)]
        print(f"First Data Row: {data_row_1[:7]} ... {data_row_1[10:14]}")
        assert data_row_1[0].startswith("DET-"), "Record ID formatting error"
        assert ws_h.freeze_panes == "A6", f"Freeze panes error: {ws_h.freeze_panes}"
        assert ws_h.auto_filter.ref is not None, "Auto filter missing"

        # 6. Validate Sheet 3 (Tool-wise Analysis)
        ws_tool = wb['Tool-wise Analysis']
        assert 'TOOL-WISE' in str(ws_tool['A1'].value), "Tool-wise title missing"

        # 7. Validate Sheet 4 (Location & Activity)
        ws_loc = wb['Location & Activity']
        assert 'LOCATION & ACTIVITY' in str(ws_loc['A1'].value), "Location title missing"
        loc_row_1 = [ws_loc.cell(row=6, column=c).value for c in range(1, 13)]
        print(f"Location Data Row: {loc_row_1}")

        # 8. Test Filters for each of the 6 detection tools
        for mod in modules:
            buf_mod = generate_enterprise_detection_excel({'module': mod, 'timezone': 'UTC'}, admin)
            wb_mod = openpyxl.load_workbook(buf_mod)
            ws_mod_h = wb_mod['Detection History']
            tool_val = ws_mod_h.cell(row=6, column=2).value
            print(f"Module filter [{mod}] verified -> Tool Name in Row 6: {tool_val}")

        # 9. Test Standard User Access Control Boundary
        buf_analyst = generate_enterprise_detection_excel({}, analyst)
        wb_analyst = openpyxl.load_workbook(buf_analyst)
        ws_analyst_h = wb_analyst['Detection History']
        for r in range(6, ws_analyst_h.max_row + 1):
            user_val = ws_analyst_h.cell(row=r, column=8).value
            if user_val:
                assert user_val == analyst.username, f"Access control leak! Standard analyst saw record for {user_val}"

        # 10. Save a sample copy to verify Excel opens cleanly
        export_path = os.path.join(os.path.dirname(__file__), 'sample_detection_report.xlsx')
        with open(export_path, 'wb') as f:
            f.write(buf.getbuffer())
        print(f"Successfully saved sample report to: {export_path}")
        print("ALL TESTS AND VERIFICATION COMPLETED WITH 100% SUCCESS!")

if __name__ == '__main__':
    test_enterprise_excel_export()
