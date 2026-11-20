"""
CyberShield AI - Enterprise-Grade Detection History Excel Export Service
Generates professional, styled .xlsx audit reports with openpyxl.
Includes 4 comprehensive worksheets:
  1. Executive Summary (KPI metrics, risk breakdown, tool stats, charts)
  2. Complete Detection History (20 audit columns, conditional formatting, filters)
  3. Tool-wise Analysis (structured telemetry per detection engine)
  4. Location & Activity (consent-verified telemetry & session events)
"""

import io
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import zoneinfo

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, PieChart, Reference

from app.extensions import db
from app.models.detection import DetectionHistory
from app.models.user import User
from app.models.location_event import LocationEvent
from app.models.phishing_result import PhishingResult
from app.models.network_analysis import NetworkAnalysis
from app.models.dns_analysis import DNSAnalysis
from app.models.ddos_analysis import DDoSAnalysis
from app.models.brute_force import BruteForceResult
from app.models.malware_analysis import MalwareAnalysis


# ---------------------------------------------------------------------------
# COLOR PALETTE & DESIGN SYSTEM
# ---------------------------------------------------------------------------
C_NAVY_TITLE = '0A192F'      # Deep SOC Navy (Header Banner)
C_NAVY_HEADER = '0F172A'     # Slate / Dark Navy (Table Headers)
C_NAVY_SUB = '1E293B'        # Secondary Dark Header
C_CYAN_ACCENT = '00D4FF'     # CyberShield Primary Accent
C_BLUE_ACCENT = '0284C7'     # Secondary Blue
C_LIGHT_BG = 'F8FAFC'        # Alternating Row Tint
C_WHITE = 'FFFFFF'           # Primary Row White
C_BORDER_GRAY = 'CBD5E1'     # Subtle Border Color
C_MUTED_TEXT = '64748B'      # Muted Gray Text

# Risk Fill & Text Colors
RISK_COLORS = {
    'critical': {'fill': 'FEE2E2', 'font': '991B1B', 'label': 'Critical'},
    'high':     {'fill': 'FFEDD5', 'font': '9A3412', 'label': 'High'},
    'medium':   {'fill': 'FEF3C7', 'font': '92400E', 'label': 'Medium'},
    'low':      {'fill': 'D1FAE5', 'font': '065F46', 'label': 'Low'},
    'very low': {'fill': 'D1FAE5', 'font': '065F46', 'label': 'Low'},
}

MODULE_DISPLAY_NAMES = {
    'phishing': 'Phishing URL Detection',
    'ip_spoofing': 'IP Spoofing Analysis',
    'dns_spoofing': 'DNS Spoofing Detection',
    'ddos': 'DDoS Attack Detection',
    'brute_force': 'Brute Force Detection',
    'malware': 'Malware Static Analysis',
}

MODULE_TYPES = {
    'phishing': 'URL Heuristic & ML Scan',
    'ip_spoofing': 'PCAP Packet Telemetry / IP Validation',
    'dns_spoofing': 'DNS Query & Cache Validation',
    'ddos': 'Traffic Flow Anomaly Analysis',
    'brute_force': 'Authentication Log Audit',
    'malware': 'Static PE / Binary Signature Scan',
}

MODULE_PROTOCOLS = {
    'phishing': 'HTTPS / HTTP',
    'ip_spoofing': 'IP / TCP / UDP',
    'dns_spoofing': 'DNS (UDP 53)',
    'ddos': 'TCP / UDP / ICMP',
    'brute_force': 'SSH / HTTP Auth / RDP',
    'malware': 'N/A (Binary Executable)',
}


def _thin_border():
    s = Side(style='thin', color=C_BORDER_GRAY)
    return Border(left=s, right=s, top=s, bottom=s)


def _convert_to_local_time(dt_utc: datetime, tz_name: Optional[str] = None):
    """Converts UTC datetime into configured timezone safely."""
    if not dt_utc:
        return None, "N/A", "N/A"
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    if tz_name:
        try:
            tz = zoneinfo.ZoneInfo(tz_name)
            local_dt = dt_utc.astimezone(tz)
            return local_dt, local_dt.strftime('%Y-%m-%d'), local_dt.strftime('%H:%M:%S')
        except Exception:
            pass
    # Fallback UTC
    return dt_utc, dt_utc.strftime('%Y-%m-%d'), dt_utc.strftime('%H:%M:%S')


def _resolve_detection_location(detection: DetectionHistory) -> Dict[str, Any]:
    """
    Resolves real location record associated with a detection.
    Strictly uses user consent records. Never invents IP geolocation!
    """
    event = LocationEvent.query.filter_by(detection_id=detection.id).first()
    if not event and detection.created_at:
        # Check if user had a consent-verified location record within +/- 3 hours
        window_start = detection.created_at - timedelta(hours=3)
        window_end = detection.created_at + timedelta(hours=3)
        event = LocationEvent.query.filter(
            LocationEvent.user_id == detection.user_id,
            LocationEvent.timestamp >= window_start,
            LocationEvent.timestamp <= window_end,
            LocationEvent.city.isnot(None)
        ).order_by(LocationEvent.timestamp.desc()).first()

    if event and (event.city or event.country):
        city = event.city or 'N/A'
        region = event.region or 'N/A'
        country = event.country or 'N/A'
        parts = [p for p in [event.city, event.region, event.country] if p]
        loc_str = ", ".join(parts) if parts else 'Not Available'
        coords = f"{event.latitude:.4f}, {event.longitude:.4f}" if (event.latitude and event.longitude) else 'N/A'
        accuracy = f"{event.accuracy:.1f}m" if event.accuracy else 'N/A'
        return {
            'city': city,
            'region': region,
            'country': country,
            'location_str': loc_str,
            'timezone': event.timezone or 'N/A',
            'coords': coords,
            'accuracy': accuracy,
            'status': 'Verified (Consent-Based)'
        }

    return {
        'city': 'Not Available',
        'region': 'Not Available',
        'country': 'Not Available',
        'location_str': 'Not Available',
        'timezone': 'Not Available',
        'coords': 'N/A',
        'accuracy': 'N/A',
        'status': 'Not Available'
    }


def _extract_module_telemetry(detection: DetectionHistory):
    """Safely extracts module-specific fields without inventing data."""
    target = detection.input_summary
    src_ip = 'N/A'
    dst_ip = 'N/A'
    file_hash = 'N/A'
    duration = 'N/A'
    detailed_findings = []

    # Indicators from base model
    if detection.indicators:
        detailed_findings.extend(detection.indicators)

    mod = (detection.module or '').lower()

    if mod == 'phishing':
        pr = detection.phishing_result
        if pr and pr.url:
            target = pr.url
            if pr.confidence:
                detailed_findings.append(f"Confidence: {pr.confidence * 100:.1f}%")
        elif target.startswith('http'):
            target = target

    elif mod == 'ip_spoofing':
        na = detection.network_analyses[0] if detection.network_analyses else None
        if na:
            if na.file_name and na.file_name != 'manual':
                target = na.file_name
            if na.suspicious_ips:
                src_ip = ", ".join(na.suspicious_ips[:3])
            if na.analysis_summary:
                detailed_findings.append(na.analysis_summary)
        if '→' in target or '->' in target:
            # manual entry summary e.g. "Manual: 1.2.3.4 -> 5.6.7.8"
            clean = target.replace('Manual:', '').strip()
            arrow = '→' if '→' in clean else '->'
            parts = clean.split(arrow)
            if len(parts) == 2:
                src_ip = parts[0].strip()
                dst_ip = parts[1].strip()

    elif mod == 'dns_spoofing':
        da = detection.dns_analyses[0] if detection.dns_analyses else None
        if da:
            if da.domain:
                target = da.domain
            if da.resolved_ips:
                dst_ip = ", ".join(da.resolved_ips[:3])
            if da.analysis_summary:
                detailed_findings.append(da.analysis_summary)

    elif mod == 'ddos':
        dda = detection.ddos_analyses[0] if detection.ddos_analyses else None
        if dda:
            if dda.duration_seconds:
                duration = f"{dda.duration_seconds:.2f}s"
            if dda.anomalies:
                detailed_findings.extend(dda.anomalies)
            if dda.analysis_summary:
                detailed_findings.append(dda.analysis_summary)
            src_ip = "Multi-Source / Volumetric"

    elif mod == 'brute_force':
        bfr = detection.brute_force_results[0] if detection.brute_force_results else None
        if bfr:
            if bfr.suspicious_ips:
                src_ip = ", ".join(bfr.suspicious_ips[:3])
            detailed_findings.append(f"Total Failed Attempts: {bfr.total_failed}")
            if bfr.analysis_summary:
                detailed_findings.append(bfr.analysis_summary)

    elif mod == 'malware':
        ma = detection.malware_analyses[0] if detection.malware_analyses else None
        if ma:
            if ma.file_name:
                target = ma.file_name
            if ma.sha256:
                file_hash = ma.sha256
            if ma.yara_matches:
                detailed_findings.append(f"YARA Matches: {', '.join(ma.yara_matches)}")
            if ma.entropy:
                detailed_findings.append(f"Entropy: {ma.entropy:.2f}")

    findings_text = "; ".join(filter(None, detailed_findings)) or "Standard signature pattern evaluation completed."

    return {
        'target': target,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'file_hash': file_hash,
        'duration': duration,
        'findings': findings_text,
    }


def generate_enterprise_detection_excel(
    query_filters: Dict[str, Any],
    current_user: User
) -> io.BytesIO:
    """
    Main entry point for generating the enterprise-grade CyberShield AI .xlsx report.
    Enforces role-based data boundaries and custom filters.
    """
    # -----------------------------------------------------------------------
    # 1. QUERY & ACCESS CONTROL ENFORCEMENT
    # -----------------------------------------------------------------------
    query = DetectionHistory.query

    # Enforce standard user restriction
    is_admin = (getattr(current_user, 'role', '') == 'admin')
    if not is_admin:
        query = query.filter(DetectionHistory.user_id == current_user.id)
    else:
        req_user_id = query_filters.get('user_id')
        if req_user_id and str(req_user_id).isdigit():
            query = query.filter(DetectionHistory.user_id == int(req_user_id))

    # Module filter
    module_filter = (query_filters.get('module') or '').strip().lower()
    if module_filter:
        query = query.filter(DetectionHistory.module == module_filter)

    # Risk level filter
    risk_filter = (query_filters.get('risk_level') or '').strip().lower()
    if risk_filter:
        query = query.filter(DetectionHistory.risk_level.ilike(risk_filter))

    # Detection status / result filter
    status_filter = (query_filters.get('status') or '').strip()
    if status_filter:
        if status_filter.lower() == 'threat':
            query = query.filter(DetectionHistory.risk_score >= 60)
        elif status_filter.lower() == 'clean':
            query = query.filter(DetectionHistory.risk_score < 30)
        else:
            query = query.filter(DetectionHistory.result.ilike(f"%{status_filter}%"))

    # Date range filter
    start_date_str = (query_filters.get('start_date') or '').strip()
    end_date_str = (query_filters.get('end_date') or '').strip()
    if start_date_str:
        try:
            s_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(DetectionHistory.created_at >= s_dt)
        except ValueError:
            pass

    if end_date_str:
        try:
            e_dt = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(DetectionHistory.created_at < e_dt)
        except ValueError:
            pass

    detections: List[DetectionHistory] = query.order_by(DetectionHistory.created_at.desc()).all()

    # Timezone resolution
    req_tz = query_filters.get('timezone')
    if not req_tz:
        # Check user's latest working session or location event
        last_ev = LocationEvent.query.filter_by(user_id=current_user.id).filter(
            LocationEvent.timezone.isnot(None)
        ).order_by(LocationEvent.timestamp.desc()).first()
        req_tz = last_ev.timezone if last_ev else 'UTC'

    # -----------------------------------------------------------------------
    # 2. WORKBOOK INITIALIZATION
    # -----------------------------------------------------------------------
    wb = openpyxl.Workbook()
    # Remove default sheet
    default_sheet = wb.active

    # Create sheets
    ws_summary = wb.create_sheet(title='Executive Summary')
    ws_history = wb.create_sheet(title='Detection History')
    ws_toolwise = wb.create_sheet(title='Tool-wise Analysis')
    ws_location = wb.create_sheet(title='Location & Activity')

    wb.remove(default_sheet)

    # Enable gridlines on all sheets
    for ws in wb.worksheets:
        ws.views.sheetView[0].showGridLines = True

    # Build each sheet
    _build_sheet_summary(ws_summary, detections, query_filters, current_user, req_tz)
    _build_sheet_history(ws_history, detections, query_filters, current_user, req_tz)
    _build_sheet_toolwise(ws_toolwise, detections, current_user, req_tz)
    _build_sheet_location(ws_location, detections, current_user, req_tz)

    # Save to BytesIO
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# SHEET 1: EXECUTIVE SUMMARY
# ---------------------------------------------------------------------------
def _build_sheet_summary(
    ws,
    detections: List[DetectionHistory],
    filters: Dict[str, Any],
    current_user: User,
    tz_name: str
):
    border = _thin_border()
    now_local, now_d, now_t = _convert_to_local_time(datetime.utcnow(), tz_name)

    # --- Header Banner ---
    ws.merge_cells('A1:J2')
    h1 = ws['A1']
    h1.value = "🛡 CYBERSHIELD AI — CYBERSECURITY DETECTION SUMMARY"
    h1.font = Font(name='Segoe UI', size=16, bold=True, color='FFFFFF')
    h1.fill = PatternFill(start_color=C_NAVY_TITLE, end_color=C_NAVY_TITLE, fill_type='solid')
    h1.alignment = Alignment(horizontal='center', vertical='center')

    ws.merge_cells('A3:J3')
    sub = ws['A3']
    sub.value = f"Executive Threat Telemetry & Operational Analytics Report | Timezone: {tz_name}"
    sub.font = Font(name='Segoe UI', size=10, italic=True, color='FFFFFF')
    sub.fill = PatternFill(start_color=C_NAVY_SUB, end_color=C_NAVY_SUB, fill_type='solid')
    sub.alignment = Alignment(horizontal='center', vertical='center')

    # --- Metadata Cards (Rows 5-7) ---
    meta_box = [
        ("Generated Date & Time", f"{now_d} {now_t}"),
        ("Report Operator", f"{current_user.username} ({current_user.role.title()})"),
        ("Filter Scope", filters.get('module') or 'All Modules'),
        ("Total Records Evaluated", len(detections)),
    ]
    for idx, (lbl, val) in enumerate(meta_box):
        c_start = 1 + (idx * 2)
        c_end = c_start + 1
        ws.merge_cells(start_row=5, start_column=c_start, end_row=5, end_column=c_end)
        ws.merge_cells(start_row=6, start_column=c_start, end_row=6, end_column=c_end)

        cell_lbl = ws.cell(row=5, column=c_start, value=lbl)
        cell_lbl.font = Font(name='Segoe UI', size=9, bold=True, color=C_MUTED_TEXT)
        cell_lbl.fill = PatternFill('solid', fgColor=C_LIGHT_BG)
        cell_lbl.alignment = Alignment(horizontal='center', vertical='center')
        cell_lbl.border = border

        cell_val = ws.cell(row=6, column=c_start, value=val)
        cell_val.font = Font(name='Segoe UI', size=11, bold=True, color=C_NAVY_TITLE)
        cell_val.fill = PatternFill('solid', fgColor=C_WHITE)
        cell_val.alignment = Alignment(horizontal='center', vertical='center')
        cell_val.border = border

    # --- KPI Metrics Aggregation ---
    counts_risk = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    module_stats = {}
    date_stats = {}
    user_stats = {}

    for d in detections:
        rl = (d.risk_level or 'low').capitalize()
        if rl in counts_risk:
            counts_risk[rl] += 1
        elif rl == 'Very low':
            counts_risk['Low'] += 1

        mod = (d.module or 'unknown').lower()
        if mod not in module_stats:
            module_stats[mod] = {'scans': 0, 'threats': 0, 'scores': []}
        module_stats[mod]['scans'] += 1
        if d.risk_score >= 60:
            module_stats[mod]['threats'] += 1
        module_stats[mod]['scores'].append(d.risk_score)

        _, dt_str, _ = _convert_to_local_time(d.created_at, tz_name)
        if dt_str not in date_stats:
            date_stats[dt_str] = {'scans': 0, 'threats': 0}
        date_stats[dt_str]['scans'] += 1
        if d.risk_score >= 60:
            date_stats[dt_str]['threats'] += 1

        uid = d.user_id
        if uid not in user_stats:
            user_stats[uid] = {'name': d.user.username if d.user else f'UID-{uid}', 'scans': 0, 'threats': 0}
        user_stats[uid]['scans'] += 1
        if d.risk_score >= 60:
            user_stats[uid]['threats'] += 1

    # --- Table 1: Risk Level Distribution (Row 9-14) ---
    ws.merge_cells('A9:D9')
    r_hdr = ws['A9']
    r_hdr.value = "THREAT SEVERITY BREAKDOWN"
    r_hdr.font = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
    r_hdr.fill = PatternFill('solid', fgColor=C_NAVY_HEADER)
    r_hdr.alignment = Alignment(horizontal='center', vertical='center')

    subheaders = ["Risk Level", "Record Count", "Percentage", "Status"]
    for col_idx, sh in enumerate(subheaders, start=1):
        c = ws.cell(row=10, column=col_idx, value=sh)
        c.font = Font(name='Segoe UI', size=10, bold=True, color='FFFFFF')
        c.fill = PatternFill('solid', fgColor=C_NAVY_SUB)
        c.alignment = Alignment(horizontal='center', vertical='center')
        c.border = border

    total_det = len(detections) or 1
    curr_r = 11
    for r_level in ['Critical', 'High', 'Medium', 'Low']:
        cnt = counts_risk.get(r_level, 0)
        pct = (cnt / total_det) * 100
        style_info = RISK_COLORS.get(r_level.lower(), RISK_COLORS['low'])

        c1 = ws.cell(row=curr_r, column=1, value=r_level)
        c1.font = Font(name='Segoe UI', size=10, bold=True, color=style_info['font'])
        c1.fill = PatternFill('solid', fgColor=style_info['fill'])
        c1.alignment = Alignment(horizontal='center', vertical='center')
        c1.border = border

        c2 = ws.cell(row=curr_r, column=2, value=cnt)
        c2.font = Font(name='Segoe UI', size=10, bold=True)
        c2.alignment = Alignment(horizontal='right', vertical='center')
        c2.border = border

        c3 = ws.cell(row=curr_r, column=3, value=f"{pct:.1f}%")
        c3.alignment = Alignment(horizontal='right', vertical='center')
        c3.border = border

        c4 = ws.cell(row=curr_r, column=4, value="Immediate Action" if r_level in ['Critical', 'High'] else "Monitored")
        c4.alignment = Alignment(horizontal='center', vertical='center')
        c4.border = border
        curr_r += 1

    # --- Embed Risk Distribution Pie Chart (Adjacent to Table 1) ---
    pie = PieChart()
    pie.title = "Risk Level Distribution"
    pie.height = 7
    pie.width = 11
    labels = Reference(ws, min_col=1, min_row=11, max_row=14)
    data = Reference(ws, min_col=2, min_row=10, max_row=14)
    pie.add_data(data, titles_from_data=True)
    pie.set_categories(labels)
    ws.add_chart(pie, "F9")

    # --- Table 2: Tool-wise Detection Breakdown (Row 17) ---
    row_tools = 17
    ws.merge_cells(f'A{row_tools}:E{row_tools}')
    t_hdr = ws[f'A{row_tools}']
    t_hdr.value = "DETECTION ENGINE ACTIVITY & THREAT BREAKDOWN"
    t_hdr.font = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
    t_hdr.fill = PatternFill('solid', fgColor=C_NAVY_HEADER)
    t_hdr.alignment = Alignment(horizontal='center', vertical='center')

    tool_headers = ["Detection Engine", "Total Scans", "Threats Found", "Clean Scans", "Avg Risk Score"]
    for col_idx, th in enumerate(tool_headers, start=1):
        c = ws.cell(row=row_tools + 1, column=col_idx, value=th)
        c.font = Font(name='Segoe UI', size=10, bold=True, color='FFFFFF')
        c.fill = PatternFill('solid', fgColor=C_NAVY_SUB)
        c.alignment = Alignment(horizontal='center', vertical='center')
        c.border = border

    tool_r = row_tools + 2
    for mod_key, mod_label in MODULE_DISPLAY_NAMES.items():
        st = module_stats.get(mod_key, {'scans': 0, 'threats': 0, 'scores': []})
        scans = st['scans']
        threats = st['threats']
        clean = scans - threats
        avg_score = round(sum(st['scores']) / len(st['scores']), 1) if st['scores'] else 0.0

        ws.cell(row=tool_r, column=1, value=mod_label).alignment = Alignment(horizontal='left', vertical='center')
        ws.cell(row=tool_r, column=2, value=scans).alignment = Alignment(horizontal='right', vertical='center')
        ws.cell(row=tool_r, column=3, value=threats).alignment = Alignment(horizontal='right', vertical='center')
        ws.cell(row=tool_r, column=4, value=clean).alignment = Alignment(horizontal='right', vertical='center')
        ws.cell(row=tool_r, column=5, value=avg_score).alignment = Alignment(horizontal='right', vertical='center')

        for col_idx in range(1, 6):
            ws.cell(row=tool_r, column=col_idx).border = border
            ws.cell(row=tool_r, column=col_idx).font = Font(name='Segoe UI', size=10)
        tool_r += 1

    # --- Embed Tool-wise Bar Chart ---
    chart_bar = BarChart()
    chart_bar.type = "col"
    chart_bar.style = 10
    chart_bar.title = "Detections per Security Engine"
    chart_bar.y_axis.title = "Number of Scans"
    chart_bar.height = 7
    chart_bar.width = 11
    data_ref = Reference(ws, min_col=2, min_row=row_tools + 1, max_row=tool_r - 1)
    cats_ref = Reference(ws, min_col=1, min_row=row_tools + 2, max_row=tool_r - 1)
    chart_bar.add_data(data_ref, titles_from_data=True)
    chart_bar.set_categories(cats_ref)
    ws.add_chart(chart_bar, f"F{row_tools}")

    # Auto-adjust column widths for Executive Summary
    for col in ws.columns:
        col_letter = get_column_letter(col[0].column)
        max_len = max(len(str(cell.value or '')) for cell in col)
        ws.column_dimensions[col_letter].width = max(max_len + 3, 14)


# ---------------------------------------------------------------------------
# SHEET 2: COMPLETE DETECTION HISTORY (20 COLUMNS)
# ---------------------------------------------------------------------------
def _build_sheet_history(
    ws,
    detections: List[DetectionHistory],
    filters: Dict[str, Any],
    current_user: User,
    tz_name: str
):
    border = _thin_border()
    now_local, now_d, now_t = _convert_to_local_time(datetime.utcnow(), tz_name)

    # --- Top Workbook Header Banner ---
    ws.merge_cells('A1:T2')
    h1 = ws['A1']
    h1.value = "🛡 CYBERSHIELD AI — CYBERSECURITY DETECTION HISTORY AUDIT"
    h1.font = Font(name='Segoe UI', size=16, bold=True, color='FFFFFF')
    h1.fill = PatternFill(start_color=C_NAVY_TITLE, end_color=C_NAVY_TITLE, fill_type='solid')
    h1.alignment = Alignment(horizontal='center', vertical='center')

    # Sub-header Metadata
    ws.merge_cells('A3:T3')
    sub = ws['A3']
    period_str = f"{filters.get('start_date') or 'Earliest'} to {filters.get('end_date') or 'Latest'}"
    sub.value = f"Generated: {now_d} {now_t} ({tz_name}) | Report Period: {period_str} | Total Records: {len(detections)} | Operator: {current_user.username}"
    sub.font = Font(name='Segoe UI', size=10, italic=True, color='FFFFFF')
    sub.fill = PatternFill(start_color=C_NAVY_SUB, end_color=C_NAVY_SUB, fill_type='solid')
    sub.alignment = Alignment(horizontal='center', vertical='center')

    # --- 20 Column Headers (Row 5) ---
    headers = [
        "Record ID",
        "Tool Name",
        "Detection Type",
        "Target / Domain / IP / File",
        "Check Date",
        "Check Time",
        "Location (City, Region, Country)",
        "User Name",
        "User Email / Account ID",
        "Detection Status",
        "Risk Level",
        "Risk Score",
        "Detection Result",
        "Detailed Findings",
        "Source IP",
        "Destination IP",
        "Protocol",
        "File Hash / SHA256",
        "Analysis Duration",
        "Report / Record Reference"
    ]

    for col_idx, title in enumerate(headers, start=1):
        cell = ws.cell(row=5, column=col_idx, value=title)
        cell.font = Font(name='Segoe UI', size=10, bold=True, color='FFFFFF')
        cell.fill = PatternFill(start_color=C_NAVY_HEADER, end_color=C_NAVY_HEADER, fill_type='solid')
        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        cell.border = border
    ws.row_dimensions[5].height = 28

    # --- Populate Data Rows (Row 6 onwards) ---
    curr_row = 6
    for idx, d in enumerate(detections):
        _, d_date, d_time = _convert_to_local_time(d.created_at, tz_name)
        loc = _resolve_detection_location(d)
        telem = _extract_module_telemetry(d)

        mod_key = (d.module or '').lower()
        tool_name = MODULE_DISPLAY_NAMES.get(mod_key, d.module.replace('_', ' ').title())
        det_type = MODULE_TYPES.get(mod_key, 'Security Threat Telemetry')
        proto = MODULE_PROTOCOLS.get(mod_key, 'N/A')

        # Status
        if d.risk_score >= 60 or d.risk_level.lower() in ['critical', 'high']:
            status_str = "Threat Detected"
        elif d.risk_score >= 30 or d.risk_level.lower() == 'medium':
            status_str = "Suspicious"
        else:
            status_str = "Normal / Clean"

        user_name = d.user.username if d.user else "System"
        user_email = d.user.email if (d.user and d.user.email) else f"UID-{d.user_id}"

        row_data = [
            f"DET-{d.id:05d}",
            tool_name,
            det_type,
            telem['target'],
            d_date,
            d_time,
            loc['location_str'],
            user_name,
            user_email,
            status_str,
            d.risk_level.title(),
            int(d.risk_score),
            d.result,
            telem['findings'],
            telem['src_ip'],
            telem['dst_ip'],
            proto,
            telem['file_hash'],
            telem['duration'],
            f"CS-DET-{d.id:06d}"
        ]

        bg_color = C_WHITE if idx % 2 == 0 else C_LIGHT_BG
        r_fill = PatternFill('solid', fgColor=bg_color)

        for col_idx, val in enumerate(row_data, start=1):
            cell = ws.cell(row=curr_row, column=col_idx, value=val)
            cell.font = Font(name='Segoe UI', size=9.5)
            cell.fill = r_fill
            cell.border = border

            # Alignments
            if col_idx in [1, 5, 6, 10, 17, 20]:
                cell.alignment = Alignment(horizontal='center', vertical='center')
            elif col_idx == 12:  # Risk Score
                cell.alignment = Alignment(horizontal='right', vertical='center')
            elif col_idx in [4, 14, 18]:  # Target, Findings, Hash
                cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
            else:
                cell.alignment = Alignment(horizontal='left', vertical='center')

            # Conditional formatting for Risk Level (Col 11)
            if col_idx == 11:
                rl_key = (d.risk_level or '').lower()
                c_style = RISK_COLORS.get(rl_key, RISK_COLORS['low'])
                cell.fill = PatternFill('solid', fgColor=c_style['fill'])
                cell.font = Font(name='Segoe UI', size=9.5, bold=True, color=c_style['font'])
                cell.alignment = Alignment(horizontal='center', vertical='center')

        ws.row_dimensions[curr_row].height = 22
        curr_row += 1

    # --- Excel View & Print Setup ---
    # Freeze header rows
    ws.freeze_panes = 'A6'
    # Auto-filter
    ws.auto_filter.ref = f"A5:T{max(curr_row - 1, 5)}"
    # Landscape orientation and print settings
    ws.page_setup.orientation = ws.ORIENTATION_LANDSCAPE
    ws.page_setup.paperSize = ws.PAPERSIZE_A4
    ws.print_title_rows = '5:5'
    ws.oddHeader.center.text = "&B CyberShield AI — Detection History Audit &B"
    ws.oddFooter.right.text = "Page &P of &N"

    # Column widths (bounded with intelligent wrapping)
    col_width_defaults = {
        1: 14,   # Record ID
        2: 22,   # Tool Name
        3: 24,   # Detection Type
        4: 35,   # Target / Domain / IP / File
        5: 14,   # Check Date
        6: 14,   # Check Time
        7: 28,   # Location
        8: 16,   # User Name
        9: 24,   # User Email
        10: 18,  # Detection Status
        11: 14,  # Risk Level
        12: 12,  # Risk Score
        13: 22,  # Detection Result
        14: 45,  # Detailed Findings
        15: 18,  # Source IP
        16: 18,  # Destination IP
        17: 18,  # Protocol
        18: 30,  # File Hash
        19: 16,  # Analysis Duration
        20: 20   # Reference
    }
    for c_idx, width in col_width_defaults.items():
        col_letter = get_column_letter(c_idx)
        ws.column_dimensions[col_letter].width = width


# ---------------------------------------------------------------------------
# SHEET 3: TOOL-WISE ANALYSIS
# ---------------------------------------------------------------------------
def _build_sheet_toolwise(
    ws,
    detections: List[DetectionHistory],
    current_user: User,
    tz_name: str
):
    border = _thin_border()
    row_idx = 1

    # Main Title
    ws.merge_cells('A1:J2')
    h1 = ws['A1']
    h1.value = "🛡 CYBERSHIELD AI — TOOL-WISE SPECIALIZED TELEMETRY"
    h1.font = Font(name='Segoe UI', size=15, bold=True, color='FFFFFF')
    h1.fill = PatternFill('solid', fgColor=C_NAVY_TITLE)
    h1.alignment = Alignment(horizontal='center', vertical='center')
    row_idx = 4

    # Group detections by module
    grouped: Dict[str, List[DetectionHistory]] = {}
    for d in detections:
        m = (d.module or 'other').lower()
        grouped.setdefault(m, []).append(d)

    for mod_key, mod_title in MODULE_DISPLAY_NAMES.items():
        recs = grouped.get(mod_key, [])

        # Section Header Banner
        ws.merge_cells(start_row=row_idx, start_column=1, end_row=row_idx, end_column=10)
        sec = ws.cell(row=row_idx, column=1, value=f"{mod_title.upper()} ({len(recs)} SCANS)")
        sec.font = Font(name='Segoe UI', size=11, bold=True, color='FFFFFF')
        sec.fill = PatternFill('solid', fgColor=C_NAVY_HEADER)
        sec.alignment = Alignment(horizontal='left', vertical='center')
        ws.row_dimensions[row_idx].height = 24
        row_idx += 1

        # Table Column Headers
        t_headers = [
            "ID", "Target / Input", "Detection Result", "Risk Level",
            "Risk Score", "Telemetry / Indicators", "Primary IP / Hash",
            "Date", "Time", "Analyst"
        ]
        for col_idx, th in enumerate(t_headers, start=1):
            c = ws.cell(row=row_idx, column=col_idx, value=th)
            c.font = Font(name='Segoe UI', size=9.5, bold=True, color='FFFFFF')
            c.fill = PatternFill('solid', fgColor=C_NAVY_SUB)
            c.alignment = Alignment(horizontal='center', vertical='center')
            c.border = border
        ws.row_dimensions[row_idx].height = 20
        row_idx += 1

        if not recs:
            ws.merge_cells(start_row=row_idx, start_column=1, end_row=row_idx, end_column=10)
            c = ws.cell(row=row_idx, column=1, value=f"No {mod_title} activity records found for the selected query scope.")
            c.font = Font(name='Segoe UI', size=9.5, italic=True, color=C_MUTED_TEXT)
            c.alignment = Alignment(horizontal='center', vertical='center')
            c.border = border
            ws.row_dimensions[row_idx].height = 20
            row_idx += 2
            continue

        for r_idx, d in enumerate(recs):
            _, d_d, d_t = _convert_to_local_time(d.created_at, tz_name)
            telem = _extract_module_telemetry(d)

            # Pick primary identifier based on module
            if mod_key == 'malware':
                primary_id = telem['file_hash']
            elif mod_key in ['ip_spoofing', 'brute_force']:
                primary_id = telem['src_ip']
            elif mod_key == 'dns_spoofing':
                primary_id = telem['dst_ip']
            else:
                primary_id = 'N/A'

            bg = C_WHITE if r_idx % 2 == 0 else C_LIGHT_BG
            fill = PatternFill('solid', fgColor=bg)

            row_data = [
                f"#{d.id}",
                telem['target'],
                d.result,
                d.risk_level.title(),
                int(d.risk_score),
                telem['findings'],
                primary_id,
                d_d,
                d_t,
                d.user.username if d.user else "System"
            ]

            for c_idx, val in enumerate(row_data, start=1):
                cell = ws.cell(row=row_idx, column=c_idx, value=val)
                cell.font = Font(name='Segoe UI', size=9)
                cell.fill = fill
                cell.border = border

                if c_idx in [1, 8, 9, 10]:
                    cell.alignment = Alignment(horizontal='center', vertical='center')
                elif c_idx == 5:
                    cell.alignment = Alignment(horizontal='right', vertical='center')
                elif c_idx in [2, 6]:
                    cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
                else:
                    cell.alignment = Alignment(horizontal='left', vertical='center')

                # Highlight risk
                if c_idx == 4:
                    rl_key = (d.risk_level or '').lower()
                    c_style = RISK_COLORS.get(rl_key, RISK_COLORS['low'])
                    cell.fill = PatternFill('solid', fgColor=c_style['fill'])
                    cell.font = Font(name='Segoe UI', size=9, bold=True, color=c_style['font'])
                    cell.alignment = Alignment(horizontal='center', vertical='center')

            ws.row_dimensions[row_idx].height = 20
            row_idx += 1

        row_idx += 2  # Gap between modules

    # Column widths
    ws.column_dimensions['A'].width = 10
    ws.column_dimensions['B'].width = 30
    ws.column_dimensions['C'].width = 22
    ws.column_dimensions['D'].width = 14
    ws.column_dimensions['E'].width = 12
    ws.column_dimensions['F'].width = 40
    ws.column_dimensions['G'].width = 24
    ws.column_dimensions['H'].width = 14
    ws.column_dimensions['I'].width = 14
    ws.column_dimensions['J'].width = 18


# ---------------------------------------------------------------------------
# SHEET 4: LOCATION & ACTIVITY AUDIT
# ---------------------------------------------------------------------------
def _build_sheet_location(
    ws,
    detections: List[DetectionHistory],
    current_user: User,
    tz_name: str
):
    border = _thin_border()
    now_local, now_d, now_t = _convert_to_local_time(datetime.utcnow(), tz_name)

    # Header Banner
    ws.merge_cells('A1:L2')
    h1 = ws['A1']
    h1.value = "🛡 CYBERSHIELD AI — OPERATIONAL LOCATION & ACTIVITY AUDIT"
    h1.font = Font(name='Segoe UI', size=15, bold=True, color='FFFFFF')
    h1.fill = PatternFill('solid', fgColor=C_NAVY_TITLE)
    h1.alignment = Alignment(horizontal='center', vertical='center')

    ws.merge_cells('A3:L3')
    sub = ws['A3']
    sub.value = "Strictly consent-based geolocation telemetry & forensic user audit records. Non-consented entries show 'Not Available'."
    sub.font = Font(name='Segoe UI', size=9.5, italic=True, color='FFFFFF')
    sub.fill = PatternFill('solid', fgColor=C_NAVY_SUB)
    sub.alignment = Alignment(horizontal='center', vertical='center')

    # Column Headers (Row 5)
    headers = [
        "Audit ID",
        "Timestamp (Local)",
        "User Account",
        "Email / ID",
        "Activity / Event",
        "Associated Module",
        "Activity Target",
        "City",
        "Region / State",
        "Country",
        "Coordinates",
        "Verification Status"
    ]
    for col_idx, th in enumerate(headers, start=1):
        c = ws.cell(row=5, column=col_idx, value=th)
        c.font = Font(name='Segoe UI', size=9.5, bold=True, color='FFFFFF')
        c.fill = PatternFill('solid', fgColor=C_NAVY_HEADER)
        c.alignment = Alignment(horizontal='center', vertical='center')
        c.border = border
    ws.row_dimensions[5].height = 24

    # Build data rows combining Detection Events and Location Events
    curr_row = 6
    for idx, d in enumerate(detections):
        _, d_date, d_time = _convert_to_local_time(d.created_at, tz_name)
        loc = _resolve_detection_location(d)
        telem = _extract_module_telemetry(d)

        mod_title = MODULE_DISPLAY_NAMES.get((d.module or '').lower(), d.module.title())
        user_name = d.user.username if d.user else "System"
        user_email = d.user.email if (d.user and d.user.email) else f"UID-{d.user_id}"

        row_data = [
            f"LOC-DET-{d.id:05d}",
            f"{d_date} {d_time}",
            user_name,
            user_email,
            "Security Scan Execution",
            mod_title,
            telem['target'],
            loc['city'],
            loc['region'],
            loc['country'],
            loc['coords'],
            loc['status']
        ]

        bg = C_WHITE if idx % 2 == 0 else C_LIGHT_BG
        fill = PatternFill('solid', fgColor=bg)

        for col_idx, val in enumerate(row_data, start=1):
            cell = ws.cell(row=curr_row, column=col_idx, value=val)
            cell.font = Font(name='Segoe UI', size=9.5)
            cell.fill = fill
            cell.border = border

            if col_idx in [1, 2, 11, 12]:
                cell.alignment = Alignment(horizontal='center', vertical='center')
            elif col_idx in [7]:
                cell.alignment = Alignment(horizontal='left', vertical='center', wrap_text=True)
            else:
                cell.alignment = Alignment(horizontal='left', vertical='center')

            if col_idx == 12:
                if loc['status'].startswith('Verified'):
                    cell.font = Font(name='Segoe UI', size=9, bold=True, color='065F46')
                else:
                    cell.font = Font(name='Segoe UI', size=9, italic=True, color=C_MUTED_TEXT)

        ws.row_dimensions[curr_row].height = 20
        curr_row += 1

    # Freeze header & auto-filter
    ws.freeze_panes = 'A6'
    ws.auto_filter.ref = f"A5:L{max(curr_row - 1, 5)}"

    # Set Column Widths
    col_widths = {
        1: 16,   # Audit ID
        2: 20,   # Timestamp
        3: 16,   # User Account
        4: 24,   # Email
        5: 22,   # Activity
        6: 24,   # Module
        7: 32,   # Target
        8: 18,   # City
        9: 18,   # Region
        10: 18,  # Country
        11: 20,  # Coordinates
        12: 24   # Status
    }
    for col_i, w in col_widths.items():
        ws.column_dimensions[get_column_letter(col_i)].width = w
