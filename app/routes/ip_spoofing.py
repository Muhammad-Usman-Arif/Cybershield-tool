import os, uuid
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.engines.ip_spoofing_engine import ip_spoofing_engine
from app.engines.risk_engine import format_result_for_db, generate_risk_summary
from app.models.detection import DetectionHistory
from app.models.network_analysis import NetworkAnalysis
from app.models.alert import SecurityAlert

ip_spoofing_bp = Blueprint('ip_spoofing_bp', __name__)


@ip_spoofing_bp.route('/')
@login_required
def index():
    return render_template('modules/ip_spoofing.html', title='IP Spoofing Analysis')


@ip_spoofing_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    file = request.files.get('file')

    if file and file.filename:
        # PCAP file analysis
        fname   = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        fpath   = os.path.join(current_app.config['UPLOAD_FOLDER'], fname)
        file.save(fpath)
        try:
            result = ip_spoofing_engine.analyze_pcap(fpath)
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)
        input_summary = f"PCAP: {file.filename}"
    else:
        # Manual entry
        data = request.get_json(silent=True) or {}
        src_ip = data.get('src_ip', '').strip()
        if not src_ip:
            return jsonify({'success': False, 'error': 'Provide a PCAP file or manual IP data.'}), 400
        result = ip_spoofing_engine.analyze_manual(data)
        input_summary = f"Manual: {src_ip} → {data.get('dst_ip', 'N/A')}"

    if not result.get('success'):
        return jsonify(result), 400

    risk_summary = generate_risk_summary(
        'ip_spoofing', result['result'], result['risk_score'], result['indicators']
    )
    result.update(risk_summary)

    db_data   = format_result_for_db(result, 'ip_spoofing', input_summary, current_user.id)
    detection = DetectionHistory(**db_data)
    db.session.add(detection)
    db.session.flush()

    details = result.get('details', {})
    na = NetworkAnalysis(
        detection_id=detection.id,
        file_name=details.get('file_name', 'manual'),
        packet_count=details.get('total_packets', 0),
        analysis_summary=str(result.get('indicators', []))[:500],
    )
    na.suspicious_ips = details.get('suspicious_ips', [])
    db.session.add(na)

    if result['risk_score'] >= 60:
        db.session.add(SecurityAlert(
            user_id=current_user.id,
            detection_id=detection.id,
            severity='high',
            message=f"IP Spoofing detected (Risk: {result['risk_score']}/100)",
            status='new',
        ))

    db.session.commit()
    result['detection_id'] = detection.id
    return jsonify(result), 200
