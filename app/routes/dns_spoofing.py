import os, uuid
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.engines.dns_engine import dns_engine
from app.engines.risk_engine import format_result_for_db, generate_risk_summary
from app.models.detection import DetectionHistory
from app.models.dns_analysis import DNSAnalysis
from app.models.alert import SecurityAlert

dns_spoofing_bp = Blueprint('dns_spoofing_bp', __name__)


@dns_spoofing_bp.route('/')
@login_required
def index():
    return render_template('modules/dns_spoofing.html', title='DNS Spoofing Detection')


@dns_spoofing_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    file = request.files.get('file')

    if file and file.filename:
        fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        fpath = os.path.join(current_app.config['UPLOAD_FOLDER'], fname)
        file.save(fpath)
        try:
            result = dns_engine.analyze_pcap(fpath)
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)
        input_summary = f"PCAP: {file.filename}"
    else:
        data   = request.get_json(silent=True) or {}
        domain = (data.get('domain') or '').strip()
        if not domain:
            return jsonify({'success': False, 'error': 'Provide a domain name or PCAP file.'}), 400
        result = dns_engine.analyze_domain(domain)
        input_summary = f"Domain: {domain}"

    if not result.get('success'):
        return jsonify(result), 400

    risk_summary = generate_risk_summary(
        'dns_spoofing', result['result'], result['risk_score'], result['indicators']
    )
    result.update(risk_summary)

    db_data   = format_result_for_db(result, 'dns_spoofing', input_summary, current_user.id)
    detection = DetectionHistory(**db_data)
    db.session.add(detection)
    db.session.flush()

    details = result.get('details', {})
    da = DNSAnalysis(
        detection_id=detection.id,
        domain=details.get('domain', input_summary),
        resolved_ip=details.get('resolved_ip', ''),
        is_suspicious=result['risk_score'] >= 30,
    )
    da.indicators = result.get('indicators', [])
    db.session.add(da)

    if result['risk_score'] >= 50:
        db.session.add(SecurityAlert(
            user_id=current_user.id,
            detection_id=detection.id,
            severity='high',
            message=f"DNS anomaly detected: {input_summary} (Risk: {result['risk_score']}/100)",
            status='new',
        ))

    db.session.commit()
    result['detection_id'] = detection.id
    return jsonify(result), 200
