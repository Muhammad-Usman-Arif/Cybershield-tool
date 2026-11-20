import os, uuid
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.engines.ddos_engine import ddos_engine
from app.engines.risk_engine import format_result_for_db, generate_risk_summary
from app.models.detection import DetectionHistory
from app.models.ddos_analysis import DDoSAnalysis
from app.models.alert import SecurityAlert

ddos_bp = Blueprint('ddos_bp', __name__)


@ddos_bp.route('/')
@login_required
def index():
    return render_template('modules/ddos.html', title='DDoS Detection')


@ddos_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    file = request.files.get('file')

    if file and file.filename:
        _, ext = os.path.splitext(file.filename.lower())
        ext = ext.lstrip('.')
        fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        fpath = os.path.join(current_app.config['UPLOAD_FOLDER'], fname)
        file.save(fpath)
        try:
            result = ddos_engine.analyze_file(fpath, file_type=ext)
        finally:
            if os.path.exists(fpath):
                os.remove(fpath)
        input_summary = f"File: {file.filename}"
    else:
        data = request.get_json(silent=True) or {}
        if not data.get('packet_count'):
            return jsonify({'success': False,
                            'error': 'Provide a CSV/PCAP file or manual traffic stats.'}), 400
        result = ddos_engine.analyze_manual(data)
        input_summary = f"Manual: {data.get('packet_count')} pkts over {data.get('duration_seconds', 1)}s"

    if not result.get('success'):
        return jsonify(result), 400

    risk_summary = generate_risk_summary(
        'ddos', result['result'], result['risk_score'], result['indicators']
    )
    result.update(risk_summary)

    db_data   = format_result_for_db(result, 'ddos', input_summary, current_user.id)
    detection = DetectionHistory(**db_data)
    db.session.add(detection)
    db.session.flush()

    details = result.get('details', {})
    da = DDoSAnalysis(
        detection_id=detection.id,
        file_name=details.get('file_name', 'manual'),
        traffic_type=result.get('attack_pattern', 'Unknown'),
        anomaly_score=result['risk_score'] / 100.0,
        attack_pattern=result.get('attack_pattern', 'Unknown'),
    )
    da.stats = details.get('traffic_stats', {})
    db.session.add(da)

    if result['risk_score'] >= 50:
        db.session.add(SecurityAlert(
            user_id=current_user.id,
            detection_id=detection.id,
            severity='critical' if result['risk_score'] >= 80 else 'high',
            message=f"Potential DDoS detected ({result.get('attack_pattern', 'Unknown')}) — Risk: {result['risk_score']}/100",
            status='new',
        ))

    db.session.commit()
    result['detection_id'] = detection.id
    return jsonify(result), 200
