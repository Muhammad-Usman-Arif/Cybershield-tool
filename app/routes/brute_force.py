import os, uuid
from flask import Blueprint, render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from app.extensions import db
from app.engines.brute_force_engine import brute_force_engine
from app.engines.risk_engine import format_result_for_db, generate_risk_summary
from app.models.detection import DetectionHistory
from app.models.brute_force import BruteForceResult
from app.models.alert import SecurityAlert

brute_force_bp = Blueprint('brute_force_bp', __name__)


@brute_force_bp.route('/')
@login_required
def index():
    return render_template('modules/brute_force.html', title='Brute Force Detection')


@brute_force_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    threshold = int(request.form.get('threshold') or
                    (request.get_json(silent=True) or {}).get('threshold') or 5)
    threshold = max(1, min(threshold, 100))

    file = request.files.get('file')
    log_text = ''

    if file and file.filename:
        try:
            log_text = file.read().decode('utf-8', errors='replace')
        except Exception as e:
            return jsonify({'success': False, 'error': f'Could not read file: {e}'}), 400
        input_summary = f"Log file: {file.filename}"
    else:
        data     = request.get_json(silent=True) or {}
        log_text = data.get('log_text', '').strip()
        if not log_text:
            # check form
            log_text = request.form.get('log_text', '').strip()
        input_summary = f"Log text ({len(log_text.splitlines())} lines)"

    if not log_text:
        return jsonify({'success': False, 'error': 'Log text or file is required.'}), 400

    if len(log_text) > 5_000_000:
        return jsonify({'success': False, 'error': 'Log file too large (max 5 MB text).'}), 400

    result = brute_force_engine.analyze_logs(log_text, threshold=threshold)
    if not result.get('success'):
        return jsonify(result), 400

    risk_summary = generate_risk_summary(
        'brute_force', result['result'], result['risk_score'], result['indicators']
    )
    result.update(risk_summary)

    db_data   = format_result_for_db(result, 'brute_force', input_summary, current_user.id)
    detection = DetectionHistory(**db_data)
    db.session.add(detection)
    db.session.flush()

    details = result.get('details', {})
    bfr = BruteForceResult(
        detection_id=detection.id,
        log_source=input_summary[:255],
        failed_attempts=details.get('failed_attempts', 0),
        threshold_exceeded=details.get('threshold_exceeded', False),
    )
    bfr.suspicious_ips = details.get('suspicious_ips', [])
    db.session.add(bfr)

    if result['risk_score'] >= 50:
        db.session.add(SecurityAlert(
            user_id=current_user.id,
            detection_id=detection.id,
            severity='high',
            message=f"Brute force attack detected — {details.get('failed_attempts', 0)} failed attempts, {len(details.get('suspicious_ips', []))} suspicious IPs",
            status='new',
        ))

    db.session.commit()
    result['detection_id'] = detection.id
    return jsonify(result), 200
