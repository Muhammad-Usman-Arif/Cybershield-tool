import json
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.engines.phishing_engine import phishing_engine
from app.engines.risk_engine import format_result_for_db, generate_risk_summary
from app.models.detection import DetectionHistory
from app.models.phishing_result import PhishingResult
from app.models.alert import SecurityAlert

phishing_bp = Blueprint('phishing_bp', __name__)


@phishing_bp.route('/')
@login_required
def index():
    return render_template('modules/phishing.html', title='Phishing Detection')


@phishing_bp.route('/api/analyze', methods=['POST'])
@login_required
def analyze():
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()

    if not url:
        return jsonify({'success': False, 'error': 'URL is required.'}), 400

    if len(url) > 2048:
        return jsonify({'success': False, 'error': 'URL too long (max 2048 chars).'}), 400

    # Run engine
    result = phishing_engine.analyze_url(url)
    if not result.get('success'):
        return jsonify(result), 400

    # Enrich with risk summary
    risk_summary = generate_risk_summary(
        'phishing', result['result'], result['risk_score'], result['indicators']
    )
    result.update(risk_summary)

    # Save to DB
    db_data = format_result_for_db(result, 'phishing', url[:200], current_user.id)
    detection = DetectionHistory(**db_data)
    db.session.add(detection)
    db.session.flush()

    pr = PhishingResult(
        detection_id=detection.id,
        url=url,
        is_phishing=result.get('is_phishing', False),
        confidence=result.get('confidence', 0.0),
    )
    pr.feature_data = result.get('features', {})
    db.session.add(pr)

    # Create alert for high-risk results
    if result['risk_score'] >= 60:
        alert = SecurityAlert(
            user_id=current_user.id,
            detection_id=detection.id,
            severity='high' if result['risk_score'] >= 80 else 'medium',
            message=f"Phishing URL detected: {url[:100]} (Risk: {result['risk_score']}/100)",
            status='new',
        )
        db.session.add(alert)

    db.session.commit()
    result['detection_id'] = detection.id
    return jsonify(result), 200
