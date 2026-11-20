from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func, text

from app.extensions import db
from app.models.detection import DetectionHistory
from app.models.alert import SecurityAlert

dashboard = Blueprint('dashboard', __name__)


@dashboard.route('/api/health')
def health_check():
    """Diagnostic health check endpoint for DB and API connectivity."""
    db_status = 'ok'
    try:
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        db_status = f'error: {str(e)}'
    return jsonify({
        'status': 'healthy' if db_status == 'ok' else 'degraded',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    })


@dashboard.route('/')
@login_required
def index():
    stats = _compute_stats()
    recent_alerts = SecurityAlert.query.filter_by(
        user_id=current_user.id
    ).order_by(SecurityAlert.created_at.desc()).limit(5).all()
    return render_template('dashboard/index.html',
                           title='Overview',
                           stats=stats,
                           recent_alerts=recent_alerts)


@dashboard.route('/api/stats')
@login_required
def get_stats():
    stats       = _compute_stats()
    timeline    = _timeline_data()
    module_dist = _module_distribution()
    severity    = _severity_distribution()
    recent      = _recent_detections()
    return jsonify({
        **stats,
        'timeline_data':          timeline,
        'module_distribution':    module_dist,
        'severity_distribution':  severity,
        'recent_detections':      recent,
    })


def _compute_stats() -> dict:
    base = DetectionHistory.query.filter_by(user_id=current_user.id)
    total_scans       = base.count()
    threats_detected  = base.filter(DetectionHistory.risk_score >= 40).count()
    phishing_count    = base.filter_by(module='phishing').count()
    network_anomalies = base.filter(DetectionHistory.module.in_(
                            ['ip_spoofing', 'dns_spoofing', 'ddos'])).count()
    malware_count     = base.filter_by(module='malware').count()
    critical_count    = base.filter(DetectionHistory.risk_level == 'Critical').count()
    return {
        'total_scans':       total_scans,
        'threats_detected':  threats_detected,
        'phishing_count':    phishing_count,
        'network_anomalies': network_anomalies,
        'malware_count':     malware_count,
        'critical_count':    critical_count,
    }


def _timeline_data() -> list:
    """Last 7 days detection counts per day."""
    result = []
    today = datetime.utcnow().date()
    for i in range(6, -1, -1):
        day   = today - timedelta(days=i)
        start = datetime.combine(day, datetime.min.time())
        end   = datetime.combine(day, datetime.max.time())
        count = DetectionHistory.query.filter(
            DetectionHistory.user_id == current_user.id,
            DetectionHistory.created_at.between(start, end)
        ).count()
        result.append({'date': day.strftime('%b %d'), 'count': count})
    return result


def _module_distribution() -> dict:
    rows = db.session.query(
        DetectionHistory.module,
        func.count(DetectionHistory.id)
    ).filter_by(user_id=current_user.id).group_by(DetectionHistory.module).all()
    return {row[0]: row[1] for row in rows}


def _severity_distribution() -> dict:
    rows = db.session.query(
        DetectionHistory.risk_level,
        func.count(DetectionHistory.id)
    ).filter_by(user_id=current_user.id).group_by(DetectionHistory.risk_level).all()
    return {row[0]: row[1] for row in rows}


def _recent_detections() -> list:
    items = DetectionHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(DetectionHistory.created_at.desc()).limit(10).all()
    return [d.to_dict() for d in items]
