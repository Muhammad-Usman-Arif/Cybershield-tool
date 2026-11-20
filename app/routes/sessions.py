from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app.extensions import db
from app.models.working_session import WorkingSession

sessions_bp = Blueprint('sessions_bp', __name__)

@sessions_bp.route('/')
@login_required
def index():
    sessions = WorkingSession.query.filter_by(
        user_id=current_user.id
    ).order_by(WorkingSession.login_at.desc()).limit(50).all()
    stats = _compute_session_stats()
    return render_template('sessions/index.html', sessions=sessions, stats=stats, title='Working Sessions')

@sessions_bp.route('/api/stats')
@login_required
def api_stats():
    return jsonify(_compute_session_stats())

def _compute_session_stats():
    now = datetime.utcnow()
    base = WorkingSession.query.filter_by(user_id=current_user.id)
    total = base.count()
    active = base.filter_by(status='active').count()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_sessions = base.filter(WorkingSession.login_at >= today_start).count()
    week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    week_sessions = base.filter(WorkingSession.login_at >= week_start).count()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_sessions = base.filter(WorkingSession.login_at >= month_start).count()
    month_closed = base.filter(
        WorkingSession.login_at >= month_start,
        WorkingSession.status == 'closed',
        WorkingSession.logout_at != None
    ).all()
    total_secs = sum(int((s.logout_at - s.login_at).total_seconds()) for s in month_closed)
    total_hours = round(total_secs / 3600, 1)
    closed = base.filter(WorkingSession.status == 'closed', WorkingSession.logout_at != None).all()
    avg_secs = int(sum(int((s.logout_at - s.login_at).total_seconds()) for s in closed) / len(closed)) if closed else 0
    h, rem = divmod(avg_secs, 3600)
    m, _ = divmod(rem, 60)
    avg_str = f'{h}h {m}m' if h > 0 else (f'{m}m' if m > 0 else '0m')
    return {
        'total': total, 'active': active,
        'today': today_sessions, 'week': week_sessions,
        'month': month_sessions, 'month_hours': total_hours,
        'avg_duration': avg_str,
    }
