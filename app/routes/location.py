from datetime import datetime
from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from app.extensions import db
from app.models.location_event import LocationEvent
from app.models.working_session import WorkingSession
import os, json, urllib.request

location_bp = Blueprint('location', __name__)

def reverse_geocode(lat, lon):
    try:
        url = f'https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=10'
        req = urllib.request.Request(url, headers={'User-Agent': 'CyberShieldAI/1.0 (educational)'})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        addr = data.get('address', {})
        return {
            'city': addr.get('city') or addr.get('town') or addr.get('village') or addr.get('county'),
            'region': addr.get('state'),
            'country': addr.get('country'),
            'timezone': None,
        }
    except Exception:
        return {}

@location_bp.route('/api/record', methods=['POST'])
@login_required
def record_location():
    payload = request.get_json() or {}
    lat = payload.get('latitude')
    lon = payload.get('longitude')
    accuracy = payload.get('accuracy')
    event_type = payload.get('event_type', 'generic')
    detection_id = payload.get('detection_id')
    timezone_str = payload.get('timezone')
    city = payload.get('city')
    region = payload.get('region')
    country = payload.get('country')
    if lat is not None and lon is not None and not city:
        loc_data = reverse_geocode(lat, lon)
        city = loc_data.get('city')
        region = loc_data.get('region')
        country = loc_data.get('country')
    event = LocationEvent(
        user_id=current_user.id, detection_id=detection_id,
        event_type=event_type, latitude=lat, longitude=lon,
        accuracy=accuracy, city=city, region=region,
        country=country, timezone=timezone_str,
    )
    db.session.add(event)
    if event_type == 'login':
        active = WorkingSession.query.filter_by(
            user_id=current_user.id, status='active'
        ).order_by(WorkingSession.login_at.desc()).first()
        if active and not active.login_city:
            active.login_city = city
            active.login_region = region
            active.login_country = country
            active.login_timezone = timezone_str
            active.login_lat = lat
            active.login_lon = lon
    if event_type not in ('login', 'logout'):
        active = WorkingSession.query.filter_by(
            user_id=current_user.id, status='active'
        ).order_by(WorkingSession.login_at.desc()).first()
        if active:
            active.last_activity = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True, 'event_id': event.id})

@location_bp.route('/api/current', methods=['GET'])
@login_required
def current_location():
    event = LocationEvent.query.filter_by(user_id=current_user.id).filter(
        LocationEvent.city != None
    ).order_by(LocationEvent.timestamp.desc()).first()
    if not event:
        event = LocationEvent.query.filter_by(user_id=current_user.id).order_by(LocationEvent.timestamp.desc()).first()
    if not event:
        return jsonify({'available': False}), 404
    return jsonify({'available': True, 'data': event.to_dict()})

@location_bp.route('/api/history', methods=['GET'])
@login_required
def location_history_api():
    events = LocationEvent.query.filter_by(
        user_id=current_user.id
    ).order_by(LocationEvent.timestamp.desc()).limit(100).all()
    return jsonify([e.to_dict() for e in events])

@location_bp.route('/api/admin/history', methods=['GET'])
@login_required
def admin_location_history_api():
    if current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403
    events = LocationEvent.query.order_by(LocationEvent.timestamp.desc()).limit(500).all()
    return jsonify([e.to_dict() for e in events])

@location_bp.route('/history')
@login_required
def location_history_page():
    events = LocationEvent.query.filter_by(
        user_id=current_user.id
    ).order_by(LocationEvent.timestamp.desc()).all()
    return render_template('location/history.html', events=events, title='Location History')

@location_bp.route('/admin')
@login_required
def admin_overview():
    if current_user.role != 'admin':
        from flask import abort
        abort(403)
    from app.models.user import User
    events = LocationEvent.query.order_by(LocationEvent.timestamp.desc()).limit(200).all()
    users = {u.id: u.username for u in User.query.all()}
    return render_template('location/admin.html', events=events, users=users, title='Admin Location Overview')

@location_bp.route('/api/update-session', methods=['POST'])
@login_required
def update_session_activity():
    active = WorkingSession.query.filter_by(
        user_id=current_user.id, status='active'
    ).order_by(WorkingSession.login_at.desc()).first()
    if active:
        active.last_activity = datetime.utcnow()
        db.session.commit()
    return jsonify({'ok': True})
