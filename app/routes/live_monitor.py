import threading
from datetime import datetime
from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user

monitor_bp = Blueprint('monitor_bp', __name__)

# Global monitoring state
_state = {
    'running':       False,
    'packets':       0,
    'alerts':        [],
    'started_at':    None,
    'interface':     None,
    'thread':        None,
    'scapy_available': False,
}

try:
    from scapy.all import sniff, IP, TCP, UDP
    _state['scapy_available'] = True
except ImportError:
    pass


def _capture_loop(iface):
    """Background packet capture thread."""
    def handle(pkt):
        if not _state['running']:
            return
        _state['packets'] += 1
        if IP in pkt:
            ip = pkt[IP]
            # Flag unusual TTLs
            if ip.ttl < 10:
                _state['alerts'].append({
                    'time': datetime.utcnow().isoformat(),
                    'msg':  f"Low TTL ({ip.ttl}) from {ip.src}",
                })
                _state['alerts'] = _state['alerts'][-50:]  # keep last 50
    try:
        sniff(iface=iface, prn=handle,
              store=False, stop_filter=lambda _: not _state['running'])
    except Exception:
        _state['running'] = False


@monitor_bp.route('/')
@login_required
def index():
    return render_template('monitoring/live.html', title='Live Monitoring',
                           scapy_available=_state['scapy_available'])


@monitor_bp.route('/threat-intel')
@login_required
def threat_intel():
    """Threat Intelligence Feed & Malicious Indicators Database."""
    from app.engines.dns_engine import KNOWN_MALICIOUS_DOMAINS
    threat_ips = [
        {'ip': '185.220.101.5', 'threat_type': 'Tor Exit Node / Scanner', 'risk': 'High', 'country': 'DE'},
        {'ip': '45.154.255.88', 'threat_type': 'Mirai Botnet C2 Node', 'risk': 'Critical', 'country': 'RU'},
        {'ip': '194.26.29.112', 'threat_type': 'Cobalt Strike TeamServer', 'risk': 'Critical', 'country': 'NL'},
        {'ip': '91.240.118.23', 'threat_type': 'Brute Force / SSH Spray', 'risk': 'Medium', 'country': 'BG'},
        {'ip': '193.106.191.80', 'threat_type': 'Phishing Kit Drop Host', 'risk': 'High', 'country': 'US'},
    ]
    return render_template('monitoring/threat_intel.html',
                           title='Threat Intelligence',
                           known_domains=sorted(list(KNOWN_MALICIOUS_DOMAINS)),
                           threat_ips=threat_ips)


@monitor_bp.route('/alerts')
@login_required
def alerts():
    """Security Alerts Management Console."""
    from app.models.alert import SecurityAlert
    if current_user.role == 'admin':
        alerts_list = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(100).all()
    else:
        alerts_list = SecurityAlert.query.filter_by(user_id=current_user.id).order_by(SecurityAlert.created_at.desc()).limit(100).all()
    return render_template('monitoring/alerts.html',
                           title='Security Alerts',
                           alerts=alerts_list)


@monitor_bp.route('/api/alerts/<int:alert_id>/status', methods=['POST'])
@login_required
def update_alert_status(alert_id):
    from flask import request
    from app.extensions import db
    from app.models.alert import SecurityAlert
    alert = SecurityAlert.query.get_or_404(alert_id)
    if alert.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    if new_status in ('acknowledged', 'resolved', 'new'):
        alert.status = new_status
        db.session.commit()
        return jsonify({'success': True, 'status': alert.status})
    return jsonify({'success': False, 'error': 'Invalid status'}), 400


@monitor_bp.route('/api/start', methods=['POST'])
@login_required
def start():
    if not _state['scapy_available']:
        return jsonify({
            'success': False,
            'error':   'Live capture requires Scapy and administrator/root privileges. '
                       'Please upload a PCAP file for analysis instead.'
        }), 503

    if _state['running']:
        return jsonify({'success': False, 'error': 'Monitoring already running.'}), 409

    _state['running']    = True
    _state['packets']    = 0
    _state['alerts']     = []
    _state['started_at'] = datetime.utcnow().isoformat()

    t = threading.Thread(target=_capture_loop, args=(None,), daemon=True)
    _state['thread'] = t
    t.start()
    return jsonify({'success': True, 'message': 'Live monitoring started.'})


@monitor_bp.route('/api/stop', methods=['POST'])
@login_required
def stop():
    _state['running'] = False
    return jsonify({'success': True, 'message': 'Monitoring stopped.'})


@monitor_bp.route('/api/status')
@login_required
def status():
    return jsonify({
        'running':          _state['running'],
        'packets_captured': _state['packets'],
        'recent_alerts':    _state['alerts'][-10:],
        'started_at':       _state['started_at'],
        'scapy_available':  _state['scapy_available'],
    })
