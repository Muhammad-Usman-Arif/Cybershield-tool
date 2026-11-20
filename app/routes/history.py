from datetime import datetime
from flask import Blueprint, render_template, jsonify, request, send_file
from flask_login import login_required, current_user

from app.extensions import db
from app.models.detection import DetectionHistory
from app.models.user import User
from app.services.excel_export import generate_enterprise_detection_excel

history_bp = Blueprint('history_bp', __name__)


@history_bp.route('/')
@login_required
def index():
    users = []
    if current_user.role == 'admin':
        users = User.query.order_by(User.username.asc()).all()
    return render_template('history/index.html', title='Detection History', users=users)


@history_bp.route('/api/data')
@login_required
def get_data():
    page       = int(request.args.get('page', 1))
    per_page   = int(request.args.get('per_page', 20))
    module     = request.args.get('module', '').strip()
    risk_lvl   = request.args.get('risk_level', '').strip()
    result_f   = request.args.get('result', '').strip()
    user_id_f  = request.args.get('user_id', '').strip()
    start_date = request.args.get('start_date', '').strip()
    end_date   = request.args.get('end_date', '').strip()

    if current_user.role == 'admin':
        if user_id_f and user_id_f.isdigit():
            q = DetectionHistory.query.filter_by(user_id=int(user_id_f))
        else:
            q = DetectionHistory.query
    else:
        q = DetectionHistory.query.filter_by(user_id=current_user.id)

    if module:
        q = q.filter_by(module=module)
    if risk_lvl:
        q = q.filter(DetectionHistory.risk_level.ilike(risk_lvl))
    if result_f:
        q = q.filter(DetectionHistory.result.ilike(f'%{result_f}%'))

    if start_date:
        try:
            s_dt = datetime.strptime(start_date, '%Y-%m-%d')
            q = q.filter(DetectionHistory.created_at >= s_dt)
        except ValueError:
            pass

    if end_date:
        try:
            from datetime import timedelta
            e_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            q = q.filter(DetectionHistory.created_at < e_dt)
        except ValueError:
            pass

    q = q.order_by(DetectionHistory.created_at.desc())
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'items':        [d.to_dict() for d in pagination.items],
        'total':        pagination.total,
        'pages':        pagination.pages,
        'current_page': page,
        'per_page':     per_page,
    })


@history_bp.route('/export/excel')
@login_required
def export_excel():
    """Download enterprise-grade formatted .xlsx detection report."""
    buf = generate_enterprise_detection_excel(request.args, current_user)
    timestamp_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"cybershield_detection_report_{timestamp_str}.xlsx"
    return send_file(
        buf,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )


@history_bp.route('/api/delete/<int:detection_id>', methods=['DELETE'])
@login_required
def delete(detection_id):
    if current_user.role == 'admin':
        d = DetectionHistory.query.filter_by(id=detection_id).first_or_404()
    else:
        d = DetectionHistory.query.filter_by(
            id=detection_id, user_id=current_user.id
        ).first_or_404()
    db.session.delete(d)
    db.session.commit()
    return jsonify({'success': True})
