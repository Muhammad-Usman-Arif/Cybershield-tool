from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app.extensions import db

settings_bp = Blueprint('settings_bp', __name__)


@settings_bp.route('/')
@login_required
def index():
    return render_template('settings/index.html', title='Settings')


@settings_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    from app.models.user import User
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip().lower()
    if not username or not email:
        flash('Username and email are required.', 'danger')
        return redirect(url_for('settings_bp.index'))
    if User.query.filter(User.username == username,
                         User.id != current_user.id).first():
        flash('Username already taken.', 'danger')
        return redirect(url_for('settings_bp.index'))
    current_user.username = username
    current_user.email    = email
    db.session.commit()
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('settings_bp.index'))


@settings_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    old_pw  = request.form.get('old_password', '')
    new_pw  = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    if not current_user.check_password(old_pw):
        flash('Current password is incorrect.', 'danger')
    elif new_pw != confirm:
        flash('New passwords do not match.', 'danger')
    elif len(new_pw) < 8:
        flash('Password must be at least 8 characters.', 'danger')
    else:
        current_user.set_password(new_pw)
        db.session.commit()
        flash('Password changed successfully.', 'success')
    return redirect(url_for('settings_bp.index'))


@settings_bp.route('/users')
@login_required
def users_list():
    """Admin User Management Console."""
    if current_user.role != 'admin':
        flash('Administrator access required.', 'danger')
        return redirect(url_for('dashboard.index'))
    from app.models.user import User
    users = User.query.order_by(User.id.asc()).all()
    return render_template('settings/users.html', title='User Management', users=users)


@settings_bp.route('/api/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from app.models.user import User
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot deactivate your own account.'}), 400
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True, 'is_active': user.is_active})


@settings_bp.route('/api/users/<int:user_id>/role', methods=['POST'])
@login_required
def change_user_role(user_id):
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from app.models.user import User
    if user_id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot change your own role.'}), 400
    data = request.get_json(silent=True) or {}
    new_role = data.get('role')
    if new_role not in ('admin', 'analyst'):
        return jsonify({'success': False, 'error': 'Invalid role.'}), 400
    user = User.query.get_or_404(user_id)
    user.role = new_role
    db.session.commit()
    return jsonify({'success': True, 'role': user.role})


@settings_bp.route('/api/users/create', methods=['POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    from app.models.user import User
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role = data.get('role') or 'analyst'

    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'All fields are required.'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'error': 'Username already taken.'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'error': 'Email already registered.'}), 400

    new_user = User(username=username, email=email, role=role, is_active=True)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True, 'user': new_user.to_dict()})

