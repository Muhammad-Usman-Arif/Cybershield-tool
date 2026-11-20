import os
from flask import Flask, render_template, request, jsonify
from flask_wtf.csrf import CSRFError
from app.config import config
from app.extensions import db, login_manager, csrf, migrate, bcrypt


def create_app(config_name='development'):
    app = Flask(__name__, instance_relative_config=True)

    # Load config
    app.config.from_object(config[config_name])

    # Ensure required folders exist
    for folder in [app.config['UPLOAD_FOLDER'],
                   app.config['REPORTS_FOLDER'],
                   app.instance_path]:
        os.makedirs(folder, exist_ok=True)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)

    # Login manager settings
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access CyberShield AI.'
    login_manager.login_message_category = 'warning'

    def _is_api_request():
        return (
            request.is_json or
            request.path.startswith('/api') or
            '/api/' in request.path or
            request.headers.get('Accept') == 'application/json' or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        )

    @login_manager.unauthorized_handler
    def unauthorized():
        if _is_api_request():
            return jsonify({
                'success': False,
                'error': 'Authentication required. Please log in to continue.',
                'code': 'UNAUTHORIZED'
            }), 401
        from flask import flash, redirect, url_for
        flash(login_manager.login_message, category=login_manager.login_message_category)
        return redirect(url_for(login_manager.login_view, next=request.url))

    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))

    # Register blueprints
    from app.routes.auth         import auth
    from app.routes.dashboard    import dashboard
    from app.routes.phishing     import phishing_bp
    from app.routes.ip_spoofing  import ip_spoofing_bp
    from app.routes.dns_spoofing import dns_spoofing_bp
    from app.routes.ddos         import ddos_bp
    from app.routes.brute_force  import brute_force_bp
    from app.routes.malware      import malware_bp
    from app.routes.live_monitor import monitor_bp
    from app.routes.history      import history_bp
    from app.routes.reports      import reports_bp
    from app.routes.settings     import settings_bp
    from app.routes.location     import location_bp
    from app.routes.sessions     import sessions_bp
    from app.routes.help         import help_bp


    app.register_blueprint(auth,           url_prefix='/auth')
    app.register_blueprint(dashboard,      url_prefix='/')
    app.register_blueprint(phishing_bp,    url_prefix='/phishing')
    app.register_blueprint(ip_spoofing_bp, url_prefix='/ip-spoofing')
    app.register_blueprint(dns_spoofing_bp,url_prefix='/dns-spoofing')
    app.register_blueprint(ddos_bp,        url_prefix='/ddos')
    app.register_blueprint(brute_force_bp, url_prefix='/brute-force')
    app.register_blueprint(malware_bp,     url_prefix='/malware')
    app.register_blueprint(monitor_bp,     url_prefix='/monitoring')
    app.register_blueprint(history_bp,     url_prefix='/history')
    app.register_blueprint(reports_bp,     url_prefix='/reports')
    app.register_blueprint(settings_bp,    url_prefix='/settings')
    app.register_blueprint(location_bp,    url_prefix='/location')
    app.register_blueprint(sessions_bp,    url_prefix='/sessions')
    app.register_blueprint(help_bp,        url_prefix='/help')

    # Error handlers
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if _is_api_request():
            return jsonify({
                'success': False,
                'error': 'Security CSRF validation failed or session expired. Please refresh the page.',
                'code': 'CSRF_ERROR'
            }), 400
        return render_template('errors/500.html'), 400

    @app.errorhandler(404)
    def not_found(e):
        if _is_api_request():
            return jsonify({
                'success': False,
                'error': 'The requested API endpoint was not found.',
                'code': 'NOT_FOUND'
            }), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        if _is_api_request():
            return jsonify({
                'success': False,
                'error': 'An internal server error occurred while processing your request.',
                'code': 'INTERNAL_ERROR'
            }), 500
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'success': False, 'error': 'File too large. Maximum size is 16 MB.'}), 413

    from app.models import working_session  # noqa
    return app
