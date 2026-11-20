"""
CyberShield AI - Security Operations Platform Entry Point
"""
import os
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()

from app import create_app
from app.extensions import db
from app.models.user import User

# Determine configuration environment
config_name = os.getenv('FLASK_ENV', 'development')
app = create_app(config_name)


def init_database(application):
    """Ensure database tables and initial root administrative account are provisioned."""
    with application.app_context():
        db.create_all()

        # Seed administrative operator if database is freshly initialized
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@cybershield.local')
        admin_password = os.getenv('ADMIN_PASSWORD', 'CyberShield2026!')

        existing_admin = User.query.filter(
            (User.username == admin_username) | (User.email == admin_email)
        ).first()

        if not existing_admin:
            admin_user = User(
                username=admin_username,
                email=admin_email,
                role='admin',
                is_active=True
            )
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()


if __name__ == '__main__':
    init_database(app)
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
