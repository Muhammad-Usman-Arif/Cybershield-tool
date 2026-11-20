import os
import sys

# Add project root directory to path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app('production' if os.getenv('VERCEL') else 'development')

# Auto-provision database on serverless cold starts
with app.app_context():
    try:
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_user = User(
                username=os.getenv('ADMIN_USERNAME', 'admin'),
                email=os.getenv('ADMIN_EMAIL', 'admin@cybershield.local'),
                role='admin',
                is_active=True
            )
            admin_user.set_password(os.getenv('ADMIN_PASSWORD', 'CyberShield2026!'))
            db.session.add(admin_user)
            db.session.commit()
    except Exception as e:
        print(f"Warning: DB initialization exception: {e}")
