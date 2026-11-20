"""
CyberShield AI - Extension Registry
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

# Database ORM
db = SQLAlchemy()

# User Session Management
login_manager = LoginManager()

# CSRF Protection
csrf = CSRFProtect()

# Database Migrations
migrate = Migrate()

# Password Hashing Extension
try:
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt()
except ImportError:
    bcrypt = None
