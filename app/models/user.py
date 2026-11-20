"""
CyberShield AI - User Model
"""
from datetime import datetime
from flask_login import UserMixin
from app.extensions import db, bcrypt


class User(UserMixin, db.Model):
    """Platform Operator / Security Analyst User Account."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    detections = db.relationship('DetectionHistory', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    alerts = db.relationship('SecurityAlert', backref='user', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')

    def set_password(self, password: str) -> None:
        """Hash and persist user passcode using bcrypt."""
        if bcrypt is not None:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        else:
            import bcrypt as py_bcrypt
            salt = py_bcrypt.gensalt(rounds=12)
            self.password_hash = py_bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Validate candidate password against cryptographic hash."""
        if not self.password_hash:
            return False
        if bcrypt is not None:
            try:
                return bcrypt.check_password_hash(self.password_hash, password)
            except Exception:
                pass
        
        # Fallback to direct python-bcrypt
        try:
            import bcrypt as py_bcrypt
            return py_bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except Exception:
            return False

    def to_dict(self) -> dict:
        """Serialize user account attributes."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}' role='{self.role}'>"
