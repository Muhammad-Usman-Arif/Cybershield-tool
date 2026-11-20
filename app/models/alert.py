from datetime import datetime
from app.extensions import db


class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'),             nullable=False, index=True)
    detection_id = db.Column(db.Integer, db.ForeignKey('detection_history.id'), nullable=True)
    severity     = db.Column(db.String(20), nullable=False, default='medium')   # low/medium/high/critical
    message      = db.Column(db.Text,       nullable=False)
    status       = db.Column(db.String(20), nullable=False, default='new')      # new/acknowledged/resolved
    created_at   = db.Column(db.DateTime,   nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id':           self.id,
            'user_id':      self.user_id,
            'detection_id': self.detection_id,
            'severity':     self.severity,
            'message':      self.message,
            'status':       self.status,
            'created_at':   self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action     = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50),  nullable=True)
    details    = db.Column(db.Text,        nullable=True)
    created_at = db.Column(db.DateTime,    nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'user_id':    self.user_id,
            'action':     self.action,
            'ip_address': self.ip_address,
            'details':    self.details,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
