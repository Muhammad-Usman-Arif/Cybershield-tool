from datetime import datetime
from app.extensions import db

class WorkingSession(db.Model):
    __tablename__ = 'working_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    login_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    logout_at = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    login_city = db.Column(db.String(100), nullable=True)
    login_region = db.Column(db.String(100), nullable=True)
    login_country = db.Column(db.String(100), nullable=True)
    login_timezone = db.Column(db.String(100), nullable=True)
    login_lat = db.Column(db.Float, nullable=True)
    login_lon = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='active', nullable=False)
    
    @property
    def duration_seconds(self):
        end = self.logout_at or datetime.utcnow()
        return int((end - self.login_at).total_seconds())
    
    @property
    def duration_str(self):
        s = self.duration_seconds
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        if h > 0: return f'{h}h {m}m'
        if m > 0: return f'{m}m {sec}s'
        return f'{sec}s'
    
    @property
    def location_str(self):
        parts = [p for p in [self.login_city, self.login_country] if p]
        return ', '.join(parts) if parts else 'Unknown'
    
    def to_dict(self):
        return {
            'id': self.id, 'user_id': self.user_id,
            'login_at': self.login_at.isoformat() if self.login_at else None,
            'logout_at': self.logout_at.isoformat() if self.logout_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'duration': self.duration_str,
            'duration_seconds': self.duration_seconds,
            'status': self.status,
            'location': self.location_str,
            'city': self.login_city, 'region': self.login_region,
            'country': self.login_country, 'timezone': self.login_timezone,
        }
    
    def __repr__(self):
        return f'<WorkingSession id={self.id} user={self.user_id} status={self.status}>'
