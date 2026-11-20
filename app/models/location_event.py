"""
LocationEvent model – stores user location/activity events (login, logout, detection, etc.).
"""

from datetime import datetime
from app.extensions import db

class LocationEvent(db.Model):
    """Location / activity record linked to a user.

    event_type: e.g. 'login', 'logout', 'phishing', 'ddos', etc.
    Optional detection_id links to DetectionHistory when the event is a detection.
    """

    __tablename__ = 'location_events'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    detection_id = db.Column(db.Integer, db.ForeignKey('detection_history.id', ondelete='SET NULL'), nullable=True, index=True)
    event_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    # Geocode fields
    city = db.Column(db.String(100), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    timezone = db.Column(db.String(100), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    accuracy = db.Column(db.Float, nullable=True)  # meters

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'detection_id': self.detection_id,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'city': self.city,
            'region': self.region,
            'country': self.country,
            'timezone': self.timezone,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'accuracy': self.accuracy,
        }

    def __repr__(self):
        return f"<LocationEvent id={self.id} user={self.user_id} type={self.event_type}>"
