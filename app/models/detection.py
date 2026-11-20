"""
CyberShield AI - Detection History Model
"""
import json
from datetime import datetime
from app.extensions import db


class DetectionHistory(db.Model):
    """Central Threat Intelligence & Detection Audit Record."""
    __tablename__ = 'detection_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    module = db.Column(db.String(50), nullable=False, index=True)
    input_summary = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(100), nullable=False)
    risk_score = db.Column(db.Integer, default=0, nullable=False)
    risk_level = db.Column(db.String(20), default='low', nullable=False)
    indicators_json = db.Column(db.Text, default='[]', nullable=False)
    model_used = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Relationships to specialized analysis records
    phishing_result = db.relationship(
        'PhishingResult',
        backref='detection',
        uselist=False,
        cascade='all, delete-orphan'
    )
    network_analyses = db.relationship(
        'NetworkAnalysis',
        backref='detection',
        cascade='all, delete-orphan'
    )
    dns_analyses = db.relationship(
        'DNSAnalysis',
        backref='detection',
        cascade='all, delete-orphan'
    )
    ddos_analyses = db.relationship(
        'DDoSAnalysis',
        backref='detection',
        cascade='all, delete-orphan'
    )
    brute_force_results = db.relationship(
        'BruteForceResult',
        backref='detection',
        cascade='all, delete-orphan'
    )
    malware_analyses = db.relationship(
        'MalwareAnalysis',
        backref='detection',
        cascade='all, delete-orphan'
    )
    alerts = db.relationship(
        'SecurityAlert',
        backref='detection',
        cascade='all, delete-orphan'
    )

    def __init__(self, **kwargs):
        # Handle indicators list or string
        indicators_val = kwargs.pop('indicators', None)
        if indicators_val is not None:
            if isinstance(indicators_val, (list, tuple, dict)):
                kwargs['indicators_json'] = json.dumps(indicators_val)
            else:
                kwargs['indicators_json'] = str(indicators_val)
        
        # Safely pop metadata kwargs that might not be DB columns
        self._confidence = kwargs.pop('confidence', None)
        self._details = kwargs.pop('details', None)

        super().__init__(**kwargs)

    @property
    def indicators(self) -> list:
        """Parse Indicators of Compromise JSON into Python list."""
        if not self.indicators_json:
            return []
        try:
            parsed = json.loads(self.indicators_json)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, TypeError):
            return []

    @indicators.setter
    def indicators(self, val: list) -> None:
        """Serialize Indicators of Compromise list into JSON string."""
        if val is None:
            self.indicators_json = '[]'
        else:
            self.indicators_json = json.dumps(list(val))

    def to_dict(self) -> dict:
        """Serialize detection telemetry into dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'module': self.module,
            'input_summary': self.input_summary,
            'result': self.result,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'indicators': self.indicators,
            'model_used': self.model_used,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self) -> str:
        return f"<DetectionHistory id={self.id} module='{self.module}' risk='{self.risk_level} ({self.risk_score})'>"
