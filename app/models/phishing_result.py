"""
CyberShield AI - Phishing Detection Result Model
"""
import json
from app.extensions import db


class PhishingResult(db.Model):
    """Phishing URL Analysis Telemetry & Extracted Heuristics."""
    __tablename__ = 'phishing_results'

    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(
        db.Integer,
        db.ForeignKey('detection_history.id', ondelete='CASCADE'),
        nullable=False,
        unique=True,
        index=True
    )
    url = db.Column(db.String(2048), nullable=False)
    is_phishing = db.Column(db.Boolean, default=False, nullable=False)
    confidence = db.Column(db.Float, default=0.0, nullable=False)
    feature_data_json = db.Column(db.Text, default='{}', nullable=False)

    @property
    def feature_data(self) -> dict:
        """Parse extracted URL syntactic and lexical features JSON."""
        if not self.feature_data_json:
            return {}
        try:
            parsed = json.loads(self.feature_data_json)
            return parsed if isinstance(parsed, dict) else {'data': parsed}
        except (ValueError, TypeError):
            return {}

    @feature_data.setter
    def feature_data(self, val: dict) -> None:
        """Serialize feature extraction dictionary into JSON."""
        if val is None:
            self.feature_data_json = '{}'
        else:
            self.feature_data_json = json.dumps(val)

    def to_dict(self) -> dict:
        """Serialize phishing result attributes."""
        return {
            'id': self.id,
            'detection_id': self.detection_id,
            'url': self.url,
            'is_phishing': self.is_phishing,
            'confidence': self.confidence,
            'feature_data': self.feature_data
        }

    def __repr__(self) -> str:
        return f"<PhishingResult id={self.id} is_phishing={self.is_phishing} confidence={self.confidence:.2f}>"
