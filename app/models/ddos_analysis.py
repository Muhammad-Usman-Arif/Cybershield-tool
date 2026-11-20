"""
DDoSAnalysis model – stores results of DDoS detection module.
"""

from app.extensions import db
import json

class DDoSAnalysis(db.Model):
    """DDoS detection result record.

    Linked to ``DetectionHistory`` via ``detection_id``.
    Stores basic traffic stats and a JSON list of identified anomaly indicators.
    """

    __tablename__ = "ddos_analyses"

    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Basic traffic metrics
    duration_seconds = db.Column(db.Float, nullable=False, default=0.0)
    total_packets = db.Column(db.Integer, nullable=False, default=0)
    avg_packet_size = db.Column(db.Float, nullable=False, default=0.0)
    # JSON field with anomaly descriptors (e.g., "SYN flood", "UDP flood")
    anomalies_json = db.Column(db.Text, default="[]", nullable=False)
    # Human‑readable summary for UI / reports
    analysis_summary = db.Column(db.Text, default="", nullable=False)

    def __init__(self, **kwargs):
        detection_id = kwargs.pop('detection_id', None)
        duration_seconds = kwargs.pop('duration_seconds', 0.0)
        total_packets = kwargs.pop('total_packets', 0)
        avg_packet_size = kwargs.pop('avg_packet_size', 0.0)
        anomalies = kwargs.pop('anomalies', None)
        analysis_summary = kwargs.pop('analysis_summary', '')
        
        # Mappings from route kwargs:
        stats = kwargs.pop('stats', {}) or kwargs.pop('traffic_stats', {})
        if stats and isinstance(stats, dict):
            if not total_packets and 'total_packets' in stats:
                total_packets = stats.get('total_packets', 0)
            if not duration_seconds and 'duration_seconds' in stats:
                duration_seconds = stats.get('duration_seconds', 0.0)
            if not avg_packet_size and 'avg_packet_size' in stats:
                avg_packet_size = stats.get('avg_packet_size', 0.0)
        attack_pattern = kwargs.pop('attack_pattern', None) or kwargs.pop('traffic_type', None)
        if attack_pattern:
            anomalies = (anomalies or []) + [attack_pattern]
        
        file_name = kwargs.pop('file_name', None)
        if file_name and not analysis_summary:
            analysis_summary = f"File: {file_name}"
            
        kwargs.pop('anomaly_score', None)
        
        super().__init__(
            detection_id=detection_id,
            duration_seconds=float(duration_seconds or 0.0),
            total_packets=int(total_packets or 0),
            avg_packet_size=float(avg_packet_size or 0.0),
            analysis_summary=analysis_summary or ''
        )
        if anomalies:
            self.anomalies = anomalies

    @property
    def anomalies(self) -> list:
        """Return the parsed list of anomaly strings."""
        if not self.anomalies_json:
            return []
        try:
            parsed = json.loads(self.anomalies_json)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, TypeError):
            return []

    @anomalies.setter
    def anomalies(self, val: list) -> None:
        """Serialize a list of anomaly strings to JSON."""
        if val is None:
            self.anomalies_json = "[]"
        else:
            self.anomalies_json = json.dumps(list(val))

    @property
    def attack_pattern(self) -> str:
        return self.anomalies[0] if self.anomalies else "Unknown"

    @attack_pattern.setter
    def attack_pattern(self, val: str) -> None:
        if val:
            self.anomalies = list(set(self.anomalies + [val]))

    @property
    def stats(self) -> dict:
        return {
            'duration_seconds': self.duration_seconds,
            'total_packets': self.total_packets,
            'avg_packet_size': self.avg_packet_size
        }

    @stats.setter
    def stats(self, val: dict) -> None:
        if isinstance(val, dict):
            if 'duration_seconds' in val:
                self.duration_seconds = float(val['duration_seconds'])
            if 'total_packets' in val:
                self.total_packets = int(val['total_packets'])
            if 'avg_packet_size' in val:
                self.avg_packet_size = float(val['avg_packet_size'])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "duration_seconds": self.duration_seconds,
            "total_packets": self.total_packets,
            "avg_packet_size": self.avg_packet_size,
            "anomalies": self.anomalies,
            "analysis_summary": self.analysis_summary,
        }

    def __repr__(self) -> str:
        return f"<DDoSAnalysis id={self.id} packets={self.total_packets} duration={self.duration_seconds}s>"
