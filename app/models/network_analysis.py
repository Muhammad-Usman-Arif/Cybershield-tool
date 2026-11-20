"""
CyberShield AI - Network Analysis Model (IP Spoofing & PCAP Telemetry)
"""
import json
from app.extensions import db


class NetworkAnalysis(db.Model):
    """Network Traffic and Packet Telemetry Analysis Record."""
    __tablename__ = 'network_analyses'

    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(
        db.Integer,
        db.ForeignKey('detection_history.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    file_name = db.Column(db.String(255), nullable=False)
    packet_count = db.Column(db.Integer, default=0, nullable=False)
    suspicious_ips_json = db.Column(db.Text, default='[]', nullable=False)
    analysis_summary = db.Column(db.Text, default='', nullable=False)

    @property
    def suspicious_ips(self) -> list:
        """Parse identified anomalous IP addresses JSON."""
        if not self.suspicious_ips_json:
            return []
        try:
            parsed = json.loads(self.suspicious_ips_json)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, TypeError):
            return []

    @suspicious_ips.setter
    def suspicious_ips(self, val: list) -> None:
        """Serialize suspicious IP addresses to JSON."""
        if val is None:
            self.suspicious_ips_json = '[]'
        else:
            self.suspicious_ips_json = json.dumps(list(val))

    def to_dict(self) -> dict:
        """Serialize network analysis attributes."""
        return {
            'id': self.id,
            'detection_id': self.detection_id,
            'file_name': self.file_name,
            'packet_count': self.packet_count,
            'suspicious_ips': self.suspicious_ips,
            'analysis_summary': self.analysis_summary
        }

    def __repr__(self) -> str:
        return f"<NetworkAnalysis id={self.id} file='{self.file_name}' packets={self.packet_count}>"
