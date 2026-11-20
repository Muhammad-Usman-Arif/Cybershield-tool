"""
DNSAnalysis model – stores results of DNS spoofing detection module.
"""

from app.extensions import db
import json

class DNSAnalysis(db.Model):
    """DNS detection result record.

    Linked to ``DetectionHistory`` via ``detection_id``.
    Stores domain examined, resolved IPs, and any suspicious indicators.
    """

    __tablename__ = "dns_analyses"

    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Queried domain name
    domain = db.Column(db.String(255), nullable=False)
    # Resolved IP addresses (JSON list of strings)
    resolved_ips_json = db.Column(db.Text, default='[]', nullable=False)
    # JSON list of suspicious indicators (e.g., "high entropy", "punycode", "unexpected TTL")
    indicators_json = db.Column(db.Text, default='[]', nullable=False)
    # Human‑readable summary for UI / reports
    analysis_summary = db.Column(db.Text, default="", nullable=False)

    def __init__(self, **kwargs):
        detection_id = kwargs.pop('detection_id', None)
        domain = kwargs.pop('domain', '')
        resolved_ips = kwargs.pop('resolved_ips', None)
        resolved_ip = kwargs.pop('resolved_ip', None)
        indicators = kwargs.pop('indicators', None)
        analysis_summary = kwargs.pop('analysis_summary', '')
        kwargs.pop('is_suspicious', None)

        super().__init__(
            detection_id=detection_id,
            domain=domain or '',
            analysis_summary=analysis_summary or ''
        )
        if resolved_ips:
            self.resolved_ips = resolved_ips
        elif resolved_ip:
            self.resolved_ips = [resolved_ip] if isinstance(resolved_ip, str) else list(resolved_ip)
        if indicators:
            self.indicators = indicators

    @property
    def resolved_ips(self) -> list:
        if not self.resolved_ips_json:
            return []
        try:
            parsed = json.loads(self.resolved_ips_json)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, TypeError):
            return []

    @resolved_ips.setter
    def resolved_ips(self, val: list) -> None:
        self.resolved_ips_json = json.dumps(list(val)) if val else '[]'

    @property
    def resolved_ip(self) -> str:
        return self.resolved_ips[0] if self.resolved_ips else ''

    @resolved_ip.setter
    def resolved_ip(self, val: str) -> None:
        self.resolved_ips = [val] if val else []

    @property
    def indicators(self) -> list:
        if not self.indicators_json:
            return []
        try:
            parsed = json.loads(self.indicators_json)
            return parsed if isinstance(parsed, list) else [str(parsed)]
        except (ValueError, TypeError):
            return []

    @indicators.setter
    def indicators(self, val: list) -> None:
        self.indicators_json = json.dumps(list(val)) if val else '[]'

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "domain": self.domain,
            "resolved_ips": self.resolved_ips,
            "resolved_ip": self.resolved_ip,
            "indicators": self.indicators,
            "analysis_summary": self.analysis_summary,
        }

    def __repr__(self) -> str:
        return f"<DNSAnalysis id={self.id} domain={self.domain}>"
