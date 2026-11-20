"""
BruteForceResult model – stores results of Brute‑Force detection module.
"""

from app.extensions import db
import json

class BruteForceResult(db.Model):
    """Brute‑Force detection result record.

    Linked to ``DetectionHistory`` via ``detection_id``.
    Stores basic statistics and a JSON list of suspicious login attempts.
    """

    __tablename__ = "brute_force_results"

    id = db.Column(db.Integer, primary_key=True)
    detection_id = db.Column(
        db.Integer,
        db.ForeignKey("detection_history.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Total number of failed attempts observed
    total_failed = db.Column(db.Integer, nullable=False, default=0)
    # JSON array of dicts: {"username": str, "source_ip": str, "timestamp": str}
    attempts_json = db.Column(db.Text, default='[]', nullable=False)
    # Human‑readable summary for UI / reports
    analysis_summary = db.Column(db.Text, default="", nullable=False)

    def __init__(self, **kwargs):
        detection_id = kwargs.pop('detection_id', None)
        total_failed = kwargs.pop('total_failed', None)
        if total_failed is None:
            total_failed = kwargs.pop('failed_attempts', 0)
        attempts = kwargs.pop('attempts', None)
        analysis_summary = kwargs.pop('analysis_summary', '')
        log_source = kwargs.pop('log_source', '')
        if log_source and not analysis_summary:
            analysis_summary = f"Source: {log_source}"
        kwargs.pop('threshold_exceeded', None)
        suspicious_ips = kwargs.pop('suspicious_ips', None)

        super().__init__(
            detection_id=detection_id,
            total_failed=int(total_failed or 0),
            analysis_summary=analysis_summary or ''
        )
        if attempts:
            self.attempts = attempts
        elif suspicious_ips:
            self.suspicious_ips = suspicious_ips

    @property
    def failed_attempts(self) -> int:
        return self.total_failed

    @failed_attempts.setter
    def failed_attempts(self, val: int) -> None:
        self.total_failed = int(val or 0)

    @property
    def attempts(self) -> list:
        """Return parsed list of attempt dictionaries."""
        if not self.attempts_json:
            return []
        try:
            parsed = json.loads(self.attempts_json)
            return parsed if isinstance(parsed, list) else [parsed]
        except (ValueError, TypeError):
            return []

    @attempts.setter
    def attempts(self, val: list) -> None:
        """Serialize list of attempts to JSON."""
        if val is None:
            self.attempts_json = "[]"
        else:
            self.attempts_json = json.dumps(list(val))

    @property
    def suspicious_ips(self) -> list:
        """Extract unique suspicious source IP addresses."""
        ips = []
        for a in self.attempts:
            if isinstance(a, dict) and 'source_ip' in a:
                ips.append(a['source_ip'])
            elif isinstance(a, str):
                ips.append(a)
        return list(dict.fromkeys(ips))

    @suspicious_ips.setter
    def suspicious_ips(self, val: list) -> None:
        if val is None:
            self.attempts_json = "[]"
        else:
            self.attempts = [{'source_ip': ip} if isinstance(ip, str) else ip for ip in val]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "total_failed": self.total_failed,
            "attempts": self.attempts,
            "suspicious_ips": self.suspicious_ips,
            "analysis_summary": self.analysis_summary,
        }

    def __repr__(self) -> str:
        return f"<BruteForceResult id={self.id} failed={self.total_failed}>"
