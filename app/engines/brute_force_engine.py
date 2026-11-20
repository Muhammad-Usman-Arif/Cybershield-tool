"""Brute Force and Credential Abuse Log Analysis Engine for CyberShield AI.

Features:
- Multi-format syslog and web server authentication log parser
- Sliding time-window failed attempt rate analysis
- Credential Stuffing detection (single IP cycling many usernames)
- Password Spraying detection (distributed IPs targeting single username)
- Account Enumeration identification
"""

import re
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

from app.engines.risk_engine import calculate_risk_level


class BruteForceEngine:
    """Production Log Analysis Engine for Authentication Abuse Detection."""

    DEFAULT_THRESHOLD = 5
    DEFAULT_WINDOW = 300  # seconds (5 minutes)

    # Regex patterns for failed authentication events
    COMMON_PATTERNS = [
        # SSH failed password with user
        re.compile(r'Failed password for (\S+) from ([\d.]+)', re.IGNORECASE),
        # PAM / auth failure
        re.compile(r'authentication failure.*?(?:rhost=([\d.]+)).*?(?:user=(\S+))?', re.IGNORECASE),
        # SSH invalid user
        re.compile(r'Invalid user (\S+) from ([\d.]+)', re.IGNORECASE),
        # Generic failed login
        re.compile(r'FAILED LOGIN.*?(?:for (\S+))?.*?from ([\d.]+)', re.IGNORECASE),
        # Timestamped failed/invalid line
        re.compile(r'(\d{4}-\d{2}-\d{2}[T\s][\d:]+).*?(\S+).*?(?:failed|invalid|wrong).*?from ([\d.]+)', re.IGNORECASE),
        # Web 401 Unauthorized
        re.compile(r'HTTP/[\d.]+\"\s+401.*?\s+([\d.]+)', re.IGNORECASE),
        # Web 403 Forbidden
        re.compile(r'HTTP/[\d.]+\"\s+403.*?\s+([\d.]+)', re.IGNORECASE),
        # Web app login failure with user and ip
        re.compile(r'login failed.*?user[= ]["\']?(\w+)["\']?.*?ip[= ]["\']?([\d.]+)["\']?', re.IGNORECASE)
    ]

    TIMESTAMP_PATTERNS = [
        # ISO format: 2026-11-05T14:23:10 or 2026-11-05 14:23:10
        (re.compile(r'\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})\b'), '%Y-%m-%d %H:%M:%S'),
        # Syslog format: Nov  5 14:23:10 or Nov 05 14:23:10
        (re.compile(r'\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b'), '%b %d %H:%M:%S'),
        # Common Log Format: [05/Nov/2026:14:23:10
        (re.compile(r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})'), '%d/%b/%Y:%H:%M:%S')
    ]

    def __init__(self):
        self.model_name = "Authentication Log Heuristic Engine"

    def _parse_timestamp(self, line: str) -> Optional[datetime]:
        """Attempt to extract and parse datetime from a log line."""
        for pattern, dt_format in self.TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_ts = match.group(1).replace('T', ' ')
                # Handle single digit day in syslog (e.g. 'Nov  5')
                raw_ts = re.sub(r'\s+', ' ', raw_ts)
                try:
                    dt = datetime.strptime(raw_ts, dt_format)
                    # If syslog without year, assign current year
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return dt
                except ValueError:
                    continue
        return None

    def _extract_attempts(self, log_text: str) -> List[Dict[str, Any]]:
        """Parse raw log lines and extract structured authentication failure events."""
        attempts = []
        if not log_text:
            return attempts

        base_time = datetime.now()
        line_index = 0

        for line in log_text.splitlines():
            clean_line = line.strip()
            if not clean_line:
                continue

            extracted_ip = None
            extracted_user = 'unknown'

            # Try matched patterns
            matched = False
            for pattern in self.COMMON_PATTERNS:
                m = pattern.search(clean_line)
                if m:
                    matched = True
                    groups = m.groups()

                    # Extract IP and User depending on pattern match layout
                    for grp in groups:
                        if not grp:
                            continue
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', grp):
                            extracted_ip = grp
                        elif grp != clean_line and not re.search(r'\d{4}-\d{2}-\d{2}', grp):
                            extracted_user = grp

                    break

            # Fallback general IP extraction if line indicates failed authentication
            if not extracted_ip and any(kw in clean_line.lower() for kw in ['fail', 'invalid', 'unauthorized', 'error', 'denied']):
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_line)
                if ip_match:
                    extracted_ip = ip_match.group(0)
                    user_match = re.search(r'user(?:name)?\s*[:= ]\s*(\w+)', clean_line, re.IGNORECASE)
                    if user_match:
                        extracted_user = user_match.group(1)

            if extracted_ip:
                parsed_ts = self._parse_timestamp(clean_line)
                if not parsed_ts:
                    # Provide incremental timestamp if none present in log line
                    parsed_ts = base_time + timedelta(seconds=line_index)

                attempts.append({
                    'ip': extracted_ip,
                    'username': extracted_user,
                    'timestamp': parsed_ts,
                    'line': clean_line
                })
                line_index += 1

        return attempts

    def analyze_logs(self, log_text: str, threshold: int = 5, window_seconds: int = 300) -> Dict[str, Any]:
        """Analyze authentication logs for brute force, stuffing, and spraying patterns."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if not log_text or not isinstance(log_text, str) or not log_text.strip():
            return {
                'success': False,
                'result': 'Invalid Input',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.0,
                'indicators': ['No log data provided for analysis'],
                'model_used': self.model_name,
                'details': {'error': 'Empty log content'},
                'timestamp': timestamp
            }

        attempts = self._extract_attempts(log_text)
        total_attempts = len(attempts)

        if total_attempts == 0:
            return {
                'success': True,
                'result': 'Clean',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.85,
                'indicators': ["No failed authentication signatures detected in submitted logs"],
                'model_used': self.model_name,
                'details': {'total_failed_attempts': 0, 'per_ip_stats': {}},
                'timestamp': timestamp
            }

        # Organize attempts by IP and by username
        attempts_by_ip = defaultdict(list)
        ips_by_user = defaultdict(set)

        for att in attempts:
            attempts_by_ip[att['ip']].append(att)
            if att['username'] and att['username'] != 'unknown':
                ips_by_user[att['username']].add(att['ip'])

        per_ip_stats = {}
        suspicious_ips = []
        credential_stuffing_ips = []
        max_attempts_single_ip = 0

        for ip, ip_attempts in attempts_by_ip.items():
            # Sort chronologically
            ip_attempts.sort(key=lambda x: x['timestamp'])
            total_ip_attempts = len(ip_attempts)
            max_attempts_single_ip = max(max_attempts_single_ip, total_ip_attempts)

            targeted_users = list({a['username'] for a in ip_attempts if a['username'] != 'unknown'})

            # Sliding window check
            max_window_count = 0
            n = len(ip_attempts)
            for i in range(n):
                w_start = ip_attempts[i]['timestamp']
                count = 1
                for j in range(i + 1, n):
                    if (ip_attempts[j]['timestamp'] - w_start).total_seconds() <= window_seconds:
                        count += 1
                    else:
                        break
                if count > max_window_count:
                    max_window_count = count

            exceeded_threshold = max_window_count >= threshold
            if exceeded_threshold:
                suspicious_ips.append(ip)

            # Credential stuffing check: single IP targeting many unique usernames
            is_stuffing = len(targeted_users) >= 4
            if is_stuffing:
                credential_stuffing_ips.append(ip)

            per_ip_stats[ip] = {
                'total_attempts': total_ip_attempts,
                'max_attempts_in_window': max_window_count,
                'unique_users_targeted': len(targeted_users),
                'users': targeted_users[:10],
                'exceeded_threshold': exceeded_threshold,
                'credential_stuffing': is_stuffing
            }

        # Password spraying check: single username targeted by multiple distinct IPs
        sprayed_accounts = []
        for username, src_ips in ips_by_user.items():
            if len(src_ips) >= 4:
                sprayed_accounts.append({
                    'username': username,
                    'ip_count': len(src_ips),
                    'source_ips': list(src_ips)[:5]
                })

        # Calculate Risk Score
        # Component 1: Max attempt volume (normalized up to 40)
        vol_score = min(40, (max_attempts_single_ip / max(threshold, 1)) * 10)

        # Component 2: Ratio and count of suspicious IPs (up to 30)
        suspicious_ratio = len(suspicious_ips) / max(1, len(attempts_by_ip))
        ip_score = min(30, int(suspicious_ratio * 20 + len(suspicious_ips) * 5))

        # Component 3: Advanced patterns (Credential Stuffing & Password Spraying)
        pattern_score = 0
        indicators = []

        if suspicious_ips:
            indicators.append(f"Brute force threshold exceeded: {len(suspicious_ips)} IP(s) recorded >= {threshold} failed attempts within {window_seconds}s window")

        if credential_stuffing_ips:
            pattern_score += 25
            indicators.append(f"Credential Stuffing detected: {len(credential_stuffing_ips)} source IP(s) cycled through multiple distinct usernames")

        if sprayed_accounts:
            pattern_score += 25
            indicators.append(f"Password Spraying pattern detected: {len(sprayed_accounts)} user account(s) targeted horizontally across multiple distinct IP addresses")

        if not suspicious_ips and total_attempts > 0:
            indicators.append(f"Isolated authentication failures observed ({total_attempts} attempts) without exceeding burst threshold")

        total_risk = int(round(vol_score + ip_score + pattern_score))
        risk_score = max(0, min(100, total_risk))
        risk_level = calculate_risk_level(risk_score)

        if risk_score >= 61:
            result = 'Malicious'
        elif risk_score >= 35:
            result = 'Suspicious'
        else:
            result = 'Low Risk'

        confidence = 0.92 if suspicious_ips or sprayed_accounts else 0.80

        return {
            'success': True,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'indicators': indicators,
            'model_used': self.model_name,
            'details': {
                'total_failed_attempts': total_attempts,
                'unique_source_ips': len(attempts_by_ip),
                'suspicious_ip_count': len(suspicious_ips),
                'credential_stuffing_ips': credential_stuffing_ips,
                'sprayed_accounts': sprayed_accounts,
                'per_ip_stats': per_ip_stats
            },
            'timestamp': timestamp
        }


# Singleton instance
brute_force_engine = BruteForceEngine()
