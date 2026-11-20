"""Centralized Risk Assessment Engine for CyberShield AI.

Provides consistent risk scoring, risk categorization, severity colors/badges,
aggregated threat calculations, recommended defensive actions, and database formatting.
"""

from datetime import datetime, timezone
import json
from typing import List, Dict, Any, Optional


RISK_LEVEL_THRESHOLDS = [
    (20, 'Very Low'),
    (40, 'Low'),
    (60, 'Medium'),
    (80, 'High'),
    (100, 'Critical')
]

RISK_COLORS = {
    'Very Low': '#10b981',   # Emerald / Green
    'Low': '#84cc16',        # Light Green / Lime
    'Medium': '#f59e0b',     # Amber / Orange
    'High': '#ef4444',       # Red
    'Critical': '#881337'    # Dark Red / Maroon
}

RISK_BADGES = {
    'Very Low': 'bg-success',
    'Low': 'bg-info',
    'Medium': 'bg-warning text-dark',
    'High': 'bg-danger',
    'Critical': 'bg-dark text-white'
}

PRIORITY_LEVELS = {
    'Very Low': 'P5 - Informational',
    'Low': 'P4 - Low Priority',
    'Medium': 'P3 - Medium Priority',
    'High': 'P2 - High Priority',
    'Critical': 'P1 - Immediate Action Required'
}


def calculate_risk_level(score: int) -> str:
    """Calculate categorical risk level from numerical score (0-100).
    
    0-20   = Very Low
    21-40  = Low
    41-60  = Medium
    61-80  = High
    81-100 = Critical
    """
    try:
        score_val = int(round(float(score)))
    except (ValueError, TypeError):
        score_val = 0

    score_val = max(0, min(100, score_val))

    if score_val <= 20:
        return 'Very Low'
    elif score_val <= 40:
        return 'Low'
    elif score_val <= 60:
        return 'Medium'
    elif score_val <= 80:
        return 'High'
    else:
        return 'Critical'


def get_risk_color(risk_level: str) -> str:
    """Return hex color corresponding to risk level."""
    return RISK_COLORS.get(risk_level, '#6b7280')


def get_risk_badge_class(risk_level: str) -> str:
    """Return Bootstrap badge CSS class for risk level."""
    return RISK_BADGES.get(risk_level, 'bg-secondary')


def aggregate_risk(scores: List[int]) -> int:
    """Compute aggregate risk from multiple risk scores using weighted average with max influence.
    
    Formula emphasizes the highest severity threat while accounting for cumulative density:
    Risk = 0.6 * max(scores) + 0.4 * mean(scores)
    """
    if not scores:
        return 0

    valid_scores = []
    for s in scores:
        try:
            val = max(0, min(100, int(round(float(s)))))
            valid_scores.append(val)
        except (ValueError, TypeError):
            continue

    if not valid_scores:
        return 0

    max_score = max(valid_scores)
    mean_score = sum(valid_scores) / len(valid_scores)
    aggregate = int(round((0.6 * max_score) + (0.4 * mean_score)))
    return max(0, min(100, aggregate))


def get_recommended_actions(module: str, risk_level: str) -> List[str]:
    """Return actionable security guidance tailored to module and risk level."""
    mod = (module or '').lower().strip()
    
    # Generic low-risk recommendations
    if risk_level in ('Very Low', 'Low'):
        return [
            "No immediate mitigation required.",
            "Continue standard passive monitoring and logging.",
            "Maintain baseline telemetry for anomaly detection."
        ]

    # Module-specific recommendations for Medium, High, and Critical
    actions: Dict[str, Dict[str, List[str]]] = {
        'phishing': {
            'Medium': [
                "Inspect URL parameters and domain registrar history manually.",
                "Verify SSL/TLS certificate chain and issuer reputation.",
                "Advise end users to exercise caution before entering credentials."
            ],
            'High': [
                "Block domain and full URI at corporate web proxy/secure web gateway.",
                "Search email gateway logs for incoming delivery of this link.",
                "Revoke active sessions for any user who clicked this URL.",
                "Submit URL to threat intelligence feeds (PhishTank, Google Safe Browsing)."
            ],
            'Critical': [
                "Immediately quarantine email messages containing this destination.",
                "Initiate emergency credential reset for targeted accounts.",
                "Enforce strict multi-factor authentication (MFA) challenge.",
                "Push firewall/DNS sinkhole rules globally across all endpoints."
            ]
        },
        'ip_spoofing': {
            'Medium': [
                "Verify edge router ingress filtering (BCP 38 / RFC 2827).",
                "Inspect TTL distributions and MAC address mappings in local ARP cache.",
                "Monitor flow records for unusual asymmetric routing patterns."
            ],
            'High': [
                "Enable Unicast Reverse Path Forwarding (uRPF) in strict mode on edge routers.",
                "Drop all inbound traffic sourced from reserved/bogon addresses at border firewall.",
                "Isolate originating switch port if source MAC corresponds to internal host."
            ],
            'Critical': [
                "Apply emergency access-control lists (ACLs) to drop spoofed IP range.",
                "Contact upstream transit ISP to verify upstream source validation.",
                "Investigate internal network segment for rogue DHCP/ARP injection appliances."
            ]
        },
        'dns': {
            'Medium': [
                "Query authoritative name servers directly and compare query responses.",
                "Review passive DNS history to inspect recent domain registration dates.",
                "Inspect host query volume to check for potential periodic beaconing."
            ],
            'High': [
                "Sinkhole suspicious domain at internal recursive DNS resolvers.",
                "Inspect endpoint process trees generating anomalous DNS requests.",
                "Enable DNS inspection/firewalling to detect DNS tunneling or exfiltration."
            ],
            'Critical': [
                "Block malicious nameservers and domain suffixes at perimeter.",
                "Quarantine compromised endpoints exhibiting DGA beaconing or tunneling patterns.",
                "Perform memory acquisition and packet capture on infected internal client."
            ]
        },
        'ddos': {
            'Medium': [
                "Enable rate-limiting and connection throttling on targeted service ports.",
                "Increase SYN backlog queue depth and enable TCP SYN cookies (syncookies).",
                "Monitor edge bandwidth utilization against baseline threshold."
            ],
            'High': [
                "Activate DDoS mitigation profile at CDN or cloud scrubbing center.",
                "Implement geo-blocking and aggressive rate-limiting on offending subnets.",
                "Divert incoming web traffic through reverse proxy with challenge/CAPTCHA."
            ],
            'Critical': [
                "Initiate BGP Anycast routing or BGP Flowspec filtering with upstream ISP.",
                "Engage DDoS incident response protocol and cloud mitigation provider.",
                "Blackhole / null-route targeted non-essential IPs to preserve core infrastructure."
            ]
        },
        'brute_force': {
            'Medium': [
                "Enforce account lockout policies after consecutive failed authentications.",
                "Check whether failed logins target active employee user IDs or default accounts.",
                "Ensure rate-limiting on login endpoints (e.g. 5 attempts / minute)."
            ],
            'High': [
                "Add offending source IP addresses to firewall / fail2ban drop jail.",
                "Notify owners of targeted accounts and require password update.",
                "Mandate FIDO2/WebAuthn or TOTP multi-factor authentication on all external services."
            ],
            'Critical': [
                "Immediately freeze and lock repeatedly targeted administrative accounts.",
                "Temporarily restrict remote management interfaces (SSH/RDP) to approved VPN IPs.",
                "Perform threat hunt for successful logins occurring after brute force bursts."
            ]
        },
        'malware': {
            'Medium': [
                "Submit file to secondary sandbox for dynamic behavioral analysis.",
                "Audit script execution policies (e.g. PowerShell ConstrainedLanguage mode).",
                "Retain sample in secure isolation container for reverse engineering."
            ],
            'High': [
                "Isolate host from local network immediately (quarantine network adapter).",
                "Kill active process trees associated with suspect binary.",
                "Block file hash (SHA-256) across EDR agent fleet and mail/web gateways."
            ],
            'Critical': [
                "Initiate full Incident Response containment protocol on compromised system.",
                "Preserve volatile RAM image and system disk image for forensic analysis.",
                "Revoke and rotate Kerberos/domain administrator credentials if system was elevated.",
                "Scan domain controllers and adjacent lateral movement paths for persistence."
            ]
        }
    }

    # Match module actions or fallback to generic high-severity response
    module_dict = actions.get(mod, {})
    if risk_level in module_dict:
        return module_dict[risk_level]
    elif 'High' in module_dict:
        return module_dict['High']

    # Fallback generic actions
    return [
        f"Apply defensive containment rules for detected {mod.replace('_', ' ')} incident.",
        "Inspect telemetry and historical logs for signs of unauthorized lateral movement.",
        "Alert security operations center (SOC) and incident handling team."
    ]


def generate_risk_summary(module: str, result: str, risk_score: int, indicators: List[str]) -> Dict[str, Any]:
    """Generate structured risk summary object for user interfaces and reports."""
    risk_level = calculate_risk_level(risk_score)
    risk_color = get_risk_color(risk_level)
    risk_badge = get_risk_badge_class(risk_level)
    priority = PRIORITY_LEVELS.get(risk_level, 'P3 - Medium Priority')
    recommended_actions = get_recommended_actions(module, risk_level)

    descriptions = {
        'Very Low': f"Minimal security anomalies detected. System operations within normal operational baselines.",
        'Low': f"Minor deviations detected with low probability of malicious exploitation.",
        'Medium': f"Notable suspicious indicators observed. Requires analyst triage and defensive review.",
        'High': f"High-confidence threat indicators detected. Immediate defensive controls strongly advised.",
        'Critical': f"Severe active security threat detected. Critical containment actions must be initiated immediately."
    }

    return {
        'risk_level': risk_level,
        'risk_color': risk_color,
        'risk_badge': risk_badge,
        'risk_description': descriptions.get(risk_level, f"Assessed as {risk_level}."),
        'priority': priority,
        'recommended_actions': recommended_actions,
        'indicator_count': len(indicators or [])
    }


def format_result_for_db(engine_result: Dict[str, Any], module: str, input_summary: str, user_id: Optional[int] = None) -> Dict[str, Any]:
    """Format an engine output dictionary ready for insertion into DetectionHistory database model."""
    risk_score = engine_result.get('risk_score', 0)
    risk_level = engine_result.get('risk_level') or calculate_risk_level(risk_score)
    indicators = engine_result.get('indicators', [])
    details = engine_result.get('details', {})

    # Ensure json serializable
    indicators_json = json.dumps(indicators) if not isinstance(indicators, str) else indicators
    details_json = json.dumps(details) if not isinstance(details, str) else details

    timestamp_str = engine_result.get('timestamp')
    if timestamp_str:
        try:
            created_at = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            created_at = datetime.now(timezone.utc)
    else:
        created_at = datetime.now(timezone.utc)

    return {
        'user_id': user_id,
        'module': module,
        'input_summary': input_summary[:255] if input_summary else 'N/A',
        'result': engine_result.get('result', 'Unknown'),
        'risk_score': int(risk_score),
        'risk_level': risk_level,
        'indicators_json': indicators_json,
        'model_used': engine_result.get('model_used', 'Heuristic Rules'),
        'created_at': created_at
    }
