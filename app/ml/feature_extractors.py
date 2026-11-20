"""Feature Extraction Module for Machine Learning Detection Models in CyberShield AI.

Provides deterministic, reproducible feature extraction for:
- Phishing URL detection (lexical, statistical, topological features)
- DDoS / Network Traffic flow classification
"""

import math
import re
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, List, Any, Union

try:
    import numpy as np
except ImportError:
    np = None  # Fallback if numpy not installed yet


FEATURE_NAMES: List[str] = [
    'url_length',
    'num_dots',
    'num_hyphens',
    'num_at',
    'num_question',
    'num_equal',
    'num_slash',
    'num_percent',
    'has_ip',
    'uses_https',
    'domain_length',
    'subdomain_count',
    'has_suspicious_keywords',
    'url_entropy',
    'digit_count',
    'letter_count',
    'special_char_count',
    'tld_in_path',
    'double_slash_in_path',
    'port_in_url',
    'url_shortener'
]

NETWORK_FEATURE_NAMES: List[str] = [
    'packet_count',
    'duration',
    'unique_src_ips',
    'unique_dst_ips',
    'unique_dst_ports',
    'avg_pkt_size',
    'src_ip_concentration',
    'port_diversity',
    'syn_ratio',
    'packet_rate',
    'byte_rate'
]

SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'update', 'confirm', 'account',
    'banking', 'verify', 'paypal', 'amazon', 'microsoft',
    'signin', 'wallet', 'security', 'password', 'credential',
    'authenticate', 'appleid', 'recovery'
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bitly.com', 'shorturl.at',
    'rb.gy', 'cutt.ly', 'tiny.cc', 'bc.vc', 'qr.net'
}

COMMON_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.biz',
    '.info', '.xyz', '.top', '.club', '.online', '.site',
    '.shop', '.vip', '.tech', '.work', '.pro', '.ru', '.cn',
    '.cc', '.me', '.io', '.co', '.app', '.live', '.icu'
]

IPV4_REGEX = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features_dict(url: str) -> Dict[str, Any]:
    """Extract lexical and structural URL features as a key-value dictionary."""
    if not url:
        url = ''
    raw_url = url.strip()
    clean_url = raw_url.lower()

    # Prepend scheme if missing for accurate urlparse parsing
    parse_url = raw_url
    if not (parse_url.startswith('http://') or parse_url.startswith('https://')):
        parse_url = 'http://' + parse_url

    parsed = urlparse(parse_url)
    netloc = parsed.netloc or ''
    path = parsed.path or ''

    # Handle port in netloc
    port_in_url = False
    domain = netloc
    if ':' in netloc:
        domain_parts = netloc.split(':')
        domain = domain_parts[0]
        port_in_url = True
    elif parsed.port is not None:
        port_in_url = True

    # 1. url_length
    url_length = len(raw_url)

    # 2-8. Character counts
    num_dots = raw_url.count('.')
    num_hyphens = raw_url.count('-')
    num_at = raw_url.count('@')
    num_question = raw_url.count('?')
    num_equal = raw_url.count('=')
    num_slash = raw_url.count('/')
    num_percent = raw_url.count('%')

    # 9. has_ip (check if domain part is raw IPv4 or IPv6)
    has_ip = bool(IPV4_REGEX.match(domain)) or bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain))

    # 10. uses_https
    uses_https = raw_url.lower().startswith('https://')

    # 11. domain_length
    domain_length = len(domain)

    # 12. subdomain_count
    domain_segments = domain.split('.')
    if len(domain_segments) > 2:
        # e.g., sub.example.com -> 1, sub1.sub2.example.com -> 2
        # If last two are known ccTLD like .co.uk, adjust
        if len(domain_segments) >= 3 and domain_segments[-1] in ('uk', 'au', 'br', 'in', 'jp', 'za') and domain_segments[-2] in ('co', 'com', 'org', 'ac', 'gov'):
            subdomain_count = max(0, len(domain_segments) - 3)
        else:
            subdomain_count = max(0, len(domain_segments) - 2)
    else:
        subdomain_count = 0

    # 13. has_suspicious_keywords
    has_suspicious_keywords = any(kw in clean_url for kw in SUSPICIOUS_KEYWORDS)

    # 14. url_entropy
    url_entropy = calculate_entropy(raw_url)

    # 15-17. digit, letter, special char counts
    digit_count = sum(1 for c in raw_url if c.isdigit())
    letter_count = sum(1 for c in raw_url if c.isalpha())
    special_char_count = sum(1 for c in raw_url if not c.isalnum())

    # 18. tld_in_path
    path_lower = path.lower()
    tld_in_path = any(tld in path_lower for tld in COMMON_TLDS)

    # 19. double_slash_in_path
    # Exclude protocol double slash (e.g., http://)
    double_slash_in_path = '//' in path

    # 20. port_in_url is already determined

    # 21. url_shortener
    clean_domain = domain.lower()
    url_shortener = any(shortener in clean_domain for shortener in URL_SHORTENERS)

    return {
        'url_length': int(url_length),
        'num_dots': int(num_dots),
        'num_hyphens': int(num_hyphens),
        'num_at': int(num_at),
        'num_question': int(num_question),
        'num_equal': int(num_equal),
        'num_slash': int(num_slash),
        'num_percent': int(num_percent),
        'has_ip': 1 if has_ip else 0,
        'uses_https': 1 if uses_https else 0,
        'domain_length': int(domain_length),
        'subdomain_count': int(subdomain_count),
        'has_suspicious_keywords': 1 if has_suspicious_keywords else 0,
        'url_entropy': float(round(url_entropy, 4)),
        'digit_count': int(digit_count),
        'letter_count': int(letter_count),
        'special_char_count': int(special_char_count),
        'tld_in_path': 1 if tld_in_path else 0,
        'double_slash_in_path': 1 if double_slash_in_path else 0,
        'port_in_url': 1 if port_in_url else 0,
        'url_shortener': 1 if url_shortener else 0
    }


def extract_url_features(url: str):
    """Extract URL features into a numpy array matching FEATURE_NAMES order."""
    feature_dict = extract_url_features_dict(url)
    ordered_values = [feature_dict[name] for name in FEATURE_NAMES]
    if np is not None:
        return np.array(ordered_values, dtype=np.float32)
    return ordered_values


def extract_network_features(flow_data: Dict[str, Any]):
    """Extract network flow features into a numpy array matching NETWORK_FEATURE_NAMES order."""
    packet_count = float(flow_data.get('packet_count', 0))
    duration = max(0.001, float(flow_data.get('duration_seconds', flow_data.get('duration', 1.0))))
    unique_src_ips = float(flow_data.get('unique_src_ips', 1))
    unique_dst_ips = float(flow_data.get('unique_dst_ips', 1))
    unique_dst_ports = float(flow_data.get('unique_dst_ports', flow_data.get('port_diversity', 1)))
    avg_pkt_size = float(flow_data.get('avg_pkt_size', 512.0))
    src_ip_concentration = float(flow_data.get('src_ip_concentration', 0.1))
    port_diversity = float(flow_data.get('port_diversity', unique_dst_ports))
    syn_ratio = float(flow_data.get('syn_ratio', 0.1))

    packet_rate = packet_count / duration
    byte_rate = (packet_count * avg_pkt_size) / duration

    ordered_values = [
        packet_count,
        duration,
        unique_src_ips,
        unique_dst_ips,
        unique_dst_ports,
        avg_pkt_size,
        src_ip_concentration,
        port_diversity,
        syn_ratio,
        packet_rate,
        byte_rate
    ]
    if np is not None:
        return np.array(ordered_values, dtype=np.float32)
    return ordered_values
