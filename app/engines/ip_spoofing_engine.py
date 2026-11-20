"""IP Spoofing Detection Engine for CyberShield AI.

Features:
- RFC Bogon/Reserved IP validation
- LAND attack detection (Source IP == Destination IP)
- TTL anomaly analysis (abnormal values, multiple varying TTLs from same origin)
- Broadcast/Multicast source address abuse detection
- Manual single-packet and full PCAP batch telemetry analysis
"""

import os
import struct
import ipaddress
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, Any, List, Optional, Set

from app.engines.risk_engine import calculate_risk_level


class IPSpoofingEngine:
    """Production rule-based IP Spoofing Detection Engine."""

    # RFC defined Bogon / Reserved / Private IP Ranges
    BOGON_RANGES = [
        ipaddress.ip_network('0.0.0.0/8'),        # RFC 1122 'This network'
        ipaddress.ip_network('10.0.0.0/8'),       # RFC 1918 Private
        ipaddress.ip_network('100.64.0.0/10'),    # RFC 6598 Shared Address Space (CGNAT)
        ipaddress.ip_network('127.0.0.0/8'),      # RFC 1122 Loopback
        ipaddress.ip_network('169.254.0.0/16'),   # RFC 3927 Link-Local
        ipaddress.ip_network('172.16.0.0/12'),    # RFC 1918 Private
        ipaddress.ip_network('192.0.0.0/24'),     # RFC 6890 IETF Protocol Assignments
        ipaddress.ip_network('192.0.2.0/24'),     # RFC 5737 TEST-NET-1
        ipaddress.ip_network('192.168.0.0/16'),   # RFC 1918 Private
        ipaddress.ip_network('198.18.0.0/15'),    # RFC 2544 Benchmarking (198.18.x and 198.19.x)
        ipaddress.ip_network('198.51.100.0/24'),  # RFC 5737 TEST-NET-2
        ipaddress.ip_network('203.0.113.0/24'),   # RFC 5737 TEST-NET-3
        ipaddress.ip_network('224.0.0.0/4'),      # RFC 5771 Multicast (224-239)
        ipaddress.ip_network('240.0.0.0/4'),      # RFC 1112 Reserved / Future Use (240-255)
        ipaddress.ip_network('255.255.255.255/32')# RFC 919 Limited Broadcast
    ]

    def __init__(self):
        self.model_name = "Rule-Based IP Spoofing Engine"

    def _is_bogon(self, ip_str: str) -> bool:
        """Check if an IPv4 address falls within Bogon or reserved spaces."""
        if not ip_str or not isinstance(ip_str, str):
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            # Check IPv6 multicast / loopback / private if IPv6
            if ip_obj.version == 6:
                return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved

            for net in self.BOGON_RANGES:
                if ip_obj in net:
                    return True
            return False
        except ValueError:
            return True  # Malformed IP is treated as invalid/bogon

    def _calculate_risk(self, suspicious_count: int, total: int, indicators: List[str]) -> int:
        """Calculate normalized risk score (0-100) based on suspicious ratio and indicator severity."""
        if total <= 0:
            return 0

        ratio = suspicious_count / total
        # Base score from ratio: 0-60 points
        base_score = ratio * 65

        # Indicator bonus severity: up to 35 points
        indicator_weight = min(35, len(indicators) * 10)

        # Critical indicators guarantee high base score
        critical_keywords = ['LAND attack', 'Broadcast address used as source', 'Bogon source address']
        for ind in indicators:
            if any(ck in ind for ck in critical_keywords):
                base_score = max(base_score, 70.0)
                break

        total_score = int(round(base_score + indicator_weight))
        return max(0, min(100, total_score))

    def analyze_manual(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single network packet specification manually entered."""
        timestamp = datetime.now(timezone.utc).isoformat()
        src_ip = str(data.get('src_ip', '')).strip()
        dst_ip = str(data.get('dst_ip', '')).strip()
        protocol = str(data.get('protocol', 'TCP')).upper().strip()

        try:
            ttl = int(data.get('ttl', 64))
        except (ValueError, TypeError):
            ttl = -1

        indicators = []
        is_suspicious = False
        details: Dict[str, Any] = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'ttl': ttl,
            'protocol': protocol,
            'flags': []
        }

        # 1. Bogon source check
        if self._is_bogon(src_ip):
            indicators.append(f"Source IP '{src_ip}' is a Bogon, private, or reserved address not routable from public internet")
            details['flags'].append('BOGON_SOURCE_IP')
            is_suspicious = True

        # 2. LAND Attack check (Source IP == Destination IP)
        if src_ip and dst_ip and src_ip == dst_ip:
            indicators.append(f"LAND attack pattern detected: Source IP matches Destination IP ({src_ip})")
            details['flags'].append('LAND_ATTACK')
            is_suspicious = True

        # 3. Broadcast or zero source
        if src_ip in ('0.0.0.0', '255.255.255.255') or src_ip.endswith('.255'):
            indicators.append(f"Invalid broadcast or unassigned source address: {src_ip}")
            details['flags'].append('BROADCAST_SOURCE')
            is_suspicious = True

        # 4. TTL validation
        if ttl < 0 or ttl > 255:
            indicators.append(f"Invalid TTL value ({ttl}): outside standard 8-bit range (0-255)")
            details['flags'].append('INVALID_TTL_RANGE')
            is_suspicious = True
        elif ttl < 10:
            indicators.append(f"Suspiciously low TTL value ({ttl}): indicates deliberate crafting or immediate hop expiry")
            details['flags'].append('ABNORMALLY_LOW_TTL')
            is_suspicious = True

        suspicious_count = 1 if is_suspicious else 0
        risk_score = self._calculate_risk(suspicious_count, 1, indicators)
        risk_level = calculate_risk_level(risk_score)

        if risk_score >= 61:
            result = 'Malicious'
        elif risk_score >= 25:
            result = 'Suspicious'
        else:
            result = 'Clean'

        if not indicators:
            indicators.append("Routable public IP addressing and valid TTL characteristics confirmed")

        confidence = 0.90 if is_suspicious else 0.80

        return {
            'success': True,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'indicators': indicators,
            'model_used': self.model_name,
            'details': details,
            'timestamp': timestamp
        }

    def analyze_pcap(self, file_path: str) -> Dict[str, Any]:
        """Analyze PCAP capture file for IP spoofing patterns."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if not os.path.exists(file_path):
            return {
                'success': False,
                'result': 'File Not Found',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.0,
                'indicators': [f"Specified PCAP file not found: {file_path}"],
                'model_used': self.model_name,
                'details': {'error': 'File not found'},
                'timestamp': timestamp
            }

        # Try to use external pcap_parser utility if available
        packets = []
        parsed_via_utility = False

        try:
            from app.utils.pcap_parser import parse_pcap
            parsed_packets = parse_pcap(file_path)
            if parsed_packets:
                packets = parsed_packets
                parsed_via_utility = True
        except (ImportError, Exception):
            pass

        # Fallback to internal PCAP parser if not parsed via utility
        if not parsed_via_utility:
            packets = self._parse_pcap_fallback(file_path)

        total_packets = len(packets)
        if total_packets == 0:
            return {
                'success': True,
                'result': 'Clean',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.70,
                'indicators': ["No IPv4 packets found in PCAP or file is empty"],
                'model_used': self.model_name,
                'details': {'total_packets': 0, 'suspicious_packets': 0},
                'timestamp': timestamp
            }

        suspicious_packets = 0
        bogon_sources: Set[str] = set()
        land_attacks: Set[str] = set()
        abnormal_ttls = 0
        broadcast_sources: Set[str] = set()
        ip_ttl_map = defaultdict(set)

        for pkt in packets:
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            ttl = pkt.get('ttl', 64)

            pkt_suspicious = False

            # Track TTL diversity per source IP
            if src_ip:
                ip_ttl_map[src_ip].add(ttl)

            # Bogon check
            if self._is_bogon(src_ip):
                bogon_sources.add(src_ip)
                pkt_suspicious = True

            # LAND attack check
            if src_ip and dst_ip and src_ip == dst_ip:
                land_attacks.add(src_ip)
                pkt_suspicious = True

            # Broadcast source
            if src_ip in ('0.0.0.0', '255.255.255.255') or src_ip.endswith('.255'):
                broadcast_sources.add(src_ip)
                pkt_suspicious = True

            # TTL anomaly
            if ttl < 10 or ttl > 255:
                abnormal_ttls += 1
                pkt_suspicious = True

            if pkt_suspicious:
                suspicious_packets += 1

        # Check for multiple drastically differing TTLs for same source IP
        fluctuating_ttl_ips = []
        for ip, ttls in ip_ttl_map.items():
            if len(ttls) >= 3 and (max(ttls) - min(ttls) > 30):
                fluctuating_ttl_ips.append(ip)

        indicators = []
        if bogon_sources:
            indicators.append(f"Bogon/unroutable source IP addresses detected ({len(bogon_sources)} unique): {', '.join(list(bogon_sources)[:5])}")
        if land_attacks:
            indicators.append(f"LAND attack packets detected where source IP equals destination IP ({len(land_attacks)} targets)")
        if abnormal_ttls > 0:
            indicators.append(f"{abnormal_ttls} packets observed with abnormal TTL (<10 or >255)")
        if broadcast_sources:
            indicators.append(f"Broadcast/all-zeros addresses used as packet source ({len(broadcast_sources)} IPs)")
        if fluctuating_ttl_ips:
            indicators.append(f"Single source IPs exhibiting wildly disparate TTLs ({len(fluctuating_ttl_ips)} IPs), indicating forged origins")

        risk_score = self._calculate_risk(suspicious_packets, total_packets, indicators)
        risk_level = calculate_risk_level(risk_score)

        if risk_score >= 61:
            result = 'Malicious'
        elif risk_score >= 25:
            result = 'Suspicious'
        else:
            result = 'Clean'

        if not indicators:
            indicators.append("All inspected packets exhibit legitimate routable addressing and consistent TTL distributions")

        confidence = round(min(0.98, 0.75 + (suspicious_packets / max(1, total_packets)) * 0.25), 2)

        return {
            'success': True,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'indicators': indicators,
            'model_used': self.model_name,
            'details': {
                'total_packets': total_packets,
                'suspicious_packets': suspicious_packets,
                'suspicious_packet_ratio': round(suspicious_packets / max(1, total_packets), 4),
                'bogon_ip_count': len(bogon_sources),
                'land_attack_targets': list(land_attacks)[:10],
                'abnormal_ttl_packet_count': abnormal_ttls,
                'fluctuating_ttl_ip_count': len(fluctuating_ttl_ips)
            },
            'timestamp': timestamp
        }

    def _parse_pcap_fallback(self, file_path: str) -> List[Dict[str, Any]]:
        """Lightweight native PCAP parser fallback reading raw Ethernet / IPv4 frames."""
        packets = []
        try:
            with open(file_path, 'rb') as f:
                header = f.read(24)
                if len(header) < 24:
                    return []

                magic_number = header[:4]
                # Standard pcap magic numbers
                if magic_number not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    return []

                little_endian = (magic_number == b'\xd4\xc3\xb2\xa1')
                endian = '<' if little_endian else '>'

                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_header)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break

                    # Check Ethernet frame (14 bytes)
                    if len(pkt_data) < 34:
                        continue

                    eth_proto = struct.unpack('!H', pkt_data[12:14])[0]
                    # IPv4 is 0x0800
                    if eth_proto == 0x0800:
                        ip_header = pkt_data[14:34]
                        version_ihl = ip_header[0]
                        ihl = (version_ihl & 0x0F) * 4
                        ttl = ip_header[8]
                        proto_num = ip_header[9]

                        src_bytes = ip_header[12:16]
                        dst_bytes = ip_header[16:20]

                        src_ip = ".".join(str(b) for b in src_bytes)
                        dst_ip = ".".join(str(b) for b in dst_bytes)

                        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                        protocol = proto_map.get(proto_num, str(proto_num))

                        packets.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'ttl': ttl,
                            'protocol': protocol,
                            'length': orig_len,
                            'timestamp': ts_sec + (ts_usec / 1000000.0)
                        })
        except Exception:
            pass

        return packets


# Singleton instance
ip_spoofing_engine = IPSpoofingEngine()
