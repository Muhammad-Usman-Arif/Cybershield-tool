"""DDoS and Traffic Anomaly Detection Engine for CyberShield AI.

Features:
- ML-driven network flow classification (RandomForest / IsolationForest)
- Statistical flow extraction from CSV (CIC-IDS / netflow formats) and PCAP files
- Rule-based detection regardless of ML (SYN floods, botnet distribution, volumetric floods)
- Manual telemetry parameter analysis
"""

import os
import struct
from datetime import datetime, timezone
from collections import Counter
from typing import Dict, Any, List, Optional

try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None

from app.engines.risk_engine import calculate_risk_level


NETWORK_FEATURE_NAMES = [
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


class DDoSEngine:
    """Production DDoS and Network Traffic Anomaly Detection Engine."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_loaded = False
        self.model_path = None
        self._load_model()

    def _load_model(self):
        """Attempt to load trained DDoS classifier and scaler."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        app_dir = os.path.abspath(os.path.join(current_dir, '..'))
        models_dir = os.path.join(app_dir, 'ml', 'trained_models')

        model_file = os.path.join(models_dir, 'ddos_model.pkl')
        scaler_file = os.path.join(models_dir, 'ddos_scaler.pkl')

        self.model_path = model_file

        if joblib and os.path.exists(model_file):
            try:
                self.model = joblib.load(model_file)
                if os.path.exists(scaler_file):
                    self.scaler = joblib.load(scaler_file)
                self.model_loaded = True
            except Exception:
                self.model_loaded = False
                self.model = None
                self.scaler = None
        else:
            self.model_loaded = False

    def reload_model(self):
        """Reload models from disk."""
        self._load_model()
        return self.model_loaded

    def _extract_csv_features(self, df: Any) -> Dict[str, Any]:
        """Extract standardized network flow statistics from a pandas DataFrame."""
        if df is None or len(df) == 0:
            return {
                'packet_count': 0,
                'duration': 1.0,
                'unique_src_ips': 0,
                'unique_dst_ips': 0,
                'unique_dst_ports': 0,
                'avg_pkt_size': 0.0,
                'src_ip_concentration': 0.0,
                'port_diversity': 0,
                'syn_ratio': 0.0,
                'packet_rate': 0.0,
                'byte_rate': 0.0
            }

        # Normalize column names to lower case for flexible matching
        col_map = {str(c).lower().strip(): c for c in df.columns}

        packet_count = len(df)

        # Source IP extraction
        src_col = next((col_map[c] for c in ['src_ip', 'source ip', 'src ip', 'source_ip', 'srcip'] if c in col_map), None)
        if src_col:
            src_series = df[src_col].astype(str)
            unique_src_ips = src_series.nunique()
            counts = src_series.value_counts()
            top_src_count = counts.iloc[0] if len(counts) > 0 else 0
            src_ip_concentration = float(top_src_count / max(1, packet_count))
        else:
            unique_src_ips = 1
            src_ip_concentration = 0.5

        # Destination IP extraction
        dst_col = next((col_map[c] for c in ['dst_ip', 'destination ip', 'dst ip', 'destination_ip', 'dstip'] if c in col_map), None)
        unique_dst_ips = df[dst_col].nunique() if dst_col else 1

        # Destination Port extraction
        port_col = next((col_map[c] for c in ['dst_port', 'destination port', 'port', 'dst port', 'dport'] if c in col_map), None)
        unique_dst_ports = df[port_col].nunique() if port_col else 1
        port_diversity = unique_dst_ports

        # Packet size
        size_col = next((col_map[c] for c in ['length', 'pkt_len', 'packet_length', 'total length of fwd packets', 'size', 'bytes'] if c in col_map), None)
        avg_pkt_size = float(df[size_col].mean()) if size_col else 512.0

        # Duration
        dur_col = next((col_map[c] for c in ['flow duration', 'duration', 'duration_seconds', 'time_span'] if c in col_map), None)
        if dur_col:
            duration = float(df[dur_col].max())
            # Convert microseconds to seconds if large
            if duration > 100000:
                duration /= 1000000.0
            duration = max(0.001, duration)
        else:
            duration = max(1.0, packet_count / 100.0)

        # SYN ratio
        syn_col = next((col_map[c] for c in ['syn flag count', 'syn', 'syn_ratio', 'flags_syn'] if c in col_map), None)
        if syn_col:
            syn_ratio = float(df[syn_col].mean())
        else:
            syn_ratio = 0.05

        packet_rate = float(packet_count / duration)
        byte_rate = float((packet_count * avg_pkt_size) / duration)

        return {
            'packet_count': int(packet_count),
            'duration': float(round(duration, 3)),
            'unique_src_ips': int(unique_src_ips),
            'unique_dst_ips': int(unique_dst_ips),
            'unique_dst_ports': int(unique_dst_ports),
            'avg_pkt_size': float(round(avg_pkt_size, 2)),
            'src_ip_concentration': float(round(src_ip_concentration, 4)),
            'port_diversity': int(port_diversity),
            'syn_ratio': float(round(syn_ratio, 4)),
            'packet_rate': float(round(packet_rate, 2)),
            'byte_rate': float(round(byte_rate, 2))
        }

    def _calculate_risk(self, indicators: List[str], scores: Dict[str, Any]) -> int:
        """Calculate unified risk score based on rule checks and statistical thresholds."""
        score = 0

        # 1. Source IP Concentration Check (> 0.8: 80% from single host)
        concentration = scores.get('src_ip_concentration', 0.0)
        pkt_count = scores.get('packet_count', 0)
        if concentration > 0.8 and pkt_count > 100:
            score += 35

        # 2. Unique Source IPs Check (> 1000: Botnet distribution)
        unique_srcs = scores.get('unique_src_ips', 0)
        if unique_srcs > 1000:
            score += 40
        elif unique_srcs > 250:
            score += 25

        # 3. Port Diversity (< 3 on heavy volume: targeted attack)
        port_div = scores.get('port_diversity', scores.get('unique_dst_ports', 10))
        if port_div < 3 and pkt_count > 300:
            score += 20

        # 4. Volumetric Packet Rate Check
        pkt_rate = scores.get('packet_rate', 0.0)
        if pkt_rate > 5000:
            score += 35
        elif pkt_rate > 1000:
            score += 20

        # 5. SYN Flood Ratio
        syn_ratio = scores.get('syn_ratio', 0.0)
        if syn_ratio > 0.6 and pkt_count > 100:
            score += 30

        return max(0, min(100, score))

    def analyze_manual(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze manual network telemetry input parameters."""
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            packet_count = int(data.get('packet_count', 0))
            duration = max(0.001, float(data.get('duration_seconds', data.get('duration', 1.0))))
            unique_src_ips = int(data.get('unique_src_ips', 1))
            unique_dst_ports = int(data.get('unique_dst_ports', data.get('port_diversity', 1)))
            src_ip_concentration = float(data.get('src_ip_concentration', 0.1))
        except (ValueError, TypeError):
            return {
                'success': False,
                'result': 'Invalid Input',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.0,
                'indicators': ['Malformed numerical telemetry inputs'],
                'model_used': 'Rule-Based Engine',
                'details': {'error': 'Invalid numerical inputs'},
                'timestamp': timestamp
            }

        avg_pkt_size = float(data.get('avg_pkt_size', 512.0))
        syn_ratio = float(data.get('syn_ratio', 0.1))
        packet_rate = float(packet_count / duration)
        byte_rate = float((packet_count * avg_pkt_size) / duration)

        stats = {
            'packet_count': packet_count,
            'duration': duration,
            'unique_src_ips': unique_src_ips,
            'unique_dst_ips': 1,
            'unique_dst_ports': unique_dst_ports,
            'avg_pkt_size': avg_pkt_size,
            'src_ip_concentration': src_ip_concentration,
            'port_diversity': unique_dst_ports,
            'syn_ratio': syn_ratio,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate
        }

        indicators = []

        # Rule-based checks REGARDLESS of ML
        if src_ip_concentration > 0.8 and packet_count > 100:
            indicators.append(f"High single-source IP concentration ({round(src_ip_concentration * 100, 1)}%) indicating DoS / SYN flood")

        if unique_src_ips > 1000:
            indicators.append(f"Massive distributed source IP footprint ({unique_src_ips} unique sources) characteristic of botnet DDoS")
        elif unique_src_ips > 300:
            indicators.append(f"Elevated source IP count ({unique_src_ips} IPs) exceeding standard traffic patterns")

        if unique_dst_ports < 3 and packet_count > 300:
            indicators.append(f"Extreme destination port focus ({unique_dst_ports} ports) targeting critical application services")

        if packet_rate > 5000:
            indicators.append(f"Volumetric packet flood detected: {int(packet_rate)} packets/sec")
        elif packet_rate > 1000:
            indicators.append(f"High packet transmission velocity: {int(packet_rate)} packets/sec")

        if syn_ratio > 0.6 and packet_count > 100:
            indicators.append(f"Abnormally high SYN packet ratio ({round(syn_ratio * 100, 1)}%) without completing handshakes")

        rule_score = self._calculate_risk(indicators, stats)

        # ML prediction if available
        if self.model_loaded and self.model is not None and np is not None:
            try:
                feature_vals = [stats.get(name, 0.0) for name in NETWORK_FEATURE_NAMES]
                X = np.array([feature_vals], dtype=np.float32)
                if self.scaler is not None:
                    X = self.scaler.transform(X)

                if hasattr(self.model, 'predict_proba'):
                    prob = float(self.model.predict_proba(X)[0][1])
                    ml_score = int(round(prob * 100))
                else:
                    pred = self.model.predict(X)[0]
                    ml_score = 85 if pred == 1 else 15

                # Blend ML and rule score
                risk_score = max(rule_score, int(round(0.5 * rule_score + 0.5 * ml_score)))
                model_used = "Hybrid ML & Rule-Based DDoS Engine"
                confidence = 0.90
            except Exception:
                risk_score = rule_score
                model_used = "Rule-Based DDoS Analysis Engine"
                confidence = 0.85
        else:
            risk_score = rule_score
            model_used = "Rule-Based DDoS Analysis Engine"
            confidence = 0.85

        risk_level = calculate_risk_level(risk_score)
        if risk_score >= 61:
            result = 'Malicious'
        elif risk_score >= 35:
            result = 'Suspicious'
        else:
            result = 'Normal'

        if not indicators:
            indicators.append("Traffic distribution, packet rates, and protocol ratios within healthy operational limits")

        return {
            'success': True,
            'result': result,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'confidence': confidence,
            'indicators': indicators,
            'model_used': model_used,
            'details': {
                'traffic_stats': stats,
                'rule_score': rule_score
            },
            'timestamp': timestamp
        }

    def analyze_file(self, file_path: str, file_type: str = 'csv') -> Dict[str, Any]:
        """Analyze PCAP or CSV network flow telemetry file."""
        timestamp = datetime.now(timezone.utc).isoformat()

        if not os.path.exists(file_path):
            return {
                'success': False,
                'result': 'File Not Found',
                'risk_score': 0,
                'risk_level': 'Very Low',
                'confidence': 0.0,
                'indicators': [f"Telemetry file not found: {file_path}"],
                'model_used': 'DDoSEngine',
                'details': {'error': 'File not found'},
                'timestamp': timestamp
            }

        # CSV handling
        if file_type.lower() == 'csv' or file_path.lower().endswith('.csv'):
            if pd is None:
                return {
                    'success': False,
                    'result': 'Dependency Error',
                    'risk_score': 0,
                    'risk_level': 'Very Low',
                    'confidence': 0.0,
                    'indicators': ['Pandas library required for CSV processing is not installed'],
                    'model_used': 'DDoSEngine',
                    'details': {'error': 'pandas unavailable'},
                    'timestamp': timestamp
                }

            try:
                df = pd.read_csv(file_path, nrows=50000)
                stats = self._extract_csv_features(df)
            except Exception as e:
                return {
                    'success': False,
                    'result': 'CSV Parse Error',
                    'risk_score': 0,
                    'risk_level': 'Very Low',
                    'confidence': 0.0,
                    'indicators': [f"Failed to read CSV: {str(e)}"],
                    'model_used': 'DDoSEngine',
                    'details': {'error': str(e)},
                    'timestamp': timestamp
                }
        else:
            # PCAP handling
            stats = self._extract_pcap_features(file_path)

        # Delegate to manual analysis logic with the extracted stats
        res = self.analyze_manual(stats)
        res['details']['source_file'] = os.path.basename(file_path)
        return res

    def _extract_pcap_features(self, file_path: str) -> Dict[str, Any]:
        """Extract DDoS features from a raw PCAP capture."""
        src_ips = Counter()
        dst_ips = Counter()
        dst_ports = Counter()
        packet_sizes = []
        syn_count = 0
        timestamps = []

        try:
            with open(file_path, 'rb') as f:
                header = f.read(24)
                if len(header) < 24:
                    return {'packet_count': 0, 'duration': 1.0, 'unique_src_ips': 0, 'unique_dst_ports': 0, 'src_ip_concentration': 0.0}

                magic_number = header[:4]
                little_endian = (magic_number == b'\xd4\xc3\xb2\xa1')
                endian = '<' if little_endian else '>'

                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break

                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_header)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < 34:
                        continue

                    timestamps.append(ts_sec + (ts_usec / 1000000.0))
                    packet_sizes.append(orig_len)

                    # IPv4 header
                    eth_proto = struct.unpack('!H', pkt_data[12:14])[0]
                    if eth_proto == 0x0800:
                        ip_proto = pkt_data[23]
                        src_ip = ".".join(str(b) for b in pkt_data[26:30])
                        dst_ip = ".".join(str(b) for b in pkt_data[30:34])
                        src_ips[src_ip] += 1
                        dst_ips[dst_ip] += 1

                        if ip_proto == 6 and len(pkt_data) >= 47:  # TCP
                            dst_port = struct.unpack('!H', pkt_data[36:38])[0]
                            dst_ports[dst_port] += 1
                            tcp_flags = pkt_data[47]
                            # Check SYN flag (bit 1)
                            if tcp_flags & 0x02:
                                syn_count += 1
                        elif ip_proto == 17 and len(pkt_data) >= 38:  # UDP
                            dst_port = struct.unpack('!H', pkt_data[36:38])[0]
                            dst_ports[dst_port] += 1
        except Exception:
            pass

        total_pkts = len(packet_sizes)
        if total_pkts == 0:
            return {'packet_count': 0, 'duration': 1.0, 'unique_src_ips': 0, 'unique_dst_ports': 0, 'src_ip_concentration': 0.0}

        duration = max(0.001, (max(timestamps) - min(timestamps))) if timestamps else 1.0
        top_src_count = src_ips.most_common(1)[0][1] if src_ips else 0
        src_concentration = float(top_src_count / total_pkts)

        return {
            'packet_count': total_pkts,
            'duration': duration,
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'unique_dst_ports': len(dst_ports),
            'avg_pkt_size': sum(packet_sizes) / total_pkts,
            'src_ip_concentration': src_concentration,
            'port_diversity': len(dst_ports),
            'syn_ratio': syn_count / total_pkts,
            'packet_rate': total_pkts / duration,
            'byte_rate': sum(packet_sizes) / duration
        }


# Singleton instance
ddos_engine = DDoSEngine()
