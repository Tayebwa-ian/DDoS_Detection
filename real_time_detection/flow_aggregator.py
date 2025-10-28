"""
flow_aggregator.py
------------------
Bidirectional flow aggregator for real-time IDS.

Enhancements:
- Adds `summarize_active_flows()` to summarize active flows at any time.
- Used by main.py to perform continuous (live) predictions.
"""

import time
from collections import defaultdict
from typing import Dict, Tuple, Any, List

FlowKey = Tuple[str, str, str, str, str]  # normalized 5-tuple


class FlowState:
    """Track packets and compute statistics for a single flow."""

    def __init__(self, first_ts: float):
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.pkts = 0
        self.total_bytes = 0
        self.packet_sizes: List[int] = []
        self.inter_arrivals: List[float] = []
        self.last_pkt_ts = first_ts
        self.tcp_flags = defaultdict(int)

    def add_packet(self, pkt_len: int, ts: float, tcp_flags_raw: str | None):
        """Add packet info and update statistics."""
        self.pkts += 1
        self.total_bytes += pkt_len
        self.packet_sizes.append(pkt_len)
        if self.pkts > 1:
            self.inter_arrivals.append(ts - self.last_pkt_ts)
        self.last_pkt_ts = ts
        self.last_ts = ts

        if tcp_flags_raw:
            try:
                flags_int = int(tcp_flags_raw, 0)
                if flags_int & 0x002:
                    self.tcp_flags['SYN'] += 1
                if flags_int & 0x008:
                    self.tcp_flags['PSH'] += 1
                if flags_int & 0x020:
                    self.tcp_flags['URG'] += 1
                if flags_int & 0x001:
                    self.tcp_flags['FIN'] += 1
                if flags_int & 0x004:
                    self.tcp_flags['RST'] += 1
                if flags_int & 0x010:
                    self.tcp_flags['ACK'] += 1
            except Exception:
                pass

    def summarize(self) -> Dict[str, Any]:
        """Return statistical summary of this flow."""
        import numpy as np
        duration = max(1e-6, self.last_ts - self.first_ts)
        pkt_mean = float(np.mean(self.packet_sizes)) if self.packet_sizes else 0.0
        pkt_std = float(np.std(self.packet_sizes)) if self.packet_sizes else 0.0
        pkt_var = float(np.var(self.packet_sizes)) if self.packet_sizes else 0.0
        avg_pkt_size = float(sum(self.packet_sizes) / len(self.packet_sizes)) if self.packet_sizes else 0.0
        avg_inter = float(np.mean(self.inter_arrivals)) if self.inter_arrivals else 0.0
        max_pkt = int(max(self.packet_sizes)) if self.packet_sizes else 0
        min_pkt = int(min(self.packet_sizes)) if self.packet_sizes else 0

        return {
            'duration': duration,
            'pkts': self.pkts,
            'total_bytes': self.total_bytes,
            'avg_pkt_size': avg_pkt_size,
            'pkt_std': pkt_std,
            'pkt_mean': pkt_mean,
            'pkt_var': pkt_var,
            'avg_inter': avg_inter,
            'max_pkt': max_pkt,
            'min_pkt': min_pkt,
            'tcp_flags': dict(self.tcp_flags)
        }

    def is_inactive(self, now: float, timeout: float) -> bool:
        """Check inactivity based on last seen packet."""
        return (now - self.last_ts) > timeout


class FlowAggregator:
    """
    Maintains active bidirectional flows.
    Allows summarizing both active and inactive flows for real-time detection.
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.flows: Dict[FlowKey, FlowState] = {}

    @staticmethod
    def _normalize_key(src: str, dst: str, srcp: str, dstp: str, proto: str) -> FlowKey:
        """Bidirectional normalization of flow keys."""
        if (src, srcp) <= (dst, dstp):
            return (src, dst, srcp, dstp, proto)
        return (dst, src, dstp, srcp, proto)

    def add_packet(self, pkt_tuple: tuple):
        """Update flow with a new packet."""
        import time
        try:
            ts = float(pkt_tuple[0]) if pkt_tuple[0] else time.time()
        except Exception:
            ts = time.time()

        src, dst = pkt_tuple[1], pkt_tuple[2]
        tcp_src, tcp_dst = pkt_tuple[3], pkt_tuple[4]
        udp_src, udp_dst = pkt_tuple[5], pkt_tuple[6]
        proto = pkt_tuple[7]
        try:
            flen = int(pkt_tuple[8]) if pkt_tuple[8] else 0
        except Exception:
            flen = 0
        tcp_flags = pkt_tuple[9] if len(pkt_tuple) > 9 else None

        srcp = tcp_src or udp_src or '0'
        dstp = tcp_dst or udp_dst or '0'

        key = self._normalize_key(src, dst, srcp, dstp, proto)
        if key not in self.flows:
            self.flows[key] = FlowState(first_ts=ts)
        self.flows[key].add_packet(flen, ts, tcp_flags)

    def summarize_active_flows(self) -> List[Tuple[FlowKey, Dict[str, Any]]]:
        """
        Return summaries for all currently active flows (for continuous prediction).
        """
        return [(k, f.summarize()) for k, f in self.flows.items()]

    def collect_inactive_flows(self) -> List[Tuple[FlowKey, Dict[str, Any]]]:
        """Return and remove timed-out flows."""
        now = time.time()
        expired = []
        result = []
        for k, f in list(self.flows.items()):
            if f.is_inactive(now, self.timeout):
                result.append((k, f.summarize()))
                expired.append(k)
        for k in expired:
            del self.flows[k]
        return result

    def flush_all(self) -> List[Tuple[FlowKey, Dict[str, Any]]]:
        """Force flush all flows."""
        result = [(k, f.summarize()) for k, f in self.flows.items()]
        self.flows.clear()
        return result
