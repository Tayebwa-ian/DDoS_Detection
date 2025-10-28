"""
feature_extractor.py (BIDIRECTIONAL)

Map the aggregated, bidirectional flow summary (FlowState.summarize()) to the
exact 20-feature vector order used for training.

Selected features (canonical order):
['Destination Port', 'Fwd Packet Length Max', 'Fwd Packet Length Mean',
 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
 'Bwd Packet Length Std', 'Fwd IAT Std', 'Bwd IAT Total', 'Bwd IAT Max',
 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
 'Packet Length Variance', 'PSH Flag Count', 'URG Flag Count', 'Average Packet Size',
 'Avg Fwd Segment Size', 'Avg Bwd Segment Size']

Important:
- This function assumes the `flow_summary` dictionary contains aggregations produced
  by the bidirectional FlowState.summarize() implementation in flow_aggregator.py.
"""

from typing import Dict, Any, List, Tuple

SELECTED_FEATURES: List[str] = [
    'Destination Port', 'Fwd Packet Length Max', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Fwd IAT Std', 'Bwd IAT Total', 'Bwd IAT Max',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'PSH Flag Count', 'URG Flag Count', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size'
]


def extract_features(norm_key: Tuple[str, str, str, str, str], flow_summary: Dict[str, Any]) -> List[float]:
    """
    Compute the 20-dimensional feature vector in EXACT order of SELECTED_FEATURES.

    Args:
        norm_key: normalized 5-tuple key (min_ip, max_ip, min_port, max_port, proto) of the flow
        flow_summary: dict returned by FlowState.summarize()

    Returns:
        List[float]: feature vector ordered to match SELECTED_FEATURES
    """
    # Map fields from flow_summary to feature names
    # Destination Port: we use origin's destination port stored in 'dest_port'
    dest_port = float(flow_summary.get('dest_port', 0) or 0)

    # Forward metrics (from origin -> responder)
    fwd_pkt_max = float(flow_summary.get('fwd_pkt_max', 0) or 0)
    fwd_pkt_mean = float(flow_summary.get('fwd_pkt_mean', 0) or 0)

    # Backward metrics
    bwd_pkt_max = float(flow_summary.get('bwd_pkt_max', 0) or 0)
    bwd_pkt_min = float(flow_summary.get('bwd_pkt_min', 0) or 0)
    bwd_pkt_mean = float(flow_summary.get('bwd_pkt_mean', 0) or 0)
    bwd_pkt_std = float(flow_summary.get('bwd_pkt_std', 0) or 0)

    # Fwd IAT Std (we approximate using stored value in summary)
    fwd_iat_std = float(flow_summary.get('fwd_iat_std', 0) or 0)
    # Bwd IAT total & max are provided by the summarizer
    bwd_iat_total = float(flow_summary.get('bwd_iat_total', 0) or 0)
    bwd_iat_max = float(flow_summary.get('bwd_iat_max', 0) or 0)

    # Global min/max/mean/std/variance
    min_pkt = float(flow_summary.get('min_pkt', 0) or 0)
    max_pkt = float(flow_summary.get('max_pkt', 0) or 0)
    pkt_mean = float(flow_summary.get('pkt_mean', 0) or 0)
    pkt_std = float(flow_summary.get('pkt_std', 0) or 0)
    pkt_var = float(flow_summary.get('pkt_var', 0) or 0)

    # Flags
    psh_count = float(flow_summary.get('psh_count', 0) or 0)
    urg_count = float(flow_summary.get('urg_count', 0) or 0)

    # Average packet size overall and approximated avg segment sizes
    avg_pkt_size = float(flow_summary.get('avg_pkt_size', 0) or 0)
    avg_fwd_seg = float(flow_summary.get('avg_fwd_seg', 0) or 0)
    avg_bwd_seg = float(flow_summary.get('avg_bwd_seg', 0) or 0)

    feature_vector: List[float] = [
        dest_port,        # Destination Port
        fwd_pkt_max,      # Fwd Packet Length Max
        fwd_pkt_mean,     # Fwd Packet Length Mean
        bwd_pkt_max,      # Bwd Packet Length Max
        bwd_pkt_min,      # Bwd Packet Length Min
        bwd_pkt_mean,     # Bwd Packet Length Mean
        bwd_pkt_std,      # Bwd Packet Length Std
        fwd_iat_std,      # Fwd IAT Std
        bwd_iat_total,    # Bwd IAT Total
        bwd_iat_max,      # Bwd IAT Max
        min_pkt,          # Min Packet Length
        max_pkt,          # Max Packet Length
        pkt_mean,         # Packet Length Mean
        pkt_std,          # Packet Length Std
        pkt_var,          # Packet Length Variance
        psh_count,        # PSH Flag Count
        urg_count,        # URG Flag Count
        avg_pkt_size,     # Average Packet Size
        avg_fwd_seg,      # Avg Fwd Segment Size
        avg_bwd_seg       # Avg Bwd Segment Size
    ]

    # Ensure correct length
    assert len(feature_vector) == len(SELECTED_FEATURES), "Feature vector length mismatch"
    return [float(x) for x in feature_vector]
