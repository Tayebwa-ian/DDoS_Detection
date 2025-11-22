import argparse
import csv
import os
import sys
import time
from tshark_runner import stream_packets
from flow_aggregator import FlowAggregator
from feature_extractor import extract_features
from predictor import Predictor
from xdp_filter_manager import XDPManager


def run(iface: str, models_dir: str, timeout: float, threshold: float, duration: float):
    """Run continuous prediction pipeline with CSV logging and XDP mitigation."""
    
    # 1. Initialize Flow Aggregator and Predictor
    agg = FlowAggregator(timeout=timeout)
    pred = Predictor(models_dir=models_dir)
    
    # 2. Initialize XDP Manager and Load Filter
    xdp_manager = XDPManager(iface=iface)
    if not xdp_manager.initialize_xdp_filter():
        # If XDP fails to initialize and isn't already loaded, exit or continue without mitigation
        print("Continuing without XDP mitigation.")
    

    # Ensure output directory exists
    os.makedirs("data", exist_ok=True)
    log_file = "data/predictions_log.csv"

    # Feature names in training order
    feature_names = [
        ' Destination Port', ' Fwd Packet Length Max',
        ' Fwd Packet Length Mean', 'Bwd Packet Length Max',
        ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
        ' Bwd Packet Length Std', ' Fwd IAT Std', 'Bwd IAT Total',
        ' Bwd IAT Max', ' Min Packet Length', ' Max Packet Length',
        ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
        ' PSH Flag Count', ' URG Flag Count', ' Average Packet Size',
        ' Avg Fwd Segment Size', ' Avg Bwd Segment Size'
    ]

    # CSV header
    header = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "proto"
    ] + feature_names + [
        "LR_proba", "DT_proba", "LR_label", "DT_label", "final_label"
    ]

    new_file = not os.path.exists(log_file) or os.path.getsize(log_file) == 0
    csv_file = open(log_file, "a", newline="")
    writer = csv.writer(csv_file)
    if new_file:
        writer.writerow(header)

    print(f"[+] Capturing on {iface} for up to {duration} seconds (real-time predictions and XDP mitigation)...")

    try:
        for pkt in stream_packets(iface, duration):
            agg.add_packet(pkt)

            # Summarize active flows
            for key, summary in agg.summarize_active_flows():
                fv = extract_features(key, summary)
                res = pred.predict(fv, threshold=threshold)

                src, dst, srcp, dstp, proto = key
                lr_is_mal = res['lr_label'] == 1
                dt_is_mal = res['dt_label'] == 1
                
                # Determine final label based on *any* model flagging it
                label = "MALICIOUS" if (lr_is_mal or dt_is_mal) else "BENIGN"

                # --- XDP MITIGATION LOGIC ---
                if label == "MALICIOUS":
                    # Block the source IP (the attacker)
                    xdp_manager.block_ip(src) 
                # ----------------------------

                # Print prediction
                print(f"[{label}] {src}:{srcp} → {dst}:{dstp} | "
                      f"LR={res['lr_proba']:.3f} DT={res['dt_proba']:.3f}")

                # --- Build CSV row ---
                row = [
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    src, dst, srcp, dstp, proto
                ]

                # --- Append features safely ---
                if isinstance(fv, dict):
                    for feat in feature_names:
                        row.append(fv.get(feat, 0.0))
                elif isinstance(fv, (list, tuple)):
                    row.extend(fv)
                else:
                    # fallback if unknown type
                    row.extend([0.0] * len(feature_names))

                # Append predictions
                row += [
                    res['lr_proba'], res['dt_proba'],
                    res['lr_label'], res['dt_label'], label
                ]

                writer.writerow(row)
                csv_file.flush()

            agg.collect_inactive_flows()

        # Flush remaining flows at end of capture
        print("\n[+] Duration elapsed, flushing remaining flows...")
        for key, summary in agg.flush_all():
            fv = extract_features(key, summary)
            res = pred.predict(fv, threshold=threshold)
            src, dst, srcp, dstp, proto = key
            lr_is_mal = res['lr_label'] == 1
            dt_is_mal = res['dt_label'] == 1
            label = "MALICIOUS" if (lr_is_mal or dt_is_mal) else "BENIGN"
            
            if label == "MALICIOUS":
                xdp_manager.block_ip(src) 

            row = [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                src, dst, srcp, dstp, proto
            ]

            if isinstance(fv, dict):
                for feat in feature_names:
                    row.append(fv.get(feat, 0.0))
            elif isinstance(fv, (list, tuple)):
                row.extend(fv)
            else:
                row.extend([0.0] * len(feature_names))

            row += [
                res['lr_proba'], res['dt_proba'],
                res['lr_label'], res['dt_label'], label
            ]

            writer.writerow(row)
            csv_file.flush()
            print(f"[{label}] {key}")

    except KeyboardInterrupt:
        print("[!] Interrupted by user, flushing remaining flows...")
        for key, summary in agg.flush_all():
            fv = extract_features(key, summary)
            res = pred.predict(fv, threshold=threshold)
            src, dst, srcp, dstp, proto = key
            lr_is_mal = res['lr_label'] == 1
            dt_is_mal = res['dt_label'] == 1
            label = "MALICIOUS" if (lr_is_mal or dt_is_mal) else "BENIGN"
            
            if label == "MALICIOUS":
                xdp_manager.block_ip(src) 

            row = [
                time.strftime("%Y-%m-%d %H:%M:%S"),
                src, dst, srcp, dstp, proto
            ]

            if isinstance(fv, dict):
                for feat in feature_names:
                    row.append(fv.get(feat, 0.0))
            elif isinstance(fv, (list, tuple)):
                row.extend(fv)
            else:
                row.extend([0.0] * len(feature_names))

            row += [
                res['lr_proba'], res['dt_proba'],
                res['lr_label'], res['dt_label'], label
            ]

            writer.writerow(row)
            csv_file.flush()
            print(f"[{label}] {key}")

    finally:
        csv_file.close()
        # Unload XDP filter on exit
        xdp_manager.unload_xdp_filter() 
        print(f"[+] All results saved to {os.path.abspath(log_file)}")


if __name__ == "__main__":
    # MANDATORY ROOT CHECK
    if os.geteuid() != 0:
        print("ERROR: This script must be run with root privileges (sudo).")
        print("Please run: sudo python3 main.py --iface <your_interface> --duration <seconds>")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Continuous IDS with real-time predictions and full flow logging")
    parser.add_argument("--iface", required=True, help="Network interface to capture (e.g., eth0)")
    parser.add_argument("--models_dir", default="models", help="Path to joblib models")
    parser.add_argument("--timeout", type=float, default=30.0, help="Flow inactivity timeout (seconds)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Malicious probability threshold")
    parser.add_argument("--duration", type=float, default=60.0, help="Total capture duration (seconds)")
    args = parser.parse_args()

    run(args.iface, args.models_dir, args.timeout, args.threshold, args.duration)
