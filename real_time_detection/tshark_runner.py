"""
tshark_runner.py
----------------
Run tshark as a subprocess and yield parsed packet information in real time.

Now includes `stream_packets(iface, duration)` that runs for a given number of seconds
and stops automatically.

Requires: tshark installed and proper capture permissions (sudo or setcap).

Output per packet:
(frame.time_epoch, ip.src, ip.dst, tcp.srcport, tcp.dstport,
 udp.srcport, udp.dstport, ip.proto, frame.len, tcp.flags)
"""

import subprocess
import time
from typing import Generator, Tuple, List

# Fields extracted from tshark
TSHARK_FIELDS: List[str] = [
    'frame.time_epoch',
    'ip.src',
    'ip.dst',
    'tcp.srcport',
    'tcp.dstport',
    'udp.srcport',
    'udp.dstport',
    'ip.proto',
    'frame.len',
    'tcp.flags'
]


def _build_tshark_command(iface: str) -> List[str]:
    """Construct tshark command line with required fields."""
    cmd = [
        'tshark', '-i', iface, '-l', '-n',
        '-T', 'fields', '-E', 'separator=,', '-E', 'quote=d', '-E', 'occurrence=f'
    ]
    for f in TSHARK_FIELDS:
        cmd += ['-e', f]
    return cmd


def stream_packets(iface: str, duration: float) -> Generator[Tuple[str, ...], None, None]:
    """
    Run tshark for a fixed duration and yield parsed rows as tuples.

    Args:
        iface: interface to capture on (e.g., 'eth0')
        duration: how long to capture (seconds)

    Yields:
        Tuple[str, ...]: values corresponding to TSHARK_FIELDS
    """
    cmd = _build_tshark_command(iface)
    start_time = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            if time.time() - start_time >= duration:
                break  # Stop after duration expires
            line = line.strip()
            if not line:
                continue
            cols = [c.strip('"') for c in line.split(',')]
            if len(cols) < len(TSHARK_FIELDS):
                cols += [''] * (len(TSHARK_FIELDS) - len(cols))
            yield tuple(cols[:len(TSHARK_FIELDS)])
    finally:
        # Terminate tshark cleanly
        proc.terminate()
        proc.wait(timeout=2)
