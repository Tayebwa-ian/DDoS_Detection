import subprocess
from pathlib import Path


class FlowExtractor:
    """Encapsulates the logic for extracting flow features using cicflowmeter."""

    def __init__(self, logger):
        self.logger = logger

    def extract_flows(self, pcap_path: Path, output_path: Path):
        """Run the CICFlowMeter command."""
        self.logger.info(f"Starting flow extraction for: {pcap_path}")
        try:
            cmd = [
                "cicflowmeter",
                "-f", str(pcap_path),
                "-c",
                str(output_path)
            ]
            subprocess.run(cmd, check=True)
            self.logger.info(f"Flow features saved to {output_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running cicflowmeter: {e}")
            raise
