from pathlib import Path


class FileManager:
    """Handles paths and directories for PCAP and output files."""

    def __init__(self, pcap_path: str, output_dir: str):
        self.pcap_path = Path(pcap_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def validate(self):
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        return True

    def get_output_path(self):
        base_name = self.pcap_path.stem
        return self.output_dir / f"{base_name}_flows.csv"
