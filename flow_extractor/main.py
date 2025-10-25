from flow_extractor.file_manager import FileManager
from flow_extractor.extractor import FlowExtractor
from flow_extractor.logger import setup_logger
from pathlib import Path


def main():
    # === CONFIGURATION ===
    pcap_path = "network_capture.pcap"      # path to PCAP file
    output_dir = "outputs"                  # where to save CSVs
    log_path = "outputs/flow_extraction.log"

    # === INITIALIZATION ===
    logger = setup_logger(Path(log_path))
    fm = FileManager(pcap_path, output_dir)
    fm.validate()
    output_path = fm.get_output_path()

    # === EXTRACTION ===
    extractor = FlowExtractor(logger)
    extractor.extract_flows(fm.pcap_path, output_path)


if __name__ == "__main__":
    main()
