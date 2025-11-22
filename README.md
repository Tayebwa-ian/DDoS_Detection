Real-Time DDoS Detection and Mitigation System🛡️ Project SummaryThis project implements a highly optimized Intrusion Prevention System (IPS) designed to detect and mitigate Distributed Denial of Service (DDoS) attacks with near-zero latency. By integrating Machine Learning (ML) for sophisticated traffic analysis with the Linux kernel's XDP (eXpress Data Path) framework, this solution moves defense from userspace deep into the networking stack. This approach provides line-rate mitigation, effectively dropping malicious packets at the earliest possible entry point.✨ FeaturesUltra-Low Latency Mitigation: Uses XDP and eBPF technology to drop malicious packets directly in the kernel's network driver, bypassing the entire conventional network stack.Real-Time ML Classification: Employs pre-trained Machine Learning models (e.g., Logistic Regression, Decision Tree) for continuous classification of network flows.Flow-Based Analysis: Aggregates packets into five-tuple flows and extracts 20 critical features (IATs, packet lengths, flag counts) for robust anomaly detection.Automated Blocking: Instantly calls the xdp-filter utility to add detected attacker source IPs to the eBPF block list.Robust Execution: Includes mandatory root privilege checks, graceful XDP filter loading (using the compatible skb mode for VMs/WSL2), and automatic cleanup upon script exit.Comprehensive Logging: Logs all flow features and prediction results to a CSV file for post-analysis and auditing.📋 Table of ContentsProject SummaryFeaturesPrerequisitesSetup and RunSystem DependenciesInstall xdp-filter UtilityPython Environment SetupRunning the ToolCleanup🛠️ PrerequisitesThese steps assume a Debian/Ubuntu environment (like WSL2) with root access.1. System DependenciesYou need to install essential tools for packet capture, Python, and the necessary utilities for XDP development.# Update system and install required tools
sudo apt update && sudo apt upgrade -y
sudo apt install tshark python3 python3-pip -y

# Install dependencies for XDP/eBPF compilation (required for xdp-tools)
sudo apt install build-essential clang llvm libelf-dev libpcap-dev -y
2. Install xdp-filter UtilityThe userspace tool xdp-filter is crucial for managing the eBPF program and the IP block list. Please follow the official installation guide:Official XDP-Tools Guide💻 Setup and Run3. Python Environment SetupClone the repository and set up your Python environment:# Clone the repository
git clone <this repo>
cd real_time_detection

# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages (requires a requirements.txt file)
pip install -r requirements.txt
4. Running the IDS/IPS ToolThe script must be executed with sudo and explicitly use the Python interpreter from the active virtual environment to find all installed dependencies.# Execute the main script with sudo, referencing the VIRTUAL_ENV path
# Adjust 'eth0' and '--duration' as needed for your environment
sudo $VIRTUAL_ENV/bin/python3 main.py --iface eth0 --duration 120
Note: Ensure your pre-trained ML models (.joblib files) are correctly placed in the models/ directory for the predictor.py module to load them.5. CleanupIf the script is interrupted (e.g., crashed, or force-closed) before its natural exit, the XDP program may remain attached to the interface. You can manually unload it using this command:sudo xdp-filter unload eth0
