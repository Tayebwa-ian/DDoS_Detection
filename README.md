# Real-Time DDoS Detection and Mitigation System

## Project Summary

This project implements a highly optimized **Intrusion Prevention System (IPS)** designed to detect and mitigate Distributed Denial of Service (DDoS) attacks with near-zero latency. By integrating Machine Learning (ML) for sophisticated traffic analysis with the Linux kernel's **XDP (eXpress Data Path)** framework, this solution moves defense from userspace deep into the networking stack. This approach provides line-rate mitigation, effectively dropping malicious packets at the earliest possible entry point.

---

## Features

* **Ultra-Low Latency Mitigation:** Uses XDP and eBPF technology to drop malicious packets directly in the kernel's network driver, bypassing the entire conventional network stack.
* **Real-Time ML Classification:** Employs pre-trained Machine Learning models (e.g., Logistic Regression, Decision Tree) for continuous classification of network flows.
* **Flow-Based Analysis:** Aggregates packets into five-tuple flows and extracts 20 critical features (IATs, packet lengths, flag counts) for robust anomaly detection.
* **Automated Blocking:** Instantly calls the `xdp-filter` utility to add detected attacker source IPs to the eBPF block list.
* **Robust Execution:** Includes mandatory root privilege checks, graceful XDP filter loading (using the compatible `skb` mode for VMs/WSL2), and automatic cleanup upon script exit.
* **Comprehensive Logging:** Logs all flow features and prediction results to a CSV file for post-analysis and auditing.

## Table of Contents

1.  [Project Summary](#project-summary)
2.  [Features](#features)
3.  [Prerequisites](#prerequisites)
4.  [Setup and Run](#setup-and-run)
    * [System Dependencies](#1-system-dependencies)
    * [Install xdp-filter Utility](#2-install-xdp-filter-utility)
    * [Python Environment Setup](#3-python-environment-setup)
    * [Running the IDS/IPS Tool](#4-running-the-idsips-tool)
5.  [Cleanup](#5-cleanup)

## Prerequisites

These steps assume a Debian/Ubuntu environment (like **WSL2**) with root access.

### 1. System Dependencies

You need to install essential tools for packet capture, Python, and the necessary utilities for XDP development.

```bash
# Update system and install required tools
sudo apt update && sudo apt upgrade -y
sudo apt install tshark python3 python3-pip -y

# Install dependencies for XDP/eBPF compilation (required for xdp-tools)
sudo apt install build-essential clang llvm libelf-dev libpcap-dev -y
```

### 2. Install xdp-filter Utility

The userspace tool `xdp-filter` is crucial for managing the eBPF program and the IP block list. Please follow the official installation guide:

[Official XDP-Tools Guide](https://github.com/xdp-project/xdp-tools)

## Setup and Run

### 3. Python Environment Setup

Clone the repository and set up your Python environment:

```bash
# Clone the repository
git clone <this repo>
cd real_time_detection

# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages (requires a requirements.txt file)
pip install -r requirements.txt
```

### 4. Running the IDS/IPS Tool

The script **must** be executed with `sudo` and explicitly use the Python interpreter from the active virtual environment to find all installed dependencies.

```bash
# Execute the main script with sudo, referencing the VIRTUAL_ENV path
# Adjust 'eth0' and '--duration' as needed for your environment
sudo $VIRTUAL_ENV/bin/python3 main.py --iface eth0 --duration 120
```
### 5. Cleanup  

If the script is interrupted (e.g., crashed, or force-closed) before its natural exit, the XDP program may remain attached to the interface. You can manually unload it using this command:
```bash
sudo xdp-filter unload eth0
```
