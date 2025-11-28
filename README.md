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
* **Real-Time Dashboard:** Provides a web interface for real-time visualization, filtering, and analysis of detected traffic flows.

## Table of Contents

1.  [Project Summary](#project-summary)
2.  [Features](#features)
3.  [Prerequisites](#prerequisites)
4.  [Setup and Run](#setup-and-run)
    * [1. System Dependencies](#1-system-dependencies)
    * [2. Install xdp-filter Utility](#2-install-xdp-filter-utility)
    * [3. Python and Node.js Environment Setup](#3-python-and-nodejs-environment-setup)
    * [4. Run the IDS/IPS Tool (Data Generator)](#4-run-the-idsips-tool-data-generator)
    * [5. Start the Real-Time Data Server](#5-start-the-real-time-data-server)
    * [6. Launch the React Dashboard](#6-launch-the-react-dashboard)
7.  [Cleanup](#7-cleanup)

## Prerequisites

These steps assume a Debian/Ubuntu environment (like **WSL2**) with root access and **Node.js installed** (required for the data server and dashboard).

### 1. System Dependencies

You need to install essential tools for packet capture, Python, and the necessary utilities for XDP development.

```bash
# Update system and install required tools
sudo apt update && sudo apt upgrade -y
sudo apt install tshark python3 python3-pip -y

# Install dependencies for XDP/eBPF compilation (required for xdp-tools)
sudo apt install build-essential clang llvm libelf-dev libpcap-dev -y

# Check for Node.js installation (or install if missing)
node -v 
```

### 2. Install xdp-filter Utility

The userspace tool xdp-filter is crucial for managing the eBPF program and the IP block list. Please follow the official installation guide: Official XDP-Tools Guide

## Setup and Run

### 3. Python and Node.js Environment Setup

Clone the repository and set up both your Python and Node.js environments.

```bash
# Clone the repository
git clone <this repo>
cd real_time_detection

# --- PYTHON SETUP (for IDS/IPS Tool) ---
# Create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required Python packages (requires a requirements.txt file)
pip install -r requirements.txt

# --- NODE.JS SETUP (for Data Server and Dashboard) ---
# Assuming 'dashboard' and 'data-server' are directories inside the repo root.

# Install server dependencies (if the server uses packages like 'fs' or 'http', they are built-in)
# If your server requires external packages (e.g., 'express'), install them here.
cd ../data-server
npm install 

# Install dashboard dependencies
cd ../dashboard
npm install
```

### 4. Run the IDS/IPS Tool (Data Generator)  

This script must run in a dedicated terminal window as it handles packet capture and continually writes results to predictions_log.csv (located in the data directory).  
  
NOTE: This must be run with sudo.  

```bash
# Execute the main script with sudo, referencing the VIRTUAL_ENV path
# Adjust 'eth0' and '--duration' as needed for your environment
cd ../real_time_detection 
sudo $VIRTUAL_ENV/bin/python3 main.py --iface eth0 --duration 120
```

### 5. Start the Real-Time Data Server

The React dashboard cannot directly read local files. This Node.js server acts as an intermediary, serving the constantly updated predictions_log.csv file over HTTP.  
  
NOTE: This must run in a separate terminal window and serve the file from the correct absolute path.  

```bash
# Navigate to the server directory
cd ../data-server 

# Start the Node.js server on port 8000
node fileServer.js

# Server output should confirm it is serving data from: http://localhost:8000/predictions_log.csv
```

### 6. Launch the React Dashboard  

The dashboard reads data from the server started in Step 5 and displays it in real-time.  
  
NOTE: This must run in a third terminal window.  

```bash
# Navigate to the dashboard directory
cd ../dashboard

# Start the dashboard application
npm run dev
```

### 7. Cleanup

If the script is interrupted (e.g., crashed, or force-closed) before its natural exit, the XDP program may remain attached to the interface. You can manually unload it using this command:

```bash
sudo xdp-filter unload eth0
```
