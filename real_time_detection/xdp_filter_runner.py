import subprocess
import os
import sys
import time

# --- Configuration ---
# You must change this to the network interface XDP is running on (e.g., 'eth0' or 'enp1s0')
INTERFACE = "eth0" 
# The script must be run using 'sudo python3 xdp_filter_runner.py'
XDP_FILTER_CMD = "xdp-filter"

def _execute_xdp_command(command: str):
    """
    Executes the constructed xdp-filter command using subprocess.
    Includes basic error handling for command execution.
    
    Returns:
        tuple[bool, str]: (Success status, Stderr output)
    """
    # The command parameter already contains the subcommand and arguments, 
    # e.g., "load eth0 -m skb" or "ip add 1.2.3.4"
    full_cmd = f"{XDP_FILTER_CMD} {command}"
    print(f"Executing: {full_cmd}")

    try:
        # Run the command and capture output
        result = subprocess.run(
            full_cmd,
            shell=True,
            check=True,  # Raise an exception for non-zero exit codes
            capture_output=True,
            text=True
        )
        print("Command executed successfully.")
        # Optionally print stdout/stderr for debugging
        if result.stdout:
            # Only print status output if it's the 'status' command
            if command.startswith("status"):
                print(f"Stdout:\n{result.stdout.strip()}")
        if result.stderr:
            print(f"Stderr:\n{result.stderr.strip()}")
        return True, ""
        
    except subprocess.CalledProcessError as e:
        # Return error details for the caller to handle specific errors (like already loaded)
        print(f"ERROR: xdp-filter failed with return code {e.returncode}")
        print(f"Command: {e.cmd}")
        stderr_output = e.stderr.strip()
        print(f"Stderr:\n{stderr_output}")
        return False, stderr_output
    except FileNotFoundError:
        error_msg = f"ERROR: The {XDP_FILTER_CMD} command was not found. Check if it's in your PATH or update XDP_FILTER_CMD."
        print(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"An unexpected error occurred: {e}"
        print(error_msg)
        return False, error_msg

def initialize_xdp_filter():
    """
    Loads the base xdp-filter program onto the configured interface.
    It checks if the filter is already loaded and skips the load command if so.
    """
    print(f"--- Initializing XDP filter on interface: {INTERFACE} ---")
    # Syntax: xdp-filter load <ifname> [options]
    command = f"load {INTERFACE} -m skb" 
    
    success, stderr = _execute_xdp_command(command)
    
    if success:
        return True
    
    # Check if the failure is due to the filter already being loaded
    if "is already loaded on" in stderr:
        print(f"XDP filter is already loaded on {INTERFACE}. Skipping initialization.")
        return True
    
    # Otherwise, it's a real failure
    print("Initialization failed. Cannot proceed.")
    return False

def block_ip(ip_address: str) -> bool:
    """
    Adds a source IP address to the XDP drop list (eBPF map).
    """
    if not ip_address:
        print("Error: IP address cannot be empty.")
        return False
        
    print(f"\n--- BLOCKING IP: {ip_address} on {INTERFACE} ---")
    # FIX: Removed the INTERFACE argument. 'xdp-filter ip' only takes the IP address 
    # as the required positional argument for addition (default mode).
    command = f"ip --mode src {ip_address}"
    success, _ = _execute_xdp_command(command)
    return success

def unblock_ip(ip_address: str) -> bool:
    """
    Removes a source IP address from the XDP drop list (eBPF map).
    """
    if not ip_address:
        print("Error: IP address cannot be empty.")
        return False
        
    print(f"\n--- UNBLOCKING IP: {ip_address} on {INTERFACE} ---")
    # FIX: Removed the INTERFACE argument and used the standard '--remove' flag 
    # for deletion as per 'xdp-filter ip --help'.
    command = f"ip --mode src --remove {ip_address}" 
    success, _ = _execute_xdp_command(command)
    return success

def get_status():
    """
    Displays the current status of the xdp-filter, including blocked IPs.
    """
    print(f"\n--- Current XDP Filter Status on {INTERFACE} ---")
    # Syntax: xdp-filter status <ifname> 
    command = f"status"
    success, _ = _execute_xdp_command(command)
    return success

if __name__ == "__main__":
    # Ensure this script is run with root permissions, as XDP commands require 'sudo'
    if os.geteuid() != 0:
        print("This script requires root privileges (sudo) to execute XDP commands.")
        sys.exit(1)

    # 1. Initialize XDP Filter (Must be done first)
    if not initialize_xdp_filter():
        sys.exit(1)

    # Define test IPs
    MALICIOUS_IP_1 = "192.168.1.100"
    MALICIOUS_IP_2 = "203.0.113.50"
    
    # 2. Simulate AI detection and blocking
    print("\n--- Simulating AI Detection ---")
    block_ip(MALICIOUS_IP_1)
    
    # Block IP 2
    time.sleep(0.5) 
    block_ip(MALICIOUS_IP_2)
    
    # 3. Check status to confirm IPs are blocked
    time.sleep(0.5)
    get_status()
    
    # 4. Simulate end of attack and unblocking
    print("\n--- Simulating End of Attack ---")
    time.sleep(1)
    
    # Unblock IP 1
    unblock_ip(MALICIOUS_IP_1)
    
    # 5. Check status again
    time.sleep(0.5)
    get_status()
    
    # 6. Final cleanup (optional, unloads the entire program)
    print("\n--- Final Cleanup: Unloading XDP Program ---")
    # Syntax: xdp-filter unload <ifname>
    success, _ = _execute_xdp_command(f"unload {INTERFACE}")
    
    print("\nScript finished.")
