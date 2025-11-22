import subprocess
import sys
import os

class XDPManager:
    """
    Manages the lifecycle of the xdp-filter program on a specified interface.
    Handles loading, blocking/unblocking IPs, and unloading.
    """
    def __init__(self, iface: str, xdp_cmd: str = "xdp-filter"):
        self.interface = iface
        self.xdp_cmd = xdp_cmd
        self.is_loaded = False
        
        # Ensure script is run with root permissions
        if os.geteuid() != 0:
            print("ERROR: XDP commands require root privileges (sudo).")
            sys.exit(1)

    def _execute_xdp_command(self, command: str) -> tuple[bool, str]:
        """
        Executes a subprocess command for xdp-filter.
        Returns: (Success status, Stderr output)
        """
        full_cmd = f"{self.xdp_cmd} {command}"
        print(f"Executing: {full_cmd}")

        try:
            result = subprocess.run(
                full_cmd,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            print("Command executed successfully.")
            return True, ""
            
        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr.strip()
            print(f"ERROR: xdp-filter failed with return code {e.returncode}")
            print(f"Command: {e.cmd}")
            print(f"Stderr:\n{stderr_output}")
            return False, stderr_output
        except FileNotFoundError:
            error_msg = f"ERROR: The {self.xdp_cmd} command was not found."
            print(error_msg)
            return False, error_msg

    def initialize_xdp_filter(self) -> bool:
        """
        Loads the xdp-filter program, skipping if already loaded.
        """
        print(f"--- Initializing XDP filter on interface: {self.interface} ---")
        # Use 'skb' mode for compatibility (WSL2)
        command = f"load {self.interface} -m skb" 
        
        success, stderr = self._execute_xdp_command(command)
        
        if success:
            self.is_loaded = True
            return True
        
        # Check if the failure is due to the filter already being loaded
        if "is already loaded on" in stderr:
            print(f"XDP filter is already loaded on {self.interface}. Skipping initialization.")
            self.is_loaded = True
            return True
        
        print("Initialization failed. Cannot proceed with XDP operations.")
        return False

    def block_ip(self, ip_address: str) -> bool:
        """
        Adds a source IP address to the XDP drop list (eBPF map).
        Uses 'xdp-filter ip <addr>'
        """
        if not self.is_loaded:
            print("WARNING: XDP filter is not loaded. Cannot block IP.")
            return False

        print(f"!!! BLOCKING MALICIOUS IP: {ip_address} !!!")
        # FIX: 'xdp-filter ip' only needs the IP address as a positional argument for adding.
        command = f"ip --mode src {ip_address}"
        success, _ = self._execute_xdp_command(command)
        return success

    def unload_xdp_filter(self) -> bool:
        """
        Unloads the XDP program from the interface.
        """
        if not self.is_loaded:
            return True

        print(f"\n--- Final Cleanup: Unloading XDP Program from {self.interface} ---")
        # Syntax: xdp-filter unload <ifname>
        command = f"unload {self.interface}"
        success, _ = self._execute_xdp_command(command)
        
        if success:
            self.is_loaded = False
        return success
