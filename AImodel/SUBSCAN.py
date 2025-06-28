# SUBSCAN.py - Updated with user-defined INITIAL_NMAP_ARGS for comprehensive initial Nmap scan
# and crucial directory creation logic.

import sys
import subprocess
import os
import time
import xml.etree.ElementTree as ET # Import for potential XML validation

# User-defined Nmap initial arguments
# -sS: SYN scan
# -sV: Service version detection
# -O: OS detection
# -sC: Default scripts (equivalent to --script=default)
# -T4: Aggressive timing template
# -p-: Scans all ports (1-65535) - CHANGED FROM --top-ports 1000
# --traceroute: Performs a traceroute to the target
# --reason: Displays the reason a port is in a particular state
# --version-intensity 9: Sets version scan intensity to 9 (more aggressive)
INITIAL_NMAP_ARGS = "-sS -sV -O -sC -T4 -p- --traceroute --reason --version-intensity 9"

def run_nmap_scan(target_ip, output_file="scanout.xml"):
    """
    Runs a basic Nmap scan and outputs results to an XML file.
    Ensures the output directory exists before running Nmap.
    """
    print(f"[{os.path.basename(__file__)}] Starting Nmap scan for {target_ip} (all ports)...") # Added (all ports)
    
    # --- CRUCIAL ADDITION: Ensure the output directory exists ---
    output_directory = os.path.dirname(output_file)
    if output_directory and not os.path.exists(output_directory):
        try:
            os.makedirs(output_directory)
            print(f"[{os.path.basename(__file__)}] Created output directory: {output_directory}")
        except OSError as e:
            print(f"[{os.path.basename(__file__)}] Error creating directory {output_directory}: {e}")
            return False

    nmap_command = f"nmap {INITIAL_NMAP_ARGS} -oX {output_file} {target_ip}"
    print(f"[{os.path.basename(__file__)}] Executing Nmap command: {nmap_command}") # DEBUG

    try:
        # Use subprocess.run for better control and error handling
        result = subprocess.run(
            nmap_command.split(), # Split the command string into a list
            capture_output=True,  # Capture stdout and stderr
            text=True,            # Decode stdout/stderr as text
            check=False           # Do not raise an exception for non-zero exit codes
        )

        # Print Nmap's stdout and stderr for debugging
        if result.stdout:
            print(f"[{os.path.basename(__file__)}] Nmap stdout:\n{result.stdout}")
        if result.stderr:
            print(f"[{os.path.basename(__file__)}] Nmap stderr:\n{result.stderr}")

        if result.returncode != 0 and not os.path.exists(output_file):
            print(f"[{os.path.basename(__file__)}] Nmap command failed with exit code {result.returncode}.")
            # If Nmap exits with an error and no output file is created, it's a failure
            return False

        # Check if the output file was actually created and is not empty
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"[{os.path.basename(__file__)}] Nmap scan completed. Output saved to {output_file}")
            try:
                # Basic XML validation to ensure it's not corrupted
                ET.parse(output_file) 
                return True
            except ET.ParseError:
                print(f"[{os.path.basename(__file__)}] Error: Output file '{output_file}' is not valid XML. Deleting corrupted file.")
                os.remove(output_file) # Remove corrupted file
                return False
        else:
            print(f"[{os.path.basename(__file__)}] Error: Nmap output file '{output_file}' was not created or is empty.")
            return False

    except FileNotFoundError:
        print(f"[{os.path.basename(__file__)}] Error: Nmap not found. Please ensure Nmap is installed and in your system's PATH, or provide the full path to the nmap executable instead of just 'nmap'.")
        return False
    except Exception as e:
        print(f"[{os.path.basename(__file__)}] An unexpected error occurred during Nmap execution: {e}")
        return False

if __name__ == "__main__":
    target_ip = sys.stdin.readline().strip()

    if not target_ip:
        print(f"[{os.path.basename(__file__)}] Error: No target IP received via stdin. Exiting.")
        sys.exit(1)

    # The hardcoded path for output within SUBSCAN.py
    # If main.py calls this, ensure main.py passes "output/scanout.xml"
    if not run_nmap_scan(target_ip, "output/scanout.xml"):
        print(f"[{os.path.basename(__file__)}] Initial Nmap scan failed. Exiting.")
        sys.exit(1)
    print(f"[{os.path.basename(__file__)}] Initial Nmap scan completed successfully for {target_ip}.")