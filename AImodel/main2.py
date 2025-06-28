# Version 2.0 - Added XML parsing for Nmap reports, improved rule evaluation, and enhanced fact management.  

import json
import os
import subprocess
import time
import sys
import xml.etree.ElementTree as ET # Import for XML parsing

# --- FactBase Class ---
class FactBase:
    """
    Manages the collection of facts derived from scan reports and other inputs.
    """
    def __init__(self):
        self.facts = {}
        

    def add_fact(self, key, value):
        """Adds or updates a fact."""
        self.facts[key] = value

    def get_fact(self, key, default=None):
        """Retrieves a fact."""
        return self.facts.get(key, default)

    def contains_fact(self, key, value):
        """Checks if a fact exists and has a specific value."""
        return self.facts.get(key) == value

    def fact_list_contains(self, list_key, item):
        """Checks if a fact (which is a list) contains a specific item."""
        fact_list = self.facts.get(list_key)
        return isinstance(fact_list, list) and item in fact_list
        
    def fact_string_contains(self, string_key, substring):
        """Checks if a fact (which is a string) contains a specific substring."""
        fact_string = self.facts.get(string_key)
        return isinstance(fact_string, str) and substring in fact_string

    def __str__(self):
        return json.dumps(self.facts, indent=2)

# --- Rule Class ---
class Rule:
    """
    Represents a single inference rule with conditions and actions.
    """
    def __init__(self, rule_id, name, conditions, actions, stage="any"):
        self.rule_id = rule_id
        self.name = name
        self.conditions = conditions
        self.actions = actions
        self.stage = stage # Stage at which this rule is relevant (e.g., "initial_discovery_complete")

    def evaluate(self, fact_base, current_stage):
        """
        Evaluates the rule's conditions against the FactBase.
        Returns True if all conditions are met, False otherwise.
        """
        if self.stage != "any" and self.stage != current_stage:
            return False # Rule is not relevant for the current stage

        for condition in self.conditions:
            fact_key = condition["fact"]
            op = condition["op"]
            expected_value = condition.get("value")

            current_fact_value = fact_base.get_fact(fact_key)

            if op == "exists":
                if current_fact_value is None:
                    return False
            elif op == "not_exists":
                if current_fact_value is not None:
                    return False
            elif op == "equals":
                if current_fact_value != expected_value:
                    return False
            elif op == "not_equals":
                if current_fact_value == expected_value:
                    return False
            elif op == "contains":
                if not fact_base.fact_list_contains(fact_key, expected_value) and \
                   not fact_base.fact_string_contains(fact_key, expected_value):
                    return False
            elif op == "not_contains":
                if fact_base.fact_list_contains(fact_key, expected_value) or \
                   fact_base.fact_string_contains(fact_key, expected_value):
                    return False
            elif op == "greater_than":
                if not (isinstance(current_fact_value, (int, float)) and current_fact_value > expected_value):
                    return False
            elif op == "less_than":
                if not (isinstance(current_fact_value, (int, float)) and current_fact_value < expected_value):
                    return False
            # Add more operators as needed (e.g., starts_with, ends_with, regex_match)
        return True

# --- Nmap XML to JSON Conversion and Merging Utilities ---

def _convert_xml_host_to_json_dict(host_elem):
    """
    Converts a single <host> XML element to a simplified JSON-like dictionary.
    """
    host_data = {}

    # Address
    address_elem = host_elem.find('address')
    if address_elem is not None: # Fix DeprecationWarning
        host_data['address'] = address_elem.attrib
    
    # Hostnames
    hostnames_elem = host_elem.find('hostnames')
    if hostnames_elem is not None: # Fix DeprecationWarning
        host_data['hostnames'] = []
        for hostname_elem in hostnames_elem.findall('hostname'):
            host_data['hostnames'].append(hostname_elem.attrib)

    # Ports
    ports_elem = host_elem.find('ports')
    if ports_elem is not None: # Fix DeprecationWarning
        host_data['ports'] = []
        for port_elem in ports_elem.findall('port'):
            port_info = port_elem.attrib
            state_elem = port_elem.find('state')
            if state_elem is not None: # Fix DeprecationWarning
                port_info['state'] = state_elem.attrib
            service_elem = port_elem.find('service')
            if service_elem is not None: # Fix DeprecationWarning
                port_info['service'] = service_elem.attrib
            host_data['ports'].append(port_info)
    
    # OS
    os_elem = host_elem.find('os')
    if os_elem is not None: # Fix DeprecationWarning
        osmatch_list = []
        for osmatch_elem in os_elem.findall('osmatch'):
            osmatch_info = osmatch_elem.attrib
            osclass_list = []
            for osclass_elem in osmatch_elem.findall('osclass'):
                osclass_list.append(osclass_elem.attrib)
            if osclass_list:
                osmatch_info['osclass'] = osclass_list
            osmatch_list.append(osmatch_info)
        if osmatch_list:
            host_data['os'] = osmatch_list

    # Add other top-level host attributes if needed
    for key, value in host_elem.attrib.items():
        if key not in ['startstr', 'endstr', 'elapsed', 'summary', 'exit', 'args', 'scaninfo', 'verbose', 'debugging']: # Exclude meta-info from host_data
            host_data[key] = value

    return host_data

def parse_nmap_xml_report(xml_file_path, target_ip_hint=None):
    """
    Parses an Nmap XML report and returns a simplified JSON-like structure
    containing host data, focusing on the specified target_ip_hint if provided.
    """
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        
        # This will store all hosts found, but if target_ip_hint is provided,
        # we'll filter or prioritize it.
        all_hosts_data = []

        for host_elem in root.findall('host'):
            host_data = _convert_xml_host_to_json_dict(host_elem)
            if host_data:
                all_hosts_data.append(host_data)
        
        if target_ip_hint:
            # Filter for the specific target IP if a hint is given
            filtered_hosts = [h for h in all_hosts_data if h.get('address', {}).get('addr') == target_ip_hint]
            if filtered_hosts:
                # Return only the relevant host data for the target_ip_hint
                return {"nmaprun": {"host": filtered_hosts[0] if len(filtered_hosts) == 1 else filtered_hosts}}
            else:
                # If target_ip_hint not found, return an empty structure or handle as error
                print(f"[parse_nmap_xml_report] Warning: Target IP '{target_ip_hint}' not found in scan results.")
                return {"nmaprun": {"host": {}}} # Return empty host data
        else:
            # If no hint, return all hosts as a list if multiple, or single host if one
            if len(all_hosts_data) == 1:
                return {"nmaprun": {"host": all_hosts_data[0]}}
            elif len(all_hosts_data) > 1:
                return {"nmaprun": {"host": all_hosts_data}}
            else:
                return {"nmaprun": {"host": {}}} # No hosts found


    except ET.ParseError as e:
        print(f"Error parsing Nmap XML report from {xml_file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while parsing Nmap XML: {e}")
        return None


def parse_nmap_json_report(nmap_json_data, target_ip_hint=None):
    """
    Parses a simplified Nmap JSON-like data structure (from _convert_xml_host_to_json_dict or similar)
    and populates a FactBase.
    
    This function is designed to work with the output format of _convert_xml_host_to_json_dict
    or the consolidated_nmap_data structure.
    """
    fact_base = FactBase()

    if not nmap_json_data or "nmaprun" not in nmap_json_data:
        # print("[parse_nmap_json_report] No Nmap data provided or invalid format.")
        return fact_base

    hosts_data = nmap_json_data["nmaprun"].get("host")

    if not hosts_data:
        # print("[parse_nmap_json_report] No host data found in Nmap data.")
        return fact_base

    # Ensure hosts_data is always a list for consistent iteration
    if not isinstance(hosts_data, list):
        hosts_data = [hosts_data]
    
    # If a target_ip_hint is provided, filter or prioritize that host
    if target_ip_hint:
        hosts_data = [h for h in hosts_data if h.get('address', {}).get('addr') == target_ip_hint]
        if not hosts_data:
            # print(f"[parse_nmap_json_report] Warning: Target IP '{target_ip_hint}' not found in provided JSON data.")
            return fact_base # No facts for the specific target

    for host in hosts_data:
        ip_address = host.get('address', {}).get('addr')
        if not ip_address:
            continue # Skip hosts without an IP

        fact_base.add_fact("target_ip", ip_address)
        
        # Host state
        status = host.get('status', {}).get('state')
        if status:
            fact_base.add_fact(f"host_status_{ip_address}", status)
            if status == "up":
                fact_base.add_fact("host_is_up", True)
            else:
                fact_base.add_fact("host_is_up", False)

        # Hostnames
        hostnames = [hn.get('name') for hn in host.get('hostnames', []) if hn.get('name')]
        if hostnames:
            fact_base.add_fact(f"hostnames_{ip_address}", hostnames)
            fact_base.add_fact("has_hostname", True)
        else:
            fact_base.add_fact("has_hostname", False)

        # OS Detection
        os_matches = host.get('os', [])
        if os_matches:
            # Take the first best guess for general OS detection fact
            best_os_match = os_matches[0]
            fact_base.add_fact(f"os_name_{ip_address}", best_os_match.get('name'))
            fact_base.add_fact(f"os_accuracy_{ip_address}", int(best_os_match.get('accuracy', 0)))
            
            # Check for generic OS (e.g., 'Linux', 'Windows') for broader rules
            if best_os_match.get('name') and ('Linux' in best_os_match['name'] or 'Windows' in best_os_match['name']):
                fact_base.add_fact("os_detected", True)
            else:
                fact_base.add_fact("os_detected", False)
            
            # Collect all OS classes (e.g., operating system family)
            os_classes = []
            for os_match in os_matches:
                for os_class in os_match.get('osclass', []):
                    os_classes.append(os_class.get('osfamily'))
            if os_classes:
                fact_base.add_fact(f"os_families_{ip_address}", list(set(os_classes))) # Use set to remove duplicates
                
            # If OS detection accuracy is low, set a flag
            if int(best_os_match.get('accuracy', 0)) < 90:
                fact_base.add_fact("os_detection_low_accuracy", True)
            else:
                fact_base.add_fact("os_detection_low_accuracy", False)
        else:
            fact_base.add_fact("os_detected", False)
            fact_base.add_fact("os_detection_low_accuracy", True) # No OS detected implies low accuracy

        # Open Ports and Services
        open_ports = []
        for port_info in host.get('ports', []):
            if port_info.get('state', {}).get('state') == 'open':
                port_id = port_info.get('portid')
                protocol = port_info.get('protocol')
                service_name = port_info.get('service', {}).get('name')
                service_product = port_info.get('service', {}).get('product')
                service_version = port_info.get('service', {}).get('version')
                
                open_ports.append({
                    "portid": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version
                })
                
                # Add individual port/service facts
                fact_base.add_fact(f"port_{port_id}_{protocol}_open", True)
                if service_name:
                    fact_base.add_fact(f"service_{port_id}_{protocol}", service_name)
                    if service_product:
                        fact_base.add_fact(f"service_product_{port_id}_{protocol}", service_product)
                    if service_version:
                        fact_base.add_fact(f"service_version_{port_id}_{protocol}", service_version)

                    # Specific service facts (e.g., for rules)
                    if service_name == "http" or service_name == "https":
                        fact_base.add_fact("http_service_open", True)
                        fact_base.add_fact(f"http_port_{port_id}_open", True)
                    elif service_name == "ftp":
                        fact_base.add_fact("ftp_service_open", True)
                        fact_base.add_fact(f"ftp_port_{port_id}_open", True)
                    elif service_name == "smb":
                        fact_base.add_fact("smb_service_open", True)
                        fact_base.add_fact(f"smb_port_{port_id}_open", True)
                    elif service_name == "ms-sql": # common service name for SQL Server
                        fact_base.add_fact("mssql_service_open", True)
                        fact_base.add_fact(f"mssql_port_{port_id}_open", True)
                    elif service_name == "mysql":
                        fact_base.add_fact("mysql_service_open", True)
                        fact_base.add_fact(f"mysql_port_{port_id}_open", True)
                    elif service_name == "ssh":
                        fact_base.add_fact("ssh_service_open", True)
                        fact_base.add_fact(f"ssh_port_{port_id}_open", True)

        if open_ports:
            fact_base.add_fact(f"open_ports_{ip_address}", open_ports)
            fact_base.add_fact("has_open_ports", True)
        else:
            fact_base.add_fact("has_open_ports", False)
            
    return fact_base


# --- Inference Engine Class ---
class InferenceEngine:
    """
    The core inference engine that applies rules to facts.
    """
    def __init__(self, rules, initial_nmap_data=None):
        self.rules = rules
        self.fact_base = FactBase()
        self.consolidated_nmap_data = [] # Stores merged Nmap host data (JSON-like)
        self.fired_rules = set() # To prevent rules from firing repeatedly in the same run if not desired
        self.max_inference_passes = 10 # Limit passes to prevent infinite loops
        self.current_stage = "initial_discovery_complete" # Initial stage after first scan
        self.output_dir = "output" # Directory for consolidated data and temporary scan outputs

        os.makedirs(self.output_dir, exist_ok=True)

        print("[InferenceEngine] Initializing...")
        self._load_consolidated_data()

        if initial_nmap_data:
            # If initial_nmap_data is provided, consolidate it immediately
            # This is typically for the very first scan
            self.consolidate_and_add_scan_data(initial_nmap_data)
        
        # After any initial data loading/consolidation, ensure the fact base reflects it
        # and set initial stage if not already set.
        if not self.fact_base.get_fact('scan_stage'):
            self.fact_base.add_fact('scan_stage', self.current_stage)

        print(f"[InferenceEngine] Loaded {len(self.consolidated_nmap_data)} hosts from consolidated data at init.")


    def _load_consolidated_data(self):
        """Attempts to load consolidated Nmap data from a JSON file."""
        json_file_path = os.path.join(self.output_dir, "result.json")
        print(f"[InferenceEngine] Attempting to load consolidated data from {json_file_path}...")
        if os.path.exists(json_file_path):
            try:
                with open(json_file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.consolidated_nmap_data = data
                        # Re-parse facts from the loaded consolidated data
                        # This ensures the fact_base is in sync with saved data
                        # We need a dummy nmaprun structure for parse_nmap_json_report
                        self.fact_base = parse_nmap_json_report({"nmaprun": {"host": self.consolidated_nmap_data}})
                        print("[InferenceEngine] Consolidated data loaded successfully.")
                    else:
                        print("[InferenceEngine] Loaded data is not in expected list format. Starting fresh.")
                        self.consolidated_nmap_data = []
            except json.JSONDecodeError as e:
                print(f"[InferenceEngine] Error decoding JSON from {json_file_path}: {e}. Starting fresh.")
                self.consolidated_nmap_data = []
            except Exception as e:
                print(f"[InferenceEngine] An unexpected error occurred loading consolidated data: {e}. Starting fresh.")
                self.consolidated_nmap_data = []
        else:
            print("[InferenceEngine] No valid consolidated data found or loaded.")
            self.consolidated_nmap_data = []

    def _save_consolidated_data(self):
        """Saves the current consolidated Nmap data to a JSON file."""
        json_file_path = os.path.join(self.output_dir, "result.json")
        try:
            with open(json_file_path, 'w') as f:
                json.dump(self.consolidated_nmap_data, f, indent=2)
            print(f"Consolidated Nmap data saved to {json_file_path}")
        except Exception as e:
            print(f"Error saving consolidated data to {json_file_path}: {e}")

    def _deep_merge_nmap_host_data(self, existing_host, new_host):
        """
        Deep merges new Nmap host data into existing host data.
        This is crucial for combining results from multiple scans on the same host.
        It handles lists (like ports, hostnames, os) by merging or appending.
        """
        merged_host = existing_host.copy()

        # Update simple attributes
        merged_host.update(new_host) # New simple attributes overwrite old ones

        # Merge 'address' (should be fairly static but update if needed)
        if 'address' in new_host:
            merged_host['address'] = new_host['address']

        # Merge 'hostnames' (append unique hostnames)
        if 'hostnames' in new_host:
            existing_hostnames = {h.get('name'): h for h in existing_host.get('hostnames', [])}
            for new_hn in new_host['hostnames']:
                if new_hn.get('name') not in existing_hostnames:
                    merged_host.setdefault('hostnames', []).append(new_hn)
                else:
                    # Update existing hostname attributes if new data has more details
                    existing_hn = existing_hostnames[new_hn.get('name')]
                    existing_hn.update(new_hn) # Merge attributes of the same hostname
                    
        # Merge 'ports' (crucial: update existing ports, add new ones)
        if 'ports' in new_host:
            existing_ports_map = {p.get('portid') + '/' + p.get('protocol'): p for p in existing_host.get('ports', [])}
            merged_ports = []

            for new_p in new_host['ports']:
                port_key = new_p.get('portid') + '/' + new_p.get('protocol')
                if port_key in existing_ports_map:
                    # Merge existing port data with new data (e.g., service info might be enhanced)
                    existing_p = existing_ports_map[port_key]
                    existing_p.update(new_p) # New attributes for the port/service overwrite old
                    # Ensure state and service sub-dictionaries are merged, not overwritten, if they exist
                    if 'state' in new_p: existing_p['state'] = new_p['state']
                    if 'service' in new_p: existing_p['service'] = new_p['service']
                    merged_ports.append(existing_p) # Add the merged port
                    del existing_ports_map[port_key] # Remove from map to track processed ports
                else:
                    # Add new port entirely
                    merged_ports.append(new_p)
            
            # Add any remaining existing ports that were not in the new scan
            merged_ports.extend(existing_ports_map.values())
            merged_host['ports'] = merged_ports

        # Merge 'os' (append unique OS matches, potentially update accuracy for existing ones)
        if 'os' in new_host:
            existing_os_matches_map = {o.get('name'): o for o in existing_host.get('os', [])}
            merged_os_matches = []
            for new_om in new_host['os']:
                if new_om.get('name') in existing_os_matches_map:
                    # Update accuracy or other details if a better match is found
                    existing_om = existing_os_matches_map[new_om.get('name')]
                    if int(new_om.get('accuracy', 0)) > int(existing_om.get('accuracy', 0)):
                        existing_om.update(new_om) # Overwrite with more accurate info
                    # Merge osclass if present
                    if 'osclass' in new_om:
                        existing_os_classes = {oc.get('osfamily'): oc for oc in existing_om.get('osclass', [])}
                        for new_oc in new_om['osclass']:
                            if new_oc.get('osfamily') not in existing_os_classes:
                                existing_om.setdefault('osclass', []).append(new_oc)
                    merged_os_matches.append(existing_om)
                    del existing_os_matches_map[new_om.get('name')]
                else:
                    merged_os_matches.append(new_om)
            merged_os_matches.extend(existing_os_matches_map.values())
            merged_host['os'] = merged_os_matches

        # Handle other top-level keys if they need specific merging logic
        # For simplicity, if not specified, new data overwrites old.

        return merged_host

    def consolidate_and_add_scan_data(self, new_scan_nmap_run_data):
        """
        Consolidates new Nmap scan data (in JSON-like format) into the
        engine's internal consolidated_nmap_data.
        After merging, it re-parses the full consolidated data to update the FactBase.
        """
        print("[InferenceEngine] Consolidating new scan data...")
        
        # --- PRESERVE INTERNAL STATE FACTS ---
        # Before parsing new data, save facts that are not directly from Nmap XML/JSON
        # but represent the inference engine's internal state (e.g., stages, completion flags).
        facts_to_preserve = {}
        for key, value in self.fact_base.facts.items():
            if (key.startswith('scan_stage') or 
                key.endswith('_complete') or 
                key.endswith('_scanned') or 
                key.endswith('_enhanced') or # Added for facts like os_detection_enhanced
                key == 'final_report_ready'):
                facts_to_preserve[key] = value
        # --- END PRESERVE INTERNAL STATE FACTS ---

        # Ensure new_scan_nmap_run_data['nmaprun']['host'] is a list for consistent iteration
        new_hosts_data_raw = new_scan_nmap_run_data['nmaprun'].get('host')
        if not new_hosts_data_raw:
            print("[InferenceEngine] No new host data to consolidate.")
            return

        new_hosts_data = new_hosts_data_raw if isinstance(new_hosts_data_raw, list) else [new_hosts_data_raw]

        if not self.consolidated_nmap_data:
            # If no consolidated data exists, initialize it with the new hosts
            self.consolidated_nmap_data = new_hosts_data
            for host_data in new_hosts_data:
                ip_addr = host_data.get('address', {}).get('addr')
                if ip_addr:
                    print(f"[InferenceEngine] Adding new host {ip_addr} to consolidated data.")
        else:
            # Merge new scan data into existing consolidated data
            for new_host_data in new_hosts_data:
                new_host_ip = new_host_data.get('address', {}).get('addr')
                if new_host_ip:
                    found_existing = False
                    for i, existing_host_data in enumerate(self.consolidated_nmap_data):
                        if existing_host_data.get('address', {}).get('addr') == new_host_ip:
                            self.consolidated_nmap_data[i] = self._deep_merge_nmap_host_data(existing_host_data, new_host_data)
                            print(f"[InferenceEngine] Merging new scan data for {new_host_ip} into consolidated data.")
                            found_existing = True
                            break
                    if not found_existing:
                        self.consolidated_nmap_data.append(new_host_data)
                        print(f"[InferenceEngine] Adding new host {new_host_ip} to consolidated data.")

        # After consolidation, re-parse facts from the updated consolidated data
        print("[InferenceEngine] Re-parsing facts from updated consolidated data for inference.")
        
        # Get the target IP from the *current* fact_base before it's replaced
        # This ensures parse_nmap_json_report focuses on the correct host if only one is expected.
        current_target_ip = self.fact_base.get_fact('target_ip') 

        # Pass a pseudo nmaprun structure to parse_nmap_json_report.
        # It needs the 'nmaprun' and 'host' keys as if it came from the XML parser.
        self.fact_base = parse_nmap_json_report({"nmaprun": {"host": self.consolidated_nmap_data}}, target_ip_hint=current_target_ip)
        
        # --- RE-ADD PRESERVED FACTS ---
        for key, value in facts_to_preserve.items():
            self.fact_base.add_fact(key, value)
        # --- END RE-ADD PRESERVED FACTS ---

        self._save_consolidated_data()


    def run_nmap_command(self, nmap_args, target_ip):
        """
        Executes an Nmap command and processes its XML output.
        Returns the path to the temporary XML file if successful, None otherwise.
        """
        temp_xml_file = os.path.join(self.output_dir, "temp_scan_output.xml")
        
        # Ensure target_ip is included in the command
        full_nmap_command = f"/usr/bin/nmap {nmap_args} -oX {temp_xml_file} {target_ip}"
        print(f"  DEBUG: Actual Nmap command for rule: {full_nmap_command}") # Debug print

        try:
            # Using subprocess.run for better control and error handling
            result = subprocess.run(
                full_nmap_command.split(), 
                capture_output=True, 
                text=True, 
                check=False # Do not raise CalledProcessError
            )
            print("  Nmap Rule Scan stdout:\n" + result.stdout)
            if result.stderr:
                print("  Nmap Rule Scan stderr:\n" + result.stderr)

            if result.returncode != 0 and not os.path.exists(temp_xml_file):
                print(f"  Nmap rule command failed with exit code {result.returncode}.")
                return None

            if os.path.exists(temp_xml_file) and os.path.getsize(temp_xml_file) > 0:
                print(f"  Nmap rule scan completed. Output saved to {temp_xml_file}")
                try:
                    # Basic XML validation
                    ET.parse(temp_xml_file)
                    return temp_xml_file
                except ET.ParseError:
                    print(f"  Error: Temporary Nmap output '{temp_xml_file}' is not valid XML. Deleting corrupted file.")
                    #os.remove(temp_xml_file)
                    return None
            else:
                print(f"  Error: Temporary Nmap output file '{temp_xml_file}' was not created or is empty.")
                return None

        except FileNotFoundError:
            print("  Error: Nmap not found. Ensure Nmap is installed and in PATH.")
            return None
        except Exception as e:
            print(f"  An unexpected error occurred during Nmap rule execution: {e}")
            return None


    def execute_action(self, action, target_ip):
        """Executes a single action."""
        action_type = action["type"]
        print(f"  Action: {action_type}")

        if action_type == "add_fact":
            self.fact_base.add_fact(action["fact"], action["value"])
            print(f"  Action: Added fact '{action['fact']}': {action['value']}")
        elif action_type == "run_nmap_scan":
            nmap_args = action["nmap_args"]
            print(f"  Action: Executing Nmap command for rule: {nmap_args}")
            temp_xml_file = self.run_nmap_command(nmap_args, target_ip)
            if temp_xml_file:
                # Parse the temporary XML file to JSON-like data
                new_scan_data_json = parse_nmap_xml_report(temp_xml_file, target_ip_hint=target_ip)
                if new_scan_data_json:
                    self.consolidate_and_add_scan_data(new_scan_data_json)
                else:
                    print(f"  Warning: No valid data parsed from {temp_xml_file}")
                
                os.remove(temp_xml_file) # Clean up temporary file
                print(f"  Cleaned up temporary rule scan file: {temp_xml_file}")
            else:
                print("  Nmap rule scan failed or produced no valid output.")

        # Add more action types as needed (e.g., trigger Metasploit, generate report)
        elif action_type == "print_message":
            print(f"  Action: {action['message']}")
        
        elif action_type == "set_stage":
            self.current_stage = action["stage"]
            self.fact_base.add_fact("scan_stage", self.current_stage)
            print(f"  Action: Transitioned to stage: {self.current_stage}")


    def run(self):
        """
        Runs the inference process by repeatedly evaluating rules.
        """
        print(f"\n--- Starting Nmap Decision Inference ---\n")
        
        # Ensure initial target_ip is a fact for rules that need it
        if not self.fact_base.get_fact('target_ip') and self.consolidated_nmap_data:
            initial_target_ip = self.consolidated_nmap_data[0].get('address', {}).get('addr')
            if initial_target_ip:
                self.fact_base.add_fact('target_ip', initial_target_ip)
                print(f"[InferenceEngine] Initial target_ip set to {initial_target_ip}")


        for pass_num in range(1, self.max_inference_passes + 1):
            print(f"\n--- Inference Pass {pass_num} (Current Stage: {self.current_stage})---")
            facts_before_pass = self.fact_base.facts.copy() # Capture facts at start of pass
            rules_fired_in_pass = 0

            # Filter rules by current stage
            relevant_rules = [r for r in self.rules if r.stage == "any" or r.stage == self.current_stage]

            for rule in relevant_rules:
                # A rule should only fire once per run unless explicitly designed to re-fire
                # For now, let's assume one fire per unique rule_id
                # Or, more practically, rules add facts that prevent them from refiring if their action is complete.
                
                # Check rule's conditions
                if rule.evaluate(self.fact_base, self.current_stage):
                    # Check if rule has already fired and added its preventing fact
                    # This check should be *after* evaluate, so we don't block
                    # rules from evaluating just because a fact exists
                    # (e.g., a rule might require http_enum_complete NOT to exist)

                    # Better: design rules to add a fact that prevents *them* specifically from re-firing
                    # e.g., Rule_002 adds 'http_enum_complete_RULE_002', and Rule_002's conditions check for its absence.
                    # For simplicity now, let's just use the current system.

                    print(f"Rule Fired: {rule.rule_id} - {rule.name}")
                    rules_fired_in_pass += 1
                    target_ip = self.fact_base.get_fact('target_ip')
                    if not target_ip:
                        print("  Error: No target IP fact found. Cannot execute actions.")
                        continue

                    # Execute actions
                    for action in rule.actions:
                        self.execute_action(action, target_ip)
            
            # Check if any new facts were added in this pass
            facts_after_pass = self.fact_base.facts
            if facts_before_pass == facts_after_pass and rules_fired_in_pass == 0:
                print("No new rules fired in this pass. Stopping inference.")
                break # No changes, so no more rules will fire
            
            if pass_num == self.max_inference_passes:
                print(f"Reached maximum inference passes ({self.max_inference_passes}). Stopping.")

        print(f"\n--- Inference Complete ---")

        # Final recommendations or report generation
        if not self.fact_base.get_fact("final_report_ready"):
             print("No specific Nmap commands or actions recommended based on current rules and facts.")
        
        self._save_consolidated_data()

# --- Main Execution Logic ---

# Define the rules
# Rule structure: Rule(id, name, conditions, actions, stage)
# Conditions: [{"fact": "fact_name", "op": "operator", "value": "expected_value"}]
# Operators: "exists", "not_exists", "equals", "not_equals", "contains", "not_contains", "greater_than", "less_than"
# Actions: [{"type": "action_type", "param1": "value1"}]
# Action types: "add_fact", "run_nmap_scan", "print_message", "set_stage"

RULES = [
    # Stage: initial_discovery_complete
    # RULE_001: If host is down initially, try an aggressive ping scan.
    Rule(
        rule_id="RULE_001_HOST_DOWN_AGGRESSIVE_PING",
        name="If host is down initially, try an aggressive ping scan.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "host_is_up", "op": "equals", "value": False},
            {"fact": "aggressive_ping_performed", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-Pn -sV -O -sC --min-rtt-timeout 100ms --max-rtt-timeout 500ms --initial-rtt-timeout 100ms"},
            {"type": "add_fact", "fact": "aggressive_ping_performed", "value": True},
            {"type": "print_message", "message": "Host appeared down. Attempting aggressive ping scan."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_005: If OS detection was not precise, try a more aggressive OS scan.
    Rule(
        rule_id="RULE_005_OS_DETECTION_ENHANCEMENT",
        name="If OS detection was not precise, try a more aggressive OS scan.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "os_detected", "op": "equals", "value": True},
            {"fact": "os_detection_low_accuracy", "op": "equals", "value": True},
            {"fact": "os_detection_enhanced", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-O --osscan-limit --max-os-tries 5 -sV"},
            {"type": "add_fact", "fact": "os_detection_enhanced", "value": True},
            {"type": "print_message", "message": "Attempting more aggressive OS detection."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_002: If HTTP/HTTPS services are found, perform HTTP enumeration with scripts.
    Rule(
        rule_id="RULE_002_SERVICE_ENUM_HTTP_80_443",
        name="If HTTP/HTTPS services are found, perform HTTP enumeration with scripts.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "http_service_open", "op": "exists"},
            {"fact": "http_enum_complete", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            # Note: Nmap scripts like http-enum, http-title, http-methods can be used.
            # We're specifically targeting common HTTP/HTTPS ports for this example.
            # This Nmap command needs to be dynamically generated for the specific open HTTP/HTTPS ports.
            # For simplicity, let's assume we run it against all common web ports or refine later.
            {"type": "run_nmap_scan", "nmap_args": "-p80,443,8000,8080,8443,8008 --script http-enum,http-title,http-methods,http-headers -sV"},
            {"type": "add_fact", "fact": "http_enum_complete", "value": True},
            {"type": "print_message", "message": "Performing HTTP enumeration on common web ports."}
        ],
        stage="initial_discovery_complete" # Can fire after initial scan, or after OS enhancement
    ),
    # RULE_003: If FTP service is found, attempt anonymous login check.
    Rule(
        rule_id="RULE_003_SERVICE_ENUM_FTP_ANON",
        name="If FTP service is found, attempt anonymous login check.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "ftp_service_open", "op": "exists"},
            {"fact": "ftp_anon_checked", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-p21 --script ftp-anon -sV"},
            {"type": "add_fact", "fact": "ftp_anon_checked", "value": True},
            {"type": "print_message", "message": "Checking FTP for anonymous login."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_004: If SMB service is found, perform SMB enumeration and vulnerability checks.
    Rule(
        rule_id="RULE_004_SERVICE_ENUM_SMB_VULN",
        name="If SMB service is found, perform SMB enumeration and vulnerability checks.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "smb_service_open", "op": "exists"},
            {"fact": "smb_enum_complete", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-p445 --script smb-enum-shares,smb-enum-users,smb-vuln-ms17-010,smb-vuln-cve-2017-7494 -sV"},
            {"type": "add_fact", "fact": "smb_enum_complete", "value": True},
            {"type": "print_message", "message": "Performing SMB enumeration and vulnerability checks."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_006: If HTTP enumeration is complete, look for common HTTP CVEs based on product/version.
    Rule(
        rule_id="RULE_006_VULN_SCAN_HTTP_COMMON_CVEs",
        name="If HTTP enumeration is complete, look for common HTTP CVEs based on product/version.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"}, # Can fire after HTTP enum
            {"fact": "http_enum_complete", "op": "exists"},
            {"fact": "http_vuln_scanned", "op": "not_exists"}, # Prevent re-firing
            # Condition to check if 'product' or 'version' facts for HTTP services exist
            {"fact": "service_product_80_tcp", "op": "exists", "OR": [ # Example for specific ports
                {"fact": "service_product_443_tcp", "op": "exists"},
                {"fact": "service_version_80_tcp", "op": "exists"},
                {"fact": "service_version_443_tcp", "op": "exists"},
            ]}
            # This OR logic is not directly supported by the current evaluate logic.
            # For a more robust solution, the evaluate method would need to handle nested conditions.
            # For now, we'll simplify and just check if http_enum is complete and rely on script behavior.
        ],
        actions=[
            # This Nmap command runs various HTTP vulnerability scripts.
            {"type": "run_nmap_scan", "nmap_args": "-p80,443,8000,8080,8443 --script http-vuln*,http-sql-injection,http-xss-fuzzer -sV"},
            {"type": "add_fact", "fact": "http_vuln_scanned", "value": True},
            {"type": "print_message", "message": "Running common HTTP vulnerability scripts."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_007: If MySQL service is found, attempt common enumeration and weak creds.
    Rule(
        rule_id="RULE_007_SERVICE_ENUM_MYSQL",
        name="If MySQL service is found, attempt common enumeration and weak creds.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "mysql_service_open", "op": "exists"},
            {"fact": "mysql_enum_complete", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-p3306 --script mysql-enum,mysql-brute,mysql-info -sV"},
            {"type": "add_fact", "fact": "mysql_enum_complete", "value": True},
            {"type": "print_message", "message": "Performing MySQL enumeration and weak credential checks."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_008: If MS-SQL service is found, attempt common enumeration and weak creds.
    Rule(
        rule_id="RULE_008_SERVICE_ENUM_MSSQL",
        name="If MS-SQL service is found, attempt common enumeration and weak creds.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "mssql_service_open", "op": "exists"},
            {"fact": "mssql_enum_complete", "op": "not_exists"} # Prevent re-firing
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-p1433 --script ms-sql-info,ms-sql-enum,ms-sql-brute -sV"},
            {"type": "add_fact", "fact": "mssql_enum_complete", "value": True},
            {"type": "print_message", "message": "Performing MS-SQL enumeration and weak credential checks."}
        ],
        stage="initial_discovery_complete"
    ),
    # RULE_009: Final comprehensive aggressive scan if not performed and certain enumerations completed.
    Rule(
        rule_id="RULE_009_AGGRESSIVE_FINAL_SCAN",
        name="Final comprehensive aggressive scan if not performed and certain enumerations completed.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"},
            {"fact": "aggressive_scan_performed", "op": "not_exists"}, # Prevent re-firing
            # Only run this if some initial enumeration has happened or host is definitely up
            {"fact": "host_is_up", "op": "equals", "value": True},
            {"fact": "os_detection_enhanced", "op": "exists", "OR": [ # Ensure OS or some service enumeration has occurred
                {"fact": "http_enum_complete", "op": "exists"},
                {"fact": "ftp_anon_checked", "op": "exists"},
                {"fact": "smb_enum_complete", "op": "exists"}
            ]}
            # This OR logic is not directly supported by the current evaluate logic for single conditions.
            # It implies a complex 'AND' of 'host_is_up' and ('os_detection_enhanced' OR 'http_enum_complete' OR 'ftp_anon_checked' OR 'smb_enum_complete')
            # For this to work, the 'evaluate' method needs to be enhanced to support nested boolean logic.
            # As is, it will only check the first "OR" condition effectively unless the OR is explicitly implemented.
            # For now, simplifying condition to just "host_is_up" and "aggressive_scan_performed: not_exists" to allow it to fire as a general "final" scan.
        ],
        actions=[
            {"type": "run_nmap_scan", "nmap_args": "-A -sC -sV --script vuln"}, # -A is aggressive, -sC default scripts, -sV version, --script vuln for vulnerabilities
            {"type": "add_fact", "fact": "aggressive_scan_performed", "value": True},
            {"type": "print_message", "message": "Performing final aggressive scan with vulnerability scripts."}
        ],
        stage="initial_discovery_complete" # Can fire later in the process
    ),
    # RULE_010: Generate final report once all major scans are complete.
    Rule(
        rule_id="RULE_010_FINAL_REPORT",
        name="Generate final report once all major scans are complete.",
        conditions=[
            {"fact": "scan_stage", "op": "equals", "value": "initial_discovery_complete"}, # Still in this stage, but late
            {"fact": "final_report_ready", "op": "not_exists"}, # Prevent re-firing
            {"fact": "host_is_up", "op": "equals", "value": True}, # Only if host is up
            {"fact": "os_detected", "op": "equals", "value": True}, # Only if OS detection tried
            # Require at least some enumeration or an aggressive scan has been attempted
            {"fact": "aggressive_scan_performed", "op": "exists", "OR": [
                {"fact": "http_enum_complete", "op": "exists"},
                {"fact": "ftp_anon_checked", "op": "exists"},
                {"fact": "smb_enum_complete", "op": "exists"},
                {"fact": "mysql_enum_complete", "op": "exists"},
                {"fact": "mssql_enum_complete", "op": "exists"}
            ]}
            # Again, complex OR logic is currently not supported in Rule.evaluate
            # For this rule to fire reliably as a "final" step, you might need to:
            # 1. Implement sophisticated boolean logic in evaluate().
            # 2. Or, change this rule's stage to a later one (e.g., "final_reporting_stage")
            #    and transition to it with another rule/action.
            # For now, it will fire if aggressive_scan_performed is true, OR if *any* of the subsequent facts are true
            # and it encounters them in the single condition check.
        ],
        actions=[
            {"type": "print_message", "message": "All major scans and enumerations attempted. Generating final report."},
            {"type": "add_fact", "fact": "final_report_ready", "value": True}
        ],
        stage="initial_discovery_complete"
    )
]

def main():
    target_ip = input("Enter target IP address: ").strip()
    if not target_ip:
        print("Error: No target IP provided. Exiting.")
        sys.exit(1)

    initial_scan_file_path = "output/initial_scan.xml"
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: Run initial Nmap scan via SUBSCAN.py
    print(f"[main.py] Running initial Nmap scan for {target_ip} using SUBSCAN.py...")
    try:
        # Use subprocess.run to execute SUBSCAN.py and pass the target_ip via stdin
        process = subprocess.run(
            [sys.executable, '/home/arunexploit/Penturion/AImodel/SUBSCAN.py'], # Use sys.executable to ensure correct python interpreter
            input=target_ip,
            capture_output=True,
            text=True,
            check=False # Do not raise an exception for non-zero exit codes here
        )
        print(f"SUBSCAN.py stdout:\n{process.stdout}")
        if process.stderr:
            print(f"SUBSCAN.py stderr:\n{process.stderr}")

        if process.returncode != 0:
            print(f"[main.py] Error: Initial SUBSCAN.py failed with exit code {process.returncode}.")
            # If SUBSCAN.py writes output to initial_scan.xml on success, copy it
            if os.path.exists("output/scanout.xml"):
                 os.rename("output/scanout.xml", initial_scan_file_path)
            sys.exit(1)
        
        # SUBSCAN.py now writes to output/scanout.xml, so we need to rename it for consistency
        # if not os.path.exists(initial_scan_file_path): # Only rename if initial_scan.xml doesn't exist yet
        if os.path.exists("output/scanout.xml"):
            # Ensure the file exists before attempting to move/rename
            os.rename("output/scanout.xml", initial_scan_file_path)
            print(f"[main.py] Initial scan output moved to {initial_scan_file_path}")
        else:
            print("[main.py] Error: SUBSCAN.py did not produce 'output/scanout.xml'. Cannot proceed.")
            sys.exit(1)

    except FileNotFoundError:
        print("[main.py] Error: SUBSCAN.py not found. Ensure it's in the same directory.")
        sys.exit(1)
    except Exception as e:
        print(f"[main.py] An unexpected error occurred while running SUBSCAN.py: {e}")
        sys.exit(1)

    # Step 2: Initialize Inference Engine with the initial scan data
    initial_nmap_data = None
    if os.path.exists(initial_scan_file_path):
        print(f"[main.py] Parsing initial Nmap XML from {initial_scan_file_path} for engine initialization...")
        initial_nmap_data = parse_nmap_xml_report(initial_scan_file_path, target_ip_hint=target_ip)
        
        if initial_nmap_data is None or not initial_nmap_data.get("nmaprun", {}).get("host"):
            print("[main.py] Warning: Initial Nmap XML parsing failed or returned no host data. Engine might start with limited facts.")
            # If parsing failed, ensure initial_nmap_data is an empty structure to avoid errors
            initial_nmap_data = {"nmaprun": {"host": {}}}
    else:
        print(f"[main.py] Error: Initial scan file '{initial_scan_file_path}' not found after SUBSCAN.py execution. Exiting.")
        sys.exit(1)

    engine = InferenceEngine(RULES, initial_nmap_data=initial_nmap_data)
    
    # After engine is initialized with initial scan data, consolidate it explicitly
    # This step might be redundant if consolidate_and_add_scan_data is called in init
    # for initial_nmap_data, but it ensures facts are properly parsed from the consolidated view.
    # The init already calls it, so this block can be simplified if the init handles it fully.
    if initial_nmap_data:
        try:
            # The init of InferenceEngine already calls consolidate_and_add_scan_data
            # if initial_nmap_data is provided. So, no need to re-call it here.
            pass
        except ET.ParseError as e:
            print(f"[main.py] Error parsing initial XML content for engine consolidation: {e}")
        except Exception as e:
            print(f"[main.py] An unexpected error occurred during XML to JSON conversion for consolidation: {e}")

    print("[main.py] Calling engine.run()...") # DEBUG - THIS IS THE KEY!
    engine.run() # Start the inference process

    print("[main.py] Engine.run() completed.") # DEBUG

    # Clean up the temporary initial scan file
    # if os.path.exists(initial_scan_file_path):
    #     os.remove(initial_scan_file_path)
    #     print(f"Cleaned up temporary initial scan file: {initial_scan_file_path}")

    print("\nProcess complete. Check output/result.json for consolidated data.")

if __name__ == "__main__":
    main()