# Version 3.2 - add penturion target ip in txt file  

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
    Defines a single rule with conditions and actions.
    """
    def __init__(self, rule_id, description, conditions, actions, priority=5, relevant_ports=None):
        self.rule_id = rule_id
        self.description = description
        self.conditions = conditions
        self.actions = actions
        self.priority = priority
        self.relevant_ports = relevant_ports if relevant_ports is not None else []
        self.fired = False # Tracks if the rule has fired in the current inference cycle

    def check_condition(self, fact_base, condition):
        """Helper to check a single condition."""
        op = condition["op"]
        fact_key = condition["fact"]
        target_value = condition.get("value")

        if op == "==":
            return fact_base.get_fact(fact_key) == target_value
        elif op == "!=":
            return fact_base.get_fact(fact_key) != target_value
        elif op == "exists":
            return fact_base.get_fact(fact_key) is not None
        elif op == "not_exists":
            return fact_base.get_fact(fact_key) is None
        elif op == "contains":
            return fact_base.fact_list_contains(fact_key, target_value)
        elif op == "is_not_empty":
            fact_value = fact_base.get_fact(fact_key)
            return isinstance(fact_value, (list, dict, str)) and bool(fact_value)
        elif op == "contains_any_of":
            fact_list = fact_base.get_fact(fact_key, [])
            return any(item in fact_list for item in target_value)
        elif op == "does_not_contain_all":
            fact_list = fact_base.get_fact(fact_key, [])
            return not all(item in fact_list for item in target_value)
        return False

    def evaluate(self, fact_base):
        """Evaluates the rule's conditions against the current FactBase."""
        # Conditions are implicitly ANDed across different 'or_group's and no_group_conditions.
        # Conditions within the same 'or_group' are ORed.

        or_groups = {} # Stores conditions grouped by 'or_group' name
        no_group_conditions = [] # Stores conditions without an 'or_group'

        for condition in self.conditions:
            or_group_name = condition.get("or_group")
            if or_group_name:
                if or_group_name not in or_groups:
                    or_groups[or_group_name] = []
                or_groups[or_group_name].append(condition)
            else:
                no_group_conditions.append(condition)

        # Evaluate no-group conditions (all must be true)
        for condition in no_group_conditions:
            if not self.check_condition(fact_base, condition):
                return False

        # Evaluate OR groups (at least one in each group must be true)
        for group_name, conditions_in_group in or_groups.items():
            group_met = False
            for condition in conditions_in_group:
                if self.check_condition(fact_base, condition):
                    group_met = True
                    break
            if not group_met: # If no condition in an OR group was met, the rule fails
                return False

        return True

# --- InferenceEngine Class ---
class InferenceEngine:
    """
    The core inference engine that applies rules to facts to derive new facts
    or trigger actions. Manages consolidation of Nmap results.
    """
    def __init__(self, fact_base, rules, consolidated_output_file="consolidated_nmap_results.json"):
        print("[InferenceEngine] Initializing...") # DEBUG
        self.fact_base = fact_base
        self.rules = sorted(rules, key=lambda r: r.priority, reverse=True) # Higher priority first
        self.consolidated_output_file = consolidated_output_file
        self.consolidated_nmap_data = self._load_consolidated_data()
        print(f"[InferenceEngine] Loaded {len(self.consolidated_nmap_data)} hosts from consolidated data at init.") # DEBUG

    def _load_consolidated_data(self):
        """Loads existing consolidated Nmap data from JSON file."""
        print(f"[InferenceEngine] Attempting to load consolidated data from {self.consolidated_output_file}...") # DEBUG
        if os.path.exists(self.consolidated_output_file) and os.path.getsize(self.consolidated_output_file) > 0:
            try:
                with open(self.consolidated_output_file, 'r') as f:
                    loaded_data = json.load(f)
                    if 'nmaprun' in loaded_data and 'host' in loaded_data['nmaprun']:
                        hosts = loaded_data['nmaprun']['host']
                        # Ensure 'hosts' is always a list, even if only one host
                        print("[InferenceEngine] Successfully loaded existing consolidated data.") # DEBUG
                        return [hosts] if isinstance(hosts, dict) else hosts
                    else:
                        print(f"[InferenceEngine] Warning: Consolidated file '{self.consolidated_output_file}' has unexpected Nmaprun structure. Starting fresh.")
            except json.JSONDecodeError:
                print(f"[InferenceEngine] Warning: Consolidated file '{self.consolidated_output_file}' is not valid JSON. Starting fresh.")
            except Exception as e:
                print(f"[InferenceEngine] Error loading existing consolidated file '{self.consolidated_output_file}': {e}. Starting fresh.")
        print("[InferenceEngine] No valid consolidated data found or loaded.") # DEBUG
        return []

    def _save_consolidated_data(self):
        """Saves consolidated Nmap data to JSON file, ensuring it's wrapped in an nmaprun structure."""
        if not self.consolidated_nmap_data:
            print(f"No Nmap scan results to consolidate and save to {self.consolidated_output_file}.")
            return

        # Ensure consolidated_nmap_data is a list of host dictionaries
        hosts_to_save = self.consolidated_nmap_data if isinstance(self.consolidated_nmap_data, list) else [self.consolidated_nmap_data]

        nmap_run_structure = {
            "nmaprun": {
                "@scanner": "nmap",
                "@args": "Consolidated by Custom AI Model",
                "@start": int(time.time()),
                "host": hosts_to_save
            }
        }
        try:
            with open(self.consolidated_output_file, 'w') as f:
                json.dump(nmap_run_structure, f, indent=2)
            print(f"Consolidated Nmap data saved to {self.consolidated_output_file}")
        except Exception as e:
            print(f"Error saving consolidated data to {self.consolidated_output_file}: {e}")

    def _deep_merge_nmap_host_data(self, existing_data, new_data):
        """
        Deep merges new Nmap scan data (a single host entry) into existing consolidated data.
        Assumes both are Nmap JSON host data structures.
        This handles lists of dictionaries (e.g., ports, hostscript, addresses) by merging
        entries based on unique identifiers (portid/protocol, script id, address).
        """
        if not existing_data:
            return new_data

        merged_data = existing_data.copy()

        for key, new_value in new_data.items():
            if key in merged_data:
                existing_value = merged_data[key]
                
                # Special handling for 'ports' list
                if key == 'ports' and isinstance(existing_value, dict) and isinstance(new_value, dict):
                    existing_port_list = existing_value.get('port', [])
                    new_port_list = new_value.get('port', [])

                    # Ensure lists are actual lists, even if Nmap JSON output has single dict
                    if not isinstance(existing_port_list, list):
                        existing_port_list = [existing_port_list]
                    if not isinstance(new_port_list, list):
                        new_port_list = [new_port_list]

                    # Create a map for quick lookup by (portid, protocol)
                    existing_ports_map = {(p.get('portid'), p.get('protocol')): p for p in existing_port_list}

                    for new_port in new_port_list:
                        port_id = new_port.get('portid')
                        protocol = new_port.get('protocol')
                        if (port_id, protocol) in existing_ports_map:
                            # Update existing port entry
                            existing_ports_map[(port_id, protocol)].update(new_port)
                        else:
                            # Add new port entry
                            existing_ports_map[(port_id, protocol)] = new_port
                    
                    merged_data[key]['port'] = list(existing_ports_map.values())

                # Special handling for 'hostscript' list
                elif key == 'hostscript' and isinstance(existing_value, list) and isinstance(new_value, list):
                    existing_script_map = {s.get('id'): s for s in existing_value}
                    for new_script in new_value:
                        script_id = new_script.get('id')
                        if script_id in existing_script_map:
                            existing_script_map[script_id].update(new_script)
                        else:
                            existing_script_map[script_id] = new_script
                    merged_data[key] = list(existing_script_map.values())
                
                # Special handling for 'addresses' list
                elif key == 'addresses' and isinstance(existing_value, list) and isinstance(new_value, list):
                    existing_addr_map = {a.get('addr'): a for a in existing_value}
                    for new_addr in new_value:
                        addr = new_addr.get('addr')
                        if addr not in existing_addr_map: # Only add if address doesn't exist
                            existing_addr_map[addr] = new_addr
                    merged_data[key] = list(existing_addr_map.values())

                # Generic list merging (append unique items)
                elif isinstance(existing_value, list) and isinstance(new_value, list):
                    for item in new_value:
                        if item not in existing_value:
                            existing_value.append(item)
                # Recursive merge for nested dictionaries
                elif isinstance(existing_value, dict) and isinstance(new_value, dict):
                    merged_data[key] = self._deep_merge_nmap_host_data(existing_value, new_value)
                # Overwrite for other types (strings, numbers, booleans)
                else:
                    merged_data[key] = new_value
            else:
                # Add new key-value pairs
                merged_data[key] = new_value
        return merged_data

    def consolidate_and_add_scan_data(self, new_scan_nmap_run_data):
        print("[InferenceEngine] Consolidating new scan data...") # Add debug print
        # Merge new scan data into existing consolidated data
        if not self.consolidated_nmap_data:
            # If consolidated data is empty, initialize it with the new scan data
            # Ensure new_scan_nmap_run_data['nmaprun']['host'] is a list
            self.consolidated_nmap_data = new_scan_nmap_run_data['nmaprun']['host'] if isinstance(new_scan_nmap_run_data['nmaprun']['host'], list) else [new_scan_nmap_run_data['nmaprun']['host']]
            print(f"[InferenceEngine] Adding new host {self.consolidated_nmap_data[0].get('address', {}).get('addr')} to consolidated data.") # Debug print for new host
        else:
            # Deep merge existing and new host data
            for new_host_data in (new_scan_nmap_run_data['nmaprun']['host'] if isinstance(new_scan_nmap_run_data['nmaprun']['host'], list) else [new_scan_nmap_run_data['nmaprun']['host']]):
                new_host_ip = new_host_data.get('address', {}).get('addr')
                if new_host_ip:
                    found_existing = False
                    for i, existing_host_data in enumerate(self.consolidated_nmap_data):
                        if existing_host_data.get('address', {}).get('addr') == new_host_ip:
                            self.consolidated_nmap_data[i] = self._deep_merge_nmap_host_data(existing_host_data, new_host_data)
                            print(f"[InferenceEngine] Merging new scan data for {new_host_ip} into consolidated data.") # Debug print for merge
                            found_existing = True
                            break
                    if not found_existing:
                        self.consolidated_nmap_data.append(new_host_data)
                        print(f"[InferenceEngine] Adding new host {new_host_ip} to consolidated data.") # Debug print for new host

        # --- NEW CODE HERE ---
        # Preserve existing facts that are not derived from Nmap XML/JSON directly, like 'scan_stage'
        facts_to_preserve = {}
        if self.fact_base.get_fact('scan_stage'):
            facts_to_preserve['scan_stage'] = self.fact_base.get_fact('scan_stage')
        # Add other such facts here if they are introduced later (e.g., 'vulnerability_found', 'exploit_attempted')
        # --- END NEW CODE ---

        # After consolidation, re-parse facts from the updated consolidated data
        print("[InferenceEngine] Re-parsing facts from updated consolidated data for inference.") # DEBUG
        # Pass a pseudo nmaprun structure to parse_nmap_json_report
        self.fact_base = parse_nmap_json_report({"nmaprun": {"host": self.consolidated_nmap_data}})
        
        # --- NEW CODE HERE ---
        # Re-add preserved facts
        for key, value in facts_to_preserve.items():
            self.fact_base.add_fact(key, value)
        # --- END NEW CODE ---

        self._save_consolidated_data()

    def run(self):
        """Runs the inference process."""
        print("\n--- Starting Nmap Decision Inference ---") # This should be seen
        num_passes = 0
        MAX_PASSES = 10 # Safety break to prevent infinite loops

        while True:
            num_passes += 1
            print(f"\n--- Inference Pass {num_passes} (Current Stage: {self.fact_base.get_fact('scan_stage', 'unknown')})---")
            fired_a_rule_in_pass = False

            # Sort rules by priority (highest first) for each pass
            # This ensures high-priority rules (e.g., initial scans) run before lower ones
            for rule in self.rules:
                # Only evaluate rules that haven't fired yet OR are designed to fire multiple times if conditions reset
                # For simplicity, current rules only fire once per run() call (rule.fired flag)
                if not rule.fired and rule.evaluate(self.fact_base):
                    print(f"Rule Fired: {rule.rule_id} - {rule.description}")
                    rule.fired = True # Mark rule as fired for this run
                    fired_a_rule_in_pass = True

                    for action in rule.actions:
                        if action["type"] == "log":
                            log_message = action["message"].format(
                                **{f"fact:{k}": v for k, v in self.fact_base.facts.items()}
                            )
                            print(f"  Action: {log_message}")
                        elif action["type"] == "add_fact":
                            self.fact_base.add_fact(action["key"], action["value"])
                            print(f"  Action: Added fact '{action['key']}': {action['value']}")
                        elif action["type"] == "update_scan_stage":
                            self.fact_base.add_fact("scan_stage", action["value"])
                            print(f"  Action: Updated scan stage to '{action['value']}'")
                        elif action["type"] == "nmap_command":
                            command_template = action["command"]
                            
                            # Format command using facts from FactBase
                            # Special handling for list facts like 'open_tcp_ports' to join them with commas
                            formatted_command = command_template.format(
                                **{f"fact:{k}": ','.join(map(str, v)) if isinstance(v, list) else str(v) 
                                   for k, v in self.fact_base.facts.items()}
                            )
                            
                            print(f"  Action: Executing Nmap command for rule: {formatted_command}") # DEBUG
                            
                            temp_scan_file = "temp_scan_output.xml" # All rule-triggered scans output to XML
                            
                            current_target_ip = self.fact_base.get_fact('target_ip')
                            if current_target_ip:
                                # Construct the full Nmap command list
                                nmap_full_command_list = [NMAP_EXECUTABLE_PATH]
                                # Add arguments from the formatted command template
                                # This simple split assumes no complex quoted arguments. For production, shlex.split is better.
                                for arg_part in formatted_command.split():
                                    if arg_part.strip():
                                        nmap_full_command_list.append(arg_part)
                                
                                # Ensure -oX and output file are correctly placed
                                # We explicitly control output to XML for easier parsing
                                if "-oX" not in nmap_full_command_list:
                                    nmap_full_command_list.extend(["-oX", os.path.abspath(temp_scan_file)])
                                else: # If -oX was in template, ensure its value is our temp file
                                    idx = nmap_full_command_list.index("-oX")
                                    nmap_full_command_list[idx+1] = os.path.abspath(temp_scan_file)
                                
                                # Always append target IP last, as Nmap expects it
                                if current_target_ip not in nmap_full_command_list:
                                    nmap_full_command_list.append(current_target_ip)

                                print(f"  DEBUG: Actual Nmap command for rule: {' '.join(nmap_full_command_list)}")

                                try:
                                    rule_scan_process = subprocess.run(
                                        nmap_full_command_list,
                                        capture_output=True,
                                        text=True,
                                        check=False # Do not raise exception for non-zero exit codes
                                    )
                                    print(f"  Nmap Rule Scan stdout:\n{rule_scan_process.stdout}")
                                    if rule_scan_process.stderr:
                                        print(f"  Nmap Rule Scan stderr:\n{rule_scan_process.stderr}")

                                    time.sleep(0.5) # Give file system a moment

                                    if os.path.exists(temp_scan_file) and os.path.getsize(temp_scan_file) > 0:
                                        print(f"  Nmap rule scan completed. Output saved to {temp_scan_file}")
                                        
                                        # Parse the new scan data (which is XML) and convert to JSON for consolidation
                                        new_scan_data_json_format = {}
                                        try:
                                            xml_tree = ET.parse(temp_scan_file)
                                            root = xml_tree.getroot()
                                            # Convert relevant host data from XML to our internal JSON structure
                                            converted_host_data = []
                                            for host_elem in root.findall('host'):
                                                host_json = _convert_xml_host_to_json_dict(host_elem)
                                                if host_json:
                                                    converted_host_data.append(host_json)
                                            
                                            if converted_host_data:
                                                # Wrap in 'nmaprun' structure for consolidate_and_add_scan_data
                                                new_scan_data_json_format = {"nmaprun": {"host": converted_host_data}}
                                                self.consolidate_and_add_scan_data(new_scan_data_json_format)
                                            else:
                                                print("  Warning: No host data found in rule-triggered XML scan to convert for consolidation.")
                                            
                                        except ET.ParseError as e:
                                            print(f"  Warning: Temp scan file '{temp_scan_file}' is not valid XML. Skipping consolidation: {e}")
                                        except Exception as ex:
                                            print(f"  Error processing XML '{temp_scan_file}': {ex}")

                                        # Clean up temporary scan file
                                        if os.path.exists(temp_scan_file):
                                            os.remove(temp_scan_file)
                                            print(f"  Cleaned up temporary rule scan file: {temp_scan_file}")

                                    else:
                                        print(f"  Warning: Nmap rule scan output file '{temp_scan_file}' was not created or is empty.")

                                except FileNotFoundError:
                                    print(f"  Error: Nmap not found at '{NMAP_EXECUTABLE_PATH}'. Please ensure Nmap is installed and the path is correct.")
                                except Exception as e:
                                    print(f"  An unexpected error occurred during Nmap rule execution: {e}")
                            else:
                                print("  Warning: Target IP not found for rule-triggered Nmap command.")

            if not fired_a_rule_in_pass:
                print("No new rules fired in this pass. Stopping inference.")
                break # No rules fired, stop the loop
            
            if num_passes > MAX_PASSES:
                print(f"Max inference passes reached ({MAX_PASSES}). Stopping to prevent infinite loop.")
                break # Safety break

        print("\n--- Inference Complete ---")
        if self.fact_base.get_fact('final_report_ready'):
            print("Scan process indicates final report is ready.")
        else:
            print("No specific Nmap commands or actions recommended based on current rules and facts.")
        
        self._save_consolidated_data() # Save final consolidated data

# --- XML to JSON Conversion Helper (for Nmap XML output) ---
def _convert_xml_host_to_json_dict(host_elem):
    """
    Converts an Nmap XML <host> element into a simplified JSON dictionary structure
    consistent with what parse_nmap_json_report expects.
    This is necessary because Nmap's -oJ (JSON) output has inconsistencies
    (e.g., single item lists vs. actual lists) that XML parsing avoids.
    """
    host_json = {}

    # Status
    status_elem = host_elem.find('status')
    if status_elem is not None:
        host_json['status'] = {"state": status_elem.get('state'), "reason": status_elem.get('reason')}

    # Addresses
    host_json['addresses'] = []
    for addr_elem in host_elem.findall('address'):
        host_json['addresses'].append({
            "addr": addr_elem.get('addr'),
            "addrtype": addr_elem.get('addrtype'),
            "vendor": addr_elem.get('vendor')
        })
    
    # Hostnames
    hostnames_elem = host_elem.find('hostnames')
    if hostnames_elem is not None:
        host_json['hostnames'] = []
        for hostname_elem in hostnames_elem.findall('hostname'):
            host_json['hostnames'].append({
                "name": hostname_elem.get('name'),
                "type": hostname_elem.get('type')
            })

    # Ports
    ports_elem = host_elem.find('ports')
    if ports_elem is not None:
        host_json['ports'] = {'port': []} # Ensure 'port' is always a list for consistency
        for port_elem in ports_elem.findall('port'):
            port_info = {
                "portid": port_elem.get('portid'),
                "protocol": port_elem.get('protocol')
            }
            state_elem = port_elem.find('state')
            if state_elem:
                port_info['state'] = {"state": state_elem.get('state'), "reason": state_elem.get('reason')}
            service_elem = port_elem.find('service')
            if service_elem:
                service_dict = {
                    "name": service_elem.get('name'),
                    "product": service_elem.get('product'),
                    "version": service_elem.get('version'),
                    "extrainfo": service_elem.get('extrainfo'),
                    "method": service_elem.get('method'),
                    "conf": service_elem.get('conf') # Add confidence if available
                }
                port_info['service'] = {k: v for k, v in service_dict.items() if v is not None}
            host_json['ports']['port'].append(port_info)
    
    # OS Detection
    os_elem = host_elem.find('os')
    if os_elem is not None :
        os_matches = os_elem.findall('osmatch')
        if os_matches:
            host_json['os'] = {'osmatch': []}
            for os_match_elem in os_matches:
                os_match_dict = {
                    "name": os_match_elem.get('name'),
                    "accuracy": os_match_elem.get('accuracy'),
                    "osclass": []
                }
                for os_class_elem in os_match_elem.findall('osclass'):
                    os_class_dict = {
                        "type": os_class_elem.get('type'),
                        "vendor": os_class_elem.get('vendor'),
                        "osfamily": os_class_elem.get('osfamily'),
                        "osgen": os_class_elem.get('osgen'),
                        "accuracy": os_class_elem.get('accuracy')
                    }
                    cpe_elem = os_class_elem.find('cpe')
                    if cpe_elem is not None:
                        os_class_dict['cpe'] = cpe_elem.text
                    os_match_dict['osclass'].append(os_class_dict)
                host_json['os']['osmatch'].append(os_match_dict)
    
    # Hostscript results
    hostscript_elem = host_elem.find('hostscript')
    if hostscript_elem is not None:
        host_json['hostscript'] = []
        for script_elem in hostscript_elem.findall('script'):
            host_json['hostscript'].append({
                "id": script_elem.get('id'),
                "output": script_elem.get('output')
            })
            
    return host_json

# --- Fact Parsing from XML ---
def parse_nmap_xml_report(xml_raw_data, target_ip_hint=None):
    """
    Parses Nmap XML report data into a FactBase.
    Can be given a target_ip_hint to prioritize finding facts for a specific IP.
    """
    facts = FactBase()
    if not xml_raw_data:
        print("Warning: No XML data provided to parse_nmap_xml_report.")
        return facts
    try:
        root = ET.fromstring(xml_raw_data)
    except ET.ParseError:
        print("Warning: Invalid XML data provided to parse_nmap_xml_report. Could not parse.")
        return facts

    target_host_elem = None
    if target_ip_hint: # Try to find the specific host if a hint is provided
        for host_elem in root.findall('host'):
            for address_elem in host_elem.findall('address'):
                if address_elem.get('addrtype') == 'ipv4' and address_elem.get('addr') == target_ip_hint:
                    target_host_elem = host_elem
                    break
            if target_host_elem is not None:
                break
    
    # If no specific target_ip_hint host found, or no hint, just take the first host
    if target_host_elem is None:
        target_host_elem = root.find('host')

    if target_host_elem is not None:
        # IP Address
        for address_elem in target_host_elem.findall('address'):
            if address_elem.get('addrtype') == 'ipv4':
                facts.add_fact('target_ip', address_elem.get('addr'))
                break
        
        # Host State (up/down)
        status_elem = target_host_elem.find('status')
        if status_elem is not None:
            facts.add_fact('host_state', status_elem.get('state'))

        # Ports and Services
        open_tcp_ports = []
        open_udp_ports = []
        open_http_ports = []
        open_https_ports = []
        known_services = []

        ports_elem = target_host_elem.find('ports')
        if ports_elem is not None:
            for port_elem in ports_elem.findall('port'):
                state_elem = port_elem.find('state')
                if state_elem is not None and state_elem.get('state') == 'open':
                    port_id = int(port_elem.get('portid'))
                    protocol = port_elem.get('protocol')
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name') if service_elem is not None else None
                    service_product = service_elem.get('product') if service_elem is not None else None
                    service_version = service_elem.get('version') if service_elem is not None else None
                    
                    if protocol == 'tcp':
                        open_tcp_ports.append(port_id)
                        # Heuristic for HTTP/HTTPS ports based on service name or common ports
                        if service_name and ('http' in service_name or 'ssl/http' in service_name):
                            open_http_ports.append(port_id)
                        if 'ssl/https' in service_name or port_id == 443: # Explicitly add 443 to https
                             open_https_ports.append(port_id)
                        # Add other common services for rule triggering
                        if service_name in ["ftp", "ssh", "mysql", "microsoft-ds", "msrpc", "rdp"]:
                            facts.add_fact(f"service_open_{service_name}", True)

                    elif protocol == 'udp':
                        open_udp_ports.append(port_id)
                    
                    if service_name is not None:
                        known_services.append(service_name)
                    if service_product is not None:
                        facts.add_fact(f"service_product_{port_id}", service_product)
                    if service_version is not None:
                        facts.add_fact(f"service_version_{port_id}", service_version)
        
        facts.add_fact('open_tcp_ports', sorted(list(set(open_tcp_ports))))
        facts.add_fact('open_udp_ports', sorted(list(set(open_udp_ports))))
        facts.add_fact('open_http_ports', sorted(list(set(open_http_ports))))
        facts.add_fact('open_https_ports', sorted(list(set(open_https_ports))))
        facts.add_fact('known_services', sorted(list(set(known_services))))

        # OS Detection
        os_elem = target_host_elem.find('os')
        if os_elem is not None and os_elem.find('osmatch') is not None:
            os_matches = os_elem.findall('osmatch')
            if os_matches:
                best_os_match = os_matches[0] # Take the highest accuracy match
                facts.add_fact('os_name', best_os_match.get('name'))
                facts.add_fact('os_accuracy', int(best_os_match.get('accuracy'))) # Convert to int
                
                os_cpes = []
                for os_class in best_os_match.findall('osclass'):
                    cpe_elem = os_class.find('cpe')
                    if cpe_elem is not None:
                        os_cpes.append(cpe_elem.text)
                if os_cpes:
                    facts.add_fact('os_cpes', sorted(list(set(os_cpes))))
        
        # Host Script Results (NSE)
        hostscript_elem = target_host_elem.find('hostscript')
        if hostscript_elem is not None:
            script_results = {}
            for script_elem in hostscript_elem.findall('script'):
                script_id = script_elem.get('id')
                output = script_elem.get('output')
                if script_id and output:
                    script_results[script_id] = output
                    facts.add_fact(f"script_output_{script_id}", output) # Add individual script output
            if script_results:
                facts.add_fact('host_script_results', script_results) # Add all script results as a dict

    return facts

# --- Fact Parsing from JSON ---
def parse_nmap_json_report(nmap_raw_data, target_ip_hint=None):
    """
    Parses Nmap JSON-like report data (which comes from our internal consolidated structure)
    into a FactBase. Can be given a target_ip_hint.
    """
    facts = FactBase()
    if not nmap_raw_data:
        print("Warning: No JSON data provided to parse_nmap_json_report.")
        return facts
    
    hosts_data = []
    # Expects nmap_raw_data to be like {"nmaprun": {"host": [...]}} or just [...]
    if isinstance(nmap_raw_data, dict) and 'nmaprun' in nmap_raw_data and 'host' in nmap_raw_data['nmaprun']:
        hosts_data = nmap_raw_data['nmaprun']['host']
        if not isinstance(hosts_data, list): # Ensure hosts_data is always a list
            hosts_data = [hosts_data]
    elif isinstance(nmap_raw_data, list): # Directly a list of host entries
        hosts_data = nmap_raw_data
    else:
        print("Warning: Unexpected Nmap report data format for JSON parsing. Cannot parse facts.")
        return facts

    target_host_entry = None
    if target_ip_hint: # Try to find the specific host if a hint is provided
        for host_entry in hosts_data:
            for addr_info in host_entry.get('addresses', []):
                if addr_info.get('addrtype') == 'ipv4' and addr_info.get('addr') == target_ip_hint:
                    target_host_entry = host_entry
                    break
            if target_host_entry:
                break
    
    # If no specific target_ip_hint host found, or no hint, just take the first host
    if not target_host_entry and hosts_data:
        target_host_entry = hosts_data[0]

    if target_host_entry:
        # IP Address
        for addr_info in target_host_entry.get('addresses', []):
            if addr_info.get('addrtype') == 'ipv4':
                facts.add_fact('target_ip', addr_info.get('addr'))
                break
        
        # Host State
        if 'status' in target_host_entry:
            facts.add_fact('host_state', target_host_entry['status'].get('state'))

        # Ports and Services
        open_tcp_ports = []
        open_udp_ports = []
        open_http_ports = []
        open_https_ports = []
        known_services = []

        if 'ports' in target_host_entry and 'port' in target_host_entry['ports']:
            ports_list = target_host_entry['ports']['port']
            if not isinstance(ports_list, list): # Handle single port as a dict, not list
                ports_list = [ports_list]
            
            for port_info in ports_list:
                if port_info.get('state', {}).get('state') == 'open':
                    port_id = int(port_info.get('portid'))
                    protocol = port_info.get('protocol')
                    service_name = port_info.get('service', {}).get('name')
                    service_product = port_info.get('service', {}).get('product')
                    service_version = port_info.get('service', {}).get('version')
                    
                    if protocol == 'tcp':
                        open_tcp_ports.append(port_id)
                        if service_name and ('http' in service_name or 'ssl/http' in service_name):
                            open_http_ports.append(port_id)
                        if 'ssl/https' in service_name or port_id == 443:
                             open_https_ports.append(port_id)
                        if service_name in ["ftp", "ssh", "mysql", "microsoft-ds", "msrpc", "rdp"]:
                            facts.add_fact(f"service_open_{service_name}", True)

                    elif protocol == 'udp':
                        open_udp_ports.append(port_id)
                    
                    if service_name:
                        known_services.append(service_name)
                    if service_product:
                        facts.add_fact(f"service_product_{port_id}", service_product)
                    if service_version:
                        facts.add_fact(f"service_version_{port_id}", service_version)
        
        facts.add_fact('open_tcp_ports', sorted(list(set(open_tcp_ports))))
        facts.add_fact('open_udp_ports', sorted(list(set(open_udp_ports))))
        facts.add_fact('open_http_ports', sorted(list(set(open_http_ports))))
        facts.add_fact('open_https_ports', sorted(list(set(open_https_ports))))
        facts.add_fact('known_services', sorted(list(set(known_services))))

        # OS Detection
        if 'os' in target_host_entry and 'osmatch' in target_host_entry['os']:
            os_matches = target_host_entry['os']['osmatch']
            if isinstance(os_matches, dict): # Handle single osmatch as a dict
                os_matches = [os_matches]
            if os_matches:
                best_os_match = os_matches[0]
                facts.add_fact('os_name', best_os_match.get('name'))
                facts.add_fact('os_accuracy', int(best_os_match.get('accuracy')))
                
                os_cpes = []
                if 'osclass' in best_os_match:
                    os_classes = best_os_match['osclass']
                    if isinstance(os_classes, dict):
                        os_classes = [os_classes]
                    for os_class in os_classes:
                        if 'cpe' in os_class:
                            if isinstance(os_class['cpe'], list):
                                os_cpes.extend(os_class['cpe'])
                            else:
                                os_cpes.append(os_class['cpe'])
                if os_cpes:
                    facts.add_fact('os_cpes', sorted(list(set(os_cpes))))
        
        # Host Script Results
        if 'hostscript' in target_host_entry:
            script_results = {}
            hostscript_list = target_host_entry['hostscript']
            if not isinstance(hostscript_list, list):
                hostscript_list = [hostscript_list]
            for script_output in hostscript_list:
                script_id = script_output.get('id')
                output = script_output.get('output')
                if script_id and output:
                    script_results[script_id] = output
                    facts.add_fact(f"script_output_{script_id}", output)
            if script_results:
                facts.add_fact('host_script_results', script_results)

    return facts

# --- Define Nmap Rules ---
def define_nmap_rules(target_ip, nmap_executable_path):
    """
    Defines the set of Nmap scanning and enumeration rules based on discovered facts.
    """
    rules = [
        # Priority 10: Initial Scan (should be handled by main, but included for completeness)
        Rule(
            rule_id="RULE_001_INITIAL_SCAN_REQUIRED",
            description="Trigger initial Nmap scan if no previous scan data is found.",
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_scan_pending"},
                {"fact": "target_ip", "op": "exists"}
            ],
            actions=[
                {"type": "log", "message": "Initial scan is pending, beginning discovery for {fact:target_ip}."},
                {"type": "update_scan_stage", "value": "initial_discovery_complete"}
                # No Nmap command here as SUBSCAN.py handles initial discovery
            ],
            priority=10
        ),
        
        # Priority 9: HTTP/HTTPS Enumeration (high priority for web services)
        Rule(
            rule_id="RULE_002_SERVICE_ENUM_HTTP_80_443",
            description="Deep scan HTTP/HTTPS services on standard or discovered ports.",
            relevant_ports=[80, 443],
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "http_enum_complete", "op": "not_exists"}, # Only fire once
                {"fact": "open_http_ports", "op": "is_not_empty", "or_group": "http_ports_exist"},
                {"fact": "open_https_ports", "op": "is_not_empty", "or_group": "http_ports_exist"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-p {{fact:open_http_ports}},{{fact:open_https_ports}} --script http-enum,http-headers,http-methods,ssl-enum-ciphers,tls-enum-ciphers,http-title -sV"},
                {"type": "add_fact", "key": "http_enum_complete", "value": True},
                {"type": "log", "message": "Initiating deep HTTP/HTTPS enumeration on ports: {fact:open_http_ports}, {fact:open_https_ports}."}
            ],
            priority=9
        ),

        # Priority 8: Specific Service Checks (FTP, MySQL)
        Rule(
            rule_id="RULE_003_SERVICE_ENUM_FTP_21",
            description="Perform anonymous login check on FTP.",
            relevant_ports=[21],
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "ftp_anon_checked", "op": "not_exists"}, # Only fire once
                {"fact": "open_tcp_ports", "op": "contains", "value": 21},
                {"fact": "service_product_21", "op": "fact_string_contains", "value": "Microsoft ftpd", "or_group": "ftp_identified"} # Check if it's Microsoft FTP or just open
            ],
            actions=[
                {"type": "nmap_command", "command": f"-p 21 --script ftp-anon -sV"},
                {"type": "add_fact", "key": "ftp_anon_checked", "value": True},
                {"type": "log", "message": "Checking FTP for anonymous login on port 21."}
            ],
            priority=8
        ),
        Rule(
            rule_id="RULE_004_SERVICE_ENUM_MYSQL_3306",
            description="Detect MySQL version and check for basic information.",
            relevant_ports=[3306],
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "mysql_enum_complete", "op": "not_exists"}, # Only fire once
                {"fact": "open_tcp_ports", "op": "contains", "value": 3306},
                {"fact": "service_open_mysql", "op": "==", "value": True, "or_group": "mysql_identified"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-p 3306 --script mysql-info,mysql-databases,mysql-users -sV"},
                {"type": "add_fact", "key": "mysql_enum_complete", "value": True},
                {"type": "log", "message": "Initiating MySQL enumeration on port 3306."}
            ],
            priority=8
        ),

        # Priority 7: OS Detection Enhancement
        Rule(
            rule_id="RULE_005_OS_DETECTION_ENHANCEMENT",
            description="If OS detection was not precise, try a more aggressive OS scan.",
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "os_detection_enhanced", "op": "not_exists"}, # Only fire once
                {"fact": "os_accuracy", "op": "!=", "value": 100, "or_group": "os_accuracy_low"}, # Nmap returns 100 for exact match
                {"fact": "os_name", "op": "not_exists", "or_group": "os_accuracy_low"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-O --osscan-limit --max-os-tries 5 -sV"}, # -sV to ensure service info is still collected
                {"type": "add_fact", "key": "os_detection_enhanced", "value": True},
                {"type": "log", "message": "Attempting more aggressive OS detection."}
            ],
            priority=7
        ),

        # Priority 6: Vulnerability Scanning (Common CVEs)
        Rule(
            rule_id="RULE_006_VULN_SCAN_HTTP_COMMON_CVEs",
            description="Run common HTTP vulnerability scripts if HTTP ports are open.",
            relevant_ports=[80, 443],
            conditions=[
                {"fact": "http_enum_complete", "op": "==", "value": True}, # Ensure enumeration happened first
                {"fact": "http_vuln_scanned", "op": "not_exists"}, # Only fire once
                {"fact": "open_http_ports", "op": "is_not_empty", "or_group": "http_ports_for_vuln"},
                {"fact": "open_https_ports", "op": "is_not_empty", "or_group": "http_ports_for_vuln"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-p {{fact:open_http_ports}},{{fact:open_https_ports}} --script http-vuln-* -sV"},
                {"type": "add_fact", "key": "http_vuln_scanned", "value": True},
                {"type": "log", "message": "Running common HTTP vulnerability checks."}
            ],
            priority=6
        ),
        
        Rule(
            rule_id="RULE_006_VULN_SCAN_SMB",
            description="Scan for common SMB vulnerabilities if SMB is detected.",
            relevant_ports=[445, 139],
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "smb_vuln_scanned", "op": "not_exists"},
                {"fact": "open_tcp_ports", "op": "contains", "value": 445, "or_group": "smb_ports_open"},
                {"fact": "open_tcp_ports", "op": "contains", "value": 139, "or_group": "smb_ports_open"},
                {"fact": "service_open_microsoft-ds", "op": "==", "value": True, "or_group": "smb_service_identified"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-p 139,445 --script smb-enum-shares,smb-vuln-ms17-010,smb-security-mode -sV"},
                {"type": "add_fact", "key": "smb_vuln_scanned", "value": True},
                {"type": "log", "message": "Running SMB enumeration and vulnerability checks."}
            ],
            priority=6
        ),

        # Priority 5: UDP Scan & Aggressive General Scan
        Rule(
            rule_id="RULE_007_UDP_SERVICE_SCAN",
            description="Perform a more thorough UDP scan if UDP ports were found.",
            relevant_ports=["udp"],
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "udp_scan_enhanced", "op": "not_exists"}, # Only fire once
                {"fact": "open_udp_ports", "op": "is_not_empty"}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-sU -p {{fact:open_udp_ports}} --version-intensity 9 -sV"},
                {"type": "add_fact", "key": "udp_scan_enhanced", "value": True},
                {"type": "log", "message": "Conducting enhanced UDP service detection on ports: {fact:open_udp_ports}."}
            ],
            priority=5
        ),
        Rule(
            rule_id="RULE_008_AGGRESSIVE_GENERAL_SCAN",
            description="Perform an aggressive scan if specific interesting services are found and not already done.",
            relevant_ports="Host",
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"},
                {"fact": "aggressive_scan_performed", "op": "not_exists"}, # Only fire once
                {"fact": "known_services", "op": "contains_any_of", "value": ["ssh", "smb", "ms-sql", "rdp", "vnc", "postgresql", "ftp", "http", "https", "mysql"]}
            ],
            actions=[
                {"type": "nmap_command", "command": f"-A -sC -sV"}, # -A includes OS detection, version detection, script scanning, and traceroute
                {"type": "add_fact", "key": "aggressive_scan_performed", "value": True},
                {"type": "log", "message": "Performing aggressive scan due to interesting services found. This includes OS detection, service enumeration, and default scripts."}
            ],
            priority=3 # Lower priority, as it's a catch-all if more specific rules didn't cover everything.
        ),

        # Priority 1: Final Report Generation (lowest priority, fires when other scans are likely complete)
        Rule(
            rule_id="RULE_009_FINAL_REPORT_GENERATION",
            description="Signal completion and readiness for final report (implies no more active scans).",
            conditions=[
                {"fact": "scan_stage", "op": "==", "value": "initial_discovery_complete"}, # Must have completed initial discovery
                {"fact": "final_report_ready", "op": "not_exists"}, # Only fire once
                # These conditions are ORed within a group. If ANY of these are true, AND there are no further
                # specific scans remaining to be done (which is implicitly handled by rules not firing),
                # then this rule will eventually fire. This is a heuristic for "enough information".
                # A more robust system would track active scan tasks or explicit "all_subtasks_complete" facts.
                {"fact": "http_enum_complete", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "ftp_anon_checked", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "mysql_enum_complete", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "os_detection_enhanced", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "udp_scan_enhanced", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "aggressive_scan_performed", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "smb_vuln_scanned", "op": "==", "value": True, "or_group": "all_enum_checks_done"},
                {"fact": "open_tcp_ports", "op": "is_not_empty", "or_group": "basic_discovery_done"} # At least something was found
            ],
            actions=[
                {"type": "update_scan_stage", "value": "scan_complete"},
                {"type": "add_fact", "key": "final_report_ready", "value": True},
                {"type": "log", "message": "All relevant scans likely completed. Final report can be generated. Review result.json."}
            ],
            priority=1
        )
    ]
    return rules

# --- Main Execution Block ---

if __name__ == "__main__":
    NMAP_EXECUTABLE_PATH = "/usr/bin/nmap" # Ensure this path is correct for your system

    initial_scan_file_path = "output/scanout.xml" # SUBSCAN.py now outputs XML
    consolidated_output_file_path = "output/result.json"

    print("[main.py] Starting main execution block.") # DEBUG

    initial_facts = FactBase()
    initial_target_ip = None
    initial_scan_xml_content = None # To hold content of initial scanout.xml if it occurs

    # Attempt to load existing consolidated data first
    existing_consolidated_nmap_data = None
    if os.path.exists(consolidated_output_file_path) and os.path.getsize(consolidated_output_file_path) > 0:
        try:
            with open(consolidated_output_file_path, 'r') as f:
                loaded_data = json.load(f)
                if 'nmaprun' in loaded_data and 'host' in loaded_data['nmaprun']:
                    existing_consolidated_nmap_data = loaded_data['nmaprun']['host']
                    print(f"[main.py] Loaded existing consolidated data from {consolidated_output_file_path}.")
                    # Parse facts from the existing consolidated data
                    initial_facts = parse_nmap_json_report({"nmaprun": {"host": existing_consolidated_nmap_data}})
                    initial_facts.add_fact('scan_stage', 'initial_discovery_complete') # Assume initial discovery done if data exists
                    initial_target_ip = initial_facts.get_fact('target_ip')
                    
                    if not initial_target_ip:
                        print("[main.py] Error: Could not determine target IP from existing consolidated data. Exiting.")
                        sys.exit(1)
                    print(f"[main.py] Target IP from consolidated data: {initial_target_ip}")
                    with open("output/penturion_target.txt", "w") as f:
                        f.write(initial_target_ip)
                        print(f"[main.py] Target IP written to penturion_target.txt: {initial_target_ip}")
                else:
                    print(f"[main.py] Warning: Consolidated file '{consolidated_output_file_path}' has unexpected Nmaprun structure. Will proceed with initial scan.")
        except json.JSONDecodeError:
            print(f"[main.py] Warning: Existing consolidated file '{consolidated_output_file_path}' is not valid JSON. Will proceed with initial scan.")
        except Exception as e:
            print(f"[main.py] Error loading existing consolidated file '{consolidated_output_file_path}': {e}. Will proceed with initial scan.")
    
    # If no valid consolidated data was loaded, perform an initial scan
    if not initial_facts.get_fact('target_ip'): # This means existing_consolidated_nmap_data was not successfully loaded
        print("[main.py] No existing consolidated data or target IP found. Initial scan required.")
        initial_target_ip = input("Enter target IP or URL for the initial scan: ").strip()
        
        if not initial_target_ip:
            print("[main.py] No target IP or URL provided. Exiting.")
            sys.exit(1)
        with open("output/penturion_target.txt", "w") as f:
             f.write(initial_target_ip)
             print(f"[main.py] Target IP written to /tmp/penturion_target.txt: {initial_target_ip}")
        initial_facts.add_fact('target_ip', initial_target_ip)
        initial_facts.add_fact('scan_stage', 'initial_scan_pending')

        print(f"[main.py] Running initial scan using SUBSCAN.py against {initial_target_ip}...")
        
        # Use subprocess to run SUBSCAN.py
        # Pass target IP via stdin
        subscan_process = subprocess.run(
            ["python3", os.path.join(os.path.dirname(__file__), "SUBSCAN.py")],
            input=initial_target_ip,
            text=True,
            capture_output=True,
            check=False # Do not raise an exception for non-zero exit codes
        )
        print("SUBSCAN.py stdout:\n" + subscan_process.stdout)
        print("SUBSCAN.py stderr:\n" + subscan_process.stderr)

        if subscan_process.returncode != 0:
            print(f"[main.py] Warning: SUBSCAN.py exited with code {subscan_process.returncode}. Please check its output for errors.")
            # If SUBSCAN.py failed to produce the file, we can't proceed
            if not os.path.exists(initial_scan_file_path) or os.path.getsize(initial_scan_file_path) == 0:
                print(f"[main.py] Error: SUBSCAN.py failed to create a valid '{initial_scan_file_path}'. Exiting.")
                sys.exit(1)
        
        try:
            with open(initial_scan_file_path, 'r') as f:
                initial_scan_xml_content = f.read()
            print(f"[main.py] Successfully loaded initial scan data from {initial_scan_file_path}.")
        except FileNotFoundError:
            print(f"[main.py] Error: Initial scan report file '{initial_scan_file_path}' not found after SUBSCAN.py execution. Exiting.")
            sys.exit(1)
        except Exception as e:
            print(f"[main.py] An unexpected error occurred while reading {initial_scan_file_path}: {e}. Exiting.")
            sys.exit(1)
        
        # Parse facts from the newly generated XML report
        # Pass the target_ip_hint to ensure we parse the correct host if multiple are in the XML
        initial_facts = parse_nmap_xml_report(initial_scan_xml_content, target_ip_hint=initial_target_ip)
        
        # Ensure target_ip and scan_stage are correctly set even if parsing missed them
        if not initial_facts.get_fact('target_ip'):
            initial_facts.add_fact('target_ip', initial_target_ip)
        if not initial_facts.get_fact('scan_stage'):
             initial_facts.add_fact('scan_stage', 'initial_discovery_complete') # Now that initial scan is done

    target_ip = initial_facts.get_fact('target_ip') # Final check for target IP
    if not target_ip:
        print("[main.py] Error: Target IP is still not set after all attempts. Exiting.")
        sys.exit(1)
    
    print("\nInitial Facts for {}:\n".format(target_ip))
    print(initial_facts)

    print("[main.py] Defining Nmap rules...") # DEBUG
    rules = define_nmap_rules(target_ip, NMAP_EXECUTABLE_PATH)
    print(f"[main.py] Defined {len(rules)} rules.") # DEBUG

    print("[main.py] Initializing Inference Engine...") # DEBUG
    engine = InferenceEngine(initial_facts, rules, consolidated_output_file_path)
    
    # Crucial step: Initialize the engine's consolidated data if it's a fresh run
    # and we just performed an initial XML scan. This sets up the base for merging.
    if not existing_consolidated_nmap_data and initial_scan_xml_content:
        print("[main.py] Initializing engine's consolidated data from initial XML scan.") # DEBUG
        try:
            xml_tree = ET.fromstring(initial_scan_xml_content)
            root = xml_tree
            converted_host_data = []
            for host_elem in root.findall('host'):
                host_json = _convert_xml_host_to_json_dict(host_elem)
                if host_json:
                    converted_host_data.append(host_json)
            
            if converted_host_data:
                # Use consolidate_and_add_scan_data to populate the engine's internal consolidated_nmap_data
                engine.consolidate_and_add_scan_data({"nmaprun": {"host": converted_host_data}})
            else:
                print("[main.py] Warning: No host data found in initial XML scan to convert for consolidation at engine init.")

        except ET.ParseError as e:
            print(f"[main.py] Error parsing initial XML content for engine consolidation: {e}")
        except Exception as e:
            print(f"[main.py] An unexpected error occurred during XML to JSON conversion for consolidation: {e}")

    print("[main.py] Calling engine.run()...") # DEBUG - THIS IS THE KEY!
    engine.run() # Start the inference process

    print("[main.py] Engine.run() completed.") # DEBUG

    # Clean up the temporary initial scan file
    #if os.path.exists(initial_scan_file_path):
     #   os.remove(initial_scan_file_path)
      #  print(f"Cleaned up temporary initial scan file: {initial_scan_file_path}")

    print("\nProcess complete. Check 'result.json' for consolidated scan data.")