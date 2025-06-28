import xml.etree.ElementTree as ET
import os

def parse_nmap_xml(xml_file, output_file):
    """
    Parses an Nmap XML output file and writes key information to a text file.

    Args:
        xml_file (str): Path to the Nmap XML input file.
        output_file (str): Path to the text file where the output will be written.
    """
    try:
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created output directory: {output_dir}")

        tree = ET.parse(xml_file)
        root = tree.getroot()

        with open(output_file, 'w') as f:
            f.write("Nmap Scan Report\n")
            f.write("=================\n\n")

            # Scan Information
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                f.write(f"Scan Type: {scaninfo.get('type')}\n")
                f.write(f"Protocol: {scaninfo.get('protocol')}\n")
                f.write(f"Number of Services Scanned: {scaninfo.get('numservices')}\n")
                f.write(f"Services: {scaninfo.get('services')}\n\n")

            # Host Information
            host = root.find('host')
            if host is not None:
                f.write(f"Host: {host.find('address').get('addr')}\n")
                
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname_elem in hostnames.findall('hostname'):
                        f.write(f"  Hostname ({hostname_elem.get('type')}): {hostname_elem.get('name')}\n")

                status = host.find('status')
                if status is not None:
                    f.write(f"  Host Status: {status.get('state')} (Reason: {status.get('reason')})\n")

                f.write("\nOpen Ports:\n")
                ports = host.find('ports')
                if ports is not None:
                    open_ports_found = False
                    for port in ports.findall('port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            open_ports_found = True
                            f.write(f"  Port: {port.get('portid')}/{port.get('protocol')}\n")
                            service = port.find('service')
                            if service is not None:
                                f.write(f"    Service: {service.get('name')}\n")
                                if service.get('product'):
                                    f.write(f"    Product: {service.get('product')}\n")
                                if service.get('version'):
                                    f.write(f"    Version: {service.get('version')}\n")
                                if service.get('extrainfo'):
                                    f.write(f"    Extra Info: {service.get('extrainfo')}\n")
                                if service.get('ostype'):
                                    f.write(f"    OS Type: {service.get('ostype')}\n")
                                if service.get('cpe'):
                                    for cpe in service.findall('cpe'):
                                        f.write(f"    CPE: {cpe.text}\n")
                            
                            # Nmap Scripts Output
                            for script in port.findall('script'):
                                f.write(f"    Script: {script.get('id')}\n")
                                f.write(f"      Output: {script.get('output').strip()}\n")
                            f.write("\n")
                    if not open_ports_found:
                        f.write("  No open ports found.\n\n")
                    
                    # Filtered Ports
                    extraports = ports.find('extraports')
                    if extraports is not None:
                        filtered_count = extraports.get('count')
                        f.write(f"Filtered Ports Count: {filtered_count}\n")
                        f.write("\n")


                # OS Information (if available)
                os_elem = host.find('os')
                if os_elem is not None:
                    f.write("Operating System Details:\n")
                    for portused in os_elem.findall('portused'):
                        f.write(f"  Port Used for OS Detection: {portused.get('portid')}/{portused.get('proto')} ({portused.get('state')})\n")
                    f.write("\n")

                # Traceroute Information
                trace = host.find('trace')
                if trace is not None:
                    f.write("Traceroute:\n")
                    for hop in trace.findall('hop'):
                        f.write(f"  Hop TTL: {hop.get('ttl')}, IP: {hop.get('ipaddr')}")
                        if hop.get('host'):
                            f.write(f", Host: {hop.get('host')}")
                        f.write(f", RTT: {hop.get('rtt')}ms\n")
                f.write("\n")

            # Run Statistics
            runstats = root.find('runstats')
            if runstats is not None:
                f.write("Scan Statistics:\n")
                f.write(f"  Finished: {runstats.get('timestr')}\n")
                f.write(f"  Elapsed Time: {runstats.get('elapsed')} seconds\n")
                f.write(f"  Hosts Up: {runstats.find('hosts').get('up')}\n")
                f.write(f"  Hosts Down: {runstats.find('hosts').get('down')}\n")
                f.write(f"  Total Hosts: {runstats.find('hosts').get('total')}\n")

        print(f"Nmap output successfully converted to {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file '{xml_file}' not found. Please ensure the file exists at this path.")
    except ET.ParseError:
        print(f"Error: Could not parse XML from '{xml_file}'. Check if it's a valid XML file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Specify the full paths for input and output files
    xml_input_file = "/home/arunexploit/Penturion/AImodel/output/initial_scan.xml"  # Input XML file location
    text_output_file = "output/nmap_report.txt"  # Output text file location

    parse_nmap_xml(xml_input_file, text_output_file)