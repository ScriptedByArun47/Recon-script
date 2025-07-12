from colorama import Fore, Style, init
import random
import subprocess
import os,json
import socket
init(autoreset=True)

def print_banner():
    
    ascii_art = f"""
{Fore.RED}{Style.BRIGHT}

     ____    ______    _   _    _____   _   _    _____    ______      __    _   _
    | __ \  |  ____|  | \ | |  |_  __| | | | |  |  __ \  |__  __|   / _ \  | \ | |
    |/_/ /  |  __|    |  \| |    | |   | | | |  | |__) |    | |    | | | | |  \| |
    |, _/   | |____   | |\  |    | |   | |_| |  |  _  /   __| |_   | |_| | | |\  |
    |_|     |______|  |_| \_|    |_|    \___/   |_| \_\  |______|   \ __/  |_| \_|
                                                            
                               
{Fore.LIGHTCYAN_EX}{Style.BRIGHT}         Automated Web Pentesting Framework
{Fore.YELLOW}      ↪ Recon | Scaning | Exploit | Bypass | Report
{Fore.GREEN}                                                                     Author : ArunKumar L
{Fore.MAGENTA}                         GitHub  : https://github.com/ScriptedByArun47
{Style.RESET_ALL}
""" 
    quote = random.choice([
        "“The quieter you become, the more you are able to hear.”",
        "“Hacking is not a crime. It’s a skill.”",
        "“Recon is not optional. It’s the war plan.”",
        "“Behind every firewall is a misconfigured hope.”",
        "“Automation doesn't replace skill — it empowers it.”"
    ])

    print(ascii_art)
    print(Fore.GREEN + Style.BRIGHT + f" [*] {quote}")
    print(Fore.MAGENTA + "-" * 65 + Style.RESET_ALL)


def get_ip_for_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_domain_for_ip(ip, json_file_path):
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
            hosts = data.get("nmaprun", {}).get("host", [])

            # Normalize single host dict
            if isinstance(hosts, dict):
                hosts = [hosts]

            for host in hosts:
                addresses = host.get("addresses", {})
                if addresses.get("addr") == ip:
                    hostnames = host.get("hostnames", {})

                    # In some cases, 'hostnames' is an empty list or dict
                    if isinstance(hostnames, dict):
                        hostnames_list = hostnames.get("hostname", [])
                        if isinstance(hostnames_list, dict):
                            hostnames_list = [hostnames_list]
                    else:
                        hostnames_list = []

                    for hn in hostnames_list:
                        name = hn.get("name")
                        if name:
                            return name
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Error reading result.json: {e}")
    return None

if __name__ == "__main__":
    print_banner()
    DEBUG_MODE = False

    if not DEBUG_MODE:
        try:
            print(Fore.GREEN + Style.BRIGHT + "\n[*] (main2.py) NMAP scanning in progress...\n")
            subprocess.run(["python3", "/home/arunexploit/Penturion/AImodel/main.py"], check=True)
            print(Fore.GREEN + Style.BRIGHT + "\n[*] NMAP scanning completed successfully!\n")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[!] Error running NMAP scan: {e}")

    try:
        with open("output/penturion_target.txt", "r") as f:
            target_input = f.read().strip()

        # Determine if input is IP or domain
        try:
            socket.inet_aton(target_input)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            target_ip = target_input
            target_domain = get_domain_for_ip(target_ip, "output/result.json")
        else:
            target_domain = target_input
            target_ip = get_ip_for_domain(target_domain)

        # Validate and proceed
        if not target_ip:
            print(Fore.RED + Style.BRIGHT + f"[!] Could not resolve IP for domain '{target_domain}'.")
        elif not target_domain:
            print(Fore.YELLOW + Style.BRIGHT + f"[!] No domain name found for IP {target_ip} in result.json.")
        else:
            print(Fore.CYAN + Style.BRIGHT + f"[*] Found domain '{target_domain}' for IP {target_ip}. Running subdomain scan...\n")
            try:
                command = ["/home/arunexploit/Penturion/inbuilt_Tool/recon/recon", "scan", "--domain", target_domain]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                print(Fore.GREEN + "[+] Subdomain scan completed successfully.\n")
                print(result.stdout)
            except subprocess.CalledProcessError as e:
                print(Fore.RED + f"[!] Error during subdomain scan:\n{e.stderr}")
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] penturion_target.txt not found. Please provide a valid target.")
    except json.JSONDecodeError:
        print(Fore.RED + Style.BRIGHT + "[!] result.json is not a valid JSON file.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Unexpected error: {e}")

 
    # Feroxbuster Scan
   
    json_output = f"/home/arunexploit/Penturion/output/ferox_output_{target_domain}.json"

    try:
        print(Fore.CYAN + Style.BRIGHT + "\n[*] Starting Feroxbuster scan...\n")
        result = subprocess.run([
            "python3",
            "/home/arunexploit/Penturion/inbuilt_Tool/recon/feroxbuster.py",
            "--target", f"https://{target_domain}",
            "--wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "--threads", "30",
            "--extensions", "php,html,js,txt,json,xml,asp,aspx,jsp",
            "--depth", "2"
        ], capture_output=True, text=True, timeout=600, check=True)

        if "Could not connect" in result.stdout or "ERROR" in result.stdout:
            print(Fore.RED + Style.BRIGHT + "[!] Feroxbuster ran but failed to connect.")
            print(Fore.YELLOW + result.stdout)
        else:
            print(Fore.GREEN + Style.BRIGHT + "\n[✔] Feroxbuster scan completed successfully!\n")
            print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Feroxbuster scan failed:\n{e.stderr}")
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] feroxbuster.py not found.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Unexpected error during Feroxbuster scan: {e}")

    
    # Nmap XML Report to Text
   
    try:
        print(Fore.GREEN + Style.BRIGHT + "\n[*] Running Nmap XML to Text conversion...\n")
        subprocess.run(["python3", "/home/arunexploit/Penturion/AImodel/reportgen.py"], check=True)
        print(Fore.GREEN + Style.BRIGHT + "[✔] Nmap XML to Text conversion completed!\n")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Error during Nmap XML to Text conversion:\n{e.stderr}")
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "[!] reportgen.py not found.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[!] Unexpected error during report generation: {e}")

    
    
    

    # Final Message

    
    print(Fore.MAGENTA + Style.BRIGHT + "\n[*] Pentesting automation completed. Check the output directory for results.")
    print("-" * 65 + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "[*] Thank you for using the Automated Web Pentesting Framework!\n" + Style.RESET_ALL)
