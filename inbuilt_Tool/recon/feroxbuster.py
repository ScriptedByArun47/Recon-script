import argparse
import os
import subprocess

def run_feroxbuster(target, wordlist, output_file, threads=20, extensions=None, depth=None):
    if not os.path.exists(wordlist):
        raise FileNotFoundError(f"[!] Wordlist not found: {wordlist}")
    
    if not target.startswith("http://") and not target.startswith("https://"):
        print("[!] Target must start with http:// or https://")
        return

    # Remove old output file if exists
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print(f"[+] Removed old output file: {output_file}")
        except Exception as e:
            print(f"[!] Failed to remove existing output file: {e}")
            return

    command = [
        "feroxbuster",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "-o", output_file,
        "--silent",
        "--insecure",  # helps avoid SSL issues
        "-H", "User-Agent: Mozilla/5.0"
    ]

    if extensions:
        command += ["-x", ",".join(extensions)]

    if depth:
        command += ["--depth", str(depth)]

    print(f"[+] Running Feroxbuster on: {target}")

    try:
        subprocess.run(command, check=True)
        print(f"[✔] Feroxbuster completed. Output saved to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Feroxbuster failed: {e}")
    except FileNotFoundError:
        print("[!] Feroxbuster not found. Is it installed and in PATH?")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python wrapper for Feroxbuster")
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--wordlist", default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                        help="Path to wordlist")
    parser.add_argument("--output", default="/home/arunexploit/Penturion/output/ferox_output.txt",
                        help="Output file path")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("--extensions", default="php,html,js,txt,json,xml,asp,aspx,jsp",
                        help="Comma-separated list of extensions")
    parser.add_argument("--depth", type=int, default=None, help="Recursion depth")

    args = parser.parse_args()

    run_feroxbuster(
        target=args.target,
        wordlist=args.wordlist,
        output_file=args.output,
        threads=args.threads,
        extensions=args.extensions.split(',') if args.extensions else None,
        depth=args.depth
    )
