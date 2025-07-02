import argparse
import os
import subprocess
import sys
import logging
from datetime import datetime

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

def validate_inputs(target, wordlist):
    if not os.path.exists(wordlist):
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    if not (target.startswith("http://") or target.startswith("https://")):
        raise ValueError("Target URL must start with http:// or https://")

def prepare_output_file(output_file):
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"Created output directory: {output_dir}")

    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            logging.info(f"Removed old output file: {output_file}")
        except Exception as e:
            logging.error(f"Failed to remove existing output file: {e}")
            raise

def build_feroxbuster_command(target, wordlist, output_file, threads, extensions, depth):
    command = [
        "feroxbuster",
        "-u", target,
        "-w", wordlist,
        "-t", str(threads),
        "-o", output_file,
        "--json",
        "--silent",
        "--insecure",
        "-H", "User-Agent: Mozilla/5.0"
    ]

    if extensions:
        command += ["-x", ",".join(extensions)]

    if depth is not None:
        command += ["--depth", str(depth)]

    return command

def run_feroxbuster(target, wordlist, output_file, threads=20, extensions=None, depth=None):
    try:
        validate_inputs(target, wordlist)
        prepare_output_file(output_file)

        command = build_feroxbuster_command(target, wordlist, output_file, threads, extensions, depth)
        logging.info(f"Running Feroxbuster on: {target}")

        result = subprocess.run(command, capture_output=True, text=True, timeout=600)

        if result.returncode == 0:
            logging.info(f"Feroxbuster completed successfully. Output saved to: {output_file}")
        else:
            logging.error(f"Feroxbuster failed with return code {result.returncode}")
            logging.error(f"stderr: {result.stderr}")

    except FileNotFoundError:
        logging.error("Feroxbuster not found. Is it installed and in your PATH?")
    except subprocess.TimeoutExpired:
        logging.error("Feroxbuster execution timed out.")
    except Exception as e:
        logging.exception(f"Unexpected error occurred: {e}")

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="Advanced Python wrapper for Feroxbuster")
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--wordlist", default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                        help="Path to wordlist")
    parser.add_argument("--output", default=f"./output/ferox_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
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
