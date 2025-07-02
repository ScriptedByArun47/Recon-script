import json
import csv
import os
from typing import List, Dict, Union


def load_json_objects(file_path: str) -> List[Dict]:
    """
    Load multiple JSON objects from a file (one JSON per line).
    """
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                data.append(obj)
            except json.JSONDecodeError as e:
                print(f"[!] Skipping invalid JSON line: {e}")
    return data


def extract_scan_results(json_data: List[Dict]) -> List[Dict]:
    """
    Extract only valid scan result entries (not config/statistics).
    """
    results = []
    for entry in json_data:
        if entry.get("type") in ("configuration", "statistics"):
            continue
        if all(k in entry for k in ("url", "status", "content_length", "words", "lines")):
            results.append({
                "url": entry["url"],
                "status": entry["status"],
                "length": entry["content_length"],
                "words": entry["words"],
                "lines": entry["lines"]
            })
    return results


def convert_to_csv(results: List[Dict], output_file: str):
    """
    Write selected fields to CSV file.
    """
    fields = ["url", "status", "length", "words", "lines"]
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"[✔] Wrote {len(results)} results to CSV: {output_file}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Convert Feroxbuster results to CSV (URL, status, length, words, lines)")
    parser.add_argument("--input", required=True, help="Path to Feroxbuster JSON output")
    parser.add_argument("--output", default=None, help="CSV output path")
    args = parser.parse_args()

    input_path = args.input
    output_path = args.output or os.path.splitext(input_path)[0] + "_results.csv"

    if not os.path.exists(input_path):
        print(f"[!] File not found: {input_path}")
        return

    print(f"[+] Reading JSON from: {input_path}")
    data = load_json_objects(input_path)

    results = extract_scan_results(data)

    if not results:
        print("[!] No valid scan result entries found.")
        return

    print(f"[+] Found {len(results)} result entries. Writing CSV...")
    convert_to_csv(results, output_path)


if __name__ == "__main__":
    main()
