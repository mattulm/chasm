import argparse
import datetime
import json
import os
import random
import subprocess
import sys

def run_dig_ns(domains_file, output_filename, output_location, include_datetime, silent_mode):
    """
    Runs DIG NS queries, processes the output, and saves it to a JSON file.
    """
    if not os.path.exists(domains_file):
        print(f"Error: Domains file '{domains_file}' not found.")
        sys.exit(1)

    now = datetime.datetime.now()
    date_str = now.strftime("%Y%m%d")
    time_str = now.strftime("%H%M")

    # Determine the output file path
    if output_location and not os.path.isdir(output_location):
        os.makedirs(output_location, exist_ok=True)
    
    if not output_location:
        output_location = os.getcwd()

    if not output_filename:
        output_filename = f"dig.ns.{date_str}.{time_str}.json"
    elif include_datetime:
        name, ext = os.path.splitext(output_filename)
        output_filename = f"{name}.{date_str}.{time_str}{ext}"
    
    output_filepath = os.path.join(output_location, output_filename)

    if not silent_mode:
        print(f"\nCHASM: Interrogating Name Servers for domains in {domains_file}")
        print(f"Output will be saved to: {output_filepath}\n")

    ns_records = []

    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # Randomized scan pattern to prevent predictable traffic
    random.shuffle(domains)

    for domain in domains:
        if not silent_mode:
            print(f"Checking Name Servers for :: {domain}")
        try:
            # Execute dig for NS records
            process = subprocess.run(
                ['dig', '-4', '-t', 'NS', domain],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            
            dig_output_lines = process.stdout.splitlines()
            
            for line in dig_output_lines:
                # Target the Answer Section and valid NS records, ignoring comments
                if "NS" in line and not line.strip().startswith(';'):
                    parts = line.split()
                    if len(parts) >= 5:
                        record = {
                            "domain": parts[0].lower().rstrip('.'),
                            "ttl": parts[1],
                            "class": parts[2].lower(),
                            "record_type": parts[3].lower(),
                            "ns_server": parts[4].lower().rstrip('.')
                        }
                        ns_records.append(record)

        except Exception as e:
            if not silent_mode:
                print(f"Error processing {domain}: {e}")

    # Write final structured intelligence to JSON
    try:
        with open(output_filepath, 'w') as f:
            json.dump(ns_records, f, indent=4)
        if not silent_mode:
            print("\nName Server Audit Complete.")
    except IOError as e:
        print(f"Error writing to output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="CHASM: Python-based DIG NS Auditor")
    parser.add_argument("-f", "--file", dest="domains_file", required=True, help="Input file of domains")
    parser.add_argument("-oF", "--output-filename", dest="output_filename", help="Output JSON filename")
    parser.add_argument("-oL", "--output-location", dest="output_location", help="Output directory")
    parser.add_argument("-oI", "--include-datetime", dest="include_datetime", action="store_true", help="Add timestamp to filename")
    parser.add_argument("-s", "--silent", dest="silent_mode", action="store_true", help="Suppress console output")

    args = parser.parse_args()
    run_dig_ns(args.domains_file, args.output_filename, args.output_location, args.include_datetime, args.silent_mode)

if __name__ == "__main__":
    main()
