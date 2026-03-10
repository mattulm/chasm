import argparse
import datetime
import json
import os
import random
import subprocess
import sys

def run_dig_soa(domains_file, output_filename, output_location, include_datetime, silent_mode):
    """
    Runs DIG SOA queries, processes the output, and saves it to a JSON file.
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
        output_filename = f"dig.soa.{date_str}.{time_str}.json"
    elif include_datetime:
        name, ext = os.path.splitext(output_filename)
        output_filename = f"{name}.{date_str}.{time_str}{ext}"
    
    output_filepath = os.path.join(output_location, output_filename)

    if not silent_mode:
        print("\nI'm going to start with the SOA record of things with DIG")
        print(f"Output will be saved to: {output_filepath}\n")

    soa_records = []

    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    random.shuffle(domains)

    for domain in domains:
        if not silent_mode:
            print(f"Checking SOA record for :: {domain}")
        try:
            # Use -4 for IPv4 and pipe output to grep and awk
            process = subprocess.run(
                ['dig', '-4', '-t', 'SOA', domain],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Filter lines that contain "ER S" and the next 3 lines, then exclude lines with ";"
            # Finally, process with awk to get desired fields and format
            dig_output_lines = process.stdout.splitlines()
            
            # This parsing mimics the bash script's `grep "ER S" -A3 | grep -v ";" | awk '{...}'`
            # It's a bit more robust to parse line by line in Python.
            record_found = False
            soa_data_line = ""
            
            for i, line in enumerate(dig_output_lines):
                if "status: NOERROR" in line or "status: NXDOMAIN" in line:
                    if "ANSWER SECTION:" in process.stdout:
                        # Find the "ANSWER SECTION:" and then the SOA record line
                        for j in range(i, len(dig_output_lines)):
                            if "SOA" in dig_output_lines[j] and not dig_output_lines[j].strip().startswith(';'):
                                soa_data_line = dig_output_lines[j]
                                record_found = True
                                break
                if record_found:
                    break

            if soa_data_line:
                parts = soa_data_line.split()
                if len(parts) >= 11: # Ensure enough parts for all fields
                    record = {
                        "domain": parts[0].lower().rstrip('.'),  # Remove trailing dot and convert to lowercase
                        "ttl": parts[1],
                        "class": parts[2].lower(),
                        "record_type": parts[3].lower(),
                        "soa_server": parts[4].lower().rstrip('.'), # Remove trailing dot and convert to lowercase
                        "email": parts[5].replace('.', '@', 1).replace('.', '-', 1).lower(), # Convert to email format
                        "serial": parts[6],
                        "refresh": parts[7],
                        "retry": parts[8],
                        "expire": parts[9],
                        "soa_ttl": parts[10]
                    }
                    soa_records.append(record)
            else:
                if not silent_mode:
                    print(f"No SOA record found or parsable for {domain}")


        except subprocess.CalledProcessError as e:
            if not silent_mode:
                print(f"Error running dig for {domain}: {e.stderr.strip()}")
        except Exception as e:
            if not silent_mode:
                print(f"An unexpected error occurred for {domain}: {e}")

    # Write results to JSON file
    try:
        with open(output_filepath, 'w') as f:
            json.dump(soa_records, f, indent=4)
        if not silent_mode:
            print("\nDone with the SOA scan")
            print(f"Results saved to {output_filepath}")
    except IOError as e:
        print(f"Error writing to output file {output_filepath}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="A Python script to run DIG SOA queries and output results in JSON format."
    )
    parser.add_argument(
        "-f", "--file",
        dest="domains_file",
        help="The file location of the hosts (domains) to be scanned.",
        required=True
    )
    parser.add_argument(
        "-oF", "--output-filename",
        dest="output_filename",
        help="The output file name. If not given, uses Date and Time variables (e.g., dig.soa.YYYYMMDD.HHMM.json)."
    )
    parser.add_argument(
        "-oL", "--output-location",
        dest="output_location",
        help="The output file location. If not specified, uses the directory where the script is being run."
    )
    parser.add_argument(
        "-oI", "--include-datetime",
        dest="include_datetime",
        action="store_true",
        help="Include date and time variables in the output filename. This requires -f or --file to be provided."
    )
    parser.add_argument(
        "-s", "--silent",
        dest="silent_mode",
        action="store_true",
        help="Prevent the output of the script from being written to the screen. Default is to show output."
    )

    args = parser.parse_args()

    # Validate -oI usage
    if args.include_datetime and not args.domains_file:
        parser.error("-oI/--include-datetime requires -f/--file to be provided.")

    run_dig_soa(
        args.domains_file,
        args.output_filename,
        args.output_location,
        args.include_datetime,
        args.silent_mode
    )

if __name__ == "__main__":
    main()
