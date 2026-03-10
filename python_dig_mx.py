import argparse
import datetime
import json
import os
import random
import subprocess
import sys

def get_mail_host(mail_server):
    """
    Extracts the main host (e.g., example.com from sub.example.com)
    from a full mail server hostname.
    """
    if not mail_server:
        return ""
    
    parts = mail_server.rstrip('.').split('.') # Remove trailing dot and split by dots
    
    # If there are at least two parts (e.g., "example", "com"), return the last two
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    # If there's only one part (e.g., "localhost" or an invalid domain), return it as is
    elif len(parts) == 1 and parts[0]:
        return parts[0]
    return "" # Return empty string for empty input

def run_dig_mx(domains_file, output_filename, output_location, include_datetime, silent_mode):
    """
    Runs DIG MX queries, processes the output, and saves it to a JSON file.
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
        output_filename = f"dig.mx.{date_str}.{time_str}.json"
    elif include_datetime:
        name, ext = os.path.splitext(output_filename)
        output_filename = f"{name}.{date_str}.{time_str}{ext}"
    
    output_filepath = os.path.join(output_location, output_filename)

    if not silent_mode:
        print("\nI'm now switching to the MX record of things with DIG")
        print(f"Output will be saved to: {output_filepath}\n")

    mx_records = []

    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    random.shuffle(domains)

    for domain in domains:
        if not silent_mode:
            print(f"Checking the MX on {domain}")
        try:
            # Use -4 for IPv4 and capture output
            process = subprocess.run(
                ['dig', '-4', '-t', 'MX', domain],
                capture_output=True,
                text=True,
                check=True
            )
            
            dig_output_lines = process.stdout.splitlines()
            
            # Find and parse MX records from the ANSWER SECTION
            in_answer_section = False
            for line in dig_output_lines:
                if "ANSWER SECTION:" in line:
                    in_answer_section = True
                    continue
                if in_answer_section and line.strip().startswith(';'):
                    # Skip comment lines within the answer section
                    continue
                if in_answer_section and "MX" in line:
                    parts = line.split()
                    if len(parts) >= 6: # Ensure enough parts for all fields
                        try:
                            mail_server = parts[5].lower().rstrip('.')
                            record = {
                                "domain": parts[0].lower().rstrip('.'),
                                "ttl": parts[1],
                                "class": parts[2].lower(),
                                "record_type": parts[3].lower(),
                                "priority": int(parts[4]), # Priority is typically an integer
                                "mail_server": mail_server,
                                "mail_host": get_mail_host(mail_server) # New field!
                            }
                            mx_records.append(record)
                        except ValueError:
                            if not silent_mode:
                                print(f"Could not parse MX record line: {line.strip()}")
            
            if not in_answer_section and "status: NXDOMAIN" in process.stdout:
                if not silent_mode:
                    print(f"No MX record found for {domain} (NXDOMAIN)")
            elif not mx_records and not silent_mode: # If no records were found in answer section
                print(f"No MX records found for {domain} or could not parse.")

        except subprocess.CalledProcessError as e:
            if not silent_mode:
                print(f"Error running dig for {domain}: {e.stderr.strip()}")
        except Exception as e:
            if not silent_mode:
                print(f"An unexpected error occurred for {domain}: {e}")

    # Write results to JSON file
    try:
        with open(output_filepath, 'w') as f:
            json.dump(mx_records, f, indent=4)
        if not silent_mode:
            print("\nDone with the MX scan")
            print(f"Results saved to {output_filepath}")
    except IOError as e:
        print(f"Error writing to output file {output_filepath}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="A Python script to run DIG MX queries and output results in JSON format."
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
        help="The output file name. If not given, uses Date and Time variables (e.g., dig.mx.YYYYMMDD.HHMM.json)."
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

    run_dig_mx(
        args.domains_file,
        args.output_filename,
        args.output_location,
        args.include_datetime,
        args.silent_mode
    )

if __name__ == "__main__":
    main()
