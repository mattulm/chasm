import argparse
import datetime
import subprocess
import json
import os
import sys # Import sys for stderr for silent mode messages

def check_host_command():
    """
    Checks if the 'host' command is installed and available in the system's PATH.
    Returns True if 'host' is found, False otherwise.
    """
    try:
        subprocess.run(['which', 'host'], capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        print("Error: 'which' command not found. Cannot check for 'host' command availability.", file=sys.stderr)
        return False

def resolve_host_info(domain_list_file, output_file_name, output_location, include_datetime, silent_mode):
    """
    Resolves IPv4 and IPv6 addresses for a list of hostnames, writes output to a JSON file
    as it's processed, and optionally prints results to the screen.

    Args:
        domain_list_file (str): Path to the file containing the list of domains.
        output_file_name (str): The desired name for the output file.
        output_location (str): The directory where the output file will be saved.
        include_datetime (bool): Whether to include date and time in the output filename.
        silent_mode (bool): If True, suppresses screen output.
    """

    if not check_host_command():
        print("Error: The 'host' command is not found on your system. Please install it to use this script.", file=sys.stderr)
        print("On Debian/Ubuntu: sudo apt-get install dnsutils", file=sys.stderr)
        print("On Fedora/RHEL: sudo dnf install bind-utils", file=sys.stderr)
        print("On macOS (if using Homebrew): brew install bind", file=sys.stderr)
        return

    # Construct the output file path
    now = datetime.datetime.now()
    date_time_str = now.strftime("%Y%m%d_%H%M")

    if include_datetime and output_file_name:
        base_name, ext = os.path.splitext(output_file_name)
        final_output_file_name = f"{base_name}_{date_time_str}{ext if ext else '.json'}"
    elif output_file_name and not include_datetime:
        final_output_file_name = f"{output_file_name}.json" if not output_file_name.endswith('.json') else output_file_name
    else: # Only include date and time if no output filename is provided
        final_output_file_name = f"{date_time_str}.json"
        
    # Ensure output directory exists
    os.makedirs(output_location, exist_ok=True)
    output_path = os.path.join(output_location, final_output_file_name)

    # Read domains from the source file
    try:
        with open(domain_list_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Source file '{domain_list_file}' not found.", file=sys.stderr)
        return
    except Exception as e:
        print(f"Error reading source file: {e}", file=sys.stderr)
        return

    if not silent_mode:
        print(f"Starting host resolution for {len(domains)} domains...")
        print(f"Output will be saved to: {output_path}")

    # Open the output file for writing JSON
    try:
        with open(output_path, 'w') as out_f:
            out_f.write("[\n") # Start of JSON array
            first_entry = True

            for domain in domains:
                ip_ver4 = "N/A"
                ip_ver6 = "N/A"

                try:
                    # Execute the 'host' command
                    result = subprocess.run(
                        ['host', domain], 
                        capture_output=True, 
                        text=True, 
                        check=True,
                        timeout=5 # Add a timeout for host command
                    )
                    output_lines = result.stdout.splitlines()

                    for line in output_lines:
                        if "has address" in line:
                            ip_ver4 = line.split()[-1]
                        if "has IPv6 address" in line:
                            ip_ver6 = line.split()[-1]

                except subprocess.CalledProcessError:
                    # print(f"Warning: Could not resolve host '{domain}'.", file=sys.stderr)
                    pass # Suppress host not found errors for cleaner output
                except FileNotFoundError:
                    print("Internal Error: 'host' command not found during execution. This should have been caught earlier.", file=sys.stderr)
                    break # Exit loop if host command mysteriously disappears
                except subprocess.TimeoutExpired:
                    if not silent_mode:
                        print(f"Warning: 'host' command timed out for '{domain}'", file=sys.stderr)
                    ip_ver4 = "Timeout"
                    ip_ver6 = "Timeout"
                except Exception as e:
                    if not silent_mode:
                        print(f"An unexpected error occurred for '{domain}': {e}", file=sys.stderr)
                    ip_ver4 = "Error"
                    ip_ver6 = "Error"


                host_data = {
                    "hostname": domain,
                    "ipVer4": ip_ver4,
                    "ipVer6": ip_ver6
                }

                # Write to JSON file
                if not first_entry:
                    out_f.write(",\n")
                
                out_f.write(json.dumps(host_data, indent=4))
                first_entry = False

                # Print to screen if not in silent mode
                if not silent_mode:
                    print(f"Hostname: {domain}, IPv4: {ip_ver4}, IPv6: {ip_ver6}")
            
            out_f.write("\n]\n") # End of JSON array

        if not silent_mode:
            print(f"\nAll results processed and saved to: {output_path}")
    except Exception as e:
        print(f"Error writing to output file: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Look for A and AAAA records for a given host list and output to JSON."
    )
    parser.add_argument(
        "-f", "--file",
        dest="source_file",
        required=True,
        help="Specify the source file containing the list of domains (required)."
    )
    parser.add_argument(
        "-oF", "--output-filename",
        dest="output_filename",
        help="Specify the name of the output JSON file. If not provided, only date and time will be used for the filename."
    )
    parser.add_argument(
        "-oL", "--output-location",
        dest="output_location",
        default=os.getcwd(),
        help="Specify the location (directory) where the output file should be placed. Defaults to the current directory."
    )
    parser.add_argument(
        "-oI", "--include-datetime",
        action="store_true",
        dest="include_datetime",
        help="Include date and time variables in the name of the output file. Requires -oF to be provided."
    )
    parser.add_argument(
        "-s", "--silent",
        action="store_true",
        dest="silent_mode",
        help="Suppress all output to the console."
    )

    args = parser.parse_args()

    if args.include_datetime and not args.output_filename:
        parser.error("-oI requires -oF to be provided.")

    resolve_host_info(args.source_file, args.output_filename, args.output_location, args.include_datetime, args.silent_mode)

if __name__ == "__main__":
    main()
