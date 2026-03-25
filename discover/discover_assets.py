#!/usr/bin/env python3
"""
Acquisition Scout - Resilient Asset Discovery (Refactored)
Author: Senior Security Engineer
Description: 
    Discovers assets via crt.sh JSON API and Shodan.
    Bypasses Postgres 5432 'recovery conflicts' by using the HTTPS front-end.
"""

import sys
import argparse
import re
import time
import requests
from shodan import Shodan, APIError

DANGER_PORTS = {
    21: "FTP", 23: "Telnet", 137: "NetBIOS", 139: "NetBIOS", 
    445: "SMB/CIFS", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
    161: "SNMP"
}

def validate_domain(domain):
    """Strictly validates domain format to ensure clean input."""
    pattern = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
    if not pattern.match(domain.lower()):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain.lower()

def query_crt_sh(domain):
    """
    Queries the crt.sh JSON API. 
    This is significantly more stable than direct Postgres connections 
    which often fail with 'conflict with recovery' errors.
    """
    assets = set()
    url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        print(f"[*] Querying crt.sh HTTPS API for {domain}...")
        # Higher timeout as crt.sh can be slow, but it won't drop the connection like SQL
        response = requests.get(url, timeout=45)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                # crt.sh returns names in 'common_name' and 'name_value'
                # These can contain multiple entries separated by newlines
                raw_names = f"{entry.get('common_name', '')}\n{entry.get('name_value', '')}"
                
                for name in raw_names.split('\n'):
                    clean_name = name.lower().strip()
                    # Filter for relevance and remove wildcards
                    if clean_name.endswith(domain) and "*" not in clean_name:
                        assets.add(clean_name)
        else:
            print(f"[-] API error: Received status code {response.status_code}")
            
    except requests.exceptions.Timeout:
        print("[-] Error: The crt.sh API timed out. The server is under heavy load.")
    except Exception as e:
        print(f"[-] Unexpected error querying crt.sh: {e}")
            
    return assets

def query_shodan(domain, api_key):
    """Standard Shodan search for common risk ports."""
    print(f"[*] Querying Shodan for {domain}...")
    findings = []
    try:
        api = Shodan(api_key)
        results = api.search(f'hostname:{domain}')
        for service in results['matches']:
            port = service['port']
            if port in DANGER_PORTS:
                findings.append({
                    "ip": service['ip_str'],
                    "port": port,
                    "service": DANGER_PORTS[port]
                })
        return findings
    except APIError as e:
        print(f"[-] Shodan API Error: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="Frugal & Resilient Asset Discovery",
        epilog="Refactored: Migrated from flaky Postgres to stable HTTPS API."
    )
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--shodan", metavar="KEY", help="Optional Shodan API Key")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    try:
        target = validate_domain(args.domain)
        subdomains = query_crt_sh(target)
        
        if subdomains:
            print(f"\n[+] Discovered {len(subdomains)} unique subdomains:")
            for s in sorted(subdomains):
                print(f"  - {s}")
        else:
            print("\n[-] No subdomains found or crt.sh is unresponsive.")

        if args.shodan:
            risk_assets = query_shodan(target, args.shodan)
            if risk_assets:
                print(f"\n!!! ALERT: {len(risk_assets)} DANGER PORTS EXPOSED !!!")
                for r in risk_assets:
                    print(f"  {r['ip']}:{r['port']} ({r['service']})")
            else:
                print("\n[*] No high-risk exposures found on Shodan.")

    except ValueError as ve:
        print(f"Error: {ve}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
