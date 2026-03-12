#!/usr/bin/env python3
"""
Module: dns_audit_v3.py
Purpose: Forensic TXT record analysis for M&A. Includes Bitwarden & IP checks.
"""

import dns.resolver
import argparse
import sys
import re

# Logic: Expanded Signatures - Added Bitwarden (bw=)
SIGS = {
    'google-site-verification': 'Google Workspace',
    'facebook-domain-verification': 'Meta/Facebook',
    'atlassian-domain-verification': 'Atlassian (Jira/Confluence)',
    'MS=': 'Microsoft 365',
    'bw=': 'Bitwarden Enterprise',
    'v=spf1': 'SPF (Email Policy)'
}

def analyze_txt(domain):
    """
    Fetches and categorizes records. 
    Using a dictionary to prevent duplicate processing.
    """
    findings = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            # Clean up the record (handle multi-part TXT records)
            txt_string = "".join([s.decode('utf-8') for s in rdata.strings])
            
            matched = False
            for key, service in SIGS.items():
                if key in txt_string:
                    findings.append(f"[+] {service}: {txt_string}")
                    matched = True
                    break
            
            if not matched:
                findings.append(f"[?] UNKNOWN/OTHER: {txt_string}")

        return findings
    except Exception as e:
        return [f"[!] Error: {str(e)}"]

def check_ip_reputation(record_list):
    """
    Look specifically for that Verizon IP or other static entries.
    """
    for rec in record_list:
        if "v=spf1" in rec:
            # Extract IPv4 addresses
            ips = re.findall(r'ip4:([0-9.]+)', rec)
            for ip in ips:
                print(f"\n[!] ALERT: Found Static IP {ip} in SPF.")
                print(f"    ACTION: Confirm if this is the Verizon Business circuit at the office.")
                print(f"    RISK: If the office closes, this IP must be removed to prevent spoofing.")

def main():
    parser = argparse.ArgumentParser(description="M&A DNS Intelligence Tool")
    parser.add_argument("domain", help="The domain to investigate")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    print(f"--- Investigation Report: {args.domain} ---")
    results = analyze_txt(args.domain)
    
    for r in results:
        print(r)
        
    check_ip_reputation(results)

if __name__ == "__main__":
    main()
