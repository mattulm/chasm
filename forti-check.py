#!/usr/bin/env python3
"""
Module: forti_audit.py
Purpose: Forensic discovery of FortiGate infrastructure for M&A due diligence.
Features: Zero hard-coded IPs, signature-based fingerprinting, and error handling.
"""

import requests
import urllib3
import argparse
import sys
from datetime import datetime

# Frugal approach: Suppress warnings for self-signed/broken M&A certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_target(target, port=443):
    """
    Probes a target for FortiGate-specific fingerprints and ACME conflicts.
    """
    url = f"https://{target}:{port}"
    print(f"[*] Starting audit of: {url}")
    
    try:
        # 5s timeout: We don't have time to wait for a dying Verizon circuit
        headers = {'User-Agent': 'Mozilla/5.0 (M&A Audit Tool)'}
        response = requests.get(url, timeout=5, verify=False, headers=headers)
        
        # Logic: Identifying the FortiGate ACME conflict
        if "ACME Access Only" in response.text:
            print("[!] ALERT: FortiGate ACME conflict detected.")
            print("    Posture: The ACME listener is intercepting traffic.")
            print("    Impact: Management GUI or SSL VPN may be inaccessible via web.")

        # Logic: Fingerprinting via Cookies (FortiGate specifics)
        # 'fgt_lang' is the default language cookie for FortiOS
        if 'fgt_lang' in response.cookies:
            print("[+] SIGNATURE: FortiGate language cookie (fgt_lang) found.")
            
        # Logic: Header-based discovery
        server_header = response.headers.get('Server', '')
        if "xxxxx" in server_header: # Placeholder for known obscured headers
             print(f"[+] HEADER: Obscured Server Header detected: {server_header}")

    except requests.exceptions.Timeout:
        print(f"[-] Error: Connection to {target} timed out.")
    except requests.exceptions.ConnectionError:
        print(f"[-] Error: Could not connect to {
