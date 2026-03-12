#!/usr/bin/env python3
"""
Module: ip_recon.py
Purpose: Investigate IP assignment size and neighbor risks for M&A targets.
"""

import requests
import sys
import argparse

def investigate_ip(target_ip):
    # RDAP is the standard for machine-readable WHOIS data
    url = f"https://rdap.arin.net/registry/ip/{target_ip}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Extract network range and handle
        start_ip = data.get('startAddress')
        end_ip = data.get('endAddress')
        net_name = data.get('name', 'Unknown')
        parent_handle = data.get('parentHandle', 'N/A')
        
        print(f"\n--- Network Intelligence for {target_ip} ---")
        print(f"[+] Network Name: {net_name}")
        print(f"[+] Assigned Range: {start_ip} - {end_ip}")
        print(f"[+] Parent Network: {parent_handle}")
        
        # Logic: If the range is huge (like a /12), they are an 'end user' in a pool.
        # If the range is small (e.g., a /29), they likely own the whole 'neighborhood'.
        if "VIS-BLOCK" in net_name:
            print("\n[!] Analysis: This is a Verizon 'Dynamic/Static Business Pool'.")
            print("    The target likely has a /30 (1 IP) or /29 (5 IPs) assignment here.")
            print("    They are NOT originating their own BGP routes.")
        
    except Exception as e:
        print(f"[-] RDAP Query failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit IP assignment details.")
    parser.add_argument("ip", help="The IP address to investigate")
    args = parser.parse_args()
    investigate_ip(args.ip)
