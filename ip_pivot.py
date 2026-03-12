#!/usr/bin/env python3
"""
Module: ip_pivot.py
Purpose: Targeted service discovery for a single-IP M&A target.
"""

import socket
import sys

# Common ports for "Single IP" SMB setups
TARGET_PORTS = {
    25: "SMTP (Legacy Mail?)",
    80: "HTTP (Insecure Management?)",
    443: "HTTPS (VPN/Webmail)",
    445: "SMB (MS File Share)",
    500: "IKE (IPsec VPN)",
    1723: "PPTP (Old/Insecure VPN)",
    3389: "RDP (Critical Risk)",
    4443: "Alt HTTPS (Admin Portal?)",
    8443: "Alt HTTPS (Admin Portal?)"
}

def check_service(ip, port, description):
    """
    Modular port checker using standard socket library.
    No heavy dependencies like Nmap required for a quick pivot.
    """
    try:
        # 2-second timeout to keep the script 'frugal' and fast
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[!] OPEN: Port {port} - {description}")
                return True
    except Exception:
        pass
    return False

def main(target_ip):
    print(f"--- Probing High-Value Services on {target_ip} ---")
    
    found_any = False
    for port, desc in TARGET_PORTS.items():
        if check_service(target_ip, port, desc):
            found_any = True
            
    if not found_any:
        print("[-] No common TCP ports open. They may be using UDP for VPN (DTLS/IPsec).")

if __name__ == "__main__":
    # Hardcoded check for our target
    target = "173.64.96.146"
    main(target)
