import json
import os
import glob
from datetime import datetime

# Configuration for CHASM directories
TLSX_OUTPUT_DIR = "/asm/output/tlsx/"
REPORT_OUTPUT = "/asm/output/reports/tls_compliance_report.txt"

def generate_report():
    print(f"CHASM: Generating TLS Compliance Report...")
    
    # Locate the latest JSON files for Certs and Ciphers
    cert_files = sorted(glob.glob(os.path.join(TLSX_OUTPUT_DIR, "tlsx_cert.host.*.json")), reverse=True)
    cipher_files = sorted(glob.glob(os.path.join(TLSX_OUTPUT_DIR, "tlsx_cipher.host.*.json")), reverse=True)

    if not cert_files or not cipher_files:
        print("Error: No recent TLSX JSON data found. Run tlsxCertHost and tlsxCipherHost first.")
        return

    report_lines = [
        "==========================================",
        "      CHASM TLS COMPLIANCE REPORT         ",
        f"      Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "==========================================\n"
    ]

    # --- Section 1: Certificate Issues ---
    report_lines.append("[!] CRITICAL CERTIFICATE ISSUES")
    with open(cert_files[0], 'r') as f:
        cert_data = json.load(f)
        for entry in cert_data:
            # Flags revoked, expired, or invalid certs
            if not entry.get("not_after") or entry.get("expired") == True:
                report_lines.append(f"[-] EXPIRED/INVALID: {entry.get('host')} (IP: {entry.get('ip')})")
            if entry.get("revoked") == True:
                report_lines.append(f"[-] REVOKED: {entry.get('host')}")

    # --- Section 2: Insecure Protocols ---
    report_lines.append("\n[!] DEPRECATED PROTOCOLS (TLS 1.0/1.1)")
    with open(cipher_files[0], 'r') as f:
        cipher_data = json.load(f)
        for entry in cipher_data:
            # Check for legacy versions
            version = entry.get("tls_version", "")
            if version in ["tls10", "tls11"]:
                report_lines.append(f"[-] INSECURE VERSION: {entry.get('host')} is using {version}")

    # --- Section 3: Weak Cipher Suites ---
    report_lines.append("\n[!] WEAK CIPHER SUITES DETECTED")
    weak_keywords = ["RC4", "3DES", "MD5", "EXPORT", "NULL", "CBC"]
    for entry in cipher_data:
        ciphers = entry.get("cipher_suites", [])
        for cipher in ciphers:
            if any(weak in cipher.upper() for weak in weak_keywords):
                report_lines.append(f"[-] WEAK CIPHER: {entry.get('host')} supports {cipher}")

    # Write the report to file
    os.makedirs(os.path.dirname(REPORT_OUTPUT), exist_ok=True)
    with open(REPORT_OUTPUT, 'w') as f:
        f.write("\n".join(report_lines))
    
    print(f"Report complete: {REPORT_OUTPUT}")

if __name__ == "__main__":
    generate_report()
