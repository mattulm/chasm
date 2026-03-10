#CHASM: CHeap Attack Surface Management

Script 01: Hostname-to-IP Validator

The Philosophy

CHASM is a collection of scripts designed to build a functional Attack Surface Management program using native Unix tools. The goal is to provide visibility into an organization's external footprint without the "enterprise" price tag.Overview: Script 01This script serves as the "pulse check" for your infrastructure. It processes a master list of hostnames to determine which records are live and actively resolving to IP addresses.

Key Features
Dual-Stack Discovery: Captures both IPv4 and IPv6 addresses for every host.
Sampling Mode: Uses shuf to scan 5,000 random entries from your list, preventing DNS rate-limiting and providing a statistical overview of host health.
Clean Output: Generates a timestamped CSV for easy integration into spreadsheets or downstream security tools.
Zero Dependencies: Relies solely on standard binaries: host, grep, awk, and shuf

