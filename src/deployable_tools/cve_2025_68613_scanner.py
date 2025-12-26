#!/usr/bin/env python3
"""
CVE-2025-68613 - n8n RCE Scanner
--------------------------------------------------
Scanner ONLY - No Exploitation via this file
Usage:
  python3 cve_2025_68613_scanner.py -u http://target
"""

import argparse
import requests
import re
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# --- Vulnerability Version Ranges ---
VULNERABLE_MIN = (0, 211, 0)
VULNERABLE_MAX_1 = (1, 120, 3)
VULNERABLE_MAX_2 = (1, 121, 0)

TIMEOUT = 8

def parse_version(text):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return None
    return tuple(map(int, match.groups()))

def is_vulnerable(version):
    if version < VULNERABLE_MIN: return False
    if version <= VULNERABLE_MAX_1: return True
    if version == VULNERABLE_MAX_2: return True
    return False

def check_target(url):
    print(f"\n[+] Target: {url}")
    headers = { "User-Agent": "DissectX-Scanner/1.0" }
    paths = ["/", "/rest/settings", "/healthz", "/api/v1/health"]
    
    for path in paths:
        try:
            target_url = url.rstrip("/") + path
            r = requests.get(target_url, headers=headers, timeout=TIMEOUT, verify=False)
            if r.status_code >= 500: continue
            
            if "n8n" in r.text.lower() or "n8n" in str(r.headers).lower():
                print(f"[+] Possible n8n detected at {path}")
                version = parse_version(r.text)
                if version:
                    print(f"[+] Detected version: {version[0]}.{version[1]}.{version[2]}")
                    return version
        except: continue
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    args = parser.parse_args()
    
    version = check_target(args.url)
    print("\n--- Result ---")
    if not version:
        print("⚠️ Unable to determine version")
        sys.exit(1)
    
    if is_vulnerable(version):
        print("🚨 IS VULNERABLE (CVE-2025-68613)")
        sys.exit(2)
    else:
        print("✅ IS NOT VULNERABLE")
        sys.exit(0)

if __name__ == "__main__":
    main()
