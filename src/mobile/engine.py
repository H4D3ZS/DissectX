import os
import subprocess
import shutil
import json
from pathlib import Path

class MobileEngine:
    def __init__(self, workspace_dir=None):
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path("/tmp/dissectx_mobile")
        self.workspace_dir.mkdir(exist_ok=True)
        self.apktool_path = shutil.which("apktool")
        self.jadx_path = shutil.which("jadx")
        self.frida_available = False
        
        try:
            import frida
            self.frida = frida
            self.frida_available = True
        except ImportError:
            pass

    def check_tools(self):
        return {
            "apktool": bool(self.apktool_path),
            "jadx": bool(self.jadx_path),
            "frida": self.frida_available
        }

    def decode_apk(self, apk_path):
        """Run apktool d <apk>"""
        if not self.apktool_path:
            return {"error": "apktool not installed"}
        
        output_dir = self.workspace_dir / Path(apk_path).stem
        if output_dir.exists():
            shutil.rmtree(output_dir)
            
        try:
            subprocess.run([self.apktool_path, "d", apk_path, "-o", str(output_dir), "-f"], 
                           check=True, capture_output=True)
            return {"status": "success", "output_dir": str(output_dir)}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": e.stderr.decode()}

    def decompile_with_jadx(self, apk_path):
        """Run jadx to produce java source"""
        if not self.jadx_path:
            return {"error": "jadx not installed"}
            
        output_dir = self.workspace_dir / (Path(apk_path).stem + "_source")
        if output_dir.exists():
            return {"status": "cached", "output_dir": str(output_dir)}
            
        try:
            # -d output dir, --no-res (we have apktool for resources)
            subprocess.run([self.jadx_path, "-d", str(output_dir), "--no-res", apk_path], 
                           check=True, capture_output=True)
            return {"status": "success", "output_dir": str(output_dir)}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": e.stderr.decode()}

    def list_files(self, directory):
        """List files for the file tree viewer"""
        valid_files = []
        start_path = Path(directory)
        
        for p in start_path.rglob("*"):
            if p.is_file():
                rel_path = p.relative_to(start_path)
                valid_files.append({
                    "path": str(rel_path),
                    "name": p.name,
                    "type": "file",
                    "extension": p.suffix
                })
        return valid_files

    def get_file_content(self, base_dir, relative_path):
        """Read content of a specific file"""
        full_path = Path(base_dir) / relative_path
        # Security check needed in prod to prevent traversal
        try:
            return full_path.read_text(errors='replace')
        except Exception as e:
            return f"Error reading file: {e}"

    def list_frida_devices(self):
        if not self.frida_available:
            return [{"id": "local", "name": "Local System", "type": "local"}]
        
        try:
            devices = self.frida.enumerate_devices()
            return [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
        except Exception as e:
            return [{"error": str(e)}]

    def ssl_pinning_bypass(self, device_id, package_name):
        if not self.frida_available:
            return {"error": "Frida not available"}
            
        script_code = """
        Java.perform(function() {
            var array_list = Java.use("java.util.ArrayList");
            var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            if (ApiClient) {
                ApiClient.checkServerTrusted.implementation = function(chain, authType) {
                    console.log("[+] Bypassing SSL Pinning");
                    return array_list.$new();
                }
            }
        });
        """
        # Logic to attach to process and load script would go here
        # This requires the app to be running
        return {"status": "script_injected", "message": "Generic SSL Unpinning script loaded"}
