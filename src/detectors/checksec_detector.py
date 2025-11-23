import subprocess
import re
from typing import Dict, Optional

class ChecksecDetector:
    """
    Detects security mitigations in binary files (ELF).
    Checks for: NX (No-Execute), PIE (Position Independent Executable), Stack Canaries, and RELRO.
    """

    def __init__(self):
        pass

    def check_security(self, filepath: str) -> Dict[str, str]:
        """
        Run all security checks on the binary.
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            Dictionary of security features and their status ('Enabled', 'Disabled', 'Partial', etc.)
        """
        results = {
            'NX': 'Unknown',
            'PIE': 'Unknown',
            'Canary': 'Unknown',
            'RELRO': 'Unknown'
        }

        # We primarily use readelf for ELF binaries as it's the standard tool.
        # If readelf is not available, we could fallback to objdump or internal parsing.
        # For now, we'll try readelf and objdump.
        
        # 1. Check Canary (Stack Protector)
        # Canaries are usually detected by looking for symbols like __stack_chk_fail
        results['Canary'] = self._check_canary(filepath)

        # 2. Check NX (No-Execute Stack)
        # Look for GNU_STACK segment permissions in program headers
        results['NX'] = self._check_nx(filepath)

        # 3. Check PIE (Position Independent Executable)
        # Check ELF header type (EXEC vs DYN) and dynamic tags
        results['PIE'] = self._check_pie(filepath)

        # 4. Check RELRO (Relocation Read-Only)
        # Check for GNU_RELRO segment and BIND_NOW flag
        results['RELRO'] = self._check_relro(filepath)

        return results

    def _run_command(self, cmd: list) -> Optional[str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None

    def _check_canary(self, filepath: str) -> str:
        # Try using nm to find symbols
        output = self._run_command(['nm', '-D', filepath])
        if not output:
             output = self._run_command(['objdump', '-t', filepath])
        
        if output:
            if '__stack_chk_fail' in output or '__stack_chk_guard' in output:
                return 'Enabled'
            return 'Disabled'
        
        # Fallback: grep binary content (less reliable but works if stripped sometimes)
        # This is risky as it might match strings, but for a simple check it's okay-ish
        # Better to rely on symbols. If no symbols found, we can't be sure.
        return 'Unknown'

    def _check_nx(self, filepath: str) -> str:
        # readelf -lW filepath | grep GNU_STACK
        output = self._run_command(['readelf', '-lW', filepath])
        if output:
            for line in output.split('\n'):
                if 'GNU_STACK' in line:
                    if 'RWE' in line:
                        return 'Disabled' # Stack is executable
                    elif 'RW' in line:
                        return 'Enabled'  # Stack is NOT executable
            # If GNU_STACK is missing, it defaults to executable on some older systems, 
            # but modern gcc implies NX. However, explicit header is best.
            return 'Unknown'
        
        # Fallback with objdump -p
        output = self._run_command(['objdump', '-p', filepath])
        if output:
             # Look for stack flags
             # This is harder to parse with objdump reliably across versions
             pass
             
        return 'Unknown'

    def _check_pie(self, filepath: str) -> str:
        # readelf -h filepath
        header_output = self._run_command(['readelf', '-h', filepath])
        if header_output:
            if 'Type:' in header_output:
                if 'EXEC (Executable file)' in header_output:
                    return 'Disabled' # Absolute address
                elif 'DYN (Shared object file)' in header_output:
                    # Could be PIE or a library. Check for DEBUG tag or similar?
                    # Actually, DYN executables are PIE.
                    # To distinguish PIE from Shared Lib, check for interpreter?
                    # readelf -l filepath | grep INTERP
                    segments_output = self._run_command(['readelf', '-lW', filepath])
                    if segments_output and 'INTERP' in segments_output:
                        return 'Enabled' # It has an interpreter, so it's a PIE executable
                    return 'DSO (Dynamic Shared Object)' # Likely a library
        return 'Unknown'

    def _check_relro(self, filepath: str) -> str:
        # readelf -lW filepath | grep GNU_RELRO
        # readelf -d filepath | grep BIND_NOW
        segments = self._run_command(['readelf', '-lW', filepath])
        dynamic = self._run_command(['readelf', '-d', filepath])
        
        has_relro = False
        if segments and 'GNU_RELRO' in segments:
            has_relro = True
            
        if has_relro:
            if dynamic and 'BIND_NOW' in dynamic:
                return 'Full'
            return 'Partial'
            
        return 'Disabled'
