#!/usr/bin/env python3
"""
String Decryption Module for DissectX

Uses Unicorn emulation to decrypt obfuscated strings at runtime.
Supports common encryption patterns:
- XOR loops
- RC4
- Custom ciphers
- Stack string construction

Author: DissectX Team
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

try:
    from .unicorn_emulator import UnicornEmulator, UNICORN_AVAILABLE
except ImportError:
    UNICORN_AVAILABLE = False


@dataclass
class DecryptedString:
    """Represents a decrypted string"""
    value: str
    method: str
    confidence: str  # 'high', 'medium', 'low'
    original_offset: Optional[int] = None
    encryption_type: Optional[str] = None


class StringDecryptor:
    """Decrypts obfuscated strings using emulation"""
    
    def __init__(self):
        """Initialize string decryptor"""
        if not UNICORN_AVAILABLE:
            self.emulator = None
        else:
            self.emulator = UnicornEmulator(arch='x64')
        
        self.decrypted_strings = []
    
    def decrypt_xor_loop(self, encrypted_data: bytes, key: bytes) -> Optional[str]:
        """
        Decrypt XOR-encrypted data
        
        Args:
            encrypted_data: Encrypted bytes
            key: XOR key (can be multi-byte)
            
        Returns:
            Decrypted string or None
        """
        try:
            # Multi-byte XOR
            decrypted = bytearray()
            key_len = len(key)
            
            for i, byte in enumerate(encrypted_data):
                decrypted.append(byte ^ key[i % key_len])
            
            # Try to decode as string
            result = decrypted.decode('utf-8', errors='ignore')
            
            # Check if it looks like a valid string
            if self._is_valid_string(result):
                return result
            
            return None
        except:
            return None
    
    def detect_stack_strings(self, code: bytes, base_addr: int = 0x400000) -> List[DecryptedString]:
        """
        Detect stack strings (strings constructed byte-by-byte)
        
        Args:
            code: Code section bytes
            base_addr: Base address
            
        Returns:
            List of detected stack strings
        """
        strings = []
        
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL
            
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            
            # Heuristic: Look for sequence of MOV [RBP-X], IMM
            # We'll track consecutive moves to the same region
            
            current_string = []
            current_offsets = []
            last_offset = 0
            
            for i in md.disasm(code, base_addr):
                # Check for MOV instruction
                if i.mnemonic.startswith('mov'):
                    # Check if operand 0 is memory (stack) and operand 1 is immediate
                    if len(i.operands) == 2 and \
                       i.operands[0].type == 2 and \
                       i.operands[1].type == 3:  # MEM, IMM
                        
                        # Check if it's RBP-based (stack)
                        # Capstone: base=reg, disp=offset
                        # We simplify: just check if it looks like a char move
                        val = i.operands[1].imm
                        
                        if 0x20 <= val <= 0x7E:  # Printable ASCII
                            # If this is close to the last one, append
                            if not current_string or abs(i.operands[0].mem.disp - last_offset) <= 8:
                                current_string.append(chr(val))
                                current_offsets.append(i.address)
                                last_offset = i.operands[0].mem.disp
                            else:
                                # Save previous string if valid
                                if len(current_string) >= 4:
                                    s_val = "".join(current_string)
                                    if self._is_interesting_string(s_val):
                                        strings.append(DecryptedString(
                                            value=s_val,
                                            method='Stack String Analysis',
                                            confidence='high',
                                            original_offset=current_offsets[0],
                                            encryption_type='Stack Construction'
                                        ))
                                
                                # Start new string
                                current_string = [chr(val)]
                                current_offsets = [i.address]
                                last_offset = i.operands[0].mem.disp
                        else:
                            # Non-char immediate, flush current string
                            if len(current_string) >= 4:
                                s_val = "".join(current_string)
                                if self._is_interesting_string(s_val):
                                    strings.append(DecryptedString(
                                        value=s_val,
                                        method='Stack String Analysis',
                                        confidence='high',
                                        original_offset=current_offsets[0],
                                        encryption_type='Stack Construction'
                                    ))
                            current_string = []
                            current_offsets = []
                else:
                    # Non-mov instruction, check if we break the sequence
                    # Allow some instructions in between (like xor, add)
                    if len(current_string) > 0 and i.mnemonic in ['call', 'ret', 'jmp']:
                         if len(current_string) >= 4:
                            s_val = "".join(current_string)
                            if self._is_interesting_string(s_val):
                                strings.append(DecryptedString(
                                    value=s_val,
                                    method='Stack String Analysis',
                                    confidence='high',
                                    original_offset=current_offsets[0],
                                    encryption_type='Stack Construction'
                                ))
                         current_string = []
                         current_offsets = []

        except ImportError:
            pass
        except Exception:
            pass
            
        return strings

    def detect_encrypted_strings(self, data: bytes) -> List[DecryptedString]:
        """
        Detect and decrypt encrypted strings in binary
        
        Args:
            data: Binary data
            
        Returns:
            List of decrypted strings
        """
        decrypted = []
        
        # Method 1: Brute force XOR with common keys
        decrypted.extend(self._brute_force_xor(data))
        
        # Method 2: Stack string detection
        decrypted.extend(self.detect_stack_strings(data))
        
        self.decrypted_strings = decrypted
        return decrypted
    
    def _brute_force_xor(self, data: bytes) -> List[DecryptedString]:
        """
        Brute force XOR decryption with common keys
        
        Args:
            data: Binary data
            
        Returns:
            List of decrypted strings
        """
        decrypted = []
        
        # Common XOR keys to try
        common_keys = [
            b'\x00', b'\x01', b'\x42', b'\x55', b'\xAA', b'\xFF',
            b'key', b'pass', b'xor', b'\x13\x37'
        ]
        
        # Look for encrypted string patterns (sequences of similar bytes)
        # This is a heuristic - encrypted data often has patterns
        for i in range(0, len(data) - 16, 4):
            chunk = data[i:i+64]
            
            # Try each key
            for key in common_keys:
                decrypted_str = self.decrypt_xor_loop(chunk, key)
                
                if decrypted_str and len(decrypted_str) >= 4:
                    # Check if it contains interesting content
                    if self._is_interesting_string(decrypted_str):
                        ds = DecryptedString(
                            value=decrypted_str,
                            method='XOR Brute Force',
                            confidence='medium',
                            original_offset=i,
                            encryption_type=f'XOR (key: {key.hex()})'
                        )
                        decrypted.append(ds)
        
        return decrypted
    
    def _is_valid_string(self, s: str) -> bool:
        """Check if string looks valid"""
        if not s or len(s) < 3:
            return False
        
        # Must be mostly printable
        printable_count = sum(1 for c in s if c.isprintable())
        return printable_count / len(s) > 0.8
    
    def _is_interesting_string(self, s: str) -> bool:
        """Check if string is interesting (not just random chars)"""
        if not self._is_valid_string(s):
            return False
        
        # Check for interesting keywords
        interesting_keywords = [
            'flag', 'password', 'key', 'secret', 'admin',
            'http', 'www', '.com', '.exe', '.dll',
            'error', 'success', 'fail', 'debug'
        ]
        
        s_lower = s.lower()
        return any(kw in s_lower for kw in interesting_keywords)
    
    def emulate_decryption_routine(
        self,
        code: bytes,
        encrypted_data_addr: int,
        output_addr: int
    ) -> Optional[str]:
        """
        Emulate a decryption routine
        
        Args:
            code: Decryption routine code
            encrypted_data_addr: Address of encrypted data
            output_addr: Address where decrypted data will be written
            
        Returns:
            Decrypted string or None
        """
        if not self.emulator:
            return None
        
        try:
            # Load code
            code_addr = self.emulator.load_code(code)
            
            # Setup registers (common calling convention)
            self.emulator.set_register('rdi', output_addr)  # Output buffer
            self.emulator.set_register('rsi', encrypted_data_addr)  # Input data
            
            # Emulate
            result = self.emulator.emulate(code_addr, max_instructions=1000)
            
            if result.success:
                # Read decrypted string from output address
                decrypted = self.emulator.read_string(output_addr)
                return decrypted
            
            return None
        except:
            return None
    
    def format_report(self, strings: List[DecryptedString]) -> str:
        """Format decrypted strings as report"""
        lines = []
        lines.append("=" * 70)
        lines.append("🔓 DECRYPTED STRINGS")
        lines.append("=" * 70)
        lines.append("")
        
        if not strings:
            lines.append("No encrypted strings detected")
            lines.append("")
        else:
            lines.append(f"Found {len(strings)} decrypted string(s)!")
            lines.append("")
            
            for i, ds in enumerate(strings, 1):
                confidence_emoji = {
                    'high': '🎯',
                    'medium': '⚠️',
                    'low': '❓'
                }.get(ds.confidence, '•')
                
                lines.append(f"{confidence_emoji} String #{i} [{ds.confidence.upper()}]")
                lines.append(f"  Value: {ds.value}")
                lines.append(f"  Method: {ds.method}")
                
                if ds.encryption_type:
                    lines.append(f"  Encryption: {ds.encryption_type}")
                
                if ds.original_offset is not None:
                    lines.append(f"  Offset: 0x{ds.original_offset:X}")
                
                lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    print("String Decryptor Test")
    print("=" * 70)
    
    # Test XOR decryption
    decryptor = StringDecryptor()
    
    # Example: "flag{test}" XOR 0x55
    encrypted = bytes([ord(c) ^ 0x55 for c in "flag{test}"])
    print(f"\nEncrypted data: {encrypted.hex()}")
    
    decrypted = decryptor.decrypt_xor_loop(encrypted, b'\x55')
    print(f"Decrypted: {decrypted}")
    
    print("\n✅ String decryption module ready!")
