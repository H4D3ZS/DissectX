#!/usr/bin/env python3
"""
Flag Finder for DissectX

Automatically detects and extracts CTF flags from binaries using:
- Pattern matching (flag{...}, picoCTF{...}, HTB{...}, etc.)
- String analysis and decoding
- XOR brute force
- Base64 decoding
- ROT13/Caesar cipher
- Memory dump analysis

Author: DissectX Team
"""

import re
import base64
import binascii
from typing import List, Dict, Optional, Set
from dataclasses import dataclass


@dataclass
class Flag:
    """Represents a detected flag"""
    value: str
    confidence: str  # 'high', 'medium', 'low'
    method: str
    location: Optional[int] = None
    context: Optional[str] = None


class FlagFinder:
    """Automatically finds CTF flags in binaries"""
    
    # Common flag patterns
    FLAG_PATTERNS = [
        rb'picoCTF\{[^}]+\}',
        rb'flag\{[^}]+\}',
        rb'FLAG\{[^}]+\}',
        rb'HTB\{[^}]+\}',
        rb'CTF\{[^}]+\}',
        rb'CHTB\{[^}]+\}',
        rb'[a-zA-Z0-9_]+\{[a-zA-Z0-9_@!?-]+\}',  # Generic flag format
    ]
    
    # Suspicious strings that might be encoded flags
    SUSPICIOUS_KEYWORDS = [
        'password', 'key', 'secret', 'flag', 'answer',
        'correct', 'success', 'win', 'congrat'
    ]
    
    def __init__(self):
        """Initialize flag finder"""
        self.found_flags: List[Flag] = []
    
    def find_flags(self, data: bytes, strings: List[str]) -> List[Flag]:
        """
        Find all flags in binary data
        
        Args:
            data: Binary data
            strings: Extracted strings from binary
            
        Returns:
            List of found flags
        """
        flags = []
        
        # Method 1: Direct pattern matching in binary
        flags.extend(self._find_pattern_flags(data))
        
        # Method 2: Search in extracted strings
        flags.extend(self._find_string_flags(strings))
        
        # Method 3: Base64 decode suspicious strings
        flags.extend(self._find_base64_flags(strings))
        
        # Method 4: XOR brute force on suspicious data
        flags.extend(self._find_xor_flags(data))
        
        # Method 5: ROT13/Caesar on strings
        flags.extend(self._find_caesar_flags(strings))
        
        # Method 6: Hex-encoded flags
        flags.extend(self._find_hex_flags(strings))
        
        # Deduplicate and sort by confidence
        flags = self._deduplicate_flags(flags)
        
        self.found_flags = flags
        return flags
    
    def _find_pattern_flags(self, data: bytes) -> List[Flag]:
        """Find flags matching common patterns"""
        flags = []
        
        for pattern in self.FLAG_PATTERNS:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                try:
                    flag_value = match.group(0).decode('utf-8', errors='ignore')
                    
                    # Validate flag format
                    if self._is_valid_flag(flag_value):
                        confidence = 'high' if 'picoCTF' in flag_value or 'HTB' in flag_value else 'medium'
                        
                        flag = Flag(
                            value=flag_value,
                            confidence=confidence,
                            method='Pattern Match',
                            location=match.start()
                        )
                        flags.append(flag)
                except:
                    pass
        
        return flags
    
    def _find_string_flags(self, strings: List[str]) -> List[Flag]:
        """Find flags in extracted strings"""
        flags = []
        
        for string in strings:
            # Check if string matches flag pattern
            for pattern in self.FLAG_PATTERNS:
                pattern_str = pattern.decode('utf-8', errors='ignore')
                if re.search(pattern_str, string, re.IGNORECASE):
                    if self._is_valid_flag(string):
                        flag = Flag(
                            value=string,
                            confidence='high',
                            method='String Analysis'
                        )
                        flags.append(flag)
        
        return flags
    
    def _find_base64_flags(self, strings: List[str]) -> List[Flag]:
        """Try Base64 decoding on suspicious strings"""
        flags = []
        
        for string in strings:
            # Skip short strings
            if len(string) < 10:
                continue
            
            # Check if it looks like Base64
            if re.match(r'^[A-Za-z0-9+/]+=*$', string):
                try:
                    decoded = base64.b64decode(string).decode('utf-8', errors='ignore')
                    
                    # Check if decoded string is a flag
                    if self._is_valid_flag(decoded):
                        flag = Flag(
                            value=decoded,
                            confidence='high',
                            method='Base64 Decode',
                            context=f'Encoded: {string[:50]}...'
                        )
                        flags.append(flag)
                    # Check if it contains flag-like content
                    elif any(kw in decoded.lower() for kw in ['flag', 'pico', 'ctf']):
                        flag = Flag(
                            value=decoded,
                            confidence='medium',
                            method='Base64 Decode (Suspicious)',
                            context=f'Encoded: {string[:50]}...'
                        )
                        flags.append(flag)
                except:
                    pass
        
        return flags
    
    def _find_xor_flags(self, data: bytes) -> List[Flag]:
        """Brute force XOR on suspicious byte sequences"""
        flags = []
        
        # Look for sequences that might be XOR-encoded flags
        # Common pattern: "flag{" or "picoCTF{" XOR with single byte
        target_patterns = [
            (b'flag{', 'flag{'),
            (b'picoCTF{', 'picoCTF{'),
            (b'FLAG{', 'FLAG{'),
            (b'HTB{', 'HTB{'),
            (b'CTF{', 'CTF{')
        ]
        
        for pattern, pattern_name in target_patterns:
            # Try XOR with single byte keys (0-255)
            for key in range(1, 256):  # Skip key 0 (no encryption)
                # XOR the pattern
                xor_pattern = bytes(b ^ key for b in pattern)
                
                # Search for XOR'd pattern in binary
                offset = 0
                while True:
                    offset = data.find(xor_pattern, offset)
                    if offset == -1:
                        break
                    
                    # Found potential XOR'd flag, try to decode more
                    # Extract up to 100 bytes to get full flag
                    chunk_end = min(offset + 100, len(data))
                    chunk = data[offset:chunk_end]
                    decoded = bytes(b ^ key for b in chunk)
                    
                    try:
                        decoded_str = decoded.decode('utf-8', errors='ignore')
                        
                        # Try to extract complete flag first
                        flag_match = re.search(r'([a-zA-Z0-9_]+\{[^}]+\})', decoded_str)
                        
                        if flag_match:
                            flag_value_raw = flag_match.group(1)
                            flag_value = ''.join(c for c in flag_value_raw if c.isprintable())
                            
                            if self._is_valid_flag(flag_value):
                                flag = Flag(
                                    value=flag_value,
                                    confidence='high',
                                    method=f'XOR Decode (key: 0x{key:02x})',
                                    location=offset,
                                    context=f'Encrypted at offset 0x{offset:X}'
                                )
                                flags.append(flag)
                        else:
                            # Try partial flag (missing closing brace)
                            # Extract up to first non-alphanumeric/underscore after opening brace
                            partial_match = re.search(r'([a-zA-Z0-9_]+\{[a-zA-Z0-9_]+)', decoded_str)
                            if partial_match:
                                # Infer closing brace
                                flag_value = partial_match.group(1) + '}'
                                
                                if self._is_valid_flag(flag_value):
                                    flag = Flag(
                                        value=flag_value,
                                        confidence='medium',
                                        method=f'XOR Decode (key: 0x{key:02x}, partial)',
                                        location=offset,
                                        context=f'Encrypted at offset 0x{offset:X} (inferred closing brace)'
                                    )
                                    flags.append(flag)
                    except:
                        pass
                    
                    offset += 1  # Continue searching
        
        return flags
    
    def _find_caesar_flags(self, strings: List[str]) -> List[Flag]:
        """Try ROT13 and other Caesar shifts"""
        flags = []
        
        for string in strings:
            # Skip short strings
            if len(string) < 10:
                continue
            
            # Try ROT13 first (most common)
            rot13 = self._rot13(string)
            if self._is_valid_flag(rot13):
                flag = Flag(
                    value=rot13,
                    confidence='medium',
                    method='ROT13',
                    context=f'Original: {string}'
                )
                flags.append(flag)
            
            # Try other Caesar shifts (1-25)
            for shift in range(1, 26):
                if shift == 13:  # Already tried ROT13
                    continue
                
                shifted = self._caesar_shift(string, shift)
                if self._is_valid_flag(shifted):
                    flag = Flag(
                        value=shifted,
                        confidence='low',
                        method=f'Caesar Shift ({shift})',
                        context=f'Original: {string}'
                    )
                    flags.append(flag)
                    break  # Only take first match per string
        
        return flags
    
    def _find_hex_flags(self, strings: List[str]) -> List[Flag]:
        """Decode hex-encoded strings"""
        flags = []
        
        for string in strings:
            # Check if string is hex-encoded
            if re.match(r'^[0-9a-fA-F]+$', string) and len(string) >= 20 and len(string) % 2 == 0:
                try:
                    decoded = bytes.fromhex(string).decode('utf-8', errors='ignore')
                    
                    if self._is_valid_flag(decoded):
                        flag = Flag(
                            value=decoded,
                            confidence='medium',
                            method='Hex Decode',
                            context=f'Hex: {string[:50]}...'
                        )
                        flags.append(flag)
                except:
                    pass
        
        return flags
    
    def _is_valid_flag(self, text: str) -> bool:
        """Check if text looks like a valid flag"""
        if not text or len(text) < 5:
            return False
        
        # Check for common flag patterns
        flag_indicators = [
            'picoCTF{', 'flag{', 'FLAG{', 'HTB{', 'CTF{', 'CHTB{'
        ]
        
        text_lower = text.lower()
        
        # Must contain flag indicator and closing brace
        has_indicator = any(ind.lower() in text_lower for ind in flag_indicators)
        has_braces = '{' in text and '}' in text
        
        if has_indicator and has_braces:
            # Extract content between braces
            match = re.search(r'\{([^}]+)\}', text)
            if match:
                content = match.group(1)
                # Flag content should be reasonable length and contain valid characters
                if 3 <= len(content) <= 200 and re.match(r'^[a-zA-Z0-9_@!?-]+$', content):
                    return True
        
        return False
    
    def _rot13(self, text: str) -> str:
        """Apply ROT13 cipher"""
        return self._caesar_shift(text, 13)
    
    def _caesar_shift(self, text: str, shift: int) -> str:
        """Apply Caesar cipher with given shift"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shifted = chr((ord(char) - base + shift) % 26 + base)
                result.append(shifted)
            else:
                result.append(char)
        return ''.join(result)
    
    def _deduplicate_flags(self, flags: List[Flag]) -> List[Flag]:
        """Remove duplicate flags, keeping highest confidence"""
        seen = {}
        
        for flag in flags:
            if flag.value not in seen:
                seen[flag.value] = flag
            else:
                # Keep higher confidence version
                existing = seen[flag.value]
                confidence_order = {'high': 3, 'medium': 2, 'low': 1}
                
                if confidence_order.get(flag.confidence, 0) > confidence_order.get(existing.confidence, 0):
                    seen[flag.value] = flag
        
        # Sort by confidence
        return sorted(seen.values(), key=lambda f: {'high': 3, 'medium': 2, 'low': 1}.get(f.confidence, 0), reverse=True)
    
    def format_report(self, flags: List[Flag]) -> str:
        """Format flag findings as report"""
        lines = []
        lines.append("=" * 70)
        lines.append("🚩 FLAG DETECTION RESULTS")
        lines.append("=" * 70)
        lines.append("")
        
        if not flags:
            lines.append("❌ No flags detected")
            lines.append("")
            lines.append("💡 Try:")
            lines.append("  • Use --full for complete disassembly analysis")
            lines.append("  • Check for encrypted/packed sections")
            lines.append("  • Run the binary in a sandbox to extract runtime flags")
            lines.append("")
        else:
            lines.append(f"✅ Found {len(flags)} potential flag(s)!")
            lines.append("")
            
            for i, flag in enumerate(flags, 1):
                confidence_emoji = {
                    'high': '🎯',
                    'medium': '⚠️',
                    'low': '❓'
                }.get(flag.confidence, '•')
                
                lines.append(f"{confidence_emoji} Flag #{i} [{flag.confidence.upper()} CONFIDENCE]")
                lines.append(f"  Value: {flag.value}")
                lines.append(f"  Method: {flag.method}")
                
                if flag.location is not None:
                    lines.append(f"  Location: 0x{flag.location:X}")
                
                if flag.context:
                    lines.append(f"  Context: {flag.context}")
                
                lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python flag_finder.py <binary>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    
    # Extract strings (simplified)
    strings = re.findall(rb'[\x20-\x7E]{4,}', data)
    strings = [s.decode('utf-8', errors='ignore') for s in strings]
    
    finder = FlagFinder()
    flags = finder.find_flags(data, strings)
    print(finder.format_report(flags))
