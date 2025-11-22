#!/usr/bin/env python3
"""
Memory Dump Analyzer for DissectX

Analyzes memory dumps for:
- Injected code
- Hidden PE files
- Shellcode patterns
- Suspicious memory regions
- String extraction from dumps

Author: DissectX Team
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

try:
    from .memory_parser import MemoryPEParser, PEFILE_AVAILABLE
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class MemoryRegion:
    """Represents a memory region"""
    start_address: int
    size: int
    is_executable: bool
    is_writable: bool
    contains_pe: bool
    contains_shellcode: bool
    entropy: float


@dataclass
class HiddenPE:
    """Represents a hidden PE in memory"""
    offset: int
    size: int
    is_valid: bool
    is_manually_mapped: bool


class MemoryDumpAnalyzer:
    """Analyze memory dumps for malicious content"""
    
    # Shellcode patterns (common x86/x64 patterns)
    SHELLCODE_PATTERNS = [
        rb'\xEB[\x00-\xFF]\x5B',  # jmp short; pop ebx
        rb'\xE8\x00\x00\x00\x00[\x58-\x5F]',  # call $+5; pop reg (pop eax-edi)
        rb'\x64\x8B[\x00-\xFF]\x30',  # mov reg, fs:[0x30] (PEB)
        rb'\x65\x48\x8B[\x00-\xFF]\x60',  # mov reg, gs:[0x60] (PEB x64)
    ]
    
    def __init__(self):
        """Initialize memory dump analyzer"""
        self.pe_parser = MemoryPEParser() if PEFILE_AVAILABLE else None
    
    def analyze_dump(self, data: bytes, base_addr: int = 0) -> Dict:
        """
        Analyze memory dump
        
        Args:
            data: Memory dump data
            base_addr: Base address of dump
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'size': len(data),
            'base_address': base_addr,
            'hidden_pes': [],
            'shellcode_locations': [],
            'suspicious_strings': [],
            'entropy_regions': [],
        }
        
        # Find hidden PE files
        results['hidden_pes'] = self.find_hidden_pes(data, base_addr)
        
        # Find shellcode patterns
        results['shellcode_locations'] = self.find_shellcode(data, base_addr)
        
        # Extract suspicious strings
        results['suspicious_strings'] = self.extract_suspicious_strings(data)
        
        # Analyze entropy
        results['entropy_regions'] = self.analyze_entropy(data, base_addr)
        
        return results
    
    def find_hidden_pes(self, data: bytes, base_addr: int = 0) -> List[HiddenPE]:
        """
        Find hidden PE files in memory dump
        
        Args:
            data: Memory data
            base_addr: Base address
            
        Returns:
            List of hidden PEs
        """
        hidden_pes = []
        
        # Search for MZ header
        mz_pattern = b'MZ'
        offset = 0
        
        while True:
            offset = data.find(mz_pattern, offset)
            if offset == -1:
                break
            
            # Check if valid PE
            try:
                # Get PE header offset
                if offset + 0x3C + 4 > len(data):
                    offset += 1
                    continue
                
                pe_offset = struct.unpack('<I', data[offset + 0x3C:offset + 0x40])[0]
                
                # Check PE signature
                if offset + pe_offset + 4 > len(data):
                    offset += 1
                    continue
                
                pe_sig = data[offset + pe_offset:offset + pe_offset + 4]
                
                if pe_sig == b'PE\x00\x00':
                    # Found valid PE
                    # Try to determine size
                    pe_size = self._estimate_pe_size(data[offset:])
                    
                    # Check if manually mapped
                    is_manually_mapped = False
                    if self.pe_parser:
                        try:
                            analysis = self.pe_parser.parse_memory_dump(
                                data[offset:offset + pe_size],
                                base_addr + offset
                            )
                            is_manually_mapped = analysis.is_manually_mapped
                        except:
                            pass
                    
                    hidden_pe = HiddenPE(
                        offset=base_addr + offset,
                        size=pe_size,
                        is_valid=True,
                        is_manually_mapped=is_manually_mapped
                    )
                    hidden_pes.append(hidden_pe)
            
            except:
                pass
            
            offset += 1
        
        return hidden_pes
    
    def _estimate_pe_size(self, data: bytes) -> int:
        """Estimate PE size from headers"""
        try:
            # Read SizeOfImage from optional header
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            
            # Optional header is at PE_offset + 24
            opt_header_offset = pe_offset + 24
            
            # SizeOfImage is at offset 56 in optional header
            size_of_image = struct.unpack('<I', 
                data[opt_header_offset + 56:opt_header_offset + 60])[0]
            
            return min(size_of_image, len(data))
        except:
            return min(0x100000, len(data))  # Default 1MB
    
    def find_shellcode(self, data: bytes, base_addr: int = 0) -> List[Tuple[int, str]]:
        """
        Find shellcode patterns
        
        Args:
            data: Memory data
            base_addr: Base address
            
        Returns:
            List of (address, pattern_description)
        """
        locations = []
        
        for pattern in self.SHELLCODE_PATTERNS:
            for match in re.finditer(pattern, data):
                addr = base_addr + match.start()
                desc = self._describe_shellcode_pattern(pattern)
                locations.append((addr, desc))
        
        return locations
    
    def _describe_shellcode_pattern(self, pattern: bytes) -> str:
        """Describe shellcode pattern"""
        if b'\xEB' in pattern:
            return "JMP/POP pattern (GetPC)"
        elif b'\xE8\x00\x00\x00\x00' in pattern:
            return "CALL $+5 pattern (GetPC)"
        elif b'\x64\x8B' in pattern:
            return "PEB access (x86)"
        elif b'\x65\x48\x8B' in pattern:
            return "PEB access (x64)"
        return "Unknown shellcode pattern"
    
    def extract_suspicious_strings(self, data: bytes) -> List[str]:
        """Extract suspicious strings from memory"""
        # Extract ASCII strings
        strings = re.findall(rb'[\x20-\x7E]{6,}', data)
        strings = [s.decode('utf-8', errors='ignore') for s in strings]
        
        # Filter for suspicious content
        suspicious_keywords = [
            'http', 'https', 'www', '.exe', '.dll', '.bat',
            'cmd', 'powershell', 'rundll32', 'regsvr32',
            'password', 'admin', 'root', 'key', 'token',
            'inject', 'payload', 'shellcode', 'exploit'
        ]
        
        suspicious = []
        for string in strings:
            string_lower = string.lower()
            if any(kw in string_lower for kw in suspicious_keywords):
                if string not in suspicious:
                    suspicious.append(string)
        
        return suspicious[:50]  # Limit to 50
    
    def analyze_entropy(
        self, data: bytes, base_addr: int = 0, 
        block_size: int = 4096
    ) -> List[Tuple[int, float]]:
        """
        Analyze entropy of memory regions
        
        High entropy may indicate:
        - Encrypted/packed data
        - Compressed data
        - Random data
        
        Args:
            data: Memory data
            base_addr: Base address
            block_size: Size of blocks to analyze
            
        Returns:
            List of (address, entropy) for high-entropy regions
        """
        import math
        from collections import Counter
        
        high_entropy_regions = []
        
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            
            if len(block) < block_size // 2:
                continue
            
            # Calculate Shannon entropy
            counter = Counter(block)
            entropy = 0.0
            
            for count in counter.values():
                p = count / len(block)
                entropy -= p * math.log2(p)
            
            # High entropy threshold (>7.0 is very high)
            if entropy > 7.0:
                addr = base_addr + i
                high_entropy_regions.append((addr, entropy))
        
        return high_entropy_regions
    
    def format_report(self, results: Dict) -> str:
        """Format analysis results as report"""
        lines = []
        lines.append("=" * 70)
        lines.append("MEMORY DUMP ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        lines.append(f"Dump Size: 0x{results['size']:X} ({results['size']} bytes)")
        lines.append(f"Base Address: 0x{results['base_address']:X}")
        lines.append("")
        
        # Hidden PEs
        if results['hidden_pes']:
            lines.append(f"🔍 Hidden PE Files ({len(results['hidden_pes'])}):")
            for pe in results['hidden_pes']:
                mapped_str = " [MANUALLY MAPPED]" if pe.is_manually_mapped else ""
                lines.append(f"  • Offset: 0x{pe.offset:X}, Size: 0x{pe.size:X}{mapped_str}")
            lines.append("")
        
        # Shellcode
        if results['shellcode_locations']:
            lines.append(f"💉 Shellcode Patterns ({len(results['shellcode_locations'])}):")
            for addr, desc in results['shellcode_locations'][:10]:
                lines.append(f"  • 0x{addr:X}: {desc}")
            if len(results['shellcode_locations']) > 10:
                lines.append(f"  ... and {len(results['shellcode_locations']) - 10} more")
            lines.append("")
        
        # Suspicious strings
        if results['suspicious_strings']:
            lines.append(f"⚠️  Suspicious Strings ({len(results['suspicious_strings'])}):")
            for string in results['suspicious_strings'][:15]:
                lines.append(f"  • {string}")
            if len(results['suspicious_strings']) > 15:
                lines.append(f"  ... and {len(results['suspicious_strings']) - 15} more")
            lines.append("")
        
        # High entropy regions
        if results['entropy_regions']:
            lines.append(f"🔐 High Entropy Regions ({len(results['entropy_regions'])}):")
            lines.append("  (Possible encrypted/packed data)")
            for addr, entropy in results['entropy_regions'][:5]:
                lines.append(f"  • 0x{addr:X}: {entropy:.2f} bits/byte")
            if len(results['entropy_regions']) > 5:
                lines.append(f"  ... and {len(results['entropy_regions']) - 5} more")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python memory_dump_analyzer.py <dump.bin>")
        sys.exit(1)
    
    # Read dump
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    # Analyze
    analyzer = MemoryDumpAnalyzer()
    results = analyzer.analyze_dump(data, base_addr=0x400000)
    
    # Print report
    print(analyzer.format_report(results))
