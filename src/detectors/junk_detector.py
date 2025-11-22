#!/usr/bin/env python3
"""
Junk Code & Fake Symbol Detector for DissectX

Detects anti-analysis techniques used by protectors:
- Fake symbols (oversized strcmp, strlen, etc.)
- Redundant code blocks
- Opaque predicates
- Fake stack operations
- VMProtect/Themida signatures

Author: DissectX Team
"""

import re
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from collections import Counter


@dataclass
class FakeSymbol:
    """Represents a detected fake symbol"""
    name: str
    size: int
    count: int
    confidence: str


@dataclass
class JunkPattern:
    """Represents a detected junk code pattern"""
    pattern_type: str
    description: str
    locations: List[int]
    severity: str


class JunkDetector:
    """Detects junk code and anti-analysis patterns"""
    
    # Suspicious function names that are often fake
    SUSPICIOUS_NAMES = [
        'strcmp', 'strncmp', 'strcpy', 'strncpy', 'strlen', 'strcat', 'strncat',
        'memcmp', 'memcpy', 'memmove', 'memset', 'memchr',
        'malloc', 'free', 'calloc', 'realloc',
        'printf', 'sprintf', 'fprintf', 'snprintf',
        'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell',
    ]
    
    # Normal sizes for common functions (in bytes)
    NORMAL_FUNCTION_SIZES = {
        'strcmp': 100,
        'strncmp': 120,
        'strcpy': 80,
        'strlen': 60,
        'memcpy': 100,
        'memset': 80,
        'malloc': 150,
        'free': 100,
    }
    
    # VMProtect/Themida signatures
    PROTECTOR_SIGNATURES = {
        'vmprotect': [
            rb'\\x55\\x8B\\xEC\\x83\\xEC.{100,}',  # Complex prologue
            rb'\\xEB.\\xE8',  # Jump-call obfuscation
            rb'[\\x90\\xCC]{10,}',  # Long NOP/INT3 sequences
        ],
        'themida': [
            rb'\\x60\\x9C',  # PUSHAD; PUSHFD
            rb'\\xE8\\x00\\x00\\x00\\x00\\x58[\\x00-\\x07]',  # call $+5; pop eax (fixed range)
            rb'[\\x87-\\x8F]{5,}',  # Multiple XCHG instructions
        ],
    }
    
    def __init__(self):
        """Initialize junk detector"""
        self.fake_symbols: List[FakeSymbol] = []
        self.junk_patterns: List[JunkPattern] = []
        self.protector_detected: Optional[str] = None
    
    def detect_fake_symbols(self, data: bytes, symbols: Optional[Dict[str, int]] = None) -> List[FakeSymbol]:
        """
        Detect fake symbols (oversized common functions)
        
        Args:
            data: Binary data
            symbols: Dictionary of {symbol_name: size} if available
            
        Returns:
            List of detected fake symbols
        """
        if symbols is None:
            # Try to extract symbols from binary
            symbols = self._extract_symbols_heuristic(data)
        
        fake_symbols = []
        symbol_counts = Counter()
        
        for name, size in symbols.items():
            # Count occurrences of suspicious names
            if any(susp in name.lower() for susp in self.SUSPICIOUS_NAMES):
                symbol_counts[name] += 1
                
                # Check if size is suspiciously large
                base_name = name.lower()
                for susp_name in self.SUSPICIOUS_NAMES:
                    if susp_name in base_name:
                        normal_size = self.NORMAL_FUNCTION_SIZES.get(susp_name, 200)
                        
                        if size > normal_size * 10:  # 10x larger than normal
                            confidence = 'high' if size > normal_size * 50 else 'medium'
                            
                            fake = FakeSymbol(
                                name=name,
                                size=size,
                                count=1,
                                confidence=confidence
                            )
                            fake_symbols.append(fake)
        
        # Detect duplicate suspicious names
        for name, count in symbol_counts.items():
            if count > 3:  # More than 3 functions with same name
                fake = FakeSymbol(
                    name=name,
                    size=0,
                    count=count,
                    confidence='high'
                )
                fake_symbols.append(fake)
        
        self.fake_symbols = fake_symbols
        return fake_symbols
    
    def _extract_symbols_heuristic(self, data: bytes) -> Dict[str, int]:
        """
        Heuristically extract symbols from binary
        (simplified - real implementation would parse PE/ELF)
        """
        symbols = {}
        
        # Look for common function name strings
        for name in self.SUSPICIOUS_NAMES:
            pattern = name.encode('ascii')
            for match in re.finditer(pattern, data):
                # Assume function size of 1000 bytes (placeholder)
                symbols[name] = 1000
        
        return symbols
    
    def detect_redundant_blocks(self, data: bytes, min_size: int = 50) -> List[JunkPattern]:
        """
        Detect redundant/duplicate code blocks
        
        Args:
            data: Binary data
            min_size: Minimum block size to consider
            
        Returns:
            List of detected redundant patterns
        """
        patterns = []
        block_hashes = {}
        
        # Slide through binary looking for repeated sequences
        for i in range(0, len(data) - min_size, 16):
            block = data[i:i+min_size]
            block_hash = hash(block)
            
            if block_hash in block_hashes:
                block_hashes[block_hash].append(i)
            else:
                block_hashes[block_hash] = [i]
        
        # Find blocks that appear multiple times
        for block_hash, locations in block_hashes.items():
            if len(locations) >= 3:  # Appears 3+ times
                pattern = JunkPattern(
                    pattern_type='redundant_block',
                    description=f'Code block repeated {len(locations)} times',
                    locations=locations[:10],  # Limit to first 10
                    severity='medium' if len(locations) < 10 else 'high'
                )
                patterns.append(pattern)
        
        return patterns
    
    def detect_opaque_predicates(self, data: bytes) -> List[JunkPattern]:
        """
        Detect opaque predicates (always true/false conditions)
        
        Common patterns:
        - cmp eax, eax; jz/jnz (always equal)
        - test eax, eax; jz after xor eax, eax (always zero)
        - Pointless arithmetic that always produces same result
        """
        patterns = []
        
        # Pattern 1: cmp reg, reg (always equal)
        cmp_same_reg = rb'[\x38-\x3D][\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF]'
        locations = [m.start() for m in re.finditer(cmp_same_reg, data)]
        if locations:
            pattern = JunkPattern(
                pattern_type='opaque_predicate',
                description='Compare register with itself (always equal)',
                locations=locations[:20],
                severity='low'
            )
            patterns.append(pattern)
        
        # Pattern 2: xor reg, reg followed by test/cmp
        xor_test = rb'[\x30-\x35][\xC0\xC9\xD2\xDB\xE4\xED\xF6\xFF][\x84-\x85]'
        locations = [m.start() for m in re.finditer(xor_test, data)]
        if locations:
            pattern = JunkPattern(
                pattern_type='opaque_predicate',
                description='XOR reg,reg followed by test (always zero)',
                locations=locations[:20],
                severity='low'
            )
            patterns.append(pattern)
        
        # Pattern 3: add/sub rsp, X followed by sub/add rsp, X (fake stack)
        fake_stack = rb'\x48[\x81\x83][\xC4\xEC].{1,4}\x48[\x81\x83][\xC4\xEC]'
        locations = [m.start() for m in re.finditer(fake_stack, data)]
        if len(locations) > 10:
            pattern = JunkPattern(
                pattern_type='fake_stack_ops',
                description='Fake stack frame operations (add/sub rsp pairs)',
                locations=locations[:20],
                severity='medium'
            )
            patterns.append(pattern)
        
        return patterns
    
    def detect_protector(self, data: bytes) -> Optional[str]:
        """
        Detect commercial protector signatures
        
        Returns:
            Name of detected protector or None
        """
        for protector, signatures in self.PROTECTOR_SIGNATURES.items():
            matches = 0
            for signature in signatures:
                if re.search(signature, data):
                    matches += 1
            
            # If 2+ signatures match, likely this protector
            if matches >= 2:
                self.protector_detected = protector
                return protector
        
        return None
    
    def detect_long_loops(self, data: bytes) -> List[JunkPattern]:
        """
        Detect suspiciously long loops (anti-analysis)
        
        Common pattern: Loop that iterates 1000+ times doing nothing useful
        """
        patterns = []
        
        # Look for loop patterns with large counters
        # Pattern: mov ecx, LARGE_NUMBER; loop_start: ... dec ecx; jnz loop_start
        loop_pattern = rb'\xB9[\x00-\xFF]{4}.{10,100}\x49\x75'
        
        for match in re.finditer(loop_pattern, data):
            # Extract counter value
            counter_bytes = match.group(0)[1:5]
            counter = int.from_bytes(counter_bytes, 'little')
            
            if counter > 1000:
                pattern = JunkPattern(
                    pattern_type='long_loop',
                    description=f'Loop with counter {counter} (likely anti-analysis)',
                    locations=[match.start()],
                    severity='high' if counter > 10000 else 'medium'
                )
                patterns.append(pattern)
        
        return patterns
    
    def analyze(self, data: bytes, symbols: Optional[Dict[str, int]] = None) -> Dict:
        """
        Perform complete junk code analysis
        
        Args:
            data: Binary data to analyze
            symbols: Optional symbol table
            
        Returns:
            Dictionary containing analysis results
        """
        # Run all detections
        fake_symbols = self.detect_fake_symbols(data, symbols)
        redundant = self.detect_redundant_blocks(data)
        opaque = self.detect_opaque_predicates(data)
        long_loops = self.detect_long_loops(data)
        protector = self.detect_protector(data)
        
        # Combine all junk patterns
        all_patterns = redundant + opaque + long_loops
        self.junk_patterns = all_patterns
        
        # Build results
        results = {
            'fake_symbols_count': len(fake_symbols),
            'fake_symbols': [],
            'junk_patterns_count': len(all_patterns),
            'junk_patterns': [],
            'protector_detected': protector,
            'threat_level': self._assess_threat_level(fake_symbols, all_patterns, protector),
        }
        
        # Add fake symbol details
        for symbol in fake_symbols:
            results['fake_symbols'].append({
                'name': symbol.name,
                'size': symbol.size if symbol.size > 0 else 'N/A',
                'count': symbol.count,
                'confidence': symbol.confidence.upper(),
            })
        
        # Add junk pattern details
        pattern_summary = Counter()
        for pattern in all_patterns:
            pattern_summary[pattern.pattern_type] += 1
        
        for pattern_type, count in pattern_summary.items():
            results['junk_patterns'].append({
                'type': pattern_type.replace('_', ' ').title(),
                'count': count,
            })
        
        return results
    
    def _assess_threat_level(self, fake_symbols: List, patterns: List, protector: Optional[str]) -> str:
        """Assess overall threat level"""
        if protector or len(fake_symbols) > 20 or len(patterns) > 50:
            return 'CRITICAL'
        elif len(fake_symbols) > 10 or len(patterns) > 20:
            return 'HIGH'
        elif len(fake_symbols) > 0 or len(patterns) > 0:
            return 'MEDIUM'
        return 'NONE'
    
    def format_report(self, results: Dict) -> str:
        """
        Format analysis results as human-readable report
        
        Args:
            results: Analysis results from analyze()
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 70)
        lines.append("JUNK CODE & ANTI-ANALYSIS DETECTION")
        lines.append("=" * 70)
        lines.append("")
        
        # Threat level
        threat = results['threat_level']
        if threat != 'NONE':
            lines.append(f"⚠️  THREAT LEVEL: {threat}")
            lines.append("")
        
        # Protector detection
        if results['protector_detected']:
            protector = results['protector_detected'].upper()
            lines.append(f"🛡️  PROTECTOR DETECTED: {protector}")
            lines.append("  This binary is protected by commercial obfuscation software.")
            lines.append("")
        
        # Fake symbols
        if results['fake_symbols_count'] > 0:
            lines.append(f"🎭 Fake Symbols Detected ({results['fake_symbols_count']}):")
            lines.append("")
            
            for symbol in results['fake_symbols'][:20]:
                if symbol['size'] != 'N/A':
                    lines.append(f"  • {symbol['name']} - {symbol['size']} bytes [{symbol['confidence']}]")
                else:
                    lines.append(f"  • {symbol['name']} - appears {symbol['count']} times [{symbol['confidence']}]")
            
            if results['fake_symbols_count'] > 20:
                lines.append(f"  ... and {results['fake_symbols_count'] - 20} more")
            lines.append("")
        
        # Junk patterns
        if results['junk_patterns_count'] > 0:
            lines.append(f"🗑️  Junk Code Patterns ({results['junk_patterns_count']} total):")
            lines.append("")
            
            for pattern in results['junk_patterns']:
                lines.append(f"  • {pattern['type']}: {pattern['count']} instances")
            lines.append("")
        
        # Recommendations
        if threat != 'NONE':
            lines.append("💡 RECOMMENDATIONS:")
            lines.append("  • This binary contains significant anti-analysis techniques")
            lines.append("  • Static analysis may be unreliable")
            lines.append("  • Consider dynamic analysis or emulation")
            if results['protector_detected']:
                lines.append(f"  • Use {results['protector_detected']}-specific unpacking tools")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python junk_detector.py <binary.exe>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    
    detector = JunkDetector()
    results = detector.analyze(data)
    print(detector.format_report(results))
