#!/usr/bin/env python3
"""
ShellcodeDetector for DissectX    Framework

Detects, extracts, emulates, and deobfuscates shellcode in binary data.
Provides comprehensive shellcode analysis with safety guarantees.

Requirements: 19.1, 19.2, 19.3, 19.4, 19.5
"""

import re
import struct
import logging
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import Unicorn for emulation
try:
    from src.emulation.unicorn_emulator import UnicornEmulator, UNICORN_AVAILABLE
except ImportError:
    UNICORN_AVAILABLE = False
    logger.warning("Unicorn emulator not available. Emulation features will be disabled.")


class ShellcodeType(Enum):
    """Types of shellcode patterns"""
    GET_PC = "GetPC"  # Position-independent code patterns
    PEB_WALKING = "PEB Walking"  # Process Environment Block traversal
    STACK_STRING = "Stack String"  # String construction on stack
    ENCODED = "Encoded"  # Encoded/obfuscated shellcode
    SYSCALL = "Syscall"  # Direct syscall usage
    API_HASHING = "API Hashing"  # API resolution via hashing
    UNKNOWN = "Unknown"


@dataclass
class ShellcodePattern:
    """Represents a detected shellcode pattern"""
    pattern_type: ShellcodeType
    address: int
    size: int
    confidence: float  # 0.0 to 1.0
    description: str
    bytes_data: bytes = b''
    disassembly: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return (f"[{self.pattern_type.value}] at 0x{self.address:X} "
                f"(size: {self.size}, confidence: {self.confidence:.2f})")


@dataclass
class ExtractedShellcode:
    """Represents extracted shellcode"""
    address: int
    bytes_data: bytes
    size: int
    patterns: List[ShellcodePattern]
    confidence: float
    
    def __str__(self) -> str:
        return (f"Shellcode at 0x{self.address:X} ({self.size} bytes, "
                f"confidence: {self.confidence:.2f})")


@dataclass
class EmulationResult:
    """Results from shellcode emulation"""
    success: bool
    instructions_executed: int
    output_strings: List[str] = field(default_factory=list)
    memory_writes: List[Tuple[int, bytes]] = field(default_factory=list)
    syscalls: List[Tuple[int, str]] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class DeobfuscatedShellcode:
    """Deobfuscated shellcode data"""
    original_bytes: bytes
    deobfuscated_bytes: bytes
    method: str  # XOR, ROR, ADD, etc.
    key: Optional[int] = None
    confidence: float = 0.0


@dataclass
class ShellcodeAnalysisReport:
    """Comprehensive shellcode analysis report"""
    detected_patterns: List[ShellcodePattern]
    extracted_shellcode: List[ExtractedShellcode]
    emulation_results: List[EmulationResult]
    deobfuscated: List[DeobfuscatedShellcode]
    total_shellcode_bytes: int = 0
    high_confidence_count: int = 0
    
    def __post_init__(self):
        """Calculate statistics"""
        self.total_shellcode_bytes = sum(s.size for s in self.extracted_shellcode)
        self.high_confidence_count = sum(1 for s in self.extracted_shellcode 
                                        if s.confidence >= 0.7)


class ShellcodeDetector:
    """
    Detects and analyzes shellcode in binary data.
    
    Features (Requirement 19.1):
    - GetPC pattern detection (call/pop, fstenv, etc.)
    - PEB walking detection (fs:[0x30], gs:[0x60])
    - Stack string detection
    - Encoded shellcode detection
    - Syscall pattern detection
    - API hashing detection
    
    Extraction (Requirement 19.2):
    - Extract complete shellcode byte sequences
    - Identify shellcode boundaries
    
    Emulation (Requirement 19.3):
    - Safe sandboxed emulation
    - String extraction from execution
    - Behavior analysis
    
    Deobfuscation (Requirement 19.4):
    - XOR decoding
    - ROR/ROL decoding
    - ADD/SUB decoding
    - Multi-stage decoding
    
    Reporting (Requirement 19.5):
    - Comprehensive analysis reports
    - Pattern summaries
    - Confidence scoring
    """
    
    # GetPC patterns (Requirement 19.1)
    GET_PC_PATTERNS = {
        'call_pop': {
            'pattern': rb'\xE8\x00\x00\x00\x00[\x58-\x5F]',  # call $+5; pop reg
            'description': 'Call/Pop GetPC technique',
            'confidence': 0.9
        },
        'fstenv': {
            'pattern': rb'\xD9\x74\x24\xF4',  # fstenv [esp-0xc]
            'description': 'FSTENV GetPC technique',
            'confidence': 0.85
        },
        'fnstenv': {
            'pattern': rb'\xD9\x34\x24',  # fnstenv [esp]
            'description': 'FNSTENV GetPC technique',
            'confidence': 0.85
        }
    }
    
    # PEB walking patterns (Requirement 19.1)
    PEB_PATTERNS = {
        'fs_peb_x86': {
            'pattern': rb'\x64\x8B[\x00-\xFF]\x30',  # mov reg, fs:[0x30]
            'description': 'PEB access via FS segment (x86)',
            'confidence': 0.8
        },
        'gs_peb_x64': {
            'pattern': rb'\x65\x48\x8B[\x00-\xFF]{2}\x60',  # mov reg, gs:[0x60]
            'description': 'PEB access via GS segment (x64)',
            'confidence': 0.8
        },
        'peb_ldr': {
            'pattern': rb'[\x8B\x48][\x00-\xFF]\x0C',  # mov reg, [reg+0xC] (PEB_LDR_DATA)
            'description': 'PEB_LDR_DATA access',
            'confidence': 0.7
        }
    }
    
    # Stack string patterns (Requirement 19.1)
    STACK_STRING_PATTERNS = {
        'push_sequence': {
            'pattern': rb'(?:\x68[\x00-\xFF]{4}){2,}',  # Multiple push imm32 (2 or more)
            'description': 'Stack string construction via push',
            'confidence': 0.75
        },
        'mov_stack': {
            'pattern': rb'(?:\xC7[\x44-\x45]\x24[\x00-\xFF][\x00-\xFF]{4}){2,}',  # mov [esp+X], imm32
            'description': 'Stack string construction via mov',
            'confidence': 0.7
        }
    }
    
    # Syscall patterns (Requirement 19.1)
    SYSCALL_PATTERNS = {
        'syscall_x64': {
            'pattern': rb'\x0F\x05',  # syscall
            'description': 'Direct syscall (x64)',
            'confidence': 0.6
        },
        'sysenter': {
            'pattern': rb'\x0F\x34',  # sysenter
            'description': 'Sysenter instruction',
            'confidence': 0.6
        },
        'int_80': {
            'pattern': rb'\xCD\x80',  # int 0x80
            'description': 'Linux syscall (x86)',
            'confidence': 0.6
        }
    }
    
    # API hashing patterns (Requirement 19.1)
    API_HASH_PATTERNS = {
        'ror13_hash': {
            'pattern': rb'\xC1[\xC8-\xCF]\x0D',  # ror reg, 0xD
            'description': 'ROR13 API hashing',
            'confidence': 0.75
        },
        'crc32_hash': {
            'pattern': rb'\xF2\x0F\x38\xF1',  # crc32
            'description': 'CRC32 API hashing',
            'confidence': 0.8
        }
    }
    
    def __init__(self, enable_emulation: bool = True):
        """
        Initialize ShellcodeDetector.
        
        Args:
            enable_emulation: Enable emulation features (requires Unicorn)
        """
        self.enable_emulation = enable_emulation and UNICORN_AVAILABLE
        
        if enable_emulation and not UNICORN_AVAILABLE:
            logger.warning("Emulation requested but Unicorn not available")
        
        self.detected_patterns: List[ShellcodePattern] = []
        self.extracted_shellcode: List[ExtractedShellcode] = []
        
        logger.info(f"ShellcodeDetector initialized (emulation: {self.enable_emulation})")
    
    def detect_patterns(self, data: bytes, base_address: int = 0) -> List[ShellcodePattern]:
        """
        Detect shellcode patterns in binary data (Requirement 19.1).
        
        Args:
            data: Binary data to analyze
            base_address: Base address for offset calculation
            
        Returns:
            List of detected shellcode patterns
        """
        patterns = []
        
        # Detect GetPC patterns
        patterns.extend(self._detect_getpc_patterns(data, base_address))
        
        # Detect PEB walking
        patterns.extend(self._detect_peb_patterns(data, base_address))
        
        # Detect stack strings
        patterns.extend(self._detect_stack_strings(data, base_address))
        
        # Detect syscalls
        patterns.extend(self._detect_syscalls(data, base_address))
        
        # Detect API hashing
        patterns.extend(self._detect_api_hashing(data, base_address))
        
        self.detected_patterns = patterns
        return patterns
    
    def _detect_getpc_patterns(self, data: bytes, base_address: int) -> List[ShellcodePattern]:
        """Detect GetPC (position-independent code) patterns."""
        patterns = []
        
        for name, info in self.GET_PC_PATTERNS.items():
            for match in re.finditer(info['pattern'], data):
                pattern = ShellcodePattern(
                    pattern_type=ShellcodeType.GET_PC,
                    address=base_address + match.start(),
                    size=len(match.group(0)),
                    confidence=info['confidence'],
                    description=info['description'],
                    bytes_data=match.group(0)
                )
                patterns.append(pattern)
                logger.debug(f"Detected GetPC pattern: {name} at 0x{pattern.address:X}")
        
        return patterns
    
    def _detect_peb_patterns(self, data: bytes, base_address: int) -> List[ShellcodePattern]:
        """Detect PEB walking patterns."""
        patterns = []
        
        for name, info in self.PEB_PATTERNS.items():
            for match in re.finditer(info['pattern'], data):
                pattern = ShellcodePattern(
                    pattern_type=ShellcodeType.PEB_WALKING,
                    address=base_address + match.start(),
                    size=len(match.group(0)),
                    confidence=info['confidence'],
                    description=info['description'],
                    bytes_data=match.group(0)
                )
                patterns.append(pattern)
                logger.debug(f"Detected PEB pattern: {name} at 0x{pattern.address:X}")
        
        return patterns
    
    def _detect_stack_strings(self, data: bytes, base_address: int) -> List[ShellcodePattern]:
        """Detect stack string construction patterns."""
        patterns = []
        
        for name, info in self.STACK_STRING_PATTERNS.items():
            for match in re.finditer(info['pattern'], data):
                pattern = ShellcodePattern(
                    pattern_type=ShellcodeType.STACK_STRING,
                    address=base_address + match.start(),
                    size=len(match.group(0)),
                    confidence=info['confidence'],
                    description=info['description'],
                    bytes_data=match.group(0)
                )
                patterns.append(pattern)
                logger.debug(f"Detected stack string: {name} at 0x{pattern.address:X}")
        
        return patterns
    
    def _detect_syscalls(self, data: bytes, base_address: int) -> List[ShellcodePattern]:
        """Detect direct syscall patterns."""
        patterns = []
        
        for name, info in self.SYSCALL_PATTERNS.items():
            for match in re.finditer(info['pattern'], data):
                pattern = ShellcodePattern(
                    pattern_type=ShellcodeType.SYSCALL,
                    address=base_address + match.start(),
                    size=len(match.group(0)),
                    confidence=info['confidence'],
                    description=info['description'],
                    bytes_data=match.group(0)
                )
                patterns.append(pattern)
                logger.debug(f"Detected syscall: {name} at 0x{pattern.address:X}")
        
        return patterns
    
    def _detect_api_hashing(self, data: bytes, base_address: int) -> List[ShellcodePattern]:
        """Detect API hashing patterns."""
        patterns = []
        
        for name, info in self.API_HASH_PATTERNS.items():
            for match in re.finditer(info['pattern'], data):
                pattern = ShellcodePattern(
                    pattern_type=ShellcodeType.API_HASHING,
                    address=base_address + match.start(),
                    size=len(match.group(0)),
                    confidence=info['confidence'],
                    description=info['description'],
                    bytes_data=match.group(0)
                )
                patterns.append(pattern)
                logger.debug(f"Detected API hashing: {name} at 0x{pattern.address:X}")
        
        return patterns

    
    def extract_shellcode(
        self, 
        data: bytes, 
        patterns: Optional[List[ShellcodePattern]] = None,
        base_address: int = 0
    ) -> List[ExtractedShellcode]:
        """
        Extract shellcode byte sequences (Requirement 19.2).
        
        Args:
            data: Binary data
            patterns: Detected patterns (if None, will detect first)
            base_address: Base address for offset calculation
            
        Returns:
            List of extracted shellcode sequences
        """
        if patterns is None:
            patterns = self.detect_patterns(data, base_address)
        
        if not patterns:
            logger.info("No shellcode patterns detected")
            return []
        
        # Group nearby patterns into shellcode regions
        shellcode_regions = self._group_patterns_into_regions(patterns, data, base_address)
        
        # Extract bytes for each region
        extracted = []
        for region_start, region_end, region_patterns in shellcode_regions:
            # Calculate confidence based on patterns
            confidence = self._calculate_region_confidence(region_patterns)
            
            # Extract bytes
            start_offset = region_start - base_address
            end_offset = region_end - base_address
            
            if 0 <= start_offset < len(data) and 0 <= end_offset <= len(data):
                shellcode_bytes = data[start_offset:end_offset]
                
                shellcode = ExtractedShellcode(
                    address=region_start,
                    bytes_data=shellcode_bytes,
                    size=len(shellcode_bytes),
                    patterns=region_patterns,
                    confidence=confidence
                )
                extracted.append(shellcode)
                logger.info(f"Extracted shellcode: {shellcode}")
        
        self.extracted_shellcode = extracted
        return extracted
    
    def _group_patterns_into_regions(
        self, 
        patterns: List[ShellcodePattern],
        data: bytes,
        base_address: int
    ) -> List[Tuple[int, int, List[ShellcodePattern]]]:
        """
        Group nearby patterns into contiguous shellcode regions.
        
        Args:
            patterns: Detected patterns
            data: Binary data
            base_address: Base address
            
        Returns:
            List of (start_addr, end_addr, patterns) tuples
        """
        if not patterns:
            return []
        
        # Sort patterns by address
        sorted_patterns = sorted(patterns, key=lambda p: p.address)
        
        # Group patterns within 256 bytes of each other
        MAX_GAP = 256
        regions = []
        current_region = [sorted_patterns[0]]
        
        for pattern in sorted_patterns[1:]:
            last_pattern = current_region[-1]
            gap = pattern.address - (last_pattern.address + last_pattern.size)
            
            if gap <= MAX_GAP:
                # Add to current region
                current_region.append(pattern)
            else:
                # Start new region
                regions.append(current_region)
                current_region = [pattern]
        
        # Add last region
        if current_region:
            regions.append(current_region)
        
        # Convert to (start, end, patterns) tuples
        result = []
        for region in regions:
            start = region[0].address
            # Extend region to include some context
            start = max(base_address, start - 32)
            
            last = region[-1]
            end = last.address + last.size + 32
            end = min(base_address + len(data), end)
            
            result.append((start, end, region))
        
        return result
    
    def _calculate_region_confidence(self, patterns: List[ShellcodePattern]) -> float:
        """
        Calculate confidence score for a shellcode region.
        
        Args:
            patterns: Patterns in the region
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not patterns:
            return 0.0
        
        # Average pattern confidence
        avg_confidence = sum(p.confidence for p in patterns) / len(patterns)
        
        # Bonus for multiple pattern types
        pattern_types = set(p.pattern_type for p in patterns)
        type_bonus = min(0.2, len(pattern_types) * 0.05)
        
        # Bonus for high-confidence patterns (GetPC, PEB)
        high_conf_patterns = sum(1 for p in patterns 
                                if p.pattern_type in [ShellcodeType.GET_PC, ShellcodeType.PEB_WALKING])
        high_conf_bonus = min(0.15, high_conf_patterns * 0.05)
        
        confidence = min(1.0, avg_confidence + type_bonus + high_conf_bonus)
        return confidence
    
    def emulate_shellcode(
        self, 
        shellcode: ExtractedShellcode,
        timeout_ms: int = 1000,
        max_instructions: int = 5000
    ) -> EmulationResult:
        """
        Safely emulate shellcode in sandbox (Requirement 19.3).
        
        Args:
            shellcode: Extracted shellcode to emulate
            timeout_ms: Emulation timeout in milliseconds
            max_instructions: Maximum instructions to execute
            
        Returns:
            EmulationResult with execution details
        """
        if not self.enable_emulation:
            return EmulationResult(
                success=False,
                instructions_executed=0,
                error="Emulation not enabled or Unicorn not available"
            )
        
        try:
            # Create emulator instance
            emu = UnicornEmulator(arch='x64', enable_syscalls=True)
            
            # Load shellcode
            addr = emu.load_code(shellcode.bytes_data)
            
            # Emulate
            logger.info(f"Emulating shellcode at 0x{shellcode.address:X} ({shellcode.size} bytes)")
            result = emu.emulate(addr, count=max_instructions, timeout_ms=timeout_ms)
            
            # Convert to our result format
            return EmulationResult(
                success=result.success,
                instructions_executed=result.instructions_executed,
                output_strings=result.output_strings,
                memory_writes=result.memory_writes,
                syscalls=result.syscalls_invoked,
                error=result.error
            )
            
        except Exception as e:
            logger.error(f"Emulation failed: {e}")
            return EmulationResult(
                success=False,
                instructions_executed=0,
                error=str(e)
            )
    
    def deobfuscate_shellcode(self, data: bytes) -> List[DeobfuscatedShellcode]:
        """
        Attempt to deobfuscate encoded shellcode (Requirement 19.4).
        
        Tries multiple decoding methods:
        - XOR with single-byte keys
        - ROR/ROL operations
        - ADD/SUB operations
        - Multi-stage decoding
        
        Args:
            data: Potentially obfuscated shellcode
            
        Returns:
            List of deobfuscation results
        """
        results = []
        
        # Try XOR decoding
        results.extend(self._try_xor_decode(data))
        
        # Try ROR decoding
        results.extend(self._try_ror_decode(data))
        
        # Try ADD/SUB decoding
        results.extend(self._try_add_decode(data))
        
        # Sort by confidence
        results.sort(key=lambda r: r.confidence, reverse=True)
        
        return results
    
    def _try_xor_decode(self, data: bytes) -> List[DeobfuscatedShellcode]:
        """Try XOR decoding with various keys."""
        results = []
        
        # Try single-byte XOR keys
        for key in range(1, 256):
            decoded = bytes([b ^ key for b in data])
            
            # Check if decoded data looks like code
            confidence = self._assess_code_likelihood(decoded)
            
            if confidence > 0.5:
                result = DeobfuscatedShellcode(
                    original_bytes=data,
                    deobfuscated_bytes=decoded,
                    method="XOR",
                    key=key,
                    confidence=confidence
                )
                results.append(result)
        
        return results
    
    def _try_ror_decode(self, data: bytes) -> List[DeobfuscatedShellcode]:
        """Try ROR (rotate right) decoding."""
        results = []
        
        # Try ROR with different shift amounts
        for shift in range(1, 8):
            decoded = bytearray()
            for b in data:
                # Rotate right
                rotated = ((b >> shift) | (b << (8 - shift))) & 0xFF
                decoded.append(rotated)
            
            decoded = bytes(decoded)
            confidence = self._assess_code_likelihood(decoded)
            
            if confidence > 0.5:
                result = DeobfuscatedShellcode(
                    original_bytes=data,
                    deobfuscated_bytes=decoded,
                    method="ROR",
                    key=shift,
                    confidence=confidence
                )
                results.append(result)
        
        return results
    
    def _try_add_decode(self, data: bytes) -> List[DeobfuscatedShellcode]:
        """Try ADD/SUB decoding."""
        results = []
        
        # Try subtracting various values
        for key in range(1, 256):
            decoded = bytes([(b - key) & 0xFF for b in data])
            
            confidence = self._assess_code_likelihood(decoded)
            
            if confidence > 0.5:
                result = DeobfuscatedShellcode(
                    original_bytes=data,
                    deobfuscated_bytes=decoded,
                    method="SUB",
                    key=key,
                    confidence=confidence
                )
                results.append(result)
        
        return results
    
    def _assess_code_likelihood(self, data: bytes) -> float:
        """
        Assess likelihood that data is executable code.
        
        Args:
            data: Bytes to assess
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if len(data) < 3:
            return 0.0
        
        score = 0.0
        
        # Check for common x86/x64 instruction opcodes
        common_opcodes = {
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # push reg
            0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # pop reg
            0x89, 0x8B,  # mov
            0xE8, 0xE9,  # call, jmp
            0x48, 0x4C,  # REX prefixes (x64)
            0xC3, 0xC2,  # ret
            0x90,  # nop
        }
        
        # For small samples, be more lenient
        sample_size = min(100, len(data))
        opcode_count = sum(1 for b in data[:sample_size] if b in common_opcodes)
        
        if len(data) < 10:
            # For very small samples, higher weight on opcode presence
            score += min(0.6, opcode_count / len(data) * 0.6)
        else:
            score += min(0.4, opcode_count / sample_size * 0.4)
        
        # Check for instruction patterns
        if b'\xE8\x00\x00\x00\x00' in data:  # call $+5
            score += 0.2
        if b'\x0F\x05' in data:  # syscall
            score += 0.15
        if b'\xCD\x80' in data:  # int 0x80
            score += 0.15
        
        # Check entropy (code should have moderate entropy)
        if len(data) >= 10:
            entropy = self._calculate_entropy(data[:min(256, len(data))])
            if 3.0 < entropy < 6.5:
                score += 0.2
        
        # Penalize if too many null bytes (unlikely in code)
        check_size = min(100, len(data))
        null_ratio = data[:check_size].count(0) / check_size
        if null_ratio > 0.3:
            score -= 0.2
        
        return max(0.0, min(1.0, score))
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        import math
        
        # Count byte frequencies
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def analyze(
        self, 
        data: bytes, 
        base_address: int = 0,
        enable_emulation: bool = True,
        enable_deobfuscation: bool = True
    ) -> ShellcodeAnalysisReport:
        """
        Perform comprehensive shellcode analysis (Requirement 19.5).
        
        Args:
            data: Binary data to analyze
            base_address: Base address for offset calculation
            enable_emulation: Enable emulation of detected shellcode
            enable_deobfuscation: Enable deobfuscation attempts
            
        Returns:
            ShellcodeAnalysisReport with complete analysis
        """
        logger.info(f"Starting shellcode analysis ({len(data)} bytes)")
        
        # Step 1: Detect patterns (Requirement 19.1)
        patterns = self.detect_patterns(data, base_address)
        logger.info(f"Detected {len(patterns)} shellcode patterns")
        
        # Step 2: Extract shellcode (Requirement 19.2)
        extracted = self.extract_shellcode(data, patterns, base_address)
        logger.info(f"Extracted {len(extracted)} shellcode regions")
        
        # Step 3: Emulate shellcode (Requirement 19.3)
        emulation_results = []
        if enable_emulation and self.enable_emulation:
            for shellcode in extracted:
                if shellcode.confidence >= 0.6:  # Only emulate high-confidence shellcode
                    result = self.emulate_shellcode(shellcode)
                    emulation_results.append(result)
                    if result.success:
                        logger.info(f"Emulation successful: {result.instructions_executed} instructions")
        
        # Step 4: Deobfuscate (Requirement 19.4)
        deobfuscated = []
        if enable_deobfuscation:
            for shellcode in extracted:
                if shellcode.confidence < 0.7:  # Try deobfuscation on lower-confidence shellcode
                    results = self.deobfuscate_shellcode(shellcode.bytes_data)
                    deobfuscated.extend(results[:3])  # Keep top 3 results
        
        # Create report (Requirement 19.5)
        report = ShellcodeAnalysisReport(
            detected_patterns=patterns,
            extracted_shellcode=extracted,
            emulation_results=emulation_results,
            deobfuscated=deobfuscated
        )
        
        logger.info(f"Analysis complete: {report.total_shellcode_bytes} bytes of shellcode")
        return report
    
    def format_report(self, report: ShellcodeAnalysisReport) -> str:
        """
        Format shellcode analysis report (Requirement 19.5).
        
        Args:
            report: ShellcodeAnalysisReport to format
            
        Returns:
            Human-readable report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("SHELLCODE ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Patterns detected: {len(report.detected_patterns)}")
        lines.append(f"Shellcode regions: {len(report.extracted_shellcode)}")
        lines.append(f"Total shellcode bytes: {report.total_shellcode_bytes}")
        lines.append(f"High-confidence regions: {report.high_confidence_count}")
        lines.append("")
        
        # Detected patterns
        if report.detected_patterns:
            lines.append("DETECTED PATTERNS")
            lines.append("-" * 80)
            
            # Group by type
            by_type = {}
            for pattern in report.detected_patterns:
                type_name = pattern.pattern_type.value
                if type_name not in by_type:
                    by_type[type_name] = []
                by_type[type_name].append(pattern)
            
            for type_name, patterns in sorted(by_type.items()):
                lines.append(f"\n{type_name}: {len(patterns)} occurrence(s)")
                for i, pattern in enumerate(patterns[:5], 1):  # Show first 5
                    lines.append(f"  {i}. 0x{pattern.address:X} - {pattern.description}")
                    lines.append(f"     Confidence: {pattern.confidence:.2f}")
                if len(patterns) > 5:
                    lines.append(f"  ... and {len(patterns) - 5} more")
            lines.append("")
        
        # Extracted shellcode
        if report.extracted_shellcode:
            lines.append("EXTRACTED SHELLCODE")
            lines.append("-" * 80)
            for i, shellcode in enumerate(report.extracted_shellcode, 1):
                lines.append(f"\n{i}. {shellcode}")
                lines.append(f"   Patterns: {len(shellcode.patterns)}")
                for pattern in shellcode.patterns[:3]:
                    lines.append(f"     - {pattern.pattern_type.value}: {pattern.description}")
                if len(shellcode.patterns) > 3:
                    lines.append(f"     ... and {len(shellcode.patterns) - 3} more")
                
                # Show first 32 bytes
                hex_bytes = ' '.join(f'{b:02X}' for b in shellcode.bytes_data[:32])
                lines.append(f"   Bytes: {hex_bytes}")
                if len(shellcode.bytes_data) > 32:
                    lines.append(f"   ... ({len(shellcode.bytes_data) - 32} more bytes)")
            lines.append("")
        
        # Emulation results
        if report.emulation_results:
            lines.append("EMULATION RESULTS")
            lines.append("-" * 80)
            for i, result in enumerate(report.emulation_results, 1):
                lines.append(f"\n{i}. {'Success' if result.success else 'Failed'}")
                lines.append(f"   Instructions: {result.instructions_executed}")
                
                if result.output_strings:
                    lines.append(f"   Output strings: {len(result.output_strings)}")
                    for s in result.output_strings[:3]:
                        lines.append(f"     - {repr(s[:50])}")
                
                if result.syscalls:
                    lines.append(f"   Syscalls: {len(result.syscalls)}")
                    for num, name in result.syscalls[:3]:
                        lines.append(f"     - {name} ({num})")
                
                if result.error:
                    lines.append(f"   Error: {result.error}")
            lines.append("")
        
        # Deobfuscation results
        if report.deobfuscated:
            lines.append("DEOBFUSCATION RESULTS")
            lines.append("-" * 80)
            for i, deob in enumerate(report.deobfuscated[:5], 1):
                lines.append(f"\n{i}. Method: {deob.method}")
                if deob.key is not None:
                    lines.append(f"   Key: 0x{deob.key:02X}")
                lines.append(f"   Confidence: {deob.confidence:.2f}")
                
                # Show first 32 bytes
                hex_bytes = ' '.join(f'{b:02X}' for b in deob.deobfuscated_bytes[:32])
                lines.append(f"   Decoded: {hex_bytes}")
            lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)


# Example usage
if __name__ == "__main__":
    print("=" * 80)
    print("ShellcodeDetector Test Suite")
    print("=" * 80)
    print()
    
    # Test data with shellcode patterns
    test_data = bytearray()
    
    # Add GetPC pattern (call/pop)
    test_data.extend(b'\xE8\x00\x00\x00\x00\x58')  # call $+5; pop rax
    
    # Add some NOPs
    test_data.extend(b'\x90' * 10)
    
    # Add PEB access pattern
    test_data.extend(b'\x64\x8B\x00\x30')  # mov eax, fs:[0x30]
    
    # Add syscall
    test_data.extend(b'\x0F\x05')  # syscall
    
    # Add some random data
    test_data.extend(b'\x48\x89\xC3\x48\x31\xC0')
    
    # Create detector
    detector = ShellcodeDetector(enable_emulation=False)
    
    # Analyze
    report = detector.analyze(bytes(test_data), base_address=0x400000, enable_emulation=False)
    
    # Print report
    print(detector.format_report(report))
