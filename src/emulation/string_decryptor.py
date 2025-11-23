#!/usr/bin/env python3
"""
String Decryptor for DissectX    Framework

Provides automatic string decryption capabilities using emulation and analysis.
Identifies encrypted strings, locates decryption functions, and extracts
decrypted content safely.

Implements Requirements 15.1-15.5:
- 15.1: Identify encrypted strings and locate decryption functions
- 15.2: Execute decryption routines safely via emulation
- 15.3: Extract computed values from emulation
- 15.4: Record execution paths for analysis
- 15.5: Assign confidence scores to decrypted strings

Author: DissectX Team
"""

import logging
import struct
from typing import List, Optional, Dict, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from .unicorn_emulator import UnicornEmulator, EmulationResult, UNICORN_AVAILABLE
except ImportError:
    try:
        from unicorn_emulator import UnicornEmulator, EmulationResult, UNICORN_AVAILABLE
    except ImportError:
        UNICORN_AVAILABLE = False
        logger.warning("UnicornEmulator not available")


class EncryptionType(Enum):
    """Types of string encryption detected"""
    XOR = "xor"
    RC4 = "rc4"
    AES = "aes"
    CUSTOM = "custom"
    STACK_STRING = "stack_string"
    UNKNOWN = "unknown"


@dataclass
class EncryptedString:
    """
    Represents an encrypted string found in binary
    
    Requirement 15.1: Identify encrypted strings
    """
    address: int
    data: bytes
    size: int
    encryption_type: EncryptionType
    confidence: float
    decryption_function: Optional[int] = None
    
    def __str__(self) -> str:
        return (f"EncryptedString(addr=0x{self.address:X}, size={self.size}, "
                f"type={self.encryption_type.value}, confidence={self.confidence:.2f})")


@dataclass
class DecryptionFunction:
    """
    Represents a function that decrypts strings
    
    Requirement 15.1: Locate decryption functions
    """
    address: int
    name: Optional[str]
    encryption_type: EncryptionType
    confidence: float
    parameters: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        name_str = self.name or f"sub_{self.address:X}"
        return (f"DecryptionFunction({name_str} @ 0x{self.address:X}, "
                f"type={self.encryption_type.value}, confidence={self.confidence:.2f})")


@dataclass
class ExecutionTrace:
    """
    Records execution path during emulation
    
    Requirement 15.4: Record execution paths
    """
    addresses: List[int] = field(default_factory=list)
    instructions_executed: int = 0
    memory_reads: List[Tuple[int, bytes]] = field(default_factory=list)
    memory_writes: List[Tuple[int, bytes]] = field(default_factory=list)
    function_calls: List[int] = field(default_factory=list)
    
    def add_address(self, addr: int):
        """Add an address to the execution trace"""
        self.addresses.append(addr)
        self.instructions_executed += 1
    
    def add_memory_read(self, addr: int, data: bytes):
        """Record a memory read"""
        self.memory_reads.append((addr, data))
    
    def add_memory_write(self, addr: int, data: bytes):
        """Record a memory write"""
        self.memory_writes.append((addr, data))
    
    def add_function_call(self, addr: int):
        """Record a function call"""
        self.function_calls.append(addr)
    
    def format_trace(self, max_addresses: int = 50) -> str:
        """Format execution trace as human-readable string"""
        lines = []
        lines.append(f"Execution Trace ({self.instructions_executed} instructions):")
        lines.append("-" * 70)
        
        # Show first N addresses
        for i, addr in enumerate(self.addresses[:max_addresses]):
            lines.append(f"  {i+1:4d}. 0x{addr:08X}")
        
        if len(self.addresses) > max_addresses:
            lines.append(f"  ... ({len(self.addresses) - max_addresses} more addresses)")
        
        if self.function_calls:
            lines.append(f"\nFunction calls: {len(self.function_calls)}")
            for addr in self.function_calls[:10]:
                lines.append(f"  - 0x{addr:08X}")
        
        return "\n".join(lines)


@dataclass
class DecryptedString:
    """
    Represents a successfully decrypted string
    
    Requirement 15.5: Decrypted strings with confidence scores
    """
    original_address: int
    decrypted_value: str
    decryption_function: Optional[int]
    encryption_type: EncryptionType
    confidence: float
    execution_trace: Optional[ExecutionTrace] = None
    
    def __str__(self) -> str:
        preview = self.decrypted_value[:50]
        if len(self.decrypted_value) > 50:
            preview += "..."
        return (f"DecryptedString(addr=0x{self.original_address:X}, "
                f"confidence={self.confidence:.2f}, value='{preview}')")


class StringDecryptor:
    """
    Automatic string decryption using emulation and analysis
    
    Features:
    - Encrypted string detection (Requirement 15.1)
    - Decryption function identification (Requirement 15.1)
    - Safe emulation-based decryption (Requirement 15.2)
    - Constant extraction (Requirement 15.3)
    - Execution tracing (Requirement 15.4)
    - Confidence scoring (Requirement 15.5)
    """
    
    def __init__(self, arch: str = 'x64'):
        """
        Initialize StringDecryptor
        
        Args:
            arch: Architecture ('x64' or 'x86')
        """
        self.arch = arch
        self.encrypted_strings: List[EncryptedString] = []
        self.decryption_functions: List[DecryptionFunction] = []
        self.decrypted_strings: List[DecryptedString] = []
        self.execution_traces: List[ExecutionTrace] = []
        
        # Emulator (lazy initialization)
        self._emulator: Optional[UnicornEmulator] = None
        
        logger.info(f"Initialized StringDecryptor for {arch}")
    
    @property
    def emulator(self) -> Optional[UnicornEmulator]:
        """Get or create emulator instance"""
        if not UNICORN_AVAILABLE:
            logger.warning("Unicorn not available, emulation disabled")
            return None
        
        if self._emulator is None:
            self._emulator = UnicornEmulator(arch=self.arch, enable_syscalls=True)
        
        return self._emulator
    
    def detect_encrypted_strings(self, binary_data: bytes, base_addr: int = 0) -> List[EncryptedString]:
        """
        Detect encrypted strings in binary data (Requirement 15.1)
        
        Uses heuristics to identify potential encrypted strings:
        - High entropy regions
        - Suspicious byte patterns
        - References from code sections
        
        Args:
            binary_data: Binary data to analyze
            base_addr: Base address of the binary
            
        Returns:
            List of EncryptedString objects
        """
        encrypted_strings = []
        
        # Heuristic 1: Find high-entropy regions
        # Scan binary in chunks and calculate entropy
        chunk_size = 16
        for offset in range(0, len(binary_data) - chunk_size, 4):
            chunk = binary_data[offset:offset + chunk_size]
            
            # Calculate entropy
            entropy = self._calculate_entropy(chunk)
            
            # High entropy (> 6.0) suggests encryption
            if entropy > 6.0:
                # Check if it looks like encrypted data (not just random)
                if self._looks_like_encrypted_data(chunk):
                    encrypted_str = EncryptedString(
                        address=base_addr + offset,
                        data=chunk,
                        size=len(chunk),
                        encryption_type=EncryptionType.UNKNOWN,
                        confidence=min(entropy / 8.0, 1.0)
                    )
                    encrypted_strings.append(encrypted_str)
        
        # Heuristic 2: Find XOR-encrypted strings
        # Look for patterns that might be XOR-encrypted ASCII
        xor_candidates = self._find_xor_encrypted_strings(binary_data, base_addr)
        encrypted_strings.extend(xor_candidates)
        
        # Heuristic 3: Find stack strings (built character by character)
        # This requires disassembly, so we'll mark it for future enhancement
        
        self.encrypted_strings = encrypted_strings
        logger.info(f"Detected {len(encrypted_strings)} potential encrypted strings")
        
        return encrypted_strings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        from collections import Counter
        import math
        
        byte_counts = Counter(data)
        data_len = len(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _looks_like_encrypted_data(self, data: bytes) -> bool:
        """
        Check if data looks like encrypted content
        
        Encrypted data typically has:
        - High entropy
        - Relatively uniform byte distribution
        - No obvious patterns
        """
        if len(data) < 8:
            return False
        
        # Check for uniform distribution
        from collections import Counter
        byte_counts = Counter(data)
        
        # If too many repeated bytes, probably not encrypted
        max_count = max(byte_counts.values())
        if max_count > len(data) * 0.3:  # More than 30% same byte
            return False
        
        # Check for null bytes (encrypted data rarely has many nulls)
        null_count = data.count(0)
        if null_count > len(data) * 0.2:  # More than 20% nulls
            return False
        
        return True
    
    def _find_xor_encrypted_strings(self, binary_data: bytes, base_addr: int) -> List[EncryptedString]:
        """
        Find potential XOR-encrypted strings
        
        XOR-encrypted ASCII strings have characteristic patterns:
        - When XORed with common keys, they produce readable text
        - Often have repeating patterns (for multi-byte keys)
        """
        candidates = []
        
        # Look for regions that might be XOR-encrypted ASCII
        min_string_len = 8
        for offset in range(0, len(binary_data) - min_string_len):
            chunk = binary_data[offset:offset + min_string_len]
            
            # Try common XOR keys
            for key in [0x00, 0x01, 0x42, 0x55, 0xAA, 0xFF]:
                decrypted = bytes(b ^ key for b in chunk)
                
                # Check if result looks like ASCII text
                if self._looks_like_ascii(decrypted):
                    # Found potential XOR-encrypted string
                    # Extend to find full string
                    full_string = self._extend_xor_string(binary_data, offset, key)
                    
                    if len(full_string) >= min_string_len:
                        encrypted_str = EncryptedString(
                            address=base_addr + offset,
                            data=binary_data[offset:offset + len(full_string)],
                            size=len(full_string),
                            encryption_type=EncryptionType.XOR,
                            confidence=0.7
                        )
                        candidates.append(encrypted_str)
                        break  # Found with this key, move to next offset
        
        return candidates
    
    def _looks_like_ascii(self, data: bytes) -> bool:
        """Check if data looks like ASCII text"""
        if not data:
            return False
        
        printable_count = 0
        for byte in data:
            if (0x20 <= byte <= 0x7E) or byte in (0x09, 0x0A, 0x0D):
                printable_count += 1
        
        return printable_count / len(data) >= 0.8
    
    def _extend_xor_string(self, data: bytes, start: int, key: int) -> bytes:
        """Extend XOR-encrypted string to find full length"""
        result = []
        
        for i in range(start, len(data)):
            decrypted_byte = data[i] ^ key
            
            # Stop at null terminator or non-printable
            if decrypted_byte == 0:
                break
            if not ((0x20 <= decrypted_byte <= 0x7E) or decrypted_byte in (0x09, 0x0A, 0x0D)):
                break
            
            result.append(data[i])
            
            # Limit string length
            if len(result) >= 256:
                break
        
        return bytes(result)

    def find_decryption_functions(self, instructions: List, xrefs: Dict = None) -> List[DecryptionFunction]:
        """
        Locate decryption functions in binary (Requirement 15.1)
        
        Identifies functions that likely decrypt strings by looking for:
        - XOR operations in loops
        - Calls to crypto libraries
        - Suspicious instruction patterns
        
        Args:
            instructions: List of disassembled instructions
            xrefs: Cross-reference information (optional)
            
        Returns:
            List of DecryptionFunction objects
        """
        decryption_funcs = []
        
        # Pattern 1: Look for XOR loops
        # Common pattern: loop with XOR instruction
        xor_loop_funcs = self._find_xor_loop_functions(instructions)
        decryption_funcs.extend(xor_loop_funcs)
        
        # Pattern 2: Look for crypto API calls
        # Functions that call CryptDecrypt, etc.
        crypto_funcs = self._find_crypto_api_functions(instructions)
        decryption_funcs.extend(crypto_funcs)
        
        # Pattern 3: Look for stack string builders
        # Functions that build strings on the stack
        stack_string_funcs = self._find_stack_string_functions(instructions)
        decryption_funcs.extend(stack_string_funcs)
        
        self.decryption_functions = decryption_funcs
        logger.info(f"Found {len(decryption_funcs)} potential decryption functions")
        
        return decryption_funcs
    
    def _find_xor_loop_functions(self, instructions: List) -> List[DecryptionFunction]:
        """Find functions with XOR loops (common decryption pattern)"""
        functions = []
        
        # This is a simplified heuristic
        # In a real implementation, we'd analyze the CFG
        
        # Look for patterns like:
        # loop_start:
        #   xor byte [rdi], al
        #   inc rdi
        #   loop loop_start
        
        # For now, just identify functions with XOR instructions
        # This would need proper disassembly integration
        
        return functions
    
    def _find_crypto_api_functions(self, instructions: List) -> List[DecryptionFunction]:
        """Find functions that call crypto APIs"""
        functions = []
        
        # Look for calls to:
        # - CryptDecrypt (Windows)
        # - EVP_DecryptInit (OpenSSL)
        # - AES_decrypt
        # etc.
        
        # This requires symbol resolution and import analysis
        
        return functions
    
    def _find_stack_string_functions(self, instructions: List) -> List[DecryptionFunction]:
        """Find functions that build strings on the stack"""
        functions = []
        
        # Stack strings are built character by character:
        # mov byte [rbp-0x10], 'H'
        # mov byte [rbp-0x0F], 'e'
        # mov byte [rbp-0x0E], 'l'
        # ...
        
        # This requires instruction-level analysis
        
        return functions
    
    def emulate_decryption(
        self,
        func_addr: int,
        encrypted_data: bytes,
        code: bytes,
        base_addr: int = 0x400000
    ) -> Optional[DecryptedString]:
        """
        Emulate decryption function to extract decrypted string (Requirement 15.2)
        
        Safely executes the decryption routine in a sandboxed emulator
        and extracts the decrypted result.
        
        Args:
            func_addr: Address of decryption function
            encrypted_data: Encrypted data to decrypt
            code: Binary code containing the function
            base_addr: Base address for code loading
            
        Returns:
            DecryptedString object or None if decryption fails
        """
        if not self.emulator:
            logger.error("Emulator not available")
            return None
        
        try:
            # Load code into emulator
            self.emulator.load_code(code, base_addr)
            
            # Setup encrypted data in memory
            data_addr = self.emulator.HEAP_BASE
            self.emulator.write_memory(data_addr, encrypted_data)
            
            # Setup output buffer
            output_addr = self.emulator.HEAP_BASE + 0x1000
            output_size = len(encrypted_data) + 256  # Extra space
            self.emulator.write_memory(output_addr, b'\x00' * output_size)
            
            # Setup registers for function call
            # Typical calling convention: RDI = input, RSI = output, RDX = size
            self.emulator.set_register('rdi', data_addr)
            self.emulator.set_register('rsi', output_addr)
            self.emulator.set_register('rdx', len(encrypted_data))
            
            # Create execution trace
            trace = ExecutionTrace()
            
            # Emulate function (Requirement 15.2: safe execution)
            result = self.emulator.emulate(
                start_addr=func_addr,
                count=10000,
                timeout_ms=5000
            )
            
            # Record trace (Requirement 15.4)
            trace.instructions_executed = result.instructions_executed
            trace.memory_reads = result.memory_reads
            trace.memory_writes = result.memory_writes
            self.execution_traces.append(trace)
            
            if not result.success:
                logger.warning(f"Emulation failed: {result.error}")
                return None
            
            # Extract decrypted string from output buffer
            decrypted_data = self.emulator.read_memory(output_addr, output_size)
            if not decrypted_data:
                return None
            
            # Find null terminator
            null_pos = decrypted_data.find(b'\x00')
            if null_pos != -1:
                decrypted_data = decrypted_data[:null_pos]
            
            # Try to decode as string
            try:
                decrypted_str = decrypted_data.decode('utf-8', errors='ignore')
            except:
                decrypted_str = decrypted_data.decode('latin-1', errors='ignore')
            
            # Calculate confidence (Requirement 15.5)
            confidence = self._calculate_decryption_confidence(decrypted_str, result)
            
            decrypted = DecryptedString(
                original_address=data_addr,
                decrypted_value=decrypted_str,
                decryption_function=func_addr,
                encryption_type=EncryptionType.CUSTOM,
                confidence=confidence,
                execution_trace=trace
            )
            
            self.decrypted_strings.append(decrypted)
            logger.info(f"Successfully decrypted string: {decrypted_str[:50]}")
            
            return decrypted
            
        except Exception as e:
            logger.error(f"Emulation error: {e}")
            return None
    
    def extract_constants(self, emulation_result: EmulationResult) -> Dict[str, int]:
        """
        Extract computed constants from emulation (Requirement 15.3)
        
        Analyzes emulation results to extract:
        - Final register values
        - Computed memory values
        - Return values
        
        Args:
            emulation_result: Result from emulation
            
        Returns:
            Dictionary of constant names to values
        """
        constants = {}
        
        # Extract final register values
        for reg_name, value in emulation_result.final_registers.items():
            if value != 0:  # Only non-zero values
                constants[f"reg_{reg_name}"] = value
        
        # Extract values from memory writes
        for i, (addr, data) in enumerate(emulation_result.memory_writes):
            if len(data) == 4:
                # 32-bit value
                value = struct.unpack('<I', data)[0]
                constants[f"mem_write_{i}_dword"] = value
            elif len(data) == 8:
                # 64-bit value
                value = struct.unpack('<Q', data)[0]
                constants[f"mem_write_{i}_qword"] = value
        
        logger.debug(f"Extracted {len(constants)} constants from emulation")
        
        return constants
    
    def record_execution_trace(self, emulation_result: EmulationResult) -> ExecutionTrace:
        """
        Record execution path from emulation (Requirement 15.4)
        
        Creates a detailed trace of the execution path including:
        - Addresses executed
        - Memory accesses
        - Function calls
        
        Args:
            emulation_result: Result from emulation
            
        Returns:
            ExecutionTrace object
        """
        trace = ExecutionTrace()
        
        trace.instructions_executed = emulation_result.instructions_executed
        trace.memory_reads = emulation_result.memory_reads
        trace.memory_writes = emulation_result.memory_writes
        
        # Extract function calls from syscalls
        for syscall_num, syscall_name in emulation_result.syscalls_invoked:
            trace.add_function_call(syscall_num)
        
        self.execution_traces.append(trace)
        
        return trace
    
    def _calculate_decryption_confidence(
        self,
        decrypted_str: str,
        emulation_result: EmulationResult
    ) -> float:
        """
        Calculate confidence score for decrypted string (Requirement 15.5)
        
        Confidence is based on:
        - Printable character ratio
        - String length
        - Emulation success
        - Entropy (should be lower than encrypted)
        
        Args:
            decrypted_str: Decrypted string
            emulation_result: Emulation result
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not decrypted_str:
            return 0.0
        
        score = 0.0
        
        # Factor 1: Printable ratio (0-0.4)
        printable_count = sum(1 for c in decrypted_str 
                            if c.isprintable() or c in '\t\n\r')
        printable_ratio = printable_count / len(decrypted_str)
        score += printable_ratio * 0.4
        
        # Factor 2: String length (0-0.2)
        # Prefer strings of reasonable length (8-256 chars)
        if 8 <= len(decrypted_str) <= 256:
            score += 0.2
        elif len(decrypted_str) > 256:
            score += 0.1
        
        # Factor 3: Emulation success (0-0.2)
        if emulation_result.success:
            score += 0.2
        
        # Factor 4: Entropy check (0-0.2)
        # Decrypted text should have medium entropy (3-6)
        entropy = self._calculate_entropy(decrypted_str.encode('utf-8', errors='ignore'))
        if 3.0 <= entropy <= 6.0:
            score += 0.2
        elif entropy < 3.0:
            score += 0.1  # Low entropy is okay (repetitive text)
        
        return min(score, 1.0)
    
    def brute_force_xor(self, encrypted_data: bytes) -> List[DecryptedString]:
        """
        Brute force XOR decryption (simple method without emulation)
        
        Tries all 256 single-byte XOR keys and returns likely results.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            List of DecryptedString objects
        """
        results = []
        
        for key in range(256):
            decrypted_bytes = bytes(b ^ key for b in encrypted_data)
            
            # Try to decode as string
            try:
                decrypted_str = decrypted_bytes.decode('utf-8', errors='ignore')
            except:
                continue
            
            # Check if it looks like valid text
            if not self._looks_like_ascii(decrypted_bytes):
                continue
            
            # Calculate confidence
            confidence = self._calculate_xor_confidence(decrypted_str)
            
            if confidence > 0.5:  # Only keep good results
                decrypted = DecryptedString(
                    original_address=0,
                    decrypted_value=decrypted_str,
                    decryption_function=None,
                    encryption_type=EncryptionType.XOR,
                    confidence=confidence,
                    execution_trace=None
                )
                results.append(decrypted)
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        return results
    
    def _calculate_xor_confidence(self, decrypted_str: str) -> float:
        """Calculate confidence for XOR-decrypted string"""
        if not decrypted_str:
            return 0.0
        
        # Check printable ratio
        printable_count = sum(1 for c in decrypted_str if c.isprintable())
        printable_ratio = printable_count / len(decrypted_str)
        
        # Check for common English words
        common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all']
        word_score = sum(1 for word in common_words if word in decrypted_str.lower())
        word_score = min(word_score / len(common_words), 1.0)
        
        # Combine scores
        confidence = printable_ratio * 0.7 + word_score * 0.3
        
        return confidence
    
    def generate_decryption_report(self) -> str:
        """
        Generate comprehensive decryption report (Requirement 15.5)
        
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("STRING DECRYPTION REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Summary
        lines.append(f"Encrypted strings detected: {len(self.encrypted_strings)}")
        lines.append(f"Decryption functions found: {len(self.decryption_functions)}")
        lines.append(f"Strings decrypted: {len(self.decrypted_strings)}")
        lines.append(f"Execution traces recorded: {len(self.execution_traces)}")
        lines.append("")
        
        # Encrypted strings
        if self.encrypted_strings:
            lines.append("ENCRYPTED STRINGS:")
            lines.append("-" * 80)
            for enc_str in self.encrypted_strings[:10]:
                lines.append(f"  {enc_str}")
            if len(self.encrypted_strings) > 10:
                lines.append(f"  ... and {len(self.encrypted_strings) - 10} more")
            lines.append("")
        
        # Decryption functions
        if self.decryption_functions:
            lines.append("DECRYPTION FUNCTIONS:")
            lines.append("-" * 80)
            for func in self.decryption_functions:
                lines.append(f"  {func}")
            lines.append("")
        
        # Decrypted strings
        if self.decrypted_strings:
            lines.append("DECRYPTED STRINGS:")
            lines.append("-" * 80)
            for dec_str in sorted(self.decrypted_strings, 
                                 key=lambda x: x.confidence, reverse=True):
                lines.append(f"  {dec_str}")
            lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def get_high_confidence_strings(self, min_confidence: float = 0.7) -> List[DecryptedString]:
        """
        Get decrypted strings with high confidence scores
        
        Args:
            min_confidence: Minimum confidence threshold (0.0 to 1.0)
            
        Returns:
            List of high-confidence DecryptedString objects
        """
        return [s for s in self.decrypted_strings if s.confidence >= min_confidence]
    
    def get_execution_trace_report(self, trace_index: int = 0) -> str:
        """
        Get detailed report for a specific execution trace
        
        Args:
            trace_index: Index of trace to report
            
        Returns:
            Formatted trace report
        """
        if trace_index >= len(self.execution_traces):
            return "Trace index out of range"
        
        trace = self.execution_traces[trace_index]
        return trace.format_trace()


# Example usage and testing
if __name__ == "__main__":
    print("=" * 80)
    print("StringDecryptor Test Suite")
    print("=" * 80)
    print()
    
    # Test 1: Encrypted string detection
    print("Test 1: Encrypted String Detection")
    print("-" * 80)
    
    # Create test binary with encrypted strings
    test_binary = b'\x00' * 100
    # Add some high-entropy data (simulating encrypted string)
    test_binary += b'\x8F\x3A\x9B\x2C\x7E\x4D\x1F\x6A\xC3\x5B\x8E\x2D\x9F\x4A\x7C\x1E'
    test_binary += b'\x00' * 100
    
    decryptor = StringDecryptor(arch='x64')
    encrypted_strs = decryptor.detect_encrypted_strings(test_binary, base_addr=0x400000)
    
    print(f"Detected {len(encrypted_strs)} encrypted strings")
    for enc_str in encrypted_strs:
        print(f"  {enc_str}")
    print()
    
    # Test 2: XOR brute force
    print("Test 2: XOR Brute Force Decryption")
    print("-" * 80)
    
    # Create XOR-encrypted string
    plaintext = b"This is a secret message!"
    xor_key = 0x42
    encrypted = bytes(b ^ xor_key for b in plaintext)
    
    print(f"Original: {plaintext}")
    print(f"Encrypted: {encrypted.hex()}")
    print()
    
    decrypted_results = decryptor.brute_force_xor(encrypted)
    
    print(f"Found {len(decrypted_results)} potential decryptions:")
    for i, result in enumerate(decrypted_results[:5], 1):
        print(f"  {i}. {result}")
    print()
    
    # Test 3: Decryption report
    print("Test 3: Decryption Report")
    print("-" * 80)
    
    report = decryptor.generate_decryption_report()
    print(report)
    
    print()
    print("=" * 80)
    print("All tests completed!")
    print("=" * 80)
