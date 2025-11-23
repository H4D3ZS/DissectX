"""Architecture detection from binary headers and heuristics"""
import struct
from typing import Optional, Tuple
from enum import Enum
from .architecture import Architecture


class BinaryFormat(Enum):
    """Supported binary formats"""
    PE = "pe"
    ELF = "elf"
    MACH_O = "macho"
    UNKNOWN = "unknown"


class ArchitectureDetector:
    """Detect architecture from binary files"""
    
    # ELF machine types (e_machine field)
    ELF_MACHINE_TYPES = {
        0x03: Architecture.X86,      # EM_386
        0x3E: Architecture.X86_64,   # EM_X86_64
        0x28: Architecture.ARM,      # EM_ARM
        0xB7: Architecture.ARM64,    # EM_AARCH64
        0x08: Architecture.MIPS,     # EM_MIPS
    }
    
    # PE machine types
    PE_MACHINE_TYPES = {
        0x014c: Architecture.X86,      # IMAGE_FILE_MACHINE_I386
        0x8664: Architecture.X86_64,   # IMAGE_FILE_MACHINE_AMD64
        0x01c0: Architecture.ARM,      # IMAGE_FILE_MACHINE_ARM
        0xaa64: Architecture.ARM64,    # IMAGE_FILE_MACHINE_ARM64
    }
    
    # Mach-O CPU types
    MACHO_CPU_TYPES = {
        0x00000007: Architecture.X86,      # CPU_TYPE_X86
        0x01000007: Architecture.X86_64,   # CPU_TYPE_X86_64
        0x0000000c: Architecture.ARM,      # CPU_TYPE_ARM
        0x0100000c: Architecture.ARM64,    # CPU_TYPE_ARM64
    }
    
    def __init__(self):
        """Initialize architecture detector"""
        self.detected_format = BinaryFormat.UNKNOWN
        self.detected_arch = None
        self.is_64bit = False
    
    def detect_from_file(self, filepath: str) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture from a binary file.
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False) if detection fails
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read(4096)  # Read first 4KB for header analysis
                return self.detect_from_bytes(data)
        except Exception as e:
            print(f"Error reading file: {e}")
            return None, False
    
    def detect_from_bytes(self, data: bytes) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture from binary data.
        
        Args:
            data: Binary data (at least first few KB)
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False) if detection fails
        """
        if len(data) < 4:
            return None, False
        
        # Try header-based detection first
        result = self._detect_elf(data)
        if result[0]:
            self.detected_format = BinaryFormat.ELF
            return result
        
        result = self._detect_pe(data)
        if result[0]:
            self.detected_format = BinaryFormat.PE
            return result
        
        result = self._detect_macho(data)
        if result[0]:
            self.detected_format = BinaryFormat.MACH_O
            return result
        
        # Fall back to heuristic-based detection
        result = self._detect_heuristic(data)
        if result[0]:
            return result
        
        return None, False
    
    def _detect_elf(self, data: bytes) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture from ELF header.
        
        ELF header structure:
        - Magic: 0x7f 'E' 'L' 'F' (4 bytes)
        - Class: 1=32-bit, 2=64-bit (1 byte at offset 4)
        - Data: 1=little-endian, 2=big-endian (1 byte at offset 5)
        - Machine type: 2 bytes at offset 18
        
        Args:
            data: Binary data
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False)
        """
        if len(data) < 20:
            return None, False
        
        # Check ELF magic number
        if data[0:4] != b'\x7fELF':
            return None, False
        
        # Get ELF class (32 or 64 bit)
        elf_class = data[4]
        is_64bit = (elf_class == 2)
        
        # Get endianness
        endian = data[5]
        is_little_endian = (endian == 1)
        
        # Get machine type (e_machine field at offset 18)
        if is_little_endian:
            machine_type = struct.unpack('<H', data[18:20])[0]
        else:
            machine_type = struct.unpack('>H', data[18:20])[0]
        
        # Map machine type to architecture
        arch = self.ELF_MACHINE_TYPES.get(machine_type)
        
        if arch:
            # For MIPS, check if it's 64-bit
            if arch == Architecture.MIPS and is_64bit:
                arch = Architecture.MIPS64
            
            self.detected_arch = arch
            self.is_64bit = is_64bit
            return arch, is_64bit
        
        return None, False
    
    def _detect_pe(self, data: bytes) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture from PE header.
        
        PE header structure:
        - DOS header starts with 'MZ' (2 bytes)
        - PE offset at 0x3C (4 bytes)
        - PE signature 'PE\0\0' at PE offset
        - Machine type: 2 bytes after PE signature
        
        Args:
            data: Binary data
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False)
        """
        if len(data) < 64:
            return None, False
        
        # Check DOS header magic
        if data[0:2] != b'MZ':
            return None, False
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        # Check if we have enough data
        if pe_offset + 6 > len(data):
            return None, False
        
        # Check PE signature
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None, False
        
        # Get machine type (2 bytes after PE signature)
        machine_type = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
        
        # Map machine type to architecture
        arch = self.PE_MACHINE_TYPES.get(machine_type)
        
        if arch:
            is_64bit = arch in [Architecture.X86_64, Architecture.ARM64]
            self.detected_arch = arch
            self.is_64bit = is_64bit
            return arch, is_64bit
        
        return None, False
    
    def _detect_macho(self, data: bytes) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture from Mach-O header.
        
        Mach-O header structure:
        - Magic: 0xfeedface (32-bit), 0xfeedfacf (64-bit), or fat binary
        - CPU type: 4 bytes at offset 4
        
        Args:
            data: Binary data
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False)
        """
        if len(data) < 8:
            return None, False
        
        # Check Mach-O magic numbers
        magic = struct.unpack('<I', data[0:4])[0]
        
        # Mach-O magic numbers
        MH_MAGIC = 0xfeedface      # 32-bit little-endian
        MH_CIGAM = 0xcefaedfe      # 32-bit big-endian
        MH_MAGIC_64 = 0xfeedfacf   # 64-bit little-endian
        MH_CIGAM_64 = 0xcffaedfe   # 64-bit big-endian
        FAT_MAGIC = 0xcafebabe     # Fat binary (universal)
        FAT_CIGAM = 0xbebafeca     # Fat binary (reversed)
        
        is_little_endian = True
        is_64bit = False
        
        if magic == MH_MAGIC:
            is_64bit = False
            is_little_endian = True
        elif magic == MH_CIGAM:
            is_64bit = False
            is_little_endian = False
        elif magic == MH_MAGIC_64:
            is_64bit = True
            is_little_endian = True
        elif magic == MH_CIGAM_64:
            is_64bit = True
            is_little_endian = False
        elif magic in [FAT_MAGIC, FAT_CIGAM]:
            # Fat binary - would need to parse further to get architecture
            # For now, just return None
            return None, False
        else:
            return None, False
        
        # Get CPU type
        if is_little_endian:
            cpu_type = struct.unpack('<I', data[4:8])[0]
        else:
            cpu_type = struct.unpack('>I', data[4:8])[0]
        
        # Map CPU type to architecture
        arch = self.MACHO_CPU_TYPES.get(cpu_type)
        
        if arch:
            self.detected_arch = arch
            self.is_64bit = is_64bit
            return arch, is_64bit
        
        return None, False
    
    def get_detected_format(self) -> BinaryFormat:
        """
        Get the detected binary format.
        
        Returns:
            BinaryFormat enum value
        """
        return self.detected_format
    
    def get_format_name(self) -> str:
        """
        Get a human-readable name for the detected format.
        
        Returns:
            Format name string
        """
        format_names = {
            BinaryFormat.PE: "Portable Executable (PE)",
            BinaryFormat.ELF: "Executable and Linkable Format (ELF)",
            BinaryFormat.MACH_O: "Mach-O",
            BinaryFormat.UNKNOWN: "Unknown",
        }
        return format_names.get(self.detected_format, "Unknown")
    
    def _detect_heuristic(self, data: bytes) -> Tuple[Optional[Architecture], bool]:
        """
        Detect architecture using instruction pattern heuristics.
        
        This is a fallback method when header-based detection fails.
        It analyzes instruction patterns to guess the architecture.
        
        Args:
            data: Binary data
            
        Returns:
            Tuple of (Architecture, is_64bit) or (None, False)
        """
        if len(data) < 64:
            return None, False
        
        # Score each architecture based on instruction patterns
        scores = {
            Architecture.X86: 0,
            Architecture.X86_64: 0,
            Architecture.ARM: 0,
            Architecture.ARM64: 0,
            Architecture.MIPS: 0,
            Architecture.MIPS64: 0,
        }
        
        # Analyze instruction patterns
        scores[Architecture.X86] += self._score_x86_patterns(data, is_64bit=False)
        scores[Architecture.X86_64] += self._score_x86_patterns(data, is_64bit=True)
        scores[Architecture.ARM] += self._score_arm_patterns(data, is_64bit=False)
        scores[Architecture.ARM64] += self._score_arm_patterns(data, is_64bit=True)
        scores[Architecture.MIPS] += self._score_mips_patterns(data, is_64bit=False)
        scores[Architecture.MIPS64] += self._score_mips_patterns(data, is_64bit=True)
        
        # Find the architecture with the highest score
        max_score = max(scores.values())
        
        # Require a minimum confidence threshold
        if max_score < 3:
            return None, False
        
        # Get the architecture with the highest score
        for arch, score in scores.items():
            if score == max_score:
                is_64bit = arch in [Architecture.X86_64, Architecture.ARM64, Architecture.MIPS64]
                self.detected_arch = arch
                self.is_64bit = is_64bit
                return arch, is_64bit
        
        return None, False
    
    def _score_x86_patterns(self, data: bytes, is_64bit: bool) -> int:
        """
        Score x86/x86-64 instruction patterns.
        
        Args:
            data: Binary data
            is_64bit: Whether to check for 64-bit patterns
            
        Returns:
            Score (higher = more likely)
        """
        score = 0
        
        # Common x86 instruction prefixes and opcodes
        x86_patterns = [
            b'\x55',           # push rbp/ebp (function prologue)
            b'\x48\x89\xe5',   # mov rbp, rsp (64-bit prologue)
            b'\x89\xe5',       # mov ebp, esp (32-bit prologue)
            b'\x48\x83\xec',   # sub rsp, imm8 (64-bit stack allocation)
            b'\x83\xec',       # sub esp, imm8 (32-bit stack allocation)
            b'\xc3',           # ret
            b'\xe8',           # call rel32
            b'\xff\x15',       # call [rip+offset] (64-bit)
            b'\x48\x8b',       # mov reg64, ... (64-bit)
            b'\x48\x89',       # mov ..., reg64 (64-bit)
        ]
        
        # REX prefixes (64-bit only)
        rex_prefixes = [b'\x48', b'\x49', b'\x4a', b'\x4b', b'\x4c', b'\x4d', b'\x4e', b'\x4f']
        
        # Count pattern occurrences
        for pattern in x86_patterns:
            count = data.count(pattern)
            if count > 0:
                score += min(count, 5)  # Cap contribution per pattern
        
        # Check for REX prefixes (64-bit indicator)
        if is_64bit:
            for prefix in rex_prefixes:
                count = data.count(prefix)
                if count > 0:
                    score += min(count, 3)
        
        # Check for common x86 instruction sequences
        if b'\x55\x48\x89\xe5' in data:  # push rbp; mov rbp, rsp
            score += 5
        if b'\x55\x89\xe5' in data:      # push ebp; mov ebp, esp
            score += 5
        
        return score
    
    def _score_arm_patterns(self, data: bytes, is_64bit: bool) -> int:
        """
        Score ARM/ARM64 instruction patterns.
        
        Args:
            data: Binary data
            is_64bit: Whether to check for 64-bit patterns
            
        Returns:
            Score (higher = more likely)
        """
        score = 0
        
        if is_64bit:
            # ARM64 instructions are always 4 bytes and aligned
            # Check for common ARM64 patterns
            for i in range(0, len(data) - 4, 4):
                instr = struct.unpack('<I', data[i:i+4])[0]
                
                # Check for common ARM64 instruction patterns
                # STP (store pair): 0x29xxxxxx or 0xa9xxxxxx
                if (instr & 0xffc00000) == 0xa9000000 or (instr & 0xffc00000) == 0x29000000:
                    score += 1
                
                # LDP (load pair): 0x28xxxxxx or 0xa8xxxxxx
                elif (instr & 0xffc00000) == 0xa8400000 or (instr & 0xffc00000) == 0x28400000:
                    score += 1
                
                # MOV (register): 0xaa0003e0 pattern
                elif (instr & 0xffe0ffe0) == 0xaa0003e0:
                    score += 1
                
                # RET: 0xd65f03c0
                elif instr == 0xd65f03c0:
                    score += 2
                
                # BL (branch with link): 0x94xxxxxx
                elif (instr & 0xfc000000) == 0x94000000:
                    score += 1
        else:
            # ARM32 instructions can be 2 or 4 bytes (Thumb vs ARM mode)
            # Check for common ARM32 patterns
            for i in range(0, len(data) - 4, 4):
                instr = struct.unpack('<I', data[i:i+4])[0]
                
                # Check for ARM mode instructions (4 bytes)
                # Conditional execution: top 4 bits are condition code
                cond = (instr >> 28) & 0xF
                if cond <= 0xE:  # Valid condition codes
                    # PUSH: 0xe92dxxxx
                    if (instr & 0xffff0000) == 0xe92d0000:
                        score += 2
                    
                    # POP: 0xe8bdxxxx
                    elif (instr & 0xffff0000) == 0xe8bd0000:
                        score += 2
                    
                    # BL (branch with link): 0xebxxxxxx
                    elif (instr & 0xff000000) == 0xeb000000:
                        score += 1
                    
                    # MOV: 0xe1axxxxx or 0xe3axxxxx
                    elif (instr & 0xfff00000) == 0xe1a00000 or (instr & 0xfff00000) == 0xe3a00000:
                        score += 1
        
        return score
    
    def _score_mips_patterns(self, data: bytes, is_64bit: bool) -> int:
        """
        Score MIPS/MIPS64 instruction patterns.
        
        Args:
            data: Binary data
            is_64bit: Whether to check for 64-bit patterns
            
        Returns:
            Score (higher = more likely)
        """
        score = 0
        
        # MIPS instructions are always 4 bytes and aligned
        for i in range(0, len(data) - 4, 4):
            instr = struct.unpack('>I', data[i:i+4])[0]  # MIPS is typically big-endian
            
            # Get opcode (top 6 bits)
            opcode = (instr >> 26) & 0x3F
            
            # Common MIPS opcodes
            # ADDIU: opcode 0x09
            if opcode == 0x09:
                score += 1
            
            # LW (load word): opcode 0x23
            elif opcode == 0x23:
                score += 1
            
            # SW (store word): opcode 0x2B
            elif opcode == 0x2B:
                score += 1
            
            # BEQ (branch if equal): opcode 0x04
            elif opcode == 0x04:
                score += 1
            
            # BNE (branch if not equal): opcode 0x05
            elif opcode == 0x05:
                score += 1
            
            # JAL (jump and link): opcode 0x03
            elif opcode == 0x03:
                score += 2
            
            # Special opcode (0x00) - check function field
            elif opcode == 0x00:
                func = instr & 0x3F
                # JR (jump register): func 0x08
                if func == 0x08:
                    score += 2
                # SYSCALL: func 0x0C
                elif func == 0x0C:
                    score += 1
        
        # Check for MIPS64-specific patterns
        if is_64bit:
            for i in range(0, len(data) - 4, 4):
                instr = struct.unpack('>I', data[i:i+4])[0]
                opcode = (instr >> 26) & 0x3F
                
                # LD (load doubleword): opcode 0x37
                if opcode == 0x37:
                    score += 1
                
                # SD (store doubleword): opcode 0x3F
                elif opcode == 0x3F:
                    score += 1
        
        return score
