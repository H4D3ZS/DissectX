"""Capstone disassembler wrapper for   disassembly"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from src.architecture import Architecture


class Syntax(Enum):
    """Disassembly syntax modes"""
    INTEL = "intel"  # Intel syntax (x86)
    ATT = "att"      # AT&T syntax (x86)
    DEFAULT = "default"  # Architecture default


@dataclass
class Instruction:
    """Represents a disassembled instruction"""
    address: int
    mnemonic: str
    operands: List[str]
    bytes: bytes
    size: int
    architecture: Architecture
    op_str: str  # Full operand string
    
    def __str__(self):
        """String representation of instruction"""
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic


class CapstoneError(Exception):
    """Exception raised for Capstone-related errors"""
    pass


class InvalidInstructionError(CapstoneError):
    """Exception raised when encountering invalid instructions"""
    def __init__(self, address: int, message: str = "Invalid instruction"):
        self.address = address
        super().__init__(f"{message} at address {address:#x}")


class CapstoneDisassembler:
    """
      disassembler using Capstone engine.
    
    Supports multiple architectures (x86, ARM, MIPS) and syntax modes.
    """
    
    def __init__(self, arch: Architecture, mode: Optional[str] = None, syntax: Syntax = Syntax.DEFAULT):
        """
        Initialize Capstone disassembler.
        
        Args:
            arch: Target architecture
            mode: Optional mode string (e.g., "32", "64", "thumb")
            syntax: Disassembly syntax mode
            
        Raises:
            CapstoneError: If Capstone is not available or initialization fails
        """
        if not CAPSTONE_AVAILABLE:
            raise CapstoneError("Capstone library is not installed. Install with: pip install capstone")
        
        self.arch = arch
        self.syntax = syntax
        self._cs = None
        
        # Initialize Capstone with appropriate architecture and mode
        try:
            cs_arch, cs_mode = self._get_capstone_arch_mode(arch, mode)
            self._cs = Cs(cs_arch, cs_mode)
            
            # Enable detail mode for operand information
            self._cs.detail = True
            
            # Set syntax mode if applicable
            self._set_syntax_mode(syntax)
            
        except CsError as e:
            raise CapstoneError(f"Failed to initialize Capstone: {e}")
    
    def _get_capstone_arch_mode(self, arch: Architecture, mode: Optional[str]) -> Tuple[int, int]:
        """
        Get Capstone architecture and mode constants.
        
        Args:
            arch: Target architecture
            mode: Optional mode string
            
        Returns:
            Tuple of (capstone_arch, capstone_mode)
            
        Raises:
            CapstoneError: If architecture is not supported
        """
        if arch == Architecture.X86:
            return (CS_ARCH_X86, CS_MODE_32)
        
        elif arch == Architecture.X86_64:
            return (CS_ARCH_X86, CS_MODE_64)
        
        elif arch == Architecture.ARM:
            # Check if Thumb mode is requested
            if mode and mode.lower() == "thumb":
                return (CS_ARCH_ARM, CS_MODE_THUMB)
            return (CS_ARCH_ARM, CS_MODE_ARM)
        
        elif arch == Architecture.ARM64:
            return (CS_ARCH_ARM64, CS_MODE_ARM)
        
        elif arch == Architecture.MIPS:
            return (CS_ARCH_MIPS, CS_MODE_MIPS32)
        
        elif arch == Architecture.MIPS64:
            return (CS_ARCH_MIPS, CS_MODE_MIPS64)
        
        else:
            raise CapstoneError(f"Unsupported architecture: {arch}")
    
    def _set_syntax_mode(self, syntax: Syntax):
        """
        Set the disassembly syntax mode.
        
        Args:
            syntax: Desired syntax mode
        """
        if syntax == Syntax.DEFAULT:
            return
        
        # Syntax mode only applies to x86/x64
        if self.arch in [Architecture.X86, Architecture.X86_64]:
            if syntax == Syntax.INTEL:
                self._cs.syntax = CS_OPT_SYNTAX_INTEL
            elif syntax == Syntax.ATT:
                self._cs.syntax = CS_OPT_SYNTAX_ATT
    
    def set_syntax(self, syntax: Syntax):
        """
        Change the disassembly syntax mode.
        
        Args:
            syntax: New syntax mode
        """
        self.syntax = syntax
        self._set_syntax_mode(syntax)
    
    def disassemble(self, code: bytes, address: int, count: int = 0) -> List[Instruction]:
        """
        Disassemble a block of code.
        
        Args:
            code: Raw bytes to disassemble
            address: Starting address
            count: Maximum number of instructions to disassemble (0 = all)
            
        Returns:
            List of Instruction objects
            
        Raises:
            CapstoneError: If disassembly fails
        """
        if not code:
            return []
        
        instructions = []
        
        try:
            for cs_insn in self._cs.disasm(code, address, count):
                # Extract operands as list of strings
                operands = self._extract_operands(cs_insn)
                
                # Create our Instruction object
                insn = Instruction(
                    address=cs_insn.address,
                    mnemonic=cs_insn.mnemonic,
                    operands=operands,
                    bytes=cs_insn.bytes,
                    size=cs_insn.size,
                    architecture=self.arch,
                    op_str=cs_insn.op_str
                )
                instructions.append(insn)
        
        except CsError as e:
            raise CapstoneError(f"Disassembly failed: {e}")
        
        return instructions
    
    def disassemble_single(self, code: bytes, address: int) -> Optional[Instruction]:
        """
        Disassemble a single instruction.
        
        Args:
            code: Raw bytes to disassemble
            address: Instruction address
            
        Returns:
            Instruction object or None if disassembly fails
        """
        try:
            instructions = self.disassemble(code, address, count=1)
            return instructions[0] if instructions else None
        except CapstoneError:
            return None
    
    def disassemble_function(self, code: bytes, start_addr: int, end_addr: int) -> List[Instruction]:
        """
        Disassemble a function between start and end addresses.
        
        Args:
            code: Raw bytes containing the function
            start_addr: Function start address
            end_addr: Function end address
            
        Returns:
            List of Instruction objects
            
        Raises:
            CapstoneError: If disassembly fails
        """
        if end_addr <= start_addr:
            return []
        
        # Calculate the size of the function
        func_size = end_addr - start_addr
        
        # Disassemble the function
        return self.disassemble(code[:func_size], start_addr)
    
    def disassemble_with_errors(self, code: bytes, address: int, count: int = 0) -> Tuple[List[Instruction], List[Tuple[int, bytes]]]:
        """
        Disassemble code and track invalid instructions.
        
        This method continues disassembly even when encountering invalid instructions,
        collecting both valid instructions and invalid byte sequences.
        
        Args:
            code: Raw bytes to disassemble
            address: Starting address
            count: Maximum number of instructions to disassemble (0 = all)
            
        Returns:
            Tuple of (valid_instructions, invalid_sequences)
            where invalid_sequences is a list of (address, bytes) tuples
        """
        instructions = []
        invalid_sequences = []
        
        offset = 0
        current_addr = address
        insn_count = 0
        
        while offset < len(code):
            # Stop if we've reached the requested count
            if count > 0 and insn_count >= count:
                break
            
            # Try to disassemble one instruction
            remaining_code = code[offset:]
            try:
                cs_insns = list(self._cs.disasm(remaining_code, current_addr, 1))
                
                if cs_insns:
                    cs_insn = cs_insns[0]
                    
                    # Extract operands
                    operands = self._extract_operands(cs_insn)
                    
                    # Create Instruction object
                    insn = Instruction(
                        address=cs_insn.address,
                        mnemonic=cs_insn.mnemonic,
                        operands=operands,
                        bytes=cs_insn.bytes,
                        size=cs_insn.size,
                        architecture=self.arch,
                        op_str=cs_insn.op_str
                    )
                    instructions.append(insn)
                    
                    # Move to next instruction
                    offset += cs_insn.size
                    current_addr += cs_insn.size
                    insn_count += 1
                else:
                    # No instruction decoded, treat as invalid
                    invalid_sequences.append((current_addr, bytes([code[offset]])))
                    offset += 1
                    current_addr += 1
            
            except CsError:
                # Capstone error, treat as invalid instruction
                invalid_sequences.append((current_addr, bytes([code[offset]])))
                offset += 1
                current_addr += 1
        
        return instructions, invalid_sequences
    
    def _extract_operands(self, cs_insn) -> List[str]:
        """
        Extract operands from a Capstone instruction.
        
        Args:
            cs_insn: Capstone instruction object
            
        Returns:
            List of operand strings
        """
        # Simple approach: split the op_str by commas
        if not cs_insn.op_str:
            return []
        
        # Split by comma and strip whitespace
        operands = [op.strip() for op in cs_insn.op_str.split(',')]
        return operands
    
    def get_architecture(self) -> Architecture:
        """Get the current architecture"""
        return self.arch
    
    def get_syntax(self) -> Syntax:
        """Get the current syntax mode"""
        return self.syntax
    
    def is_available(self) -> bool:
        """Check if Capstone is available and initialized"""
        return self._cs is not None


def create_disassembler(arch: Architecture, mode: Optional[str] = None, syntax: Syntax = Syntax.DEFAULT) -> CapstoneDisassembler:
    """
    Factory function to create a CapstoneDisassembler instance.
    
    Args:
        arch: Target architecture
        mode: Optional mode string
        syntax: Disassembly syntax mode
        
    Returns:
        CapstoneDisassembler instance
        
    Raises:
        CapstoneError: If initialization fails
    """
    return CapstoneDisassembler(arch, mode, syntax)
