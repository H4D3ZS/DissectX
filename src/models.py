"""Core data models for DissectX"""
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class Operand:
    """Represents an instruction operand with type information"""
    raw: str                         # Original text
    type: str                        # 'register', 'memory', 'immediate', 'label'
    register: Optional[str] = None   # Register name if applicable
    offset: Optional[int] = None     # Memory offset if applicable
    base_register: Optional[str] = None  # Base register for memory references
    size: Optional[int] = None       # Data size in bytes
    
    @staticmethod
    def parse(operand_str: str) -> 'Operand':
        """Parse an operand string and detect its type"""
        operand_str = operand_str.strip()
        
        # Check for memory reference (contains brackets)
        if '[' in operand_str and ']' in operand_str:
            return Operand._parse_memory(operand_str)
        
        # Check for register (common x86-64 registers)
        registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
                    'ax', 'bx', 'cx', 'dx', 'al', 'bl', 'cl', 'dl',
                    'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']
        if operand_str.lower() in registers:
            return Operand(raw=operand_str, type='register', register=operand_str.lower())
        
        # Check for immediate value (starts with 0x or is numeric)
        if operand_str.startswith('0x') or operand_str.startswith('-0x'):
            return Operand(raw=operand_str, type='immediate')
        try:
            int(operand_str)
            return Operand(raw=operand_str, type='immediate')
        except ValueError:
            pass
        
        # Default to label
        return Operand(raw=operand_str, type='label')
    
    @staticmethod
    def _parse_memory(operand_str: str) -> 'Operand':
        """Parse a memory reference operand, handling malformed input gracefully"""
        # Extract content between brackets
        start = operand_str.find('[')
        end = operand_str.find(']')
        
        # Handle malformed brackets gracefully
        if start == -1 or end == -1 or end < start:
            # Malformed memory reference - treat as label
            return Operand(raw=operand_str, type='label')
        
        content = operand_str[start+1:end].strip()
        
        # Handle empty brackets
        if not content:
            return Operand(raw=operand_str, type='memory', base_register=None, offset=None)
        
        base_reg = None
        offset = None
        
        # Parse content (e.g., "rsp+0x10", "rbp-0x8", "rax")
        if '+' in content:
            parts = content.split('+', 1)  # Split only on first +
            base_reg = parts[0].strip()
            if len(parts) > 1:
                try:
                    offset = int(parts[1].strip(), 0)
                except ValueError:
                    # Malformed offset - keep base_reg, offset stays None
                    pass
        elif '-' in content:
            parts = content.split('-', 1)  # Split only on first -
            base_reg = parts[0].strip()
            if len(parts) > 1:
                try:
                    offset = -int(parts[1].strip(), 0)
                except ValueError:
                    # Malformed offset - keep base_reg, offset stays None
                    pass
        else:
            base_reg = content
        
        return Operand(
            raw=operand_str,
            type='memory',
            base_register=base_reg,
            offset=offset
        )


@dataclass
class Instruction:
    """Represents a single assembly instruction"""
    address: Optional[str]          # Memory address (e.g., "140001313")
    mnemonic: str                    # Instruction name (e.g., "mov", "call")
    operands: List[str]              # List of operands as strings
    comment: Optional[str] = None    # Ghidra comment
    label: Optional[str] = None      # Label if present
    size_specifier: Optional[str] = None  # byte ptr, qword ptr, etc.
    
    def get_parsed_operands(self) -> List[Operand]:
        """Parse and return operands as Operand objects"""
        return [Operand.parse(op) for op in self.operands]


@dataclass
class CodeBlock:
    """Represents a group of related instructions forming a logical unit"""
    instructions: List[Instruction]
    block_type: str                  # Type of block (e.g., 'loop', 'conditional', 'function_prologue')
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    description: str = ""            # High-level description
    security_relevant: bool = False  # Flag for security operations
