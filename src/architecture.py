"""Architecture abstraction layer for multi-architecture support"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum


class Architecture(Enum):
    """Supported architectures"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"


class CallingConvention(Enum):
    """Calling conventions"""
    # x86/x64
    CDECL = "cdecl"
    STDCALL = "stdcall"
    FASTCALL = "fastcall"
    MS_X64 = "ms_x64"
    SYSV_X64 = "sysv_x64"
    # ARM
    AAPCS = "aapcs"
    AAPCS64 = "aapcs64"
    # MIPS
    O32 = "o32"
    N64 = "n64"


@dataclass
class RegisterInfo:
    """Information about a register"""
    name: str
    size: int  # Size in bits
    description: str
    aliases: List[str] = None  # Alternative names (e.g., rax -> eax, ax, al, ah)
    
    def __post_init__(self):
        if self.aliases is None:
            self.aliases = []


@dataclass
class CallingConventionInfo:
    """Information about a calling convention"""
    name: CallingConvention
    integer_args: List[str]  # Registers used for integer arguments
    float_args: List[str]  # Registers used for floating-point arguments
    return_reg: str  # Register used for return value
    stack_cleanup: str  # Who cleans up stack: "caller" or "callee"
    stack_alignment: int  # Stack alignment in bytes
    description: str


class ArchitectureBase(ABC):
    """Abstract base class for architecture-specific implementations"""
    
    @abstractmethod
    def get_architecture_name(self) -> Architecture:
        """Return the architecture identifier"""
        pass
    
    @abstractmethod
    def get_register_names(self) -> List[str]:
        """Return list of all register names for this architecture"""
        pass
    
    @abstractmethod
    def get_register_info(self, register: str) -> Optional[RegisterInfo]:
        """Get detailed information about a specific register"""
        pass
    
    @abstractmethod
    def get_calling_convention(self) -> CallingConventionInfo:
        """Return the default calling convention for this architecture"""
        pass
    
    @abstractmethod
    def get_all_calling_conventions(self) -> List[CallingConventionInfo]:
        """Return all supported calling conventions for this architecture"""
        pass
    
    @abstractmethod
    def translate_instruction(self, mnemonic: str, operands: List[str]) -> str:
        """
        Translate an assembly instruction to pseudo-code.
        
        Args:
            mnemonic: The instruction mnemonic (e.g., "mov", "add")
            operands: List of operand strings
            
        Returns:
            Pseudo-code representation of the instruction
        """
        pass
    
    @abstractmethod
    def get_register_size(self, register: str) -> int:
        """
        Get the size of a register in bits.
        
        Args:
            register: Register name
            
        Returns:
            Size in bits, or 0 if register not found
        """
        pass
    
    @abstractmethod
    def is_branch_instruction(self, mnemonic: str) -> bool:
        """
        Check if an instruction is a branch/jump instruction.
        
        Args:
            mnemonic: The instruction mnemonic
            
        Returns:
            True if this is a branch instruction
        """
        pass
    
    @abstractmethod
    def is_call_instruction(self, mnemonic: str) -> bool:
        """
        Check if an instruction is a function call instruction.
        
        Args:
            mnemonic: The instruction mnemonic
            
        Returns:
            True if this is a call instruction
        """
        pass
    
    @abstractmethod
    def is_return_instruction(self, mnemonic: str) -> bool:
        """
        Check if an instruction is a return instruction.
        
        Args:
            mnemonic: The instruction mnemonic
            
        Returns:
            True if this is a return instruction
        """
        pass
    
    def normalize_register_name(self, register: str) -> str:
        """
        Normalize a register name to canonical form.
        
        Args:
            register: Register name (may be in various cases)
            
        Returns:
            Normalized register name
        """
        return register.lower().strip()
    
    def get_instruction_category(self, mnemonic: str) -> str:
        """
        Categorize an instruction by type.
        
        Args:
            mnemonic: The instruction mnemonic
            
        Returns:
            Category string: "data_transfer", "arithmetic", "logic", 
                           "control_flow", "system", "other"
        """
        mnemonic = mnemonic.lower()
        
        # Data transfer
        if mnemonic in ['mov', 'movz', 'movs', 'lea', 'push', 'pop', 'ldr', 'str', 'lw', 'sw']:
            return "data_transfer"
        
        # Arithmetic
        if mnemonic in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg', 'imul', 'idiv']:
            return "arithmetic"
        
        # Logic
        if mnemonic in ['and', 'or', 'xor', 'not', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror']:
            return "logic"
        
        # Control flow
        if self.is_branch_instruction(mnemonic) or self.is_call_instruction(mnemonic) or self.is_return_instruction(mnemonic):
            return "control_flow"
        
        # System
        if mnemonic in ['syscall', 'sysenter', 'int', 'svc', 'hlt']:
            return "system"
        
        return "other"



class X86Architecture(ArchitectureBase):
    """x86 and x86-64 architecture implementation"""
    
    def __init__(self, is_64bit: bool = True):
        """
        Initialize x86 architecture.
        
        Args:
            is_64bit: True for x86-64, False for x86-32
        """
        self.is_64bit = is_64bit
        self._init_registers()
    
    def _init_registers(self):
        """Initialize register information"""
        if self.is_64bit:
            # x86-64 registers
            self.registers = {
                # General purpose 64-bit
                'rax': RegisterInfo('rax', 64, 'Accumulator register', ['eax', 'ax', 'al', 'ah']),
                'rbx': RegisterInfo('rbx', 64, 'Base register', ['ebx', 'bx', 'bl', 'bh']),
                'rcx': RegisterInfo('rcx', 64, 'Counter register', ['ecx', 'cx', 'cl', 'ch']),
                'rdx': RegisterInfo('rdx', 64, 'Data register', ['edx', 'dx', 'dl', 'dh']),
                'rsi': RegisterInfo('rsi', 64, 'Source index', ['esi', 'si', 'sil']),
                'rdi': RegisterInfo('rdi', 64, 'Destination index', ['edi', 'di', 'dil']),
                'rbp': RegisterInfo('rbp', 64, 'Base pointer', ['ebp', 'bp', 'bpl']),
                'rsp': RegisterInfo('rsp', 64, 'Stack pointer', ['esp', 'sp', 'spl']),
                'r8': RegisterInfo('r8', 64, 'General purpose register 8', ['r8d', 'r8w', 'r8b']),
                'r9': RegisterInfo('r9', 64, 'General purpose register 9', ['r9d', 'r9w', 'r9b']),
                'r10': RegisterInfo('r10', 64, 'General purpose register 10', ['r10d', 'r10w', 'r10b']),
                'r11': RegisterInfo('r11', 64, 'General purpose register 11', ['r11d', 'r11w', 'r11b']),
                'r12': RegisterInfo('r12', 64, 'General purpose register 12', ['r12d', 'r12w', 'r12b']),
                'r13': RegisterInfo('r13', 64, 'General purpose register 13', ['r13d', 'r13w', 'r13b']),
                'r14': RegisterInfo('r14', 64, 'General purpose register 14', ['r14d', 'r14w', 'r14b']),
                'r15': RegisterInfo('r15', 64, 'General purpose register 15', ['r15d', 'r15w', 'r15b']),
                # Instruction pointer
                'rip': RegisterInfo('rip', 64, 'Instruction pointer', ['eip', 'ip']),
                # Flags
                'rflags': RegisterInfo('rflags', 64, 'Flags register', ['eflags', 'flags']),
            }
        else:
            # x86-32 registers
            self.registers = {
                'eax': RegisterInfo('eax', 32, 'Accumulator register', ['ax', 'al', 'ah']),
                'ebx': RegisterInfo('ebx', 32, 'Base register', ['bx', 'bl', 'bh']),
                'ecx': RegisterInfo('ecx', 32, 'Counter register', ['cx', 'cl', 'ch']),
                'edx': RegisterInfo('edx', 32, 'Data register', ['dx', 'dl', 'dh']),
                'esi': RegisterInfo('esi', 32, 'Source index', ['si']),
                'edi': RegisterInfo('edi', 32, 'Destination index', ['di']),
                'ebp': RegisterInfo('ebp', 32, 'Base pointer', ['bp']),
                'esp': RegisterInfo('esp', 32, 'Stack pointer', ['sp']),
                'eip': RegisterInfo('eip', 32, 'Instruction pointer', ['ip']),
                'eflags': RegisterInfo('eflags', 32, 'Flags register', ['flags']),
            }
    
    def get_architecture_name(self) -> Architecture:
        """Return the architecture identifier"""
        return Architecture.X86_64 if self.is_64bit else Architecture.X86
    
    def get_register_names(self) -> List[str]:
        """Return list of all register names for this architecture"""
        names = list(self.registers.keys())
        # Add all aliases
        for reg_info in self.registers.values():
            names.extend(reg_info.aliases)
        return names
    
    def get_register_info(self, register: str) -> Optional[RegisterInfo]:
        """Get detailed information about a specific register"""
        register = self.normalize_register_name(register)
        
        # Check if it's a primary register
        if register in self.registers:
            return self.registers[register]
        
        # Check if it's an alias
        for reg_info in self.registers.values():
            if register in reg_info.aliases:
                return reg_info
        
        return None
    
    def get_calling_convention(self) -> CallingConventionInfo:
        """Return the default calling convention for this architecture"""
        if self.is_64bit:
            # System V AMD64 ABI (Linux/Unix)
            return CallingConventionInfo(
                name=CallingConvention.SYSV_X64,
                integer_args=['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
                float_args=['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'],
                return_reg='rax',
                stack_cleanup='caller',
                stack_alignment=16,
                description='System V AMD64 ABI calling convention (Linux/Unix)'
            )
        else:
            # cdecl (most common for x86-32)
            return CallingConventionInfo(
                name=CallingConvention.CDECL,
                integer_args=[],  # All arguments on stack
                float_args=[],
                return_reg='eax',
                stack_cleanup='caller',
                stack_alignment=4,
                description='C declaration calling convention (x86-32)'
            )
    
    def get_all_calling_conventions(self) -> List[CallingConventionInfo]:
        """Return all supported calling conventions for this architecture"""
        if self.is_64bit:
            return [
                # System V AMD64 ABI (Linux/Unix)
                CallingConventionInfo(
                    name=CallingConvention.SYSV_X64,
                    integer_args=['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
                    float_args=['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7'],
                    return_reg='rax',
                    stack_cleanup='caller',
                    stack_alignment=16,
                    description='System V AMD64 ABI calling convention (Linux/Unix)'
                ),
                # Microsoft x64 calling convention (Windows)
                CallingConventionInfo(
                    name=CallingConvention.MS_X64,
                    integer_args=['rcx', 'rdx', 'r8', 'r9'],
                    float_args=['xmm0', 'xmm1', 'xmm2', 'xmm3'],
                    return_reg='rax',
                    stack_cleanup='caller',
                    stack_alignment=16,
                    description='Microsoft x64 calling convention (Windows)'
                ),
            ]
        else:
            return [
                # cdecl
                CallingConventionInfo(
                    name=CallingConvention.CDECL,
                    integer_args=[],
                    float_args=[],
                    return_reg='eax',
                    stack_cleanup='caller',
                    stack_alignment=4,
                    description='C declaration calling convention'
                ),
                # stdcall
                CallingConventionInfo(
                    name=CallingConvention.STDCALL,
                    integer_args=[],
                    float_args=[],
                    return_reg='eax',
                    stack_cleanup='callee',
                    stack_alignment=4,
                    description='Standard calling convention (Windows API)'
                ),
                # fastcall
                CallingConventionInfo(
                    name=CallingConvention.FASTCALL,
                    integer_args=['ecx', 'edx'],
                    float_args=[],
                    return_reg='eax',
                    stack_cleanup='callee',
                    stack_alignment=4,
                    description='Fast calling convention (first 2 args in registers)'
                ),
            ]
    
    def translate_instruction(self, mnemonic: str, operands: List[str]) -> str:
        """Translate an x86 assembly instruction to pseudo-code"""
        mnemonic = mnemonic.lower()
        
        # Data transfer instructions
        if mnemonic == 'mov':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[1]}"
        
        elif mnemonic == 'lea':
            if len(operands) >= 2:
                return f"{operands[0]} = &({operands[1]})"
        
        elif mnemonic == 'push':
            if len(operands) >= 1:
                return f"push({operands[0]})"
        
        elif mnemonic == 'pop':
            if len(operands) >= 1:
                return f"{operands[0]} = pop()"
        
        # Arithmetic instructions
        elif mnemonic == 'add':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} + {operands[1]}"
        
        elif mnemonic == 'sub':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} - {operands[1]}"
        
        elif mnemonic == 'imul' or mnemonic == 'mul':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} * {operands[1]}"
            elif len(operands) == 1:
                return f"rax = rax * {operands[0]}"
        
        elif mnemonic == 'idiv' or mnemonic == 'div':
            if len(operands) >= 1:
                return f"rax = rax / {operands[0]}"
        
        elif mnemonic == 'inc':
            if len(operands) >= 1:
                return f"{operands[0]} = {operands[0]} + 1"
        
        elif mnemonic == 'dec':
            if len(operands) >= 1:
                return f"{operands[0]} = {operands[0]} - 1"
        
        elif mnemonic == 'neg':
            if len(operands) >= 1:
                return f"{operands[0]} = -{operands[0]}"
        
        # Logical instructions
        elif mnemonic == 'and':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} & {operands[1]}"
        
        elif mnemonic == 'or':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} | {operands[1]}"
        
        elif mnemonic == 'xor':
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} ^ {operands[1]}"
        
        elif mnemonic == 'not':
            if len(operands) >= 1:
                return f"{operands[0]} = ~{operands[0]}"
        
        elif mnemonic in ['shl', 'sal']:
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} << {operands[1]}"
        
        elif mnemonic in ['shr', 'sar']:
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[0]} >> {operands[1]}"
        
        # Comparison
        elif mnemonic == 'cmp':
            if len(operands) >= 2:
                return f"compare({operands[0]}, {operands[1]})"
        
        elif mnemonic == 'test':
            if len(operands) >= 2:
                return f"test({operands[0]} & {operands[1]})"
        
        # Control flow
        elif mnemonic == 'call':
            if len(operands) >= 1:
                return f"call {operands[0]}()"
        
        elif mnemonic == 'ret':
            return "return"
        
        elif mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe']:
            if len(operands) >= 1:
                condition = self._get_jump_condition(mnemonic)
                if condition:
                    return f"if ({condition}) goto {operands[0]}"
                else:
                    return f"goto {operands[0]}"
        
        # System calls
        elif mnemonic == 'syscall':
            return "syscall()"
        
        elif mnemonic == 'int':
            if len(operands) >= 1:
                return f"interrupt({operands[0]})"
        
        # Default: return mnemonic with operands
        if operands:
            return f"{mnemonic}({', '.join(operands)})"
        return f"{mnemonic}()"
    
    def _get_jump_condition(self, mnemonic: str) -> Optional[str]:
        """Get the condition for a conditional jump instruction"""
        conditions = {
            'je': 'equal',
            'jz': 'zero',
            'jne': 'not_equal',
            'jnz': 'not_zero',
            'jg': 'greater',
            'jge': 'greater_or_equal',
            'jl': 'less',
            'jle': 'less_or_equal',
            'ja': 'above',
            'jae': 'above_or_equal',
            'jb': 'below',
            'jbe': 'below_or_equal',
        }
        return conditions.get(mnemonic.lower())
    
    def get_register_size(self, register: str) -> int:
        """Get the size of a register in bits"""
        register = self.normalize_register_name(register)
        
        # Check primary registers
        if register in self.registers:
            return self.registers[register].size
        
        # Check aliases and determine size
        if self.is_64bit:
            # 64-bit registers
            if register in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 
                           'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags']:
                return 64
            # 32-bit registers
            if register in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags',
                           'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']:
                return 32
            # 16-bit registers
            if register in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip', 'flags',
                           'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']:
                return 16
            # 8-bit registers
            if register in ['al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil', 'bpl', 'spl',
                           'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']:
                return 8
        else:
            # 32-bit registers
            if register in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'eflags']:
                return 32
            # 16-bit registers
            if register in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip', 'flags']:
                return 16
            # 8-bit registers
            if register in ['al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh']:
                return 8
        
        return 0
    
    def is_branch_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a branch/jump instruction"""
        mnemonic = mnemonic.lower()
        branch_instructions = [
            'jmp', 'je', 'jz', 'jne', 'jnz', 'jg', 'jge', 'jl', 'jle',
            'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
            'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne'
        ]
        return mnemonic in branch_instructions
    
    def is_call_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a function call instruction"""
        return mnemonic.lower() == 'call'
    
    def is_return_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a return instruction"""
        mnemonic = mnemonic.lower()
        return mnemonic in ['ret', 'retn', 'retf', 'iret', 'iretd', 'iretq']



class ARMArchitecture(ArchitectureBase):
    """ARM and ARM64 (AArch64) architecture implementation"""
    
    def __init__(self, is_64bit: bool = False):
        """
        Initialize ARM architecture.
        
        Args:
            is_64bit: True for ARM64/AArch64, False for ARM32
        """
        self.is_64bit = is_64bit
        self._init_registers()
    
    def _init_registers(self):
        """Initialize register information"""
        if self.is_64bit:
            # ARM64/AArch64 registers
            self.registers = {
                # General purpose 64-bit registers
                'x0': RegisterInfo('x0', 64, 'General purpose register 0 / Argument 1', ['w0']),
                'x1': RegisterInfo('x1', 64, 'General purpose register 1 / Argument 2', ['w1']),
                'x2': RegisterInfo('x2', 64, 'General purpose register 2 / Argument 3', ['w2']),
                'x3': RegisterInfo('x3', 64, 'General purpose register 3 / Argument 4', ['w3']),
                'x4': RegisterInfo('x4', 64, 'General purpose register 4 / Argument 5', ['w4']),
                'x5': RegisterInfo('x5', 64, 'General purpose register 5 / Argument 6', ['w5']),
                'x6': RegisterInfo('x6', 64, 'General purpose register 6 / Argument 7', ['w6']),
                'x7': RegisterInfo('x7', 64, 'General purpose register 7 / Argument 8', ['w7']),
                'x8': RegisterInfo('x8', 64, 'General purpose register 8', ['w8']),
                'x9': RegisterInfo('x9', 64, 'General purpose register 9', ['w9']),
                'x10': RegisterInfo('x10', 64, 'General purpose register 10', ['w10']),
                'x11': RegisterInfo('x11', 64, 'General purpose register 11', ['w11']),
                'x12': RegisterInfo('x12', 64, 'General purpose register 12', ['w12']),
                'x13': RegisterInfo('x13', 64, 'General purpose register 13', ['w13']),
                'x14': RegisterInfo('x14', 64, 'General purpose register 14', ['w14']),
                'x15': RegisterInfo('x15', 64, 'General purpose register 15', ['w15']),
                'x16': RegisterInfo('x16', 64, 'General purpose register 16 / IP0', ['w16']),
                'x17': RegisterInfo('x17', 64, 'General purpose register 17 / IP1', ['w17']),
                'x18': RegisterInfo('x18', 64, 'General purpose register 18 / Platform register', ['w18']),
                'x19': RegisterInfo('x19', 64, 'General purpose register 19', ['w19']),
                'x20': RegisterInfo('x20', 64, 'General purpose register 20', ['w20']),
                'x21': RegisterInfo('x21', 64, 'General purpose register 21', ['w21']),
                'x22': RegisterInfo('x22', 64, 'General purpose register 22', ['w22']),
                'x23': RegisterInfo('x23', 64, 'General purpose register 23', ['w23']),
                'x24': RegisterInfo('x24', 64, 'General purpose register 24', ['w24']),
                'x25': RegisterInfo('x25', 64, 'General purpose register 25', ['w25']),
                'x26': RegisterInfo('x26', 64, 'General purpose register 26', ['w26']),
                'x27': RegisterInfo('x27', 64, 'General purpose register 27', ['w27']),
                'x28': RegisterInfo('x28', 64, 'General purpose register 28', ['w28']),
                'x29': RegisterInfo('x29', 64, 'Frame pointer', ['w29', 'fp']),
                'x30': RegisterInfo('x30', 64, 'Link register', ['w30', 'lr']),
                'sp': RegisterInfo('sp', 64, 'Stack pointer', ['wsp']),
                'pc': RegisterInfo('pc', 64, 'Program counter', []),
                'xzr': RegisterInfo('xzr', 64, 'Zero register', ['wzr']),
            }
        else:
            # ARM32 registers
            self.registers = {
                'r0': RegisterInfo('r0', 32, 'General purpose register 0 / Argument 1', []),
                'r1': RegisterInfo('r1', 32, 'General purpose register 1 / Argument 2', []),
                'r2': RegisterInfo('r2', 32, 'General purpose register 2 / Argument 3', []),
                'r3': RegisterInfo('r3', 32, 'General purpose register 3 / Argument 4', []),
                'r4': RegisterInfo('r4', 32, 'General purpose register 4', []),
                'r5': RegisterInfo('r5', 32, 'General purpose register 5', []),
                'r6': RegisterInfo('r6', 32, 'General purpose register 6', []),
                'r7': RegisterInfo('r7', 32, 'General purpose register 7', []),
                'r8': RegisterInfo('r8', 32, 'General purpose register 8', []),
                'r9': RegisterInfo('r9', 32, 'General purpose register 9', []),
                'r10': RegisterInfo('r10', 32, 'General purpose register 10', []),
                'r11': RegisterInfo('r11', 32, 'Frame pointer', ['fp']),
                'r12': RegisterInfo('r12', 32, 'Intra-procedure call register', ['ip']),
                'r13': RegisterInfo('r13', 32, 'Stack pointer', ['sp']),
                'r14': RegisterInfo('r14', 32, 'Link register', ['lr']),
                'r15': RegisterInfo('r15', 32, 'Program counter', ['pc']),
                'cpsr': RegisterInfo('cpsr', 32, 'Current program status register', []),
            }
    
    def get_architecture_name(self) -> Architecture:
        """Return the architecture identifier"""
        return Architecture.ARM64 if self.is_64bit else Architecture.ARM
    
    def get_register_names(self) -> List[str]:
        """Return list of all register names for this architecture"""
        names = list(self.registers.keys())
        # Add all aliases
        for reg_info in self.registers.values():
            names.extend(reg_info.aliases)
        return names
    
    def get_register_info(self, register: str) -> Optional[RegisterInfo]:
        """Get detailed information about a specific register"""
        register = self.normalize_register_name(register)
        
        # Check if it's a primary register
        if register in self.registers:
            return self.registers[register]
        
        # Check if it's an alias
        for reg_info in self.registers.values():
            if register in reg_info.aliases:
                return reg_info
        
        return None
    
    def get_calling_convention(self) -> CallingConventionInfo:
        """Return the default calling convention for this architecture"""
        if self.is_64bit:
            # AAPCS64 (ARM Architecture Procedure Call Standard for ARM64)
            return CallingConventionInfo(
                name=CallingConvention.AAPCS64,
                integer_args=['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
                float_args=['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7'],
                return_reg='x0',
                stack_cleanup='caller',
                stack_alignment=16,
                description='ARM Architecture Procedure Call Standard for ARM64'
            )
        else:
            # AAPCS (ARM Architecture Procedure Call Standard)
            return CallingConventionInfo(
                name=CallingConvention.AAPCS,
                integer_args=['r0', 'r1', 'r2', 'r3'],
                float_args=['s0', 's1', 's2', 's3'],
                return_reg='r0',
                stack_cleanup='caller',
                stack_alignment=8,
                description='ARM Architecture Procedure Call Standard'
            )
    
    def get_all_calling_conventions(self) -> List[CallingConventionInfo]:
        """Return all supported calling conventions for this architecture"""
        return [self.get_calling_convention()]
    
    def translate_instruction(self, mnemonic: str, operands: List[str]) -> str:
        """Translate an ARM assembly instruction to pseudo-code"""
        mnemonic = mnemonic.lower()
        
        # Data transfer instructions
        if mnemonic in ['mov', 'movz', 'movk']:
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[1]}"
        
        elif mnemonic in ['ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh']:
            if len(operands) >= 2:
                size = self._get_load_size(mnemonic)
                return f"{operands[0]} = *({size}*)({operands[1]})"
        
        elif mnemonic in ['str', 'strb', 'strh']:
            if len(operands) >= 2:
                size = self._get_store_size(mnemonic)
                return f"*({size}*)({operands[1]}) = {operands[0]}"
        
        elif mnemonic in ['ldp']:
            if len(operands) >= 3:
                return f"{operands[0]}, {operands[1]} = load_pair({operands[2]})"
        
        elif mnemonic in ['stp']:
            if len(operands) >= 3:
                return f"store_pair({operands[2]}, {operands[0]}, {operands[1]})"
        
        # Arithmetic instructions
        elif mnemonic in ['add', 'adds']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} + {operands[2]}"
            elif len(operands) == 2:
                return f"{operands[0]} = {operands[0]} + {operands[1]}"
        
        elif mnemonic in ['sub', 'subs']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} - {operands[2]}"
            elif len(operands) == 2:
                return f"{operands[0]} = {operands[0]} - {operands[1]}"
        
        elif mnemonic in ['mul', 'madd']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} * {operands[2]}"
        
        elif mnemonic in ['sdiv', 'udiv']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} / {operands[2]}"
        
        # Logical instructions
        elif mnemonic in ['and', 'ands']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} & {operands[2]}"
        
        elif mnemonic in ['orr']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} | {operands[2]}"
        
        elif mnemonic in ['eor']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} ^ {operands[2]}"
        
        elif mnemonic in ['mvn']:
            if len(operands) >= 2:
                return f"{operands[0]} = ~{operands[1]}"
        
        elif mnemonic in ['lsl']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} << {operands[2]}"
        
        elif mnemonic in ['lsr', 'asr']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} >> {operands[2]}"
        
        # Comparison
        elif mnemonic in ['cmp']:
            if len(operands) >= 2:
                return f"compare({operands[0]}, {operands[1]})"
        
        elif mnemonic in ['tst']:
            if len(operands) >= 2:
                return f"test({operands[0]} & {operands[1]})"
        
        # Control flow
        elif mnemonic in ['bl', 'blr']:
            if len(operands) >= 1:
                return f"call {operands[0]}()"
        
        elif mnemonic in ['br']:
            if len(operands) >= 1:
                return f"goto *{operands[0]}"
        
        elif mnemonic in ['ret']:
            return "return"
        
        elif mnemonic in ['b', 'b.eq', 'b.ne', 'b.lt', 'b.le', 'b.gt', 'b.ge', 'b.lo', 'b.ls', 'b.hi', 'b.hs']:
            if len(operands) >= 1:
                condition = self._get_branch_condition(mnemonic)
                if condition:
                    return f"if ({condition}) goto {operands[0]}"
                else:
                    return f"goto {operands[0]}"
        
        # System calls
        elif mnemonic in ['svc']:
            if len(operands) >= 1:
                return f"syscall({operands[0]})"
        
        # Default: return mnemonic with operands
        if operands:
            return f"{mnemonic}({', '.join(operands)})"
        return f"{mnemonic}()"
    
    def _get_load_size(self, mnemonic: str) -> str:
        """Get the size specifier for load instructions"""
        if 'b' in mnemonic:
            return 'byte'
        elif 'h' in mnemonic:
            return 'half'
        else:
            return 'word' if not self.is_64bit else 'dword'
    
    def _get_store_size(self, mnemonic: str) -> str:
        """Get the size specifier for store instructions"""
        if 'b' in mnemonic:
            return 'byte'
        elif 'h' in mnemonic:
            return 'half'
        else:
            return 'word' if not self.is_64bit else 'dword'
    
    def _get_branch_condition(self, mnemonic: str) -> Optional[str]:
        """Get the condition for a conditional branch instruction"""
        conditions = {
            'b.eq': 'equal',
            'b.ne': 'not_equal',
            'b.lt': 'less_than',
            'b.le': 'less_or_equal',
            'b.gt': 'greater_than',
            'b.ge': 'greater_or_equal',
            'b.lo': 'lower',
            'b.ls': 'lower_or_same',
            'b.hi': 'higher',
            'b.hs': 'higher_or_same',
        }
        return conditions.get(mnemonic.lower())
    
    def get_register_size(self, register: str) -> int:
        """Get the size of a register in bits"""
        register = self.normalize_register_name(register)
        
        # Check primary registers
        if register in self.registers:
            return self.registers[register].size
        
        # Check aliases
        if self.is_64bit:
            # 64-bit registers (x0-x30, sp, pc, xzr)
            if register.startswith('x') or register in ['sp', 'pc', 'fp', 'lr', 'xzr']:
                return 64
            # 32-bit registers (w0-w30, wsp, wzr)
            if register.startswith('w'):
                return 32
        else:
            # 32-bit registers (r0-r15, sp, pc, lr, fp, ip, cpsr)
            if register.startswith('r') or register in ['sp', 'pc', 'lr', 'fp', 'ip', 'cpsr']:
                return 32
        
        return 0
    
    def is_branch_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a branch/jump instruction"""
        mnemonic = mnemonic.lower()
        # Unconditional branches
        if mnemonic in ['b', 'br', 'bx']:
            return True
        # Conditional branches
        if mnemonic.startswith('b.') or mnemonic.startswith('cb') or mnemonic.startswith('tb'):
            return True
        return False
    
    def is_call_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a function call instruction"""
        mnemonic = mnemonic.lower()
        return mnemonic in ['bl', 'blr', 'blx']
    
    def is_return_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a return instruction"""
        return mnemonic.lower() == 'ret'



class MIPSArchitecture(ArchitectureBase):
    """MIPS and MIPS64 architecture implementation"""
    
    def __init__(self, is_64bit: bool = False):
        """
        Initialize MIPS architecture.
        
        Args:
            is_64bit: True for MIPS64, False for MIPS32
        """
        self.is_64bit = is_64bit
        self._init_registers()
    
    def _init_registers(self):
        """Initialize register information"""
        bit_size = 64 if self.is_64bit else 32
        
        # MIPS registers (same names for 32 and 64-bit, just different sizes)
        self.registers = {
            # Special registers
            '$zero': RegisterInfo('$zero', bit_size, 'Constant zero', ['$0']),
            '$at': RegisterInfo('$at', bit_size, 'Assembler temporary', ['$1']),
            # Return values
            '$v0': RegisterInfo('$v0', bit_size, 'Return value 0', ['$2']),
            '$v1': RegisterInfo('$v1', bit_size, 'Return value 1', ['$3']),
            # Arguments
            '$a0': RegisterInfo('$a0', bit_size, 'Argument 0', ['$4']),
            '$a1': RegisterInfo('$a1', bit_size, 'Argument 1', ['$5']),
            '$a2': RegisterInfo('$a2', bit_size, 'Argument 2', ['$6']),
            '$a3': RegisterInfo('$a3', bit_size, 'Argument 3', ['$7']),
            # Temporaries
            '$t0': RegisterInfo('$t0', bit_size, 'Temporary 0', ['$8']),
            '$t1': RegisterInfo('$t1', bit_size, 'Temporary 1', ['$9']),
            '$t2': RegisterInfo('$t2', bit_size, 'Temporary 2', ['$10']),
            '$t3': RegisterInfo('$t3', bit_size, 'Temporary 3', ['$11']),
            '$t4': RegisterInfo('$t4', bit_size, 'Temporary 4', ['$12']),
            '$t5': RegisterInfo('$t5', bit_size, 'Temporary 5', ['$13']),
            '$t6': RegisterInfo('$t6', bit_size, 'Temporary 6', ['$14']),
            '$t7': RegisterInfo('$t7', bit_size, 'Temporary 7', ['$15']),
            # Saved temporaries
            '$s0': RegisterInfo('$s0', bit_size, 'Saved temporary 0', ['$16']),
            '$s1': RegisterInfo('$s1', bit_size, 'Saved temporary 1', ['$17']),
            '$s2': RegisterInfo('$s2', bit_size, 'Saved temporary 2', ['$18']),
            '$s3': RegisterInfo('$s3', bit_size, 'Saved temporary 3', ['$19']),
            '$s4': RegisterInfo('$s4', bit_size, 'Saved temporary 4', ['$20']),
            '$s5': RegisterInfo('$s5', bit_size, 'Saved temporary 5', ['$21']),
            '$s6': RegisterInfo('$s6', bit_size, 'Saved temporary 6', ['$22']),
            '$s7': RegisterInfo('$s7', bit_size, 'Saved temporary 7', ['$23']),
            # More temporaries
            '$t8': RegisterInfo('$t8', bit_size, 'Temporary 8', ['$24']),
            '$t9': RegisterInfo('$t9', bit_size, 'Temporary 9', ['$25']),
            # Kernel registers
            '$k0': RegisterInfo('$k0', bit_size, 'Kernel temporary 0', ['$26']),
            '$k1': RegisterInfo('$k1', bit_size, 'Kernel temporary 1', ['$27']),
            # Special purpose
            '$gp': RegisterInfo('$gp', bit_size, 'Global pointer', ['$28']),
            '$sp': RegisterInfo('$sp', bit_size, 'Stack pointer', ['$29']),
            '$fp': RegisterInfo('$fp', bit_size, 'Frame pointer', ['$30', '$s8']),
            '$ra': RegisterInfo('$ra', bit_size, 'Return address', ['$31']),
            # Program counter
            'pc': RegisterInfo('pc', bit_size, 'Program counter', []),
        }
    
    def get_architecture_name(self) -> Architecture:
        """Return the architecture identifier"""
        return Architecture.MIPS64 if self.is_64bit else Architecture.MIPS
    
    def get_register_names(self) -> List[str]:
        """Return list of all register names for this architecture"""
        names = list(self.registers.keys())
        # Add all aliases
        for reg_info in self.registers.values():
            names.extend(reg_info.aliases)
        return names
    
    def get_register_info(self, register: str) -> Optional[RegisterInfo]:
        """Get detailed information about a specific register"""
        register = self.normalize_register_name(register)
        
        # Check if it's a primary register
        if register in self.registers:
            return self.registers[register]
        
        # Check if it's an alias
        for reg_info in self.registers.values():
            if register in reg_info.aliases:
                return reg_info
        
        return None
    
    def get_calling_convention(self) -> CallingConventionInfo:
        """Return the default calling convention for this architecture"""
        if self.is_64bit:
            # N64 calling convention (MIPS64)
            return CallingConventionInfo(
                name=CallingConvention.N64,
                integer_args=['$a0', '$a1', '$a2', '$a3', '$a4', '$a5', '$a6', '$a7'],
                float_args=['$f12', '$f13', '$f14', '$f15', '$f16', '$f17', '$f18', '$f19'],
                return_reg='$v0',
                stack_cleanup='caller',
                stack_alignment=16,
                description='MIPS N64 calling convention'
            )
        else:
            # O32 calling convention (MIPS32)
            return CallingConventionInfo(
                name=CallingConvention.O32,
                integer_args=['$a0', '$a1', '$a2', '$a3'],
                float_args=['$f12', '$f14'],
                return_reg='$v0',
                stack_cleanup='caller',
                stack_alignment=8,
                description='MIPS O32 calling convention'
            )
    
    def get_all_calling_conventions(self) -> List[CallingConventionInfo]:
        """Return all supported calling conventions for this architecture"""
        return [self.get_calling_convention()]
    
    def translate_instruction(self, mnemonic: str, operands: List[str]) -> str:
        """Translate a MIPS assembly instruction to pseudo-code"""
        mnemonic = mnemonic.lower()
        
        # Data transfer instructions
        if mnemonic in ['move', 'mov']:
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[1]}"
        
        elif mnemonic in ['li']:
            if len(operands) >= 2:
                return f"{operands[0]} = {operands[1]}"
        
        elif mnemonic in ['la']:
            if len(operands) >= 2:
                return f"{operands[0]} = &({operands[1]})"
        
        elif mnemonic in ['lw', 'ld']:
            if len(operands) >= 2:
                size = 'word' if mnemonic == 'lw' else 'dword'
                return f"{operands[0]} = *({size}*)({operands[1]})"
        
        elif mnemonic in ['lb', 'lbu']:
            if len(operands) >= 2:
                return f"{operands[0]} = *(byte*)({operands[1]})"
        
        elif mnemonic in ['lh', 'lhu']:
            if len(operands) >= 2:
                return f"{operands[0]} = *(half*)({operands[1]})"
        
        elif mnemonic in ['sw', 'sd']:
            if len(operands) >= 2:
                size = 'word' if mnemonic == 'sw' else 'dword'
                return f"*({size}*)({operands[1]}) = {operands[0]}"
        
        elif mnemonic in ['sb']:
            if len(operands) >= 2:
                return f"*(byte*)({operands[1]}) = {operands[0]}"
        
        elif mnemonic in ['sh']:
            if len(operands) >= 2:
                return f"*(half*)({operands[1]}) = {operands[0]}"
        
        # Arithmetic instructions
        elif mnemonic in ['add', 'addu', 'addi', 'addiu']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} + {operands[2]}"
        
        elif mnemonic in ['sub', 'subu']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} - {operands[2]}"
        
        elif mnemonic in ['mul', 'mult', 'multu']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} * {operands[2]}"
            elif len(operands) == 2:
                return f"hi, lo = {operands[0]} * {operands[1]}"
        
        elif mnemonic in ['div', 'divu']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} / {operands[2]}"
            elif len(operands) == 2:
                return f"lo = {operands[0]} / {operands[1]}; hi = {operands[0]} % {operands[1]}"
        
        # Logical instructions
        elif mnemonic in ['and', 'andi']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} & {operands[2]}"
        
        elif mnemonic in ['or', 'ori']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} | {operands[2]}"
        
        elif mnemonic in ['xor', 'xori']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} ^ {operands[2]}"
        
        elif mnemonic in ['nor']:
            if len(operands) >= 3:
                return f"{operands[0]} = ~({operands[1]} | {operands[2]})"
        
        elif mnemonic in ['sll', 'sllv']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} << {operands[2]}"
        
        elif mnemonic in ['srl', 'srlv', 'sra', 'srav']:
            if len(operands) >= 3:
                return f"{operands[0]} = {operands[1]} >> {operands[2]}"
        
        # Comparison and set instructions
        elif mnemonic in ['slt', 'slti']:
            if len(operands) >= 3:
                return f"{operands[0]} = ({operands[1]} < {operands[2]}) ? 1 : 0"
        
        elif mnemonic in ['sltu', 'sltiu']:
            if len(operands) >= 3:
                return f"{operands[0]} = (unsigned({operands[1]}) < unsigned({operands[2]})) ? 1 : 0"
        
        # Control flow
        elif mnemonic in ['j']:
            if len(operands) >= 1:
                return f"goto {operands[0]}"
        
        elif mnemonic in ['jr']:
            if len(operands) >= 1:
                return f"goto *{operands[0]}"
        
        elif mnemonic in ['jal']:
            if len(operands) >= 1:
                return f"call {operands[0]}()"
        
        elif mnemonic in ['jalr']:
            if len(operands) >= 1:
                return f"call *{operands[0]}()"
        
        elif mnemonic in ['beq']:
            if len(operands) >= 3:
                return f"if ({operands[0]} == {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['bne']:
            if len(operands) >= 3:
                return f"if ({operands[0]} != {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['blt']:
            if len(operands) >= 3:
                return f"if ({operands[0]} < {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['ble']:
            if len(operands) >= 3:
                return f"if ({operands[0]} <= {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['bgt']:
            if len(operands) >= 3:
                return f"if ({operands[0]} > {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['bge']:
            if len(operands) >= 3:
                return f"if ({operands[0]} >= {operands[1]}) goto {operands[2]}"
        
        elif mnemonic in ['bgez']:
            if len(operands) >= 2:
                return f"if ({operands[0]} >= 0) goto {operands[1]}"
        
        elif mnemonic in ['bgtz']:
            if len(operands) >= 2:
                return f"if ({operands[0]} > 0) goto {operands[1]}"
        
        elif mnemonic in ['blez']:
            if len(operands) >= 2:
                return f"if ({operands[0]} <= 0) goto {operands[1]}"
        
        elif mnemonic in ['bltz']:
            if len(operands) >= 2:
                return f"if ({operands[0]} < 0) goto {operands[1]}"
        
        # Special instructions
        elif mnemonic in ['nop']:
            return "/* no operation */"
        
        elif mnemonic in ['syscall']:
            return "syscall()"
        
        elif mnemonic in ['break']:
            if len(operands) >= 1:
                return f"break({operands[0]})"
            return "break()"
        
        # Default: return mnemonic with operands
        if operands:
            return f"{mnemonic}({', '.join(operands)})"
        return f"{mnemonic}()"
    
    def get_register_size(self, register: str) -> int:
        """Get the size of a register in bits"""
        register = self.normalize_register_name(register)
        
        # Check primary registers
        if register in self.registers:
            return self.registers[register].size
        
        # All MIPS general purpose registers are the same size
        if register.startswith('$') or register == 'pc':
            return 64 if self.is_64bit else 32
        
        return 0
    
    def is_branch_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a branch/jump instruction"""
        mnemonic = mnemonic.lower()
        branch_instructions = [
            'j', 'jr', 'b', 'beq', 'bne', 'blt', 'ble', 'bgt', 'bge',
            'bgez', 'bgtz', 'blez', 'bltz', 'beqz', 'bnez'
        ]
        return mnemonic in branch_instructions
    
    def is_call_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a function call instruction"""
        mnemonic = mnemonic.lower()
        return mnemonic in ['jal', 'jalr']
    
    def is_return_instruction(self, mnemonic: str) -> bool:
        """Check if an instruction is a return instruction"""
        mnemonic = mnemonic.lower()
        # MIPS doesn't have a dedicated return instruction
        # Returns are typically "jr $ra"
        return False  # This would need context to determine
