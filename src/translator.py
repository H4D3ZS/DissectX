"""Instruction translator for DissectX - converting assembly to English"""
import re
import subprocess
from typing import Dict, Optional
from src.models import Instruction, Operand


class InstructionTranslator:
    """Translates assembly instructions into human-readable English"""
    
    def __init__(self):
        """Initialize the translator with instruction database and register descriptions"""
        # Register descriptions for human-friendly explanations
        self.register_descriptions = {
            # 64-bit general purpose registers
            'rax': 'accumulator register',
            'rbx': 'base register',
            'rcx': 'counter register',
            'rdx': 'data register',
            'rsi': 'source index register',
            'rdi': 'destination index register',
            'rbp': 'base pointer (stack frame base)',
            'rsp': 'stack pointer',
            'r8': 'general purpose register R8',
            'r9': 'general purpose register R9',
            'r10': 'general purpose register R10',
            'r11': 'general purpose register R11',
            'r12': 'general purpose register R12',
            'r13': 'general purpose register R13',
            'r14': 'general purpose register R14',
            'r15': 'general purpose register R15',
            
            # 32-bit general purpose registers
            'eax': '32-bit accumulator register',
            'ebx': '32-bit base register',
            'ecx': '32-bit counter register',
            'edx': '32-bit data register',
            'esi': '32-bit source index register',
            'edi': '32-bit destination index register',
            'ebp': '32-bit base pointer',
            'esp': '32-bit stack pointer',
            'r8d': '32-bit R8 register',
            'r9d': '32-bit R9 register',
            'r10d': '32-bit R10 register',
            'r11d': '32-bit R11 register',
            'r12d': '32-bit R12 register',
            'r13d': '32-bit R13 register',
            'r14d': '32-bit R14 register',
            'r15d': '32-bit R15 register',
            
            # 16-bit general purpose registers
            'ax': '16-bit accumulator register',
            'bx': '16-bit base register',
            'cx': '16-bit counter register',
            'dx': '16-bit data register',
            'si': '16-bit source index register',
            'di': '16-bit destination index register',
            'bp': '16-bit base pointer',
            'sp': '16-bit stack pointer',
            
            # 8-bit general purpose registers
            'al': '8-bit accumulator register (low byte)',
            'ah': '8-bit accumulator register (high byte)',
            'bl': '8-bit base register (low byte)',
            'bh': '8-bit base register (high byte)',
            'cl': '8-bit counter register (low byte)',
            'ch': '8-bit counter register (high byte)',
            'dl': '8-bit data register (low byte)',
            'dh': '8-bit data register (high byte)',
            'sil': '8-bit source index register (low byte)',
            'dil': '8-bit destination index register (low byte)',
            'bpl': '8-bit base pointer (low byte)',
            'spl': '8-bit stack pointer (low byte)',
            'r8b': '8-bit R8 register (low byte)',
            'r9b': '8-bit R9 register (low byte)',
            'r10b': '8-bit R10 register (low byte)',
            'r11b': '8-bit R11 register (low byte)',
            'r12b': '8-bit R12 register (low byte)',
            'r13b': '8-bit R13 register (low byte)',
            'r14b': '8-bit R14 register (low byte)',
            'r15b': '8-bit R15 register (low byte)',
            
            # XMM registers (SSE/AVX)
            'xmm0': 'XMM register 0 (floating point/SIMD)',
            'xmm1': 'XMM register 1 (floating point/SIMD)',
            'xmm2': 'XMM register 2 (floating point/SIMD)',
            'xmm3': 'XMM register 3 (floating point/SIMD)',
            'xmm4': 'XMM register 4 (floating point/SIMD)',
            'xmm5': 'XMM register 5 (floating point/SIMD)',
            'xmm6': 'XMM register 6 (floating point/SIMD)',
            'xmm7': 'XMM register 7 (floating point/SIMD)',
            'xmm8': 'XMM register 8 (floating point/SIMD)',
            'xmm9': 'XMM register 9 (floating point/SIMD)',
            'xmm10': 'XMM register 10 (floating point/SIMD)',
            'xmm11': 'XMM register 11 (floating point/SIMD)',
            'xmm12': 'XMM register 12 (floating point/SIMD)',
            'xmm13': 'XMM register 13 (floating point/SIMD)',
            'xmm14': 'XMM register 14 (floating point/SIMD)',
            'xmm15': 'XMM register 15 (floating point/SIMD)',
            
            # Segment registers
            'cs': 'code segment register',
            'ds': 'data segment register',
            'es': 'extra segment register',
            'fs': 'FS segment register (often used for thread-local storage)',
            'gs': 'GS segment register (often used for thread-local storage)',
            'ss': 'stack segment register',
        }
        
        # Comprehensive instruction database mapping mnemonics to operation types
        self.instruction_types = {
            # Data movement instructions
            'mov': 'move',
            'movabs': 'move',
            'lea': 'load_effective_address',
            'movzx': 'move_zero_extend',
            'movzb': 'move_zero_extend',
            'movzw': 'move_zero_extend',
            'movsxd': 'move_sign_extend',
            'movsx': 'move_sign_extend',
            'movsb': 'move_sign_extend',
            'movsw': 'move_sign_extend',
            'push': 'push',
            'pop': 'pop',
            'xchg': 'exchange',
            'movq': 'move',
            'movd': 'move',
            'movdqa': 'move',
            'movdqu': 'move',
            'movaps': 'move',
            'movups': 'move',
            'movss': 'move',
            'movsd': 'move',
            
            # Arithmetic instructions
            'add': 'arithmetic',
            'sub': 'arithmetic',
            'xor': 'arithmetic',
            'xorps': 'arithmetic',
            'xorpd': 'arithmetic',
            'inc': 'arithmetic',
            'dec': 'arithmetic',
            'imul': 'arithmetic',
            'mul': 'arithmetic',
            'idiv': 'arithmetic',
            'div': 'arithmetic',
            'neg': 'arithmetic',
            'and': 'arithmetic',
            'or': 'arithmetic',
            'not': 'arithmetic',
            'shl': 'arithmetic',
            'shr': 'arithmetic',
            'sal': 'arithmetic',
            'sar': 'arithmetic',
            'rol': 'arithmetic',
            'ror': 'arithmetic',
            'rcl': 'arithmetic',
            'rcr': 'arithmetic',
            'adc': 'arithmetic',
            'sbb': 'arithmetic',
            'addss': 'arithmetic',
            'addsd': 'arithmetic',
            'subss': 'arithmetic',
            'subsd': 'arithmetic',
            'mulss': 'arithmetic',
            'mulsd': 'arithmetic',
            'divss': 'arithmetic',
            'divsd': 'arithmetic',
            
            # Comparison instructions
            'cmp': 'comparison',
            'test': 'comparison',
            'bt': 'comparison',
            'bts': 'comparison',
            'btr': 'comparison',
            'btc': 'comparison',
            'cmpxchg': 'comparison',
            'comiss': 'comparison',
            'comisd': 'comparison',
            'ucomiss': 'comparison',
            'ucomisd': 'comparison',
            
            # Conditional jumps
            'jmp': 'jump',
            'jnz': 'jump',
            'jz': 'jump',
            'je': 'jump',
            'jne': 'jump',
            'jg': 'jump',
            'jge': 'jump',
            'jl': 'jump',
            'jle': 'jump',
            'ja': 'jump',
            'jae': 'jump',
            'jb': 'jump',
            'jbe': 'jump',
            'jnb': 'jump',
            'jnbe': 'jump',
            'jna': 'jump',
            'jnae': 'jump',
            'jng': 'jump',
            'jnge': 'jump',
            'jnl': 'jump',
            'jnle': 'jump',
            'jo': 'jump',
            'jno': 'jump',
            'js': 'jump',
            'jns': 'jump',
            'jp': 'jump',
            'jpe': 'jump',
            'jnp': 'jump',
            'jpo': 'jump',
            'jcxz': 'jump',
            'jecxz': 'jump',
            'jrcxz': 'jump',
            
            # Function calls and returns
            'call': 'call',
            'ret': 'return',
            'retn': 'return',
            'retf': 'return',
            'leave': 'leave',
            
            # Conditional moves
            'cmove': 'conditional_move',
            'cmovz': 'conditional_move',
            'cmovne': 'conditional_move',
            'cmovnz': 'conditional_move',
            'cmovg': 'conditional_move',
            'cmovge': 'conditional_move',
            'cmovl': 'conditional_move',
            'cmovle': 'conditional_move',
            'cmova': 'conditional_move',
            'cmovae': 'conditional_move',
            'cmovb': 'conditional_move',
            'cmovbe': 'conditional_move',
            'cmovs': 'conditional_move',
            'cmovns': 'conditional_move',
            
            # Set byte on condition
            'sete': 'set_condition',
            'setz': 'set_condition',
            'setne': 'set_condition',
            'setnz': 'set_condition',
            'setg': 'set_condition',
            'setge': 'set_condition',
            'setl': 'set_condition',
            'setle': 'set_condition',
            'seta': 'set_condition',
            'setae': 'set_condition',
            'setb': 'set_condition',
            'setbe': 'set_condition',
            'sets': 'set_condition',
            'setns': 'set_condition',
            
            # String operations
            'movs': 'string_op',
            'movsb': 'string_op',
            'movsw': 'string_op',
            'movsd': 'string_op',
            'movsq': 'string_op',
            'cmps': 'string_op',
            'cmpsb': 'string_op',
            'cmpsw': 'string_op',
            'cmpsd': 'string_op',
            'cmpsq': 'string_op',
            'scas': 'string_op',
            'scasb': 'string_op',
            'scasw': 'string_op',
            'scasd': 'string_op',
            'scasq': 'string_op',
            'lods': 'string_op',
            'lodsb': 'string_op',
            'lodsw': 'string_op',
            'lodsd': 'string_op',
            'lodsq': 'string_op',
            'stos': 'string_op',
            'stosb': 'string_op',
            'stosw': 'string_op',
            'stosd': 'string_op',
            'stosq': 'string_op',
            'rep': 'string_prefix',
            'repe': 'string_prefix',
            'repz': 'string_prefix',
            'repne': 'string_prefix',
            'repnz': 'string_prefix',
            
            # System and control
            'nop': 'nop',
            'hlt': 'system',
            'int': 'interrupt',
            'syscall': 'system',
            'sysenter': 'system',
            'sysexit': 'system',
            'sysret': 'system',
            'cpuid': 'system',
            'rdtsc': 'system',
            'rdtscp': 'system',
            
            # Stack frame operations
            'enter': 'stack_frame',
            'leave': 'stack_frame',
            
            # Conversion instructions
            'cbw': 'conversion',
            'cwde': 'conversion',
            'cdqe': 'conversion',
            'cwd': 'conversion',
            'cdq': 'conversion',
            'cqo': 'conversion',
            'cvtsi2ss': 'conversion',
            'cvtsi2sd': 'conversion',
            'cvtss2sd': 'conversion',
            'cvtsd2ss': 'conversion',
            'cvttss2si': 'conversion',
            'cvttsd2si': 'conversion',
        }
    
    def translate(self, instruction: Instruction) -> str:
        """
        Translate an assembly instruction to English.
        
        Args:
            instruction: Instruction object to translate
            
        Returns:
            English description of the instruction
        """
        mnemonic = instruction.mnemonic.lower()
        
        # Get instruction type
        instr_type = self.instruction_types.get(mnemonic, 'unknown')
        
        # Route to appropriate translation method
        if instr_type in ['move', 'load_effective_address', 'move_zero_extend', 
                          'move_sign_extend', 'push', 'pop', 'exchange']:
            return self.translate_mov(instruction)
        elif instr_type == 'arithmetic':
            return self.translate_arithmetic(instruction)
        elif instr_type == 'comparison':
            return self.translate_comparison(instruction)
        elif instr_type == 'jump':
            return self.translate_jump(instruction)
        elif instr_type in ['call', 'return', 'leave']:
            return self.translate_call(instruction)
        elif instr_type == 'conditional_move':
            return self.translate_conditional_move(instruction)
        elif instr_type == 'set_condition':
            return self.translate_set_condition(instruction)
        elif instr_type in ['string_op', 'string_prefix']:
            return self.translate_string_op(instruction)
        elif instr_type == 'nop':
            return "No operation (do nothing)"
        elif instr_type in ['system', 'interrupt']:
            return self.translate_system(instruction)
        elif instr_type in ['stack_frame', 'conversion']:
            return self.translate_special(instruction)
        else:
            # Unknown instruction - provide best-effort translation
            return self._translate_unknown(instruction)

    def translate_to_pseudocode(self, instruction: Instruction) -> str:
        """
        Translate instruction to C-like pseudo-code.
        
        Args:
            instruction: Instruction object
            
        Returns:
            Pseudo-code string (e.g., "eax = 1;")
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Helper to get operand string
        def op_str(idx):
            if idx < len(operands):
                # Clean up operand (remove size directives like 'DWORD PTR')
                op = operands[idx].raw
                op = re.sub(r'(?:BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD)\s+PTR\s+', '', op, flags=re.IGNORECASE)
                return op
            return "?"

        # Data Movement
        if mnemonic in ['mov', 'movabs', 'movq', 'movd', 'movss', 'movsd']:
            return f"{op_str(0)} = {op_str(1)};"
        elif mnemonic == 'lea':
            return f"{op_str(0)} = &{op_str(1)};"
        elif mnemonic == 'xor':
            if len(operands) == 2 and operands[0].raw == operands[1].raw:
                return f"{op_str(0)} = 0;"
            return f"{op_str(0)} ^= {op_str(1)};"
        
        # Arithmetic
        elif mnemonic == 'add':
            return f"{op_str(0)} += {op_str(1)};"
        elif mnemonic == 'sub':
            return f"{op_str(0)} -= {op_str(1)};"
        elif mnemonic == 'inc':
            return f"{op_str(0)}++;"
        elif mnemonic == 'dec':
            return f"{op_str(0)}--;"
        elif mnemonic == 'imul':
            if len(operands) == 1:
                return f"rax *= {op_str(0)};"
            elif len(operands) == 2:
                return f"{op_str(0)} *= {op_str(1)};"
            elif len(operands) == 3:
                return f"{op_str(0)} = {op_str(1)} * {op_str(2)};"
        elif mnemonic in ['and', 'or']:
            op = '&=' if mnemonic == 'and' else '|='
            return f"{op_str(0)} {op} {op_str(1)};"
            
        # Comparison
        elif mnemonic == 'cmp':
            return f"// Compare {op_str(0)} vs {op_str(1)}"
        elif mnemonic == 'test':
            return f"// Test {op_str(0)} & {op_str(1)}"
            
        # Control Flow
        elif mnemonic == 'jmp':
            return f"goto {op_str(0)};"
        elif mnemonic == 'je' or mnemonic == 'jz':
            return f"if (==) goto {op_str(0)};"
        elif mnemonic == 'jne' or mnemonic == 'jnz':
            return f"if (!=) goto {op_str(0)};"
        elif mnemonic == 'jg':
            return f"if (>) goto {op_str(0)};"
        elif mnemonic == 'jge':
            return f"if (>=) goto {op_str(0)};"
        elif mnemonic == 'jl':
            return f"if (<) goto {op_str(0)};"
        elif mnemonic == 'jle':
            return f"if (<=) goto {op_str(0)};"
            
        # Function Calls
        elif mnemonic == 'call':
            return f"{op_str(0)}();"
        elif mnemonic == 'ret':
            return "return;"
            
        # Stack
        elif mnemonic == 'push':
            return f"push({op_str(0)});"
        elif mnemonic == 'pop':
            return f"{op_str(0)} = pop();"
            
        return ""
    
    def translate_mov(self, instruction: Instruction) -> str:
        """
        Translate data movement instructions.
        
        Handles: mov, lea, movzx, movsxd, push, pop, xchg
        Special cases: lea for address calculation, xchg for exchange
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        if mnemonic == 'xchg':
            # Exchange instruction
            if len(operands) >= 2:
                op1 = self.explain_operand(operands[0])
                op2 = self.explain_operand(operands[1])
                return f"Exchange {op1} with {op2}"
            return "Exchange values"
        
        elif mnemonic == 'lea':
            # LEA is special - it loads an address, not the value at that address
            if len(operands) >= 2:
                dest = self.explain_operand(operands[0])
                src = self.explain_operand(operands[1], is_lea=True)
                return f"Load the address {src} into {dest}"
            return "Load effective address"
        
        elif mnemonic == 'push':
            if len(operands) >= 1:
                src = self.explain_operand(operands[0])
                return f"Push {src} onto the stack"
            return "Push value onto stack"
        
        elif mnemonic == 'pop':
            if len(operands) >= 1:
                dest = self.explain_operand(operands[0])
                return f"Pop value from stack into {dest}"
            return "Pop value from stack"
        
        elif mnemonic == 'movzx':
            if len(operands) >= 2:
                dest = self.explain_operand(operands[0])
                src = self.explain_operand(operands[1])
                return f"Move {src} to {dest} with zero extension"
            return "Move with zero extension"
        
        elif mnemonic in ['movsxd', 'movsx', 'movsb', 'movsw']:
            if len(operands) >= 2:
                dest = self.explain_operand(operands[0])
                src = self.explain_operand(operands[1])
                return f"Move {src} to {dest} with sign extension"
            return "Move with sign extension"
        
        else:  # mov, movabs, movq, movd, movdqa, movdqu, movaps, movups, movss, movsd
            if len(operands) >= 2:
                dest = self.explain_operand(operands[0])
                src = self.explain_operand(operands[1])
                
                # Add context for special mov variants
                if mnemonic == 'movabs':
                    return f"Move absolute 64-bit {src} into {dest}"
                elif mnemonic in ['movq', 'movd']:
                    return f"Move {src} into {dest} (SIMD/MMX)"
                elif mnemonic in ['movdqa', 'movdqu']:
                    align = 'aligned' if mnemonic == 'movdqa' else 'unaligned'
                    return f"Move {align} 128-bit {src} into {dest}"
                elif mnemonic in ['movaps', 'movups']:
                    align = 'aligned' if mnemonic == 'movaps' else 'unaligned'
                    return f"Move {align} packed single-precision {src} into {dest}"
                elif mnemonic in ['movss', 'movsd']:
                    precision = 'single' if mnemonic == 'movss' else 'double'
                    return f"Move scalar {precision}-precision {src} into {dest}"
                else:
                    return f"Move {src} into {dest}"
            return "Move data"
    
    def translate_arithmetic(self, instruction: Instruction) -> str:
        """
        Translate arithmetic operations.
        
        Handles: add, sub, xor, xorps, inc, dec, imul, mul, and, or, not, shifts
        Special case: xor reg, reg for zeroing
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Special case: XOR reg, reg (zeroing)
        if mnemonic == 'xor' and len(operands) == 2:
            if operands[0].type == 'register' and operands[1].type == 'register':
                if operands[0].register == operands[1].register:
                    dest = self.explain_operand(operands[0])
                    return f"Zero out {dest} (XOR with itself)"
        
        # Special case: XORPS reg, reg (zeroing floating point)
        if mnemonic == 'xorps' and len(operands) == 2:
            if operands[0].type == 'register' and operands[1].type == 'register':
                if operands[0].register == operands[1].register:
                    dest = self.explain_operand(operands[0])
                    return f"Zero out {dest} (XOR floating point with itself)"
        
        # Operation descriptions
        operations = {
            'add': 'Add',
            'sub': 'Subtract',
            'xor': 'XOR',
            'xorps': 'XOR (floating point)',
            'inc': 'Increment',
            'dec': 'Decrement',
            'imul': 'Multiply (signed)',
            'mul': 'Multiply (unsigned)',
            'idiv': 'Divide (signed)',
            'div': 'Divide (unsigned)',
            'neg': 'Negate',
            'and': 'Bitwise AND',
            'or': 'Bitwise OR',
            'not': 'Bitwise NOT',
            'shl': 'Shift left',
            'shr': 'Shift right (logical)',
            'sal': 'Shift left (arithmetic)',
            'sar': 'Shift right (arithmetic)',
        }
        
        operation = operations.get(mnemonic, mnemonic.upper())
        
        if len(operands) == 1:
            # Unary operations (inc, dec, neg, not)
            dest = self.explain_operand(operands[0])
            return f"{operation} {dest}"
        elif len(operands) == 2:
            dest = self.explain_operand(operands[0])
            src = self.explain_operand(operands[1])
            
            if mnemonic in ['add', 'sub', 'xor', 'xorps', 'and', 'or']:
                return f"{operation} {src} to {dest}"
            elif mnemonic in ['imul', 'mul']:
                return f"{operation} {dest} by {src}"
            elif mnemonic in ['shl', 'shr', 'sal', 'sar']:
                return f"{operation} {dest} by {src}"
            else:
                return f"{operation} {src} and {dest}"
        elif len(operands) == 3:
            # Three-operand form (e.g., imul dest, src1, src2)
            dest = self.explain_operand(operands[0])
            src1 = self.explain_operand(operands[1])
            src2 = self.explain_operand(operands[2])
            return f"{operation} {src1} by {src2} and store in {dest}"
        
        return f"{operation} operation"
    
    def translate_comparison(self, instruction: Instruction) -> str:
        """
        Translate comparison instructions.
        
        Handles: cmp, test
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        if len(operands) >= 2:
            op1 = self.explain_operand(operands[0])
            op2 = self.explain_operand(operands[1])
            
            if mnemonic == 'cmp':
                return f"Compare {op1} with {op2}"
            elif mnemonic == 'test':
                return f"Test {op1} against {op2} (bitwise AND, set flags)"
        
        if mnemonic == 'cmp':
            return "Compare values"
        else:
            return "Test values"
    
    def translate_jump(self, instruction: Instruction) -> str:
        """
        Translate jump instructions.
        
        Handles: jmp, jnz, jz, je, jne, jg, jge, jl, jle, ja, jae, jb, jbe
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Jump condition descriptions
        conditions = {
            'jmp': 'unconditionally',
            'jnz': 'if not zero',
            'jz': 'if zero',
            'je': 'if equal',
            'jne': 'if not equal',
            'jg': 'if greater (signed)',
            'jge': 'if greater or equal (signed)',
            'jl': 'if less (signed)',
            'jle': 'if less or equal (signed)',
            'ja': 'if above (unsigned)',
            'jae': 'if above or equal (unsigned)',
            'jb': 'if below (unsigned)',
            'jbe': 'if below or equal (unsigned)',
        }
        
        condition = conditions.get(mnemonic, '')
        
        if len(operands) >= 1:
            target = self.explain_operand(operands[0])
            if condition:
                return f"Jump to {target} {condition}"
            else:
                return f"Jump to {target}"
        
        if condition:
            return f"Jump {condition}"
        return "Jump"
    
    def translate_call(self, instruction: Instruction) -> str:
        """
        Translate function call instructions.
        
        Handles: call, ret
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        if mnemonic == 'call':
            if len(operands) >= 1:
                target = self.explain_operand(operands[0])
                return f"Call function {target}"
            return "Call function"
        elif mnemonic == 'ret':
            return "Return from function"
        
        return "Function call operation"
    
    def explain_operand(self, operand: Operand, is_lea: bool = False) -> str:
        """
        Generate a human-readable explanation of an operand.
        
        Args:
            operand: Operand object to explain
            is_lea: True if this is for LEA instruction (affects memory reference explanation)
            
        Returns:
            English description of the operand
        """
        if operand.type == 'register':
            reg_name = operand.register
            if reg_name in self.register_descriptions:
                return f"{reg_name} ({self.register_descriptions[reg_name]})"
            return reg_name
        
        elif operand.type == 'memory':
            # For LEA, we describe the address calculation, not memory access
            if is_lea:
                if operand.offset is not None:
                    offset_explanation = self._explain_hex_value(operand.offset)
                    if operand.offset >= 0:
                        return f"of {operand.base_register} + {offset_explanation}"
                    else:
                        return f"of {operand.base_register} - {self._explain_hex_value(-operand.offset)}"
                else:
                    return f"in {operand.base_register}"
            else:
                # Normal memory access
                if operand.offset is not None:
                    offset_explanation = self._explain_hex_value(operand.offset)
                    if operand.offset >= 0:
                        return f"the value at [{operand.base_register} + {offset_explanation}]"
                    else:
                        return f"the value at [{operand.base_register} - {self._explain_hex_value(-operand.offset)}]"
                else:
                    return f"the value at [{operand.base_register}]"
        
        elif operand.type == 'immediate':
            # Try to provide context for immediate values
            raw = operand.raw
            if raw.startswith('0x') or raw.startswith('-0x'):
                try:
                    val = int(raw, 0)
                    return f"the immediate value {raw} {self._explain_hex_value(val)}"
                except ValueError:
                    return f"the immediate value {raw}"
            else:
                try:
                    val = int(raw)
                    return f"the immediate value {val} ({hex(val)})"
                except ValueError:
                    return f"the immediate value {raw}"
        
        elif operand.type == 'label':
            # Handle symbolic names and potentially mangled names
            label_name = operand.raw
            demangled = self._demangle_name(label_name)
            if demangled and demangled != label_name:
                return f"label {label_name} ({demangled})"
            
            # Check if it looks like a hex address
            if self._is_hex_address(label_name):
                addr_type = self._identify_address_type(label_name)
                return f"address {label_name} ({addr_type})"
            
            return f"label {label_name}"
        
        return operand.raw
    
    def _explain_hex_value(self, value: int) -> str:
        """
        Provide contextual explanation for hexadecimal values.
        
        Args:
            value: Integer value to explain
            
        Returns:
            Explanation string with context
        """
        hex_str = hex(value)
        
        # Provide context based on value range
        if value == 0:
            return f"{hex_str} (zero)"
        elif 0 < value <= 8:
            return f"{hex_str} (small offset)"
        elif 8 < value <= 0x100:
            return f"{hex_str} (byte-sized value)"
        elif 0x100 < value <= 0x10000:
            return f"{hex_str} (word/dword-sized value)"
        elif value > 0x100000:
            # Could be an address
            return f"{hex_str} (possible address)"
        else:
            return hex_str
    
    def _identify_address_type(self, address_str: str) -> str:
        """
        Identify whether a hex address likely points to code or data.
        
        Args:
            address_str: Hexadecimal address string
            
        Returns:
            Description of address type
        """
        try:
            addr = int(address_str, 0) if address_str.startswith('0x') else int(address_str, 16)
            
            # Common x86-64 memory regions (heuristics)
            # Code typically in lower addresses or specific ranges
            # These are rough heuristics based on common patterns
            
            if 0x140000000 <= addr < 0x180000000:
                return "likely code section"
            elif 0x400000 <= addr < 0x500000:
                return "likely code section"
            elif addr < 0x1000:
                return "likely data/offset"
            else:
                return "code or data reference"
        except ValueError:
            return "unknown reference"
    
    def _is_hex_address(self, text: str) -> bool:
        """
        Check if a string looks like a hexadecimal address.
        
        Args:
            text: String to check
            
        Returns:
            True if it looks like a hex address
        """
        # Check for hex patterns (with or without 0x prefix)
        if text.startswith('0x'):
            try:
                int(text, 16)
                return len(text) > 4  # At least a few hex digits
            except ValueError:
                return False
        
        # Check for bare hex (all hex digits, reasonably long)
        if len(text) >= 6 and all(c in '0123456789abcdefABCDEF' for c in text):
            return True
        
        return False
    
    def _demangle_name(self, name: str) -> Optional[str]:
        """
        Attempt to demangle C++ mangled names.
        
        Tries to use c++filt if available, otherwise provides basic detection.
        
        Args:
            name: Potentially mangled name
            
        Returns:
            Demangled name or None if not mangled/cannot demangle
        """
        # Check if name looks like a mangled C++ name
        if not self._is_mangled_name(name):
            return None
        
        # Try using c++filt
        try:
            result = subprocess.run(
                ['c++filt', name],
                capture_output=True,
                text=True,
                timeout=1
            )
            if result.returncode == 0:
                demangled = result.stdout.strip()
                # c++filt returns the original if it can't demangle
                if demangled != name:
                    return demangled
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            # c++filt not available or failed, try manual parsing
            pass
        
        # Basic manual demangling for common patterns
        return self._manual_demangle(name)
    
    def _is_mangled_name(self, name: str) -> bool:
        """
        Check if a name looks like a C++ mangled name.
        
        Args:
            name: Name to check
            
        Returns:
            True if it looks mangled
        """
        # Common C++ mangling patterns
        # Itanium ABI: starts with _Z
        # MSVC: starts with ? or contains @@
        if name.startswith('_Z'):
            return True
        if name.startswith('?'):
            return True
        if '@@' in name:
            return True
        
        return False
    
    def _manual_demangle(self, name: str) -> Optional[str]:
        """
        Perform basic manual demangling for common patterns.
        
        Args:
            name: Mangled name
            
        Returns:
            Partially demangled name or None
        """
        # Itanium ABI basic patterns
        if name.startswith('_Z'):
            # Very basic: extract function name after length prefix
            # _Z<length><name>...
            match = re.match(r'_Z(\d+)([a-zA-Z_]\w*)', name)
            if match:
                length = int(match.group(1))
                func_name = match.group(2)[:length]
                return f"{func_name} (C++ function)"
        
        # MSVC patterns
        if name.startswith('?'):
            # Extract name between ? and @@
            match = re.match(r'\?([a-zA-Z_]\w*)@@', name)
            if match:
                return f"{match.group(1)} (C++ function)"
        
        return None
    
    def translate_conditional_move(self, instruction: Instruction) -> str:
        """
        Translate conditional move instructions.
        
        Handles: cmove, cmovz, cmovne, cmovg, etc.
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Condition descriptions
        conditions = {
            'cmove': 'if equal',
            'cmovz': 'if zero',
            'cmovne': 'if not equal',
            'cmovnz': 'if not zero',
            'cmovg': 'if greater (signed)',
            'cmovge': 'if greater or equal (signed)',
            'cmovl': 'if less (signed)',
            'cmovle': 'if less or equal (signed)',
            'cmova': 'if above (unsigned)',
            'cmovae': 'if above or equal (unsigned)',
            'cmovb': 'if below (unsigned)',
            'cmovbe': 'if below or equal (unsigned)',
            'cmovs': 'if sign flag set',
            'cmovns': 'if sign flag not set',
        }
        
        condition = conditions.get(mnemonic, '')
        
        if len(operands) >= 2:
            dest = self.explain_operand(operands[0])
            src = self.explain_operand(operands[1])
            return f"Conditionally move {src} to {dest} {condition}"
        
        return f"Conditional move {condition}"
    
    def translate_set_condition(self, instruction: Instruction) -> str:
        """
        Translate set byte on condition instructions.
        
        Handles: sete, setz, setne, setg, etc.
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Condition descriptions
        conditions = {
            'sete': 'if equal',
            'setz': 'if zero',
            'setne': 'if not equal',
            'setnz': 'if not zero',
            'setg': 'if greater (signed)',
            'setge': 'if greater or equal (signed)',
            'setl': 'if less (signed)',
            'setle': 'if less or equal (signed)',
            'seta': 'if above (unsigned)',
            'setae': 'if above or equal (unsigned)',
            'setb': 'if below (unsigned)',
            'setbe': 'if below or equal (unsigned)',
            'sets': 'if sign flag set',
            'setns': 'if sign flag not set',
        }
        
        condition = conditions.get(mnemonic, '')
        
        if len(operands) >= 1:
            dest = self.explain_operand(operands[0])
            return f"Set {dest} to 1 {condition}, otherwise set to 0"
        
        return f"Set byte {condition}"
    
    def translate_string_op(self, instruction: Instruction) -> str:
        """
        Translate string operation instructions.
        
        Handles: movs, cmps, scas, lods, stos, rep prefixes
        """
        mnemonic = instruction.mnemonic.lower()
        
        # String operation descriptions
        operations = {
            'movs': 'Move string (copy from [rsi] to [rdi])',
            'movsb': 'Move byte from [rsi] to [rdi]',
            'movsw': 'Move word from [rsi] to [rdi]',
            'movsd': 'Move dword from [rsi] to [rdi]',
            'movsq': 'Move qword from [rsi] to [rdi]',
            'cmps': 'Compare strings at [rsi] and [rdi]',
            'cmpsb': 'Compare bytes at [rsi] and [rdi]',
            'cmpsw': 'Compare words at [rsi] and [rdi]',
            'cmpsd': 'Compare dwords at [rsi] and [rdi]',
            'cmpsq': 'Compare qwords at [rsi] and [rdi]',
            'scas': 'Scan string at [rdi] for value in accumulator',
            'scasb': 'Scan byte at [rdi] for value in AL',
            'scasw': 'Scan word at [rdi] for value in AX',
            'scasd': 'Scan dword at [rdi] for value in EAX',
            'scasq': 'Scan qword at [rdi] for value in RAX',
            'lods': 'Load string from [rsi] into accumulator',
            'lodsb': 'Load byte from [rsi] into AL',
            'lodsw': 'Load word from [rsi] into AX',
            'lodsd': 'Load dword from [rsi] into EAX',
            'lodsq': 'Load qword from [rsi] into RAX',
            'stos': 'Store accumulator to [rdi]',
            'stosb': 'Store AL to [rdi]',
            'stosw': 'Store AX to [rdi]',
            'stosd': 'Store EAX to [rdi]',
            'stosq': 'Store RAX to [rdi]',
            'rep': 'Repeat following string operation RCX times',
            'repe': 'Repeat following string operation while equal',
            'repz': 'Repeat following string operation while zero',
            'repne': 'Repeat following string operation while not equal',
            'repnz': 'Repeat following string operation while not zero',
        }
        
        return operations.get(mnemonic, f"String operation: {mnemonic.upper()}")
    
    def translate_system(self, instruction: Instruction) -> str:
        """
        Translate system and interrupt instructions.
        
        Handles: int, syscall, cpuid, rdtsc, etc.
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        if mnemonic == 'int':
            if len(operands) >= 1:
                int_num = operands[0].raw
                if int_num == '0x80' or int_num == '128':
                    return "Software interrupt 0x80 (Linux system call)"
                elif int_num == '0x21' or int_num == '33':
                    return "Software interrupt 0x21 (DOS system call)"
                else:
                    return f"Software interrupt {int_num}"
            return "Software interrupt"
        elif mnemonic == 'syscall':
            return "System call (invoke kernel service)"
        elif mnemonic == 'sysenter':
            return "Fast system call entry"
        elif mnemonic == 'sysexit':
            return "Fast system call exit"
        elif mnemonic == 'sysret':
            return "Return from system call"
        elif mnemonic == 'cpuid':
            return "Get CPU identification and feature information"
        elif mnemonic == 'rdtsc':
            return "Read time-stamp counter into EDX:EAX"
        elif mnemonic == 'rdtscp':
            return "Read time-stamp counter and processor ID"
        elif mnemonic == 'hlt':
            return "Halt processor until interrupt"
        
        return f"System instruction: {mnemonic.upper()}"
    
    def translate_special(self, instruction: Instruction) -> str:
        """
        Translate special instructions (stack frame, conversion, etc.).
        
        Handles: enter, leave, cbw, cwde, cdqe, etc.
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        if mnemonic == 'enter':
            return "Create stack frame for procedure"
        elif mnemonic == 'leave':
            return "Restore stack frame and prepare to return (mov rsp, rbp; pop rbp)"
        elif mnemonic == 'cbw':
            return "Convert byte in AL to word in AX (sign extend)"
        elif mnemonic == 'cwde':
            return "Convert word in AX to dword in EAX (sign extend)"
        elif mnemonic == 'cdqe':
            return "Convert dword in EAX to qword in RAX (sign extend)"
        elif mnemonic == 'cwd':
            return "Convert word in AX to dword in DX:AX (sign extend)"
        elif mnemonic == 'cdq':
            return "Convert dword in EAX to qword in EDX:EAX (sign extend)"
        elif mnemonic == 'cqo':
            return "Convert qword in RAX to oword in RDX:RAX (sign extend)"
        elif mnemonic.startswith('cvt'):
            # Floating point conversions
            if len(operands) >= 2:
                dest = self.explain_operand(operands[0])
                src = self.explain_operand(operands[1])
                return f"Convert {src} to different format and store in {dest}"
            return f"Convert floating point value"
        
        return f"Special instruction: {mnemonic.upper()}"
    
    def _translate_unknown(self, instruction: Instruction) -> str:
        """
        Provide best-effort translation for unknown instructions.
        
        Args:
            instruction: Instruction with unknown mnemonic
            
        Returns:
            Generic description
        """
        mnemonic = instruction.mnemonic.upper()
        if instruction.operands:
            operands_str = ", ".join(instruction.operands)
            return f"{mnemonic} instruction with operands: {operands_str}"
        return f"{mnemonic} instruction"
