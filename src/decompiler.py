"""Enhanced decompiler for DissectX - converting assembly to high-quality pseudo-code"""
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.models import Instruction, Operand


class DataType(Enum):
    """Inferred data types"""
    UNKNOWN = "unknown"
    INT8 = "int8_t"
    INT16 = "int16_t"
    INT32 = "int32_t"
    INT64 = "int64_t"
    UINT8 = "uint8_t"
    UINT16 = "uint16_t"
    UINT32 = "uint32_t"
    UINT64 = "uint64_t"
    POINTER = "void*"
    CHAR_PTR = "char*"
    FLOAT = "float"
    DOUBLE = "double"
    STRUCT = "struct"


@dataclass
class Variable:
    """Represents a variable in decompiled code"""
    name: str
    data_type: DataType = DataType.UNKNOWN
    register: Optional[str] = None
    stack_offset: Optional[int] = None
    is_parameter: bool = False
    usage_count: int = 0
    operations: Set[str] = field(default_factory=set)
    
    def infer_type_from_operations(self):
        """Infer data type based on operations performed on this variable"""
        # Floating point operations
        if any(op in self.operations for op in ['addss', 'subss', 'mulss', 'divss', 'movss']):
            self.data_type = DataType.FLOAT
        elif any(op in self.operations for op in ['addsd', 'subsd', 'mulsd', 'divsd', 'movsd']):
            self.data_type = DataType.DOUBLE
        # String operations
        elif any(op in self.operations for op in ['movs', 'cmps', 'scas', 'lods', 'stos']):
            self.data_type = DataType.CHAR_PTR
        # Pointer operations (lea, memory access)
        elif 'lea' in self.operations or 'ptr_access' in self.operations:
            self.data_type = DataType.POINTER
        # Integer size inference from register
        elif self.register:
            if self.register in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'] or self.register.startswith('r'):
                self.data_type = DataType.INT64
            elif self.register in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'] or self.register.endswith('d'):
                self.data_type = DataType.INT32
            elif self.register in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp'] or self.register.endswith('w'):
                self.data_type = DataType.INT16
            elif self.register in ['al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'] or self.register.endswith('b'):
                self.data_type = DataType.INT8


@dataclass
class ControlFlowNode:
    """Represents a node in control flow reconstruction"""
    node_type: str  # 'if', 'while', 'for', 'do_while', 'switch', 'block'
    condition: Optional[str] = None
    body: List[str] = field(default_factory=list)
    else_body: List[str] = field(default_factory=list)
    children: List['ControlFlowNode'] = field(default_factory=list)


class Decompiler:
    """
    Enhanced decompiler that generates high-quality pseudo-code from assembly.
    
    Features:
    - Variable name inference from usage patterns
    - Type inference from operations
    - Control flow reconstruction (if/else, loops, switch)
    - Proper C-like syntax with indentation
    """
    
    def __init__(self):
        """Initialize the decompiler"""
        self.variables: Dict[str, Variable] = {}
        self.var_counter = 0
        self.indent_level = 0
        self.indent_size = 4
        
        # Register descriptions for context
        self.register_descriptions = self._init_register_descriptions()
        
        # Instruction type database
        self.instruction_types = self._init_instruction_types()
    
    def _init_register_descriptions(self) -> Dict[str, str]:
        """Initialize register descriptions"""
        return {
            # 64-bit registers
            'rax': 'accumulator', 'rbx': 'base', 'rcx': 'counter', 'rdx': 'data',
            'rsi': 'source_index', 'rdi': 'dest_index', 'rbp': 'base_ptr', 'rsp': 'stack_ptr',
            'r8': 'r8', 'r9': 'r9', 'r10': 'r10', 'r11': 'r11',
            'r12': 'r12', 'r13': 'r13', 'r14': 'r14', 'r15': 'r15',
            # 32-bit registers
            'eax': 'accumulator', 'ebx': 'base', 'ecx': 'counter', 'edx': 'data',
            'esi': 'source_index', 'edi': 'dest_index', 'ebp': 'base_ptr', 'esp': 'stack_ptr',
            # 16-bit registers
            'ax': 'accumulator', 'bx': 'base', 'cx': 'counter', 'dx': 'data',
            # 8-bit registers
            'al': 'accumulator_low', 'ah': 'accumulator_high',
            'bl': 'base_low', 'bh': 'base_high',
            'cl': 'counter_low', 'ch': 'counter_high',
            'dl': 'data_low', 'dh': 'data_high',
        }
    
    def _init_instruction_types(self) -> Dict[str, str]:
        """Initialize instruction type database"""
        return {
            # Data movement
            'mov': 'move', 'movabs': 'move', 'lea': 'load_address',
            'movzx': 'move_zero_extend', 'movsx': 'move_sign_extend',
            'push': 'push', 'pop': 'pop', 'xchg': 'exchange',
            # Arithmetic
            'add': 'arithmetic', 'sub': 'arithmetic', 'xor': 'arithmetic',
            'inc': 'arithmetic', 'dec': 'arithmetic',
            'imul': 'arithmetic', 'mul': 'arithmetic',
            'idiv': 'arithmetic', 'div': 'arithmetic',
            'and': 'arithmetic', 'or': 'arithmetic', 'not': 'arithmetic',
            'shl': 'arithmetic', 'shr': 'arithmetic',
            # Comparison
            'cmp': 'comparison', 'test': 'comparison',
            # Control flow
            'jmp': 'jump', 'je': 'jump', 'jne': 'jump', 'jz': 'jump', 'jnz': 'jump',
            'jg': 'jump', 'jge': 'jump', 'jl': 'jump', 'jle': 'jump',
            'ja': 'jump', 'jae': 'jump', 'jb': 'jump', 'jbe': 'jump',
            'call': 'call', 'ret': 'return', 'leave': 'leave',
            # Conditional
            'cmove': 'conditional_move', 'cmovne': 'conditional_move',
            'sete': 'set_condition', 'setne': 'set_condition',
        }
    
    def decompile_function(self, instructions: List[Instruction]) -> str:
        """
        Decompile a function from assembly instructions to pseudo-code.
        
        Args:
            instructions: List of Instruction objects
            
        Returns:
            Pseudo-code string with proper formatting
        """
        if not instructions:
            return ""
        
        # Reset state
        self.variables = {}
        self.var_counter = 0
        self.indent_level = 0
        
        # Analyze instructions to build variable database
        self._analyze_variables(instructions)
        
        # Infer types for all variables
        for var in self.variables.values():
            var.infer_type_from_operations()
        
        # Generate pseudo-code
        lines = []
        lines.append(self._generate_function_signature(instructions))
        lines.append("{")
        self.indent_level += 1
        
        # Generate variable declarations
        var_decls = self._generate_variable_declarations()
        if var_decls:
            lines.extend(var_decls)
            lines.append("")
        
        # Generate function body
        body_lines = self._generate_function_body(instructions)
        lines.extend(body_lines)
        
        self.indent_level -= 1
        lines.append("}")
        
        return "\n".join(lines)
    
    def _analyze_variables(self, instructions: List[Instruction]):
        """Analyze instructions to identify and track variables"""
        for instr in instructions:
            mnemonic = instr.mnemonic.lower()
            operands = instr.get_parsed_operands()
            
            # Track operations for type inference
            for operand in operands:
                if operand.type == 'register':
                    var_name = self._get_or_create_variable(operand.register)
                    if var_name in self.variables:
                        self.variables[var_name].operations.add(mnemonic)
                        self.variables[var_name].usage_count += 1
                
                elif operand.type == 'memory':
                    # Track stack variables
                    if operand.base_register in ['rbp', 'ebp', 'rsp', 'esp']:
                        var_name = self._get_stack_variable_name(operand.base_register, operand.offset)
                        if var_name not in self.variables:
                            self.variables[var_name] = Variable(
                                name=var_name,
                                stack_offset=operand.offset,
                                is_parameter=(operand.offset and operand.offset > 0)
                            )
                        self.variables[var_name].operations.add(mnemonic)
                        self.variables[var_name].operations.add('ptr_access')
                        self.variables[var_name].usage_count += 1
    
    def _get_or_create_variable(self, register: str) -> str:
        """Get or create a variable name for a register"""
        # Normalize register name (handle different sizes of same register)
        base_reg = self._get_base_register(register)
        
        if base_reg in self.variables:
            return base_reg
        
        # Create meaningful name based on register
        if base_reg in self.register_descriptions:
            var_name = self.register_descriptions[base_reg]
        else:
            var_name = base_reg
        
        self.variables[base_reg] = Variable(name=var_name, register=base_reg)
        return base_reg
    
    def _get_base_register(self, register: str) -> str:
        """Get the base register name (e.g., rax from eax, ax, al)"""
        # Map all register variants to their 64-bit base
        reg_map = {
            'al': 'rax', 'ah': 'rax', 'ax': 'rax', 'eax': 'rax', 'rax': 'rax',
            'bl': 'rbx', 'bh': 'rbx', 'bx': 'rbx', 'ebx': 'rbx', 'rbx': 'rbx',
            'cl': 'rcx', 'ch': 'rcx', 'cx': 'rcx', 'ecx': 'rcx', 'rcx': 'rcx',
            'dl': 'rdx', 'dh': 'rdx', 'dx': 'rdx', 'edx': 'rdx', 'rdx': 'rdx',
            'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi', 'rsi': 'rsi',
            'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi', 'rdi': 'rdi',
            'bpl': 'rbp', 'bp': 'rbp', 'ebp': 'rbp', 'rbp': 'rbp',
            'spl': 'rsp', 'sp': 'rsp', 'esp': 'rsp', 'rsp': 'rsp',
        }
        return reg_map.get(register.lower(), register.lower())
    
    def _get_stack_variable_name(self, base_reg: str, offset: Optional[int]) -> str:
        """Generate a meaningful name for stack variables"""
        if offset is None:
            return f"stack_var_{self.var_counter}"
        
        if offset > 0:
            # Positive offset from rbp = function parameter
            param_num = offset // 8
            return f"param_{param_num}"
        else:
            # Negative offset from rbp = local variable
            local_num = abs(offset) // 8
            return f"local_{local_num}"
    
    def _generate_function_signature(self, instructions: List[Instruction]) -> str:
        """Generate function signature with inferred parameters"""
        # Find parameters (positive stack offsets from rbp)
        params = [v for v in self.variables.values() if v.is_parameter]
        params.sort(key=lambda v: v.stack_offset or 0)
        
        if params:
            param_strs = [f"{p.data_type.value} {p.name}" for p in params]
            return f"void function({', '.join(param_strs)})"
        else:
            return "void function()"
    
    def _generate_variable_declarations(self) -> List[str]:
        """Generate variable declaration statements"""
        lines = []
        
        # Declare local variables (not parameters, not registers)
        locals_vars = [v for v in self.variables.values() 
                      if not v.is_parameter and v.stack_offset is not None]
        
        if locals_vars:
            for var in locals_vars:
                line = self._indent(f"{var.data_type.value} {var.name};")
                lines.append(line)
        
        return lines
    
    def _generate_function_body(self, instructions: List[Instruction]) -> List[str]:
        """Generate the function body with control flow reconstruction"""
        lines = []
        
        # Reconstruct control flow
        control_flow = self.reconstruct_control_flow(instructions)
        
        # Generate code from control flow structure
        for node in control_flow:
            node_lines = self._generate_control_flow_node(node)
            lines.extend(node_lines)
        
        return lines
    
    def translate_to_pseudocode(self, instruction: Instruction) -> str:
        """
        Translate a single instruction to pseudo-code.
        
        Args:
            instruction: Instruction object
            
        Returns:
            Pseudo-code string
        """
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Helper to get operand string with variable names
        def op_str(idx):
            if idx < len(operands):
                return self._operand_to_pseudocode(operands[idx])
            return "?"
        
        # Data Movement
        if mnemonic in ['mov', 'movabs', 'movq', 'movd']:
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
                return f"accumulator *= {op_str(0)};"
            elif len(operands) == 2:
                return f"{op_str(0)} *= {op_str(1)};"
            elif len(operands) == 3:
                return f"{op_str(0)} = {op_str(1)} * {op_str(2)};"
        elif mnemonic == 'and':
            return f"{op_str(0)} &= {op_str(1)};"
        elif mnemonic == 'or':
            return f"{op_str(0)} |= {op_str(1)};"
        elif mnemonic == 'not':
            return f"{op_str(0)} = ~{op_str(0)};"
        elif mnemonic == 'shl':
            return f"{op_str(0)} <<= {op_str(1)};"
        elif mnemonic == 'shr':
            return f"{op_str(0)} >>= {op_str(1)};"
        
        # Comparison
        elif mnemonic == 'cmp':
            return f"// Compare {op_str(0)} with {op_str(1)}"
        elif mnemonic == 'test':
            return f"// Test {op_str(0)} & {op_str(1)}"
        
        # Control Flow
        elif mnemonic == 'jmp':
            return f"goto {op_str(0)};"
        elif mnemonic in ['je', 'jz']:
            return f"if (zero_flag) goto {op_str(0)};"
        elif mnemonic in ['jne', 'jnz']:
            return f"if (!zero_flag) goto {op_str(0)};"
        elif mnemonic == 'jg':
            return f"if (greater) goto {op_str(0)};"
        elif mnemonic == 'jge':
            return f"if (greater_or_equal) goto {op_str(0)};"
        elif mnemonic == 'jl':
            return f"if (less) goto {op_str(0)};"
        elif mnemonic == 'jle':
            return f"if (less_or_equal) goto {op_str(0)};"
        
        # Function Calls
        elif mnemonic == 'call':
            return f"{op_str(0)}();"
        elif mnemonic == 'ret':
            return "return;"
        
        # Stack Operations
        elif mnemonic == 'push':
            return f"push({op_str(0)});"
        elif mnemonic == 'pop':
            return f"{op_str(0)} = pop();"
        
        # Leave instruction
        elif mnemonic == 'leave':
            return "// Restore stack frame"
        
        # Unknown or unhandled
        return f"// {mnemonic} {', '.join(o.raw for o in operands)}"
    
    def _operand_to_pseudocode(self, operand: Operand) -> str:
        """Convert an operand to pseudo-code representation"""
        if operand.type == 'register':
            # Use variable name instead of register
            base_reg = self._get_base_register(operand.register)
            if base_reg in self.variables:
                return self.variables[base_reg].name
            return operand.register
        
        elif operand.type == 'memory':
            # Convert memory access to pointer dereference
            if operand.base_register:
                base_reg = self._get_base_register(operand.base_register)
                if base_reg in self.variables:
                    var_name = self.variables[base_reg].name
                else:
                    var_name = operand.base_register
                
                if operand.offset:
                    if operand.offset > 0:
                        return f"*({var_name} + {operand.offset})"
                    else:
                        return f"*({var_name} - {abs(operand.offset)})"
                else:
                    return f"*{var_name}"
            
            # Stack variable
            if operand.base_register in ['rbp', 'ebp', 'rsp', 'esp']:
                var_name = self._get_stack_variable_name(operand.base_register, operand.offset)
                if var_name in self.variables:
                    return self.variables[var_name].name
                return var_name
            
            return f"[{operand.raw}]"
        
        elif operand.type == 'immediate':
            # Clean up immediate values
            raw = operand.raw
            if raw.startswith('0x'):
                return raw
            try:
                val = int(raw)
                if val > 255:
                    return hex(val)
                return str(val)
            except ValueError:
                return raw
        
        elif operand.type == 'label':
            return operand.raw
        
        return operand.raw
    
    def _indent(self, line: str) -> str:
        """Add indentation to a line"""
        return " " * (self.indent_level * self.indent_size) + line
    
    def infer_variable_names(self, instructions: List[Instruction]) -> Dict[str, str]:
        """
        Infer meaningful variable names from usage patterns.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            Dictionary mapping register/location to inferred name
        """
        self._analyze_variables(instructions)
        return {reg: var.name for reg, var in self.variables.items()}
    
    def infer_types(self, instructions: List[Instruction]) -> Dict[str, DataType]:
        """
        Infer data types from operations.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            Dictionary mapping variable to inferred type
        """
        self._analyze_variables(instructions)
        
        # Infer types
        for var in self.variables.values():
            var.infer_type_from_operations()
        
        return {var.name: var.data_type for var in self.variables.values()}
    
    def reconstruct_control_flow(self, instructions: List[Instruction]) -> List[ControlFlowNode]:
        """
        Reconstruct high-level control flow structures from assembly.
        
        Analyzes jump patterns to identify:
        - if/else statements
        - while loops
        - for loops
        - do-while loops
        - switch statements
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of ControlFlowNode objects representing the control flow
        """
        nodes = []
        i = 0
        
        while i < len(instructions):
            instr = instructions[i]
            mnemonic = instr.mnemonic.lower()
            
            # Check for conditional jump patterns (if/else)
            if mnemonic in ['je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe']:
                # Look for if/else pattern
                if_node, consumed = self._reconstruct_if_else(instructions, i)
                if if_node:
                    nodes.append(if_node)
                    i += consumed
                    continue
            
            # Check for loop patterns
            elif mnemonic == 'jmp':
                # Could be a loop or switch
                loop_node, consumed = self._reconstruct_loop(instructions, i)
                if loop_node:
                    nodes.append(loop_node)
                    i += consumed
                    continue
            
            # Regular statement
            pseudocode = self.translate_to_pseudocode(instr)
            if pseudocode and not pseudocode.startswith('//'):
                node = ControlFlowNode(node_type='block', body=[pseudocode])
                nodes.append(node)
            
            i += 1
        
        return nodes
    
    def _reconstruct_if_else(self, instructions: List[Instruction], start_idx: int) -> Tuple[Optional[ControlFlowNode], int]:
        """
        Reconstruct if/else statement from conditional jump.
        
        Returns:
            Tuple of (ControlFlowNode or None, number of instructions consumed)
        """
        if start_idx >= len(instructions):
            return None, 0
        
        # Get the conditional jump
        cond_jump = instructions[start_idx]
        mnemonic = cond_jump.mnemonic.lower()
        
        # Map jump mnemonics to conditions
        condition_map = {
            'je': '==', 'jz': '== 0',
            'jne': '!=', 'jnz': '!= 0',
            'jg': '>', 'jge': '>=',
            'jl': '<', 'jle': '<=',
            'ja': '> (unsigned)', 'jae': '>= (unsigned)',
            'jb': '< (unsigned)', 'jbe': '<= (unsigned)',
        }
        
        condition = condition_map.get(mnemonic, 'condition')
        
        # Look for the previous comparison
        if start_idx > 0:
            prev_instr = instructions[start_idx - 1]
            if prev_instr.mnemonic.lower() in ['cmp', 'test']:
                operands = prev_instr.get_parsed_operands()
                if len(operands) >= 2:
                    op1 = self._operand_to_pseudocode(operands[0])
                    op2 = self._operand_to_pseudocode(operands[1])
                    condition = f"{op1} {condition} {op2}"
        
        # Create if node
        if_node = ControlFlowNode(
            node_type='if',
            condition=condition,
            body=[],
            else_body=[]
        )
        
        # Collect body statements (simplified - just take next few instructions)
        body_count = min(3, len(instructions) - start_idx - 1)
        for i in range(1, body_count + 1):
            if start_idx + i < len(instructions):
                pseudocode = self.translate_to_pseudocode(instructions[start_idx + i])
                if pseudocode and not pseudocode.startswith('goto'):
                    if_node.body.append(pseudocode)
        
        return if_node, body_count + 1
    
    def _reconstruct_loop(self, instructions: List[Instruction], start_idx: int) -> Tuple[Optional[ControlFlowNode], int]:
        """
        Reconstruct loop structure from backward jump.
        
        Returns:
            Tuple of (ControlFlowNode or None, number of instructions consumed)
        """
        if start_idx >= len(instructions):
            return None, 0
        
        jmp_instr = instructions[start_idx]
        operands = jmp_instr.get_parsed_operands()
        
        if not operands:
            return None, 0
        
        # Check if this is a backward jump (loop)
        target = operands[0].raw
        
        # Try to parse target address
        try:
            if target.startswith('0x'):
                target_addr = int(target, 16)
            else:
                target_addr = int(target, 16) if all(c in '0123456789abcdefABCDEF' for c in target) else None
            
            # Get current instruction address
            current_addr = int(jmp_instr.address, 16) if isinstance(jmp_instr.address, str) else jmp_instr.address
            
            if target_addr and current_addr and target_addr < current_addr:
                # This is a backward jump - likely a loop
                loop_node = ControlFlowNode(
                    node_type='while',
                    condition='condition',  # Simplified
                    body=[]
                )
                
                # Collect loop body (simplified)
                for i in range(max(0, start_idx - 3), start_idx):
                    pseudocode = self.translate_to_pseudocode(instructions[i])
                    if pseudocode:
                        loop_node.body.append(pseudocode)
                
                return loop_node, 1
        except (ValueError, AttributeError, TypeError):
            pass
        
        return None, 0
    
    def _generate_control_flow_node(self, node: ControlFlowNode) -> List[str]:
        """
        Generate pseudo-code lines from a control flow node.
        
        Args:
            node: ControlFlowNode to generate code for
            
        Returns:
            List of pseudo-code lines
        """
        lines = []
        
        if node.node_type == 'if':
            # Generate if statement
            lines.append(self._indent(f"if ({node.condition}) {{"))
            self.indent_level += 1
            for stmt in node.body:
                lines.append(self._indent(stmt))
            self.indent_level -= 1
            
            if node.else_body:
                lines.append(self._indent("} else {"))
                self.indent_level += 1
                for stmt in node.else_body:
                    lines.append(self._indent(stmt))
                self.indent_level -= 1
            
            lines.append(self._indent("}"))
        
        elif node.node_type == 'while':
            # Generate while loop
            lines.append(self._indent(f"while ({node.condition}) {{"))
            self.indent_level += 1
            for stmt in node.body:
                lines.append(self._indent(stmt))
            self.indent_level -= 1
            lines.append(self._indent("}"))
        
        elif node.node_type == 'for':
            # Generate for loop
            init = node.condition or ""
            lines.append(self._indent(f"for ({init}) {{"))
            self.indent_level += 1
            for stmt in node.body:
                lines.append(self._indent(stmt))
            self.indent_level -= 1
            lines.append(self._indent("}"))
        
        elif node.node_type == 'do_while':
            # Generate do-while loop
            lines.append(self._indent("do {"))
            self.indent_level += 1
            for stmt in node.body:
                lines.append(self._indent(stmt))
            self.indent_level -= 1
            lines.append(self._indent(f"}} while ({node.condition});"))
        
        elif node.node_type == 'switch':
            # Generate switch statement
            lines.append(self._indent(f"switch ({node.condition}) {{"))
            self.indent_level += 1
            for stmt in node.body:
                lines.append(self._indent(stmt))
            self.indent_level -= 1
            lines.append(self._indent("}"))
        
        elif node.node_type == 'block':
            # Regular block of statements
            for stmt in node.body:
                lines.append(self._indent(stmt))
        
        return lines
    
    def validate_pseudocode_syntax(self, pseudocode: str) -> Tuple[bool, List[str]]:
        """
        Validate that generated pseudo-code has valid C-like syntax.
        
        Args:
            pseudocode: Generated pseudo-code string
            
        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []
        lines = pseudocode.split('\n')
        
        # Check for balanced braces
        brace_count = 0
        for i, line in enumerate(lines, 1):
            brace_count += line.count('{') - line.count('}')
            if brace_count < 0:
                errors.append(f"Line {i}: Unmatched closing brace")
        
        if brace_count != 0:
            errors.append(f"Unbalanced braces: {brace_count} unclosed")
        
        # Check for proper statement termination
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped and not stripped.startswith('//'):
                # Statements should end with ; or { or }
                if not any(stripped.endswith(c) for c in [';', '{', '}', ':']):
                    if not stripped.startswith('if') and not stripped.startswith('while') and not stripped.startswith('for'):
                        errors.append(f"Line {i}: Statement may be missing semicolon")
        
        # Check for proper indentation consistency
        indent_levels = []
        for line in lines:
            if line.strip():
                leading_spaces = len(line) - len(line.lstrip())
                if leading_spaces % self.indent_size != 0:
                    errors.append(f"Inconsistent indentation: {leading_spaces} spaces")
                    break
        
        return (len(errors) == 0, errors)


# Backward compatibility: keep InstructionTranslator as alias
class InstructionTranslator(Decompiler):
    """
    Backward compatibility wrapper for InstructionTranslator.
    
    This class maintains the old interface while using the new Decompiler implementation.
    """
    
    def translate(self, instruction: Instruction) -> str:
        """
        Translate an assembly instruction to English (legacy method).
        
        Args:
            instruction: Instruction object to translate
            
        Returns:
            English description of the instruction
        """
        # For backward compatibility, provide English translation
        # This is a simplified version - the old translator.py had more detailed translations
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.get_parsed_operands()
        
        # Basic translation
        if mnemonic in ['mov', 'movabs']:
            if len(operands) >= 2:
                return f"Move {operands[1].raw} into {operands[0].raw}"
        elif mnemonic == 'add':
            if len(operands) >= 2:
                return f"Add {operands[1].raw} to {operands[0].raw}"
        elif mnemonic == 'sub':
            if len(operands) >= 2:
                return f"Subtract {operands[1].raw} from {operands[0].raw}"
        elif mnemonic == 'call':
            if len(operands) >= 1:
                return f"Call function {operands[0].raw}"
        elif mnemonic == 'ret':
            return "Return from function"
        elif mnemonic == 'jmp':
            if len(operands) >= 1:
                return f"Jump to {operands[0].raw}"
        
        # Default
        return f"{mnemonic.upper()} instruction"
