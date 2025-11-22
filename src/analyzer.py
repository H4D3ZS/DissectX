"""Pattern analyzer for identifying high-level constructs in assembly code"""
from typing import List, Optional
from src.models import Instruction, CodeBlock


class PatternAnalyzer:
    """Analyzes instruction sequences to identify high-level patterns and constructs"""
    
    def __init__(self):
        """Initialize the pattern analyzer"""
        pass
    
    def analyze(self, instructions: List[Instruction]) -> List[CodeBlock]:
        """
        Analyze a list of instructions and identify high-level patterns.
        
        Detects:
        - Function prologues and epilogues
        - Loops (backward jumps with counters)
        - Conditionals (cmp followed by conditional jumps)
        - String operations
        
        Args:
            instructions: List of Instruction objects to analyze
            
        Returns:
            List of CodeBlock objects representing identified patterns
        """
        if not instructions:
            return []
        
        blocks = []
        
        # Detect function prologue at the beginning
        prologue = self.detect_function_prologue(instructions)
        if prologue:
            blocks.append(prologue)
        
        # Detect loops
        loops = self.detect_loops(instructions)
        blocks.extend(loops)
        
        # Detect conditionals
        conditionals = self.detect_conditionals(instructions)
        blocks.extend(conditionals)
        
        # Detect string operations
        string_ops = self.detect_string_operations(instructions)
        blocks.extend(string_ops)
        
        # Detect function epilogue at the end
        epilogue = self.detect_function_epilogue(instructions)
        if epilogue:
            blocks.append(epilogue)
        
        return blocks
    
    def detect_loops(self, instructions: List[Instruction]) -> List[CodeBlock]:
        """
        Identify loop structures by detecting backward jumps with loop counters.
        
        A loop is typically characterized by:
        - A label or address that serves as the loop start
        - Instructions that modify a counter (inc, dec, add, sub on rcx or similar)
        - A comparison (cmp, test)
        - A conditional jump back to the loop start
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of CodeBlock objects representing detected loops
        """
        loops = []
        
        # Build address/label map for jump target resolution
        address_map = {}
        for i, instr in enumerate(instructions):
            if instr.address:
                address_map[instr.address] = i
            if instr.label:
                address_map[instr.label] = i
        
        # Look for backward jumps (jumps to earlier addresses/labels)
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check if this is a conditional jump
            if mnemonic in ['jnz', 'jz', 'je', 'jne', 'jl', 'jle', 'jg', 'jge', 'jb', 'jbe', 'ja', 'jae', 'jmp']:
                if not instr.operands:
                    continue
                
                target = instr.operands[0]
                
                # Check if target is a backward jump
                target_idx = address_map.get(target)
                if target_idx is not None and target_idx < i:
                    # This is a backward jump - likely a loop
                    loop_start = target_idx
                    loop_end = i
                    
                    # Extract loop instructions
                    loop_instructions = instructions[loop_start:loop_end + 1]
                    
                    # Try to identify loop counter
                    counter_reg = self._identify_loop_counter(loop_instructions)
                    
                    # Build description
                    if counter_reg:
                        description = f"Loop using {counter_reg} as counter, jumping back to {target}"
                    else:
                        description = f"Loop jumping back to {target}"
                    
                    # Determine start and end addresses
                    start_addr = instructions[loop_start].address
                    end_addr = instructions[loop_end].address
                    
                    loop_block = CodeBlock(
                        instructions=loop_instructions,
                        block_type='loop',
                        start_address=start_addr,
                        end_address=end_addr,
                        description=description
                    )
                    loops.append(loop_block)
        
        return loops
    
    def _identify_loop_counter(self, instructions: List[Instruction]) -> Optional[str]:
        """
        Identify the register used as a loop counter.
        
        Looks for registers that are:
        - Incremented/decremented (inc, dec)
        - Modified with add/sub
        - Compared (cmp, test)
        
        Common loop counters: rcx, ecx, rax, eax, r8, etc.
        
        Args:
            instructions: Instructions within the loop
            
        Returns:
            Register name if identified, None otherwise
        """
        counter_candidates = {}
        
        for instr in instructions:
            mnemonic = instr.mnemonic.lower()
            
            # Look for increment/decrement operations
            if mnemonic in ['inc', 'dec', 'add', 'sub']:
                if instr.operands:
                    operand = instr.operands[0]
                    # Simple heuristic: if it's a register, it might be a counter
                    if not '[' in operand:  # Not a memory reference
                        counter_candidates[operand] = counter_candidates.get(operand, 0) + 2
            
            # Look for comparisons
            elif mnemonic in ['cmp', 'test']:
                if instr.operands:
                    operand = instr.operands[0]
                    if not '[' in operand:
                        counter_candidates[operand] = counter_candidates.get(operand, 0) + 1
        
        # Return the most likely counter (highest score)
        if counter_candidates:
            return max(counter_candidates, key=counter_candidates.get)
        
        return None
    
    def detect_conditionals(self, instructions: List[Instruction]) -> List[CodeBlock]:
        """
        Identify conditional branching patterns (if-else, switch-case).
        
        A conditional is typically:
        - A comparison instruction (cmp, test)
        - Followed by a conditional jump (je, jne, jg, jl, etc.)
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of CodeBlock objects representing detected conditionals
        """
        conditionals = []
        
        i = 0
        while i < len(instructions):
            instr = instructions[i]
            mnemonic = instr.mnemonic.lower()
            
            # Look for comparison instructions
            if mnemonic in ['cmp', 'test']:
                # Check if next instruction is a conditional jump
                if i + 1 < len(instructions):
                    next_instr = instructions[i + 1]
                    next_mnemonic = next_instr.mnemonic.lower()
                    
                    if next_mnemonic in ['jz', 'jnz', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe']:
                        # Found a conditional pattern
                        conditional_instructions = [instr, next_instr]
                        
                        # Build description
                        if instr.operands and len(instr.operands) >= 2:
                            op1 = instr.operands[0]
                            op2 = instr.operands[1]
                            
                            condition_map = {
                                'jz': 'if equal to zero',
                                'jnz': 'if not equal to zero',
                                'je': 'if equal',
                                'jne': 'if not equal',
                                'jg': 'if greater',
                                'jge': 'if greater or equal',
                                'jl': 'if less',
                                'jle': 'if less or equal',
                                'ja': 'if above',
                                'jae': 'if above or equal',
                                'jb': 'if below',
                                'jbe': 'if below or equal',
                            }
                            
                            condition = condition_map.get(next_mnemonic, 'conditionally')
                            target = next_instr.operands[0] if next_instr.operands else 'target'
                            
                            if mnemonic == 'test':
                                description = f"Conditional: test {op1} against {op2}, jump to {target} {condition}"
                            else:
                                description = f"Conditional: compare {op1} with {op2}, jump to {target} {condition}"
                        else:
                            description = f"Conditional branch"
                        
                        start_addr = instr.address
                        end_addr = next_instr.address
                        
                        conditional_block = CodeBlock(
                            instructions=conditional_instructions,
                            block_type='conditional',
                            start_address=start_addr,
                            end_address=end_addr,
                            description=description
                        )
                        conditionals.append(conditional_block)
                        
                        # Skip the next instruction since we've already processed it
                        i += 1
            
            i += 1
        
        return conditionals
    
    def detect_function_prologue(self, instructions: List[Instruction]) -> Optional[CodeBlock]:
        """
        Identify function prologue (stack frame setup).
        
        Common prologue pattern:
        - push rbp          (save old base pointer)
        - mov rbp, rsp      (set new base pointer)
        - sub rsp, <size>   (allocate stack space)
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            CodeBlock if prologue detected, None otherwise
        """
        if len(instructions) < 2:
            return None
        
        # Look for prologue at the beginning of the instruction list
        prologue_instructions = []
        i = 0
        
        # Pattern 1: push rbp
        if i < len(instructions):
            instr = instructions[i]
            if instr.mnemonic.lower() == 'push' and instr.operands:
                if 'rbp' in instr.operands[0].lower():
                    prologue_instructions.append(instr)
                    i += 1
        
        # Pattern 2: mov rbp, rsp
        if i < len(instructions):
            instr = instructions[i]
            if instr.mnemonic.lower() == 'mov' and len(instr.operands) >= 2:
                if 'rbp' in instr.operands[0].lower() and 'rsp' in instr.operands[1].lower():
                    prologue_instructions.append(instr)
                    i += 1
        
        # Pattern 3: sub rsp, <size> (optional)
        if i < len(instructions):
            instr = instructions[i]
            if instr.mnemonic.lower() == 'sub' and len(instr.operands) >= 2:
                if 'rsp' in instr.operands[0].lower():
                    prologue_instructions.append(instr)
                    i += 1
        
        # We need at least the first two instructions for a valid prologue
        if len(prologue_instructions) >= 2:
            start_addr = prologue_instructions[0].address
            end_addr = prologue_instructions[-1].address
            
            # Calculate stack space if sub rsp was present
            stack_space = None
            if len(prologue_instructions) >= 3:
                sub_instr = prologue_instructions[2]
                if sub_instr.operands and len(sub_instr.operands) >= 2:
                    try:
                        stack_space = int(sub_instr.operands[1], 0)
                    except ValueError:
                        pass
            
            if stack_space:
                description = f"Function prologue: set up stack frame with {hex(stack_space)} bytes of local space"
            else:
                description = "Function prologue: set up stack frame"
            
            return CodeBlock(
                instructions=prologue_instructions,
                block_type='function_prologue',
                start_address=start_addr,
                end_address=end_addr,
                description=description
            )
        
        return None
    
    def detect_function_epilogue(self, instructions: List[Instruction]) -> Optional[CodeBlock]:
        """
        Identify function epilogue (function return sequence).
        
        Common epilogue patterns:
        - add rsp, <size>   (deallocate stack space) [optional]
        - pop rbp           (restore old base pointer)
        - ret               (return from function)
        
        Or simpler:
        - pop rbp
        - ret
        
        Or simplest:
        - ret
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            CodeBlock if epilogue detected, None otherwise
        """
        if len(instructions) < 1:
            return None
        
        # Look for epilogue at the end of the instruction list
        epilogue_instructions = []
        
        # Start from the end and work backwards
        i = len(instructions) - 1
        
        # Pattern 1: ret (must be present)
        if i >= 0:
            instr = instructions[i]
            if instr.mnemonic.lower() == 'ret':
                epilogue_instructions.insert(0, instr)
                i -= 1
            else:
                return None  # No ret, no epilogue
        
        # Pattern 2: pop rbp (optional but common)
        if i >= 0:
            instr = instructions[i]
            if instr.mnemonic.lower() == 'pop' and instr.operands:
                if 'rbp' in instr.operands[0].lower():
                    epilogue_instructions.insert(0, instr)
                    i -= 1
        
        # Pattern 3: add rsp, <size> (optional)
        if i >= 0:
            instr = instructions[i]
            if instr.mnemonic.lower() == 'add' and len(instr.operands) >= 2:
                if 'rsp' in instr.operands[0].lower():
                    epilogue_instructions.insert(0, instr)
                    i -= 1
        
        # We have at least ret, which is enough for an epilogue
        if epilogue_instructions:
            start_addr = epilogue_instructions[0].address
            end_addr = epilogue_instructions[-1].address
            
            # Calculate stack space if add rsp was present
            stack_space = None
            if len(epilogue_instructions) >= 3:
                add_instr = epilogue_instructions[0]
                if add_instr.mnemonic.lower() == 'add' and add_instr.operands and len(add_instr.operands) >= 2:
                    try:
                        stack_space = int(add_instr.operands[1], 0)
                    except ValueError:
                        pass
            
            if stack_space:
                description = f"Function epilogue: clean up stack frame ({hex(stack_space)} bytes) and return"
            elif len(epilogue_instructions) > 1:
                description = "Function epilogue: restore stack frame and return"
            else:
                description = "Function epilogue: return from function"
            
            return CodeBlock(
                instructions=epilogue_instructions,
                block_type='function_epilogue',
                start_address=start_addr,
                end_address=end_addr,
                description=description
            )
        
        return None
    
    def detect_string_operations(self, instructions: List[Instruction]) -> List[CodeBlock]:
        """
        Identify string manipulation patterns.
        
        Common string operations:
        - movs/movsb/movsw/movsd/movsq (move string)
        - stos/stosb/stosw/stosd/stosq (store string)
        - lods/lodsb/lodsw/lodsd/lodsq (load string)
        - scas/scasb/scasw/scasd/scasq (scan string)
        - cmps/cmpsb/cmpsw/cmpsd/cmpsq (compare string)
        - rep prefix (repeat while rcx != 0)
        
        Also look for patterns like:
        - Loop with byte-by-byte operations on rsi/rdi
        - Operations on character data with increment
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of CodeBlock objects representing detected string operations
        """
        string_ops = []
        
        # String instruction mnemonics
        string_mnemonics = [
            'movs', 'movsb', 'movsw', 'movsd', 'movsq',
            'stos', 'stosb', 'stosw', 'stosd', 'stosq',
            'lods', 'lodsb', 'lodsw', 'lodsd', 'lodsq',
            'scas', 'scasb', 'scasw', 'scasd', 'scasq',
            'cmps', 'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq',
            'rep', 'repe', 'repz', 'repne', 'repnz'
        ]
        
        i = 0
        while i < len(instructions):
            instr = instructions[i]
            mnemonic = instr.mnemonic.lower()
            
            # Check for string instructions
            if mnemonic in string_mnemonics:
                string_instructions = [instr]
                has_rep_prefix = False
                actual_op = mnemonic
                
                # Check if there's a rep prefix or if next instruction is a string op
                if mnemonic in ['rep', 'repe', 'repz', 'repne', 'repnz']:
                    has_rep_prefix = True
                    # Rep prefix - check if operand is a string operation (parser may combine them)
                    if instr.operands and len(instr.operands) > 0:
                        # Parser combined "rep movsb" into one instruction
                        operand = instr.operands[0].lower()
                        if operand in string_mnemonics:
                            actual_op = operand
                    # Or check if next instruction is the actual string operation
                    elif i + 1 < len(instructions):
                        next_instr = instructions[i + 1]
                        if next_instr.mnemonic.lower() in string_mnemonics:
                            string_instructions.append(next_instr)
                            actual_op = next_instr.mnemonic.lower()
                            i += 1
                
                # Build description based on the operation
                operation_desc = {
                    'movs': 'move string data',
                    'movsb': 'move string bytes',
                    'movsw': 'move string words',
                    'movsd': 'move string doublewords',
                    'movsq': 'move string quadwords',
                    'stos': 'store string data',
                    'stosb': 'store string bytes',
                    'stosw': 'store string words',
                    'stosd': 'store string doublewords',
                    'stosq': 'store string quadwords',
                    'lods': 'load string data',
                    'lodsb': 'load string bytes',
                    'lodsw': 'load string words',
                    'lodsd': 'load string doublewords',
                    'lodsq': 'load string quadwords',
                    'scas': 'scan string data',
                    'scasb': 'scan string bytes',
                    'scasw': 'scan string words',
                    'scasd': 'scan string doublewords',
                    'scasq': 'scan string quadwords',
                    'cmps': 'compare string data',
                    'cmpsb': 'compare string bytes',
                    'cmpsw': 'compare string words',
                    'cmpsd': 'compare string doublewords',
                    'cmpsq': 'compare string quadwords',
                }
                
                # Get the operation description
                op_desc = operation_desc.get(actual_op, 'string operation')
                
                if has_rep_prefix:
                    description = f"String operation: repeat {op_desc} while rcx != 0"
                else:
                    description = f"String operation: {op_desc}"
                
                start_addr = string_instructions[0].address
                end_addr = string_instructions[-1].address
                
                string_block = CodeBlock(
                    instructions=string_instructions,
                    block_type='string_operation',
                    start_address=start_addr,
                    end_address=end_addr,
                    description=description
                )
                string_ops.append(string_block)
            
            i += 1
        
        return string_ops
