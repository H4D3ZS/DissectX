"""Security highlighter for identifying security-relevant operations in assembly code"""
from typing import List, Dict, Any
from src.models import Instruction


class SecurityHighlighter:
    """Identifies and highlights security-relevant operations in assembly code"""
    
    def __init__(self):
        """Initialize the security highlighter"""
        # Common security-related function names and patterns
        self.security_functions = [
            'malloc', 'calloc', 'realloc', 'free',
            'strcpy', 'strncpy', 'strcat', 'strncat',
            'sprintf', 'snprintf', 'gets', 'fgets',
            'memcpy', 'memmove', 'memset',
            '__security_cookie', '__security_check_cookie',
            'strcmp', 'strncmp', 'memcmp'
        ]
    
    def highlight(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Analyze instructions and identify security-relevant operations.
        
        Returns a list of security observations with:
        - type: category of security operation
        - description: explanation of the security implication
        - instructions: list of relevant instructions
        - addresses: list of addresses where this occurs
        
        Args:
            instructions: List of Instruction objects to analyze
            
        Returns:
            List of security observation dictionaries
        """
        observations = []
        
        # Detect various security patterns
        observations.extend(self.detect_buffer_operations(instructions))
        observations.extend(self.detect_authentication_checks(instructions))
        observations.extend(self.detect_crypto_operations(instructions))
        observations.extend(self.detect_stack_canary(instructions))
        observations.extend(self.detect_memory_management(instructions))
        
        return observations
    
    def detect_buffer_operations(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Identify buffer access and bounds checks.
        
        Looks for:
        - Array/buffer access patterns (memory references with offsets)
        - Bounds checking (cmp with buffer size before access)
        - Unsafe string operations (strcpy, gets, etc.)
        - Buffer size calculations
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of security observations related to buffer operations
        """
        observations = []
        
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check for calls to unsafe string/buffer functions
            if mnemonic == 'call' and instr.operands:
                target = instr.operands[0].lower()
                
                unsafe_functions = ['strcpy', 'strcat', 'sprintf', 'gets']
                safe_functions = ['strncpy', 'strncat', 'snprintf', 'fgets']
                
                for unsafe_func in unsafe_functions:
                    if unsafe_func in target:
                        observations.append({
                            'type': 'buffer_operation',
                            'severity': 'high',
                            'description': f"Potentially unsafe buffer operation: call to {unsafe_func} (no bounds checking)",
                            'instructions': [instr],
                            'addresses': [instr.address] if instr.address else []
                        })
                        break
                
                for safe_func in safe_functions:
                    if safe_func in target:
                        observations.append({
                            'type': 'buffer_operation',
                            'severity': 'low',
                            'description': f"Safe buffer operation: call to {safe_func} (includes bounds checking)",
                            'instructions': [instr],
                            'addresses': [instr.address] if instr.address else []
                        })
                        break
                
                # Check for memcpy/memmove with size parameter
                if 'memcpy' in target or 'memmove' in target:
                    # Look backwards for size parameter setup (typically in r8 or on stack)
                    context_instrs = instructions[max(0, i-3):i+1]
                    observations.append({
                        'type': 'buffer_operation',
                        'severity': 'medium',
                        'description': f"Buffer copy operation: {target} - verify size parameter is validated",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
            
            # Check for bounds checking patterns (cmp before memory access)
            if mnemonic == 'cmp' and i + 1 < len(instructions):
                next_instr = instructions[i + 1]
                next_mnemonic = next_instr.mnemonic.lower()
                
                # If cmp is followed by conditional jump, and then memory access
                if next_mnemonic in ['jae', 'jbe', 'ja', 'jb', 'jge', 'jle', 'jg', 'jl']:
                    # Look ahead for memory operations
                    for j in range(i + 2, min(i + 5, len(instructions))):
                        check_instr = instructions[j]
                        # Check if any operand is a memory reference
                        if any('[' in op for op in check_instr.operands):
                            observations.append({
                                'type': 'buffer_operation',
                                'severity': 'low',
                                'description': "Bounds check detected: comparison before buffer access (good practice)",
                                'instructions': [instr, next_instr, check_instr],
                                'addresses': [inst.address for inst in [instr, next_instr, check_instr] if inst.address]
                            })
                            break
        
        return observations
    
    def detect_authentication_checks(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Identify comparisons on user input that may be authentication checks.
        
        Looks for:
        - String comparison functions (strcmp, strncmp, memcmp)
        - Direct value comparisons that might be password checks
        - Patterns of multiple comparisons (checking multiple characters)
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of security observations related to authentication
        """
        observations = []
        
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check for calls to comparison functions
            if mnemonic == 'call' and instr.operands:
                target = instr.operands[0].lower()
                
                comparison_functions = ['strcmp', 'strncmp', 'memcmp', 'strcasecmp', 'strncasecmp']
                
                for comp_func in comparison_functions:
                    if comp_func in target:
                        # Look for the result check (test/cmp on rax after call)
                        context_instrs = [instr]
                        for j in range(i + 1, min(i + 4, len(instructions))):
                            check_instr = instructions[j]
                            if check_instr.mnemonic.lower() in ['test', 'cmp']:
                                if check_instr.operands and 'rax' in check_instr.operands[0].lower():
                                    context_instrs.append(check_instr)
                                    if j + 1 < len(instructions):
                                        context_instrs.append(instructions[j + 1])
                                    break
                        
                        observations.append({
                            'type': 'authentication_check',
                            'severity': 'high',
                            'description': f"Authentication check: {comp_func} comparison - potential password/credential verification",
                            'instructions': context_instrs,
                            'addresses': [inst.address for inst in context_instrs if inst.address]
                        })
                        break
            
            # Check for patterns of byte-by-byte comparison (manual string comparison)
            if mnemonic == 'cmp' and instr.operands and len(instr.operands) >= 2:
                # Check if comparing memory or register with immediate value
                op1 = instr.operands[0]
                op2 = instr.operands[1]
                
                # Look for patterns like: cmp byte ptr [rax], 0x41 (comparing with ASCII)
                if '[' in op1 and (op2.startswith('0x') or op2.isdigit()):
                    try:
                        value = int(op2, 0)
                        # Check if it's a printable ASCII character (potential password check)
                        if 0x20 <= value <= 0x7E:
                            # Look for conditional jump after comparison
                            if i + 1 < len(instructions):
                                next_instr = instructions[i + 1]
                                if next_instr.mnemonic.lower() in ['je', 'jne', 'jz', 'jnz']:
                                    observations.append({
                                        'type': 'authentication_check',
                                        'severity': 'medium',
                                        'description': f"Character comparison: comparing with ASCII value {hex(value)} ('{chr(value)}') - possible password check",
                                        'instructions': [instr, next_instr],
                                        'addresses': [inst.address for inst in [instr, next_instr] if inst.address]
                                    })
                    except ValueError:
                        pass
        
        return observations
    
    def detect_crypto_operations(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Identify XOR-based encryption or obfuscation routines.
        
        Looks for:
        - XOR operations on data (especially in loops)
        - XOR with non-zero values (not register zeroing)
        - Patterns of repeated XOR operations
        - XOR with keys or constants
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of security observations related to cryptographic operations
        """
        observations = []
        
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check for XOR operations
            if mnemonic == 'xor' and instr.operands and len(instr.operands) >= 2:
                op1 = instr.operands[0]
                op2 = instr.operands[1]
                
                # Skip register zeroing (xor reg, reg)
                if op1.lower() == op2.lower():
                    continue
                
                # XOR with different operands - potential encryption
                context_instrs = [instr]
                
                # Check if this is in a loop (look for nearby backward jumps)
                in_loop = False
                for j in range(max(0, i - 10), min(i + 10, len(instructions))):
                    check_instr = instructions[j]
                    if check_instr.mnemonic.lower() in ['jmp', 'jnz', 'jz', 'loop']:
                        in_loop = True
                        break
                
                # Check if XOR is with a constant (potential key)
                is_constant_key = op2.startswith('0x') or op2.isdigit()
                
                if in_loop and is_constant_key:
                    observations.append({
                        'type': 'crypto_operation',
                        'severity': 'high',
                        'description': f"Encryption/obfuscation detected: XOR operation with constant key {op2} in loop - likely XOR cipher",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                elif in_loop:
                    observations.append({
                        'type': 'crypto_operation',
                        'severity': 'medium',
                        'description': f"Potential encryption: XOR operation in loop - possible data obfuscation",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                elif is_constant_key:
                    observations.append({
                        'type': 'crypto_operation',
                        'severity': 'low',
                        'description': f"XOR with constant {op2} - possible data obfuscation or checksum",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
            
            # Check for XORPS (XOR packed single-precision floating-point)
            # Sometimes used for data obfuscation
            if mnemonic == 'xorps' and instr.operands and len(instr.operands) >= 2:
                op1 = instr.operands[0]
                op2 = instr.operands[1]
                
                # Skip zeroing (xorps xmm0, xmm0)
                if op1.lower() != op2.lower():
                    observations.append({
                        'type': 'crypto_operation',
                        'severity': 'low',
                        'description': f"XORPS operation on different registers - possible data manipulation or obfuscation",
                        'instructions': [instr],
                        'addresses': [instr.address] if instr.address else []
                    })
        
        return observations
    
    def detect_stack_canary(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Identify stack canary operations (__security_cookie).
        
        Looks for:
        - References to __security_cookie or __security_check_cookie
        - Stack canary setup (storing value on stack)
        - Stack canary verification (comparing before return)
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of security observations related to stack protection
        """
        observations = []
        
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check for calls to security cookie functions
            if mnemonic == 'call' and instr.operands:
                target = instr.operands[0].lower()
                
                if '__security_check_cookie' in target or 'security_check_cookie' in target:
                    observations.append({
                        'type': 'stack_canary',
                        'severity': 'info',
                        'description': "Stack protection: verifying stack canary before function return (buffer overflow protection)",
                        'instructions': [instr],
                        'addresses': [instr.address] if instr.address else []
                    })
            
            # Check for references to __security_cookie in operands or comments
            if instr.comment and '__security_cookie' in instr.comment.lower():
                # Look at the instruction to determine if it's setup or check
                if mnemonic == 'mov':
                    observations.append({
                        'type': 'stack_canary',
                        'severity': 'info',
                        'description': "Stack protection: loading stack canary value (buffer overflow protection)",
                        'instructions': [instr],
                        'addresses': [instr.address] if instr.address else []
                    })
                elif mnemonic in ['xor', 'cmp']:
                    observations.append({
                        'type': 'stack_canary',
                        'severity': 'info',
                        'description': "Stack protection: verifying stack canary integrity (buffer overflow protection)",
                        'instructions': [instr],
                        'addresses': [instr.address] if instr.address else []
                    })
            
            # Check for operands containing security_cookie
            for operand in instr.operands:
                if '__security_cookie' in operand.lower() or 'security_cookie' in operand.lower():
                    if mnemonic == 'mov':
                        # Determine direction (loading or storing)
                        if operand == instr.operands[0]:
                            desc = "Stack protection: storing stack canary value"
                        else:
                            desc = "Stack protection: loading stack canary value"
                    elif mnemonic in ['xor', 'cmp']:
                        desc = "Stack protection: verifying stack canary"
                    else:
                        desc = "Stack protection: stack canary operation"
                    
                    observations.append({
                        'type': 'stack_canary',
                        'severity': 'info',
                        'description': desc,
                        'instructions': [instr],
                        'addresses': [instr.address] if instr.address else []
                    })
                    break
        
        return observations
    
    def detect_memory_management(self, instructions: List[Instruction]) -> List[Dict[str, Any]]:
        """
        Identify memory allocation and deallocation operations.
        
        Looks for:
        - Calls to malloc, calloc, realloc, free
        - Memory allocation patterns
        - Potential memory leaks (allocation without corresponding free)
        - Use-after-free patterns
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of security observations related to memory management
        """
        observations = []
        allocations = []
        deallocations = []
        
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check for calls to memory management functions
            if mnemonic == 'call' and instr.operands:
                target = instr.operands[0].lower()
                
                # Allocation functions
                if 'malloc' in target:
                    # Look backwards for size parameter (typically in rcx or first arg register)
                    context_instrs = instructions[max(0, i-3):i+1]
                    observations.append({
                        'type': 'memory_management',
                        'severity': 'medium',
                        'description': "Memory allocation: malloc - ensure proper size validation and null check",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                    allocations.append(i)
                
                elif 'calloc' in target:
                    context_instrs = instructions[max(0, i-3):i+1]
                    observations.append({
                        'type': 'memory_management',
                        'severity': 'medium',
                        'description': "Memory allocation: calloc - allocates zeroed memory, ensure proper null check",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                    allocations.append(i)
                
                elif 'realloc' in target:
                    context_instrs = instructions[max(0, i-3):i+1]
                    observations.append({
                        'type': 'memory_management',
                        'severity': 'high',
                        'description': "Memory reallocation: realloc - verify null check and handle allocation failure",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                
                # Deallocation functions
                elif 'free' in target:
                    context_instrs = instructions[max(0, i-2):i+1]
                    observations.append({
                        'type': 'memory_management',
                        'severity': 'medium',
                        'description': "Memory deallocation: free - ensure pointer is not used after free (use-after-free)",
                        'instructions': context_instrs,
                        'addresses': [inst.address for inst in context_instrs if inst.address]
                    })
                    deallocations.append(i)
        
        # Check for potential memory leak (more allocations than deallocations)
        if len(allocations) > len(deallocations) and len(allocations) > 0:
            observations.append({
                'type': 'memory_management',
                'severity': 'medium',
                'description': f"Potential memory leak: {len(allocations)} allocation(s) but only {len(deallocations)} deallocation(s) detected",
                'instructions': [],
                'addresses': []
            })
        
        return observations
