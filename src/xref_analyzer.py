"""Cross-Reference Analysis Engine for tracking code and data relationships"""
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from src.models import Instruction


@dataclass
class XREFDatabase:
    """Database storing bidirectional cross-reference relationships"""
    # Function call relationships
    function_calls: Dict[int, List[int]] = field(default_factory=dict)  # caller -> [callees]
    function_callers: Dict[int, List[int]] = field(default_factory=dict)  # callee -> [callers]
    
    # String reference relationships
    string_refs: Dict[str, List[int]] = field(default_factory=dict)  # string -> [addresses]
    address_strings: Dict[int, List[str]] = field(default_factory=dict)  # address -> [strings]
    
    # Data reference relationships
    data_refs: Dict[int, List[int]] = field(default_factory=dict)  # data_addr -> [code_addresses]
    code_data_refs: Dict[int, List[int]] = field(default_factory=dict)  # code_addr -> [data_addresses]


class XREFAnalyzer:
    """
    Analyzes assembly code to build comprehensive cross-reference database.
    
    Tracks:
    - Function call relationships (caller-to-callee and callee-to-caller)
    - String references (which code uses which strings)
    - Data references (which code accesses which data)
    
    Provides bidirectional lookup for all relationships.
    """
    
    def __init__(self):
        """Initialize the XREF analyzer"""
        self.xref_db = XREFDatabase()
        self._current_function = None
        self._function_boundaries = {}  # address -> function_start_address
    
    def analyze(self, instructions: List[Instruction]) -> XREFDatabase:
        """
        Analyze a list of instructions and build cross-reference database.
        
        Args:
            instructions: List of Instruction objects to analyze
            
        Returns:
            XREFDatabase containing all cross-reference relationships
        """
        if not instructions:
            return self.xref_db
        
        # First pass: identify function boundaries
        self._identify_function_boundaries(instructions)
        
        # Second pass: analyze instructions and build XREF database
        for i, instr in enumerate(instructions):
            # Update current function context
            if instr.address:
                addr = self._parse_address(instr.address)
                if addr in self._function_boundaries:
                    self._current_function = addr
            
            # Analyze instruction for cross-references
            self._analyze_instruction(instr, instructions, i)
        
        return self.xref_db
    
    def _identify_function_boundaries(self, instructions: List[Instruction]):
        """
        Identify function start addresses from instruction list.
        
        Looks for:
        - Instructions with labels (function names)
        - Function prologue patterns
        - Addresses that are call targets
        """
        call_targets = set()
        
        # Collect all call targets
        for instr in instructions:
            if instr.mnemonic.lower() == 'call' and instr.operands:
                target = self._parse_operand_address(instr.operands[0])
                if target is not None:
                    call_targets.add(target)
        
        # Mark function boundaries
        for instr in instructions:
            if not instr.address:
                continue
            
            addr = self._parse_address(instr.address)
            
            # Function has a label
            if instr.label:
                self._function_boundaries[addr] = addr
            
            # Address is a call target
            elif addr in call_targets:
                self._function_boundaries[addr] = addr
            
            # Function prologue pattern (push rbp/ebp)
            elif instr.mnemonic.lower() == 'push' and instr.operands:
                if any(reg in instr.operands[0].lower() for reg in ['rbp', 'ebp']):
                    self._function_boundaries[addr] = addr
    
    def _analyze_instruction(self, instr: Instruction, all_instructions: List[Instruction], index: int):
        """
        Analyze a single instruction for cross-references.
        
        Args:
            instr: Instruction to analyze
            all_instructions: Complete list of instructions for context
            index: Index of current instruction in the list
        """
        mnemonic = instr.mnemonic.lower()
        
        # Analyze function calls
        if mnemonic == 'call':
            self._analyze_call_instruction(instr)
        
        # Analyze jumps (for control flow, not function calls)
        elif mnemonic.startswith('j'):  # jmp, je, jne, jz, etc.
            self._analyze_jump_instruction(instr)
        
        # Analyze data references (lea, mov with memory operands)
        elif mnemonic in ['lea', 'mov', 'movabs']:
            self._analyze_data_reference(instr)
        
        # Analyze string references
        self._analyze_string_reference(instr, all_instructions, index)
    
    def _analyze_call_instruction(self, instr: Instruction):
        """
        Analyze a call instruction and track function call relationships.
        
        Args:
            instr: Call instruction to analyze
        """
        if not instr.operands or not self._current_function:
            return
        
        # Parse the call target
        target = self._parse_operand_address(instr.operands[0])
        
        if target is not None:
            # Add to function_calls (caller -> callee)
            if self._current_function not in self.xref_db.function_calls:
                self.xref_db.function_calls[self._current_function] = []
            if target not in self.xref_db.function_calls[self._current_function]:
                self.xref_db.function_calls[self._current_function].append(target)
            
            # Add to function_callers (callee -> caller) - bidirectional
            if target not in self.xref_db.function_callers:
                self.xref_db.function_callers[target] = []
            if self._current_function not in self.xref_db.function_callers[target]:
                self.xref_db.function_callers[target].append(self._current_function)
    
    def _analyze_jump_instruction(self, instr: Instruction):
        """
        Analyze jump instructions for control flow references.
        
        Args:
            instr: Jump instruction to analyze
        """
        # For now, we primarily track function calls
        # Jump analysis can be extended for CFG generation
        pass
    
    def _analyze_data_reference(self, instr: Instruction):
        """
        Analyze instructions that reference data addresses.
        
        Args:
            instr: Instruction with potential data reference
        """
        if not instr.operands or not self._current_function:
            return
        
        current_addr = self._parse_address(instr.address) if instr.address else None
        if current_addr is None:
            return
        
        # Look for memory references or immediate addresses
        for operand in instr.operands:
            # Check for memory reference [address]
            if '[' in operand and ']' in operand:
                # Extract address from memory reference
                data_addr = self._extract_address_from_memory_ref(operand)
                if data_addr is not None:
                    self._add_data_reference(current_addr, data_addr)
            
            # Check for immediate address (lea rax, [rip+offset] or mov rax, address)
            else:
                data_addr = self._parse_operand_address(operand)
                if data_addr is not None and data_addr != current_addr:
                    self._add_data_reference(current_addr, data_addr)
    
    def _analyze_string_reference(self, instr: Instruction, all_instructions: List[Instruction], index: int):
        """
        Analyze instruction for string references.
        
        Looks for string literals in comments or nearby instructions.
        
        Args:
            instr: Instruction to analyze
            all_instructions: Complete instruction list
            index: Current instruction index
        """
        if not self._current_function:
            return
        
        current_addr = self._parse_address(instr.address) if instr.address else None
        if current_addr is None:
            return
        
        # Check instruction comment for string literals
        if instr.comment:
            # Ghidra-style comments often contain string literals
            # Example: "Hello, World!"
            strings = self._extract_strings_from_comment(instr.comment)
            for string in strings:
                self._add_string_reference(string, current_addr)
        
        # Check for lea/mov instructions that load string addresses
        # These often have the string in a nearby comment or can be inferred
        mnemonic = instr.mnemonic.lower()
        if mnemonic in ['lea', 'mov', 'movabs']:
            # Look ahead a few instructions for string usage (printf, puts, etc.)
            for j in range(index + 1, min(index + 5, len(all_instructions))):
                next_instr = all_instructions[j]
                if next_instr.mnemonic.lower() == 'call':
                    # Check if this is a string function call
                    if next_instr.operands:
                        func_name = next_instr.operands[0].lower()
                        if any(sf in func_name for sf in ['printf', 'puts', 'sprintf', 'fprintf', 'strcmp', 'strcpy', 'strlen']):
                            # The lea/mov likely loaded a string address
                            if next_instr.comment:
                                strings = self._extract_strings_from_comment(next_instr.comment)
                                for string in strings:
                                    self._add_string_reference(string, current_addr)
                    break
    
    def _add_data_reference(self, code_addr: int, data_addr: int):
        """
        Add a data reference to the XREF database (bidirectional).
        
        Args:
            code_addr: Address of code referencing data
            data_addr: Address of data being referenced
        """
        # data_addr -> [code_addresses]
        if data_addr not in self.xref_db.data_refs:
            self.xref_db.data_refs[data_addr] = []
        if code_addr not in self.xref_db.data_refs[data_addr]:
            self.xref_db.data_refs[data_addr].append(code_addr)
        
        # code_addr -> [data_addresses] - bidirectional
        if code_addr not in self.xref_db.code_data_refs:
            self.xref_db.code_data_refs[code_addr] = []
        if data_addr not in self.xref_db.code_data_refs[code_addr]:
            self.xref_db.code_data_refs[code_addr].append(data_addr)
    
    def _add_string_reference(self, string: str, address: int):
        """
        Add a string reference to the XREF database (bidirectional).
        
        Args:
            string: String being referenced
            address: Address of code referencing the string
        """
        # string -> [addresses]
        if string not in self.xref_db.string_refs:
            self.xref_db.string_refs[string] = []
        if address not in self.xref_db.string_refs[string]:
            self.xref_db.string_refs[string].append(address)
        
        # address -> [strings] - bidirectional
        if address not in self.xref_db.address_strings:
            self.xref_db.address_strings[address] = []
        if string not in self.xref_db.address_strings[address]:
            self.xref_db.address_strings[address].append(string)
    
    def _parse_address(self, address_str: str) -> Optional[int]:
        """
        Parse an address string to integer.
        
        Args:
            address_str: Address as string (hex or decimal)
            
        Returns:
            Address as integer or None if parsing fails
        """
        if not address_str:
            return None
        
        try:
            # Remove any whitespace
            address_str = address_str.strip()
            
            # Try parsing as hex (with or without 0x prefix)
            if address_str.startswith('0x') or address_str.startswith('0X'):
                return int(address_str, 16)
            else:
                # Try hex without prefix first
                try:
                    return int(address_str, 16)
                except ValueError:
                    # Fall back to decimal
                    return int(address_str, 10)
        except (ValueError, AttributeError):
            return None
    
    def _parse_operand_address(self, operand: str) -> Optional[int]:
        """
        Parse an operand to extract an address if present.
        
        Args:
            operand: Operand string
            
        Returns:
            Address as integer or None
        """
        if not operand:
            return None
        
        operand = operand.strip()
        
        # Direct address (0x1234, 1234)
        if operand.startswith('0x') or operand.startswith('0X'):
            try:
                return int(operand, 16)
            except ValueError:
                return None
        
        # Try parsing as hex without prefix
        try:
            return int(operand, 16)
        except ValueError:
            pass
        
        # Try parsing as decimal
        try:
            return int(operand, 10)
        except ValueError:
            pass
        
        return None
    
    def _extract_address_from_memory_ref(self, memory_ref: str) -> Optional[int]:
        """
        Extract address from memory reference like [0x1234] or [rip+0x1234].
        
        Args:
            memory_ref: Memory reference string
            
        Returns:
            Address as integer or None
        """
        import re
        
        # Extract content between brackets
        match = re.search(r'\[([^\]]+)\]', memory_ref)
        if not match:
            return None
        
        content = match.group(1).strip()
        
        # Simple address [0x1234]
        if content.startswith('0x') or content.startswith('0X'):
            try:
                return int(content, 16)
            except ValueError:
                return None
        
        # RIP-relative [rip+0x1234] - we can't resolve without runtime info
        # For now, skip these
        if 'rip' in content.lower():
            return None
        
        # Try parsing as hex
        try:
            return int(content, 16)
        except ValueError:
            return None
    
    def _extract_strings_from_comment(self, comment: str) -> List[str]:
        """
        Extract string literals from instruction comments.
        
        Args:
            comment: Comment text
            
        Returns:
            List of extracted strings
        """
        import re
        
        strings = []
        
        # Look for quoted strings
        # Match strings in double quotes
        matches = re.findall(r'"([^"]*)"', comment)
        strings.extend(matches)
        
        # Match strings in single quotes
        matches = re.findall(r"'([^']*)'", comment)
        strings.extend(matches)
        
        return [s for s in strings if s]  # Filter empty strings
    
    # Query Interface Methods
    
    def get_callers(self, function_addr: int) -> List[int]:
        """
        Get all functions that call the specified function.
        
        Args:
            function_addr: Address of the function
            
        Returns:
            List of caller addresses
        """
        return self.xref_db.function_callers.get(function_addr, [])
    
    def get_callees(self, function_addr: int) -> List[int]:
        """
        Get all functions called by the specified function.
        
        Args:
            function_addr: Address of the function
            
        Returns:
            List of callee addresses
        """
        return self.xref_db.function_calls.get(function_addr, [])
    
    def get_string_refs(self, string: str) -> List[int]:
        """
        Get all code addresses that reference the specified string.
        
        Args:
            string: The string to look up
            
        Returns:
            List of code addresses referencing this string
        """
        return self.xref_db.string_refs.get(string, [])
    
    def get_strings_at_address(self, address: int) -> List[str]:
        """
        Get all strings referenced at the specified address.
        
        Args:
            address: Code address
            
        Returns:
            List of strings referenced at this address
        """
        return self.xref_db.address_strings.get(address, [])
    
    def get_data_refs(self, address: int) -> List[int]:
        """
        Get all code addresses that reference the specified data address.
        
        Args:
            address: Data address
            
        Returns:
            List of code addresses referencing this data
        """
        return self.xref_db.data_refs.get(address, [])
    
    def get_data_refs_from_code(self, address: int) -> List[int]:
        """
        Get all data addresses referenced by code at the specified address.
        
        Args:
            address: Code address
            
        Returns:
            List of data addresses referenced by this code
        """
        return self.xref_db.code_data_refs.get(address, [])
    
    def query_where_used(self, address: int) -> Dict[str, List[int]]:
        """
        Query "where is this used" - find all references TO this address.
        
        Args:
            address: Address to query
            
        Returns:
            Dictionary with 'callers' and 'data_refs' lists
        """
        return {
            'callers': self.get_callers(address),
            'data_refs': self.get_data_refs(address)
        }
    
    def query_what_uses(self, address: int) -> Dict[str, any]:
        """
        Query "what does this use" - find all references FROM this address.
        
        Args:
            address: Address to query
            
        Returns:
            Dictionary with 'callees', 'strings', and 'data_refs' lists
        """
        return {
            'callees': self.get_callees(address),
            'strings': self.get_strings_at_address(address),
            'data_refs': self.get_data_refs_from_code(address)
        }
    
    def generate_xref_report(self, address: int) -> str:
        """
        Generate a comprehensive cross-reference report for an address.
        
        Args:
            address: Address to generate report for
            
        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append(f"CROSS-REFERENCE REPORT FOR ADDRESS: 0x{address:x}")
        report.append("=" * 80)
        report.append("")
        
        # What this address uses
        report.append("OUTGOING REFERENCES (What this address uses):")
        report.append("-" * 80)
        
        callees = self.get_callees(address)
        if callees:
            report.append(f"  Calls {len(callees)} function(s):")
            for callee in callees:
                report.append(f"    → 0x{callee:x}")
        else:
            report.append("  No function calls")
        
        report.append("")
        
        strings = self.get_strings_at_address(address)
        if strings:
            report.append(f"  References {len(strings)} string(s):")
            for string in strings:
                display_str = string if len(string) <= 60 else string[:57] + "..."
                report.append(f"    → \"{display_str}\"")
        else:
            report.append("  No string references")
        
        report.append("")
        
        data_refs = self.get_data_refs_from_code(address)
        if data_refs:
            report.append(f"  References {len(data_refs)} data address(es):")
            for data_addr in data_refs:
                report.append(f"    → 0x{data_addr:x}")
        else:
            report.append("  No data references")
        
        report.append("")
        report.append("INCOMING REFERENCES (What uses this address):")
        report.append("-" * 80)
        
        callers = self.get_callers(address)
        if callers:
            report.append(f"  Called by {len(callers)} function(s):")
            for caller in callers:
                report.append(f"    ← 0x{caller:x}")
        else:
            report.append("  Not called by any function")
        
        report.append("")
        
        data_refs_to = self.get_data_refs(address)
        if data_refs_to:
            report.append(f"  Referenced as data by {len(data_refs_to)} location(s):")
            for ref_addr in data_refs_to:
                report.append(f"    ← 0x{ref_addr:x}")
        else:
            report.append("  Not referenced as data")
        
        report.append("")
        report.append("=" * 80)
        
        return '\n'.join(report)
    
    def generate_summary_report(self) -> str:
        """
        Generate a summary report of all cross-references in the database.
        
        Returns:
            Formatted summary report
        """
        report = []
        report.append("=" * 80)
        report.append("CROSS-REFERENCE DATABASE SUMMARY")
        report.append("=" * 80)
        report.append("")
        
        # Function call statistics
        total_callers = len(self.xref_db.function_calls)
        total_callees = len(self.xref_db.function_callers)
        total_call_edges = sum(len(callees) for callees in self.xref_db.function_calls.values())
        
        report.append("FUNCTION CALL RELATIONSHIPS:")
        report.append(f"  Functions that make calls: {total_callers}")
        report.append(f"  Functions that are called: {total_callees}")
        report.append(f"  Total call edges: {total_call_edges}")
        report.append("")
        
        # String reference statistics
        total_strings = len(self.xref_db.string_refs)
        total_string_refs = sum(len(refs) for refs in self.xref_db.string_refs.values())
        
        report.append("STRING REFERENCES:")
        report.append(f"  Unique strings referenced: {total_strings}")
        report.append(f"  Total string references: {total_string_refs}")
        report.append("")
        
        # Data reference statistics
        total_data_addrs = len(self.xref_db.data_refs)
        total_data_refs = sum(len(refs) for refs in self.xref_db.data_refs.values())
        
        report.append("DATA REFERENCES:")
        report.append(f"  Data addresses referenced: {total_data_addrs}")
        report.append(f"  Total data references: {total_data_refs}")
        report.append("")
        
        # Top referenced functions
        if self.xref_db.function_callers:
            report.append("TOP 10 MOST CALLED FUNCTIONS:")
            sorted_funcs = sorted(
                self.xref_db.function_callers.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:10]
            
            for func_addr, callers in sorted_funcs:
                report.append(f"  0x{func_addr:x} - called by {len(callers)} function(s)")
            report.append("")
        
        # Top referenced strings
        if self.xref_db.string_refs:
            report.append("TOP 10 MOST REFERENCED STRINGS:")
            sorted_strings = sorted(
                self.xref_db.string_refs.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:10]
            
            for string, refs in sorted_strings:
                display_str = string if len(string) <= 50 else string[:47] + "..."
                report.append(f"  \"{display_str}\" - {len(refs)} reference(s)")
            report.append("")
        
        report.append("=" * 80)
        
        return '\n'.join(report)
