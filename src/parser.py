"""Assembly parser for x86-64 assembly code"""
import re
from typing import List, Optional
from src.models import Instruction


class AssemblyParser:
    """Parses x86-64 assembly code into structured Instruction objects"""
    
    def __init__(self):
        # Common size specifiers in Intel syntax
        self.size_specifiers = ['byte ptr', 'word ptr', 'dword ptr', 'qword ptr', 
                                'xmmword ptr', 'ymmword ptr', 'ptr']
    
    def parse(self, assembly_text: str) -> List[Instruction]:
        """
        Parse assembly text into a list of Instruction objects.

        Handles standalone labels by attaching them to the next instruction.

        Args:
            assembly_text: Multi-line assembly code string

        Returns:
            List of parsed Instruction objects
        """
        instructions = []
        lines = assembly_text.strip().split('\n')
        pending_label = None

        for line in lines:
            instruction = self.parse_instruction(line)
            if instruction:
                # If this is a label-only instruction, save it for the next real instruction
                if instruction.mnemonic == '' and instruction.label:
                    pending_label = instruction.label
                else:
                    # If we have a pending label, attach it to this instruction
                    if pending_label:
                        instruction.label = pending_label
                        pending_label = None
                    instructions.append(instruction)

        return instructions

    def quick_parse(self, assembly_text: str, limit: int = 10) -> tuple[List[Instruction], int]:
        """
        Quickly parse first N instructions for preview purposes.

        Args:
            assembly_text: Multi-line assembly code string
            limit: Maximum number of instructions to parse (default: 10)

        Returns:
            Tuple of (parsed_instructions, total_lines)
        """
        instructions = []
        lines = assembly_text.strip().split('\n')
        total_lines = len(lines)
        pending_label = None

        for line in lines:
            # Stop if we have enough instructions
            if len(instructions) >= limit:
                break

            instruction = self.parse_instruction(line)
            if instruction:
                # If this is a label-only instruction, save it for the next real instruction
                if instruction.mnemonic == '' and instruction.label:
                    pending_label = instruction.label
                else:
                    # If we have a pending label, attach it to this instruction
                    if pending_label:
                        instruction.label = pending_label
                        pending_label = None
                    instructions.append(instruction)

        return instructions, total_lines
    
    def parse_instruction(self, line: str) -> Optional[Instruction]:
        """
        Parse a single line of assembly code.
        
        Handles:
        - Labels (ending with ':')
        - Memory addresses at the start
        - Mnemonics and operands
        - Comments (starting with ';' or '#')
        - Ghidra-style annotations
        - Size specifiers (byte ptr, qword ptr, etc.)
        
        Args:
            line: Single line of assembly code
            
        Returns:
            Instruction object or None if line is empty/comment-only
        """
        if not line or not line.strip():
            return None
        
        original_line = line
        line = line.strip()
        
        # Skip pure comment lines
        if line.startswith(';') or line.startswith('#'):
            return None
        
        # Skip lines that are just hex bytes (continuation lines in Ghidra format)
        # These are lines that start with whitespace followed by only hex digits and spaces
        if re.match(r'^\s+[0-9a-fA-F\s]+$', line):
            return None
        
        address = None
        label = None
        comment = None
        mnemonic = None
        operands = []
        size_specifier = None
        
        # Extract comment (everything after ';' or '#')
        comment_match = re.search(r'[;#](.*)$', line)
        if comment_match:
            comment = comment_match.group(1).strip()
            line = line[:comment_match.start()].strip()
        
        # Extract label (ends with ':')
        # Handles standard labels "main:" and objdump style "<main>:"
        label_match = re.match(r'^<?([a-zA-Z_][a-zA-Z0-9_]*)>?:(.*)$', line)
        if label_match:
            label = label_match.group(1)
            line = label_match.group(2).strip()
            
            # If line is now empty (label-only line), return instruction with just label
            if not line:
                return Instruction(
                    address=address,
                    mnemonic='',
                    operands=[],
                    comment=comment,
                    label=label,
                    size_specifier=size_specifier
                )
        
        # Extract address (hex number at the start, often followed by whitespace)
        # Matches patterns like: "140001313", "0x140001313", "00401000", "140001313:"
        # Also handles Ghidra format: "140001313 55 48 89 e5  push rbp"
        # Require at least 6 hex digits to avoid matching mnemonics like "add"
        address_match = re.match(r'^(0x)?([0-9a-fA-F]{6,})[:]?\s+([0-9a-fA-F\s]+)\s+(.*)$', line)
        if address_match:
            # Ghidra format with hex bytes
            address = address_match.group(2)
            line = address_match.group(4).strip()
        else:
            # Try simpler format without hex bytes
            address_match = re.match(r'^(0x)?([0-9a-fA-F]{6,})[:]?\s+(.*)$', line)
            if address_match:
                address = address_match.group(2)
                line = address_match.group(3).strip()
        
        # Check if the remaining line is a label (e.g. "<free>:" or "main:")
        # Must have <...> OR end with : to avoid matching mnemonics like "int3"
        label_match = re.match(r'^(?:<([a-zA-Z_][a-zA-Z0-9_]*)>:?|([a-zA-Z_][a-zA-Z0-9_]*):)$', line)
        if label_match:
            # Group 1 is for <label>, Group 2 is for label:
            label = label_match.group(1) or label_match.group(2)
            return Instruction(
                address=address,
                mnemonic='',
                operands=[],
                comment=comment,
                label=label,
                size_specifier=size_specifier
            )
        
        # Now parse mnemonic and operands
        if not line:
            return None
        
        # Split by whitespace to separate mnemonic from operands
        parts = line.split(None, 1)
        if not parts:
            return None
        
        mnemonic = parts[0].lower()
        
        # Parse operands if present
        if len(parts) > 1:
            operands_str = parts[1].strip()
            operands, size_specifier = self._parse_operands(operands_str)
        
        return Instruction(
            address=address,
            mnemonic=mnemonic,
            operands=operands,
            comment=comment,
            label=label,
            size_specifier=size_specifier
        )
    
    def _parse_operands(self, operands_str: str) -> tuple[List[str], Optional[str]]:
        """
        Parse operands string into individual operands.
        
        Handles:
        - Comma-separated operands
        - Size specifiers (byte ptr, qword ptr, etc.)
        - Memory references with brackets
        - Register names
        - Immediate values
        - Malformed operands (gracefully)
        
        Args:
            operands_str: String containing all operands
            
        Returns:
            Tuple of (list of operand strings, size specifier if found)
        """
        size_specifier = None
        
        # Split operands by comma first, but be careful with brackets
        operands = []
        current_operand = ""
        bracket_depth = 0
        
        for char in operands_str:
            if char == '[':
                bracket_depth += 1
                current_operand += char
            elif char == ']':
                bracket_depth -= 1
                current_operand += char
            elif char == ',' and bracket_depth == 0:
                # Found a separator outside of brackets
                if current_operand.strip():
                    operands.append(current_operand.strip())
                current_operand = ""
            else:
                current_operand += char
        
        # Add the last operand
        if current_operand.strip():
            operands.append(current_operand.strip())
        
        # Handle malformed operands with mismatched brackets
        # If bracket depth is not zero, we have mismatched brackets
        # In this case, still return the operands but they may be malformed
        # The translator will handle them gracefully
        
        # Now check each operand for size specifiers and extract them
        cleaned_operands = []
        for operand in operands:
            operand_cleaned = operand
            for spec in self.size_specifiers:
                if operand.lower().startswith(spec):
                    if size_specifier is None:  # Only capture first size specifier
                        size_specifier = spec
                    operand_cleaned = operand[len(spec):].strip()
                    break
            cleaned_operands.append(operand_cleaned)
        
        return cleaned_operands, size_specifier
