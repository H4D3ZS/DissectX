"""Output formatter for assembly translations"""
from typing import List, Set
from src.models import Instruction, CodeBlock


class OutputFormatter:
    """Formats assembly translations into readable output"""
    
    def __init__(self):
        """Initialize the output formatter"""
        pass
    
    def format(self, instructions: List[Instruction], blocks: List[CodeBlock], 
               translations: List[str], security_highlights: List[str] = None) -> str:
        """
        Format the complete output with instructions, translations, and block summaries.
        
        Combines instruction-level translations with block-level summaries,
        maintaining instruction order and grouping related instructions.
        
        Args:
            instructions: List of Instruction objects in original order
            blocks: List of CodeBlock objects representing patterns
            translations: List of translation strings (one per instruction)
            security_highlights: Optional list of security observations
            
        Returns:
            Formatted output string
        """
        if not instructions:
            return ""
        
        output_lines = []
        
        # Add security highlights at the top if present
        if security_highlights:
            output_lines.append("=== SECURITY OBSERVATIONS ===")
            for highlight in security_highlights:
                output_lines.append(f"⚠ {highlight}")
            output_lines.append("")
        
        # Create a mapping of instruction addresses to block information
        instruction_to_block = self._map_instructions_to_blocks(instructions, blocks)
        
        # Track which blocks we've already printed summaries for
        printed_blocks = set()
        
        # Process each instruction in order
        for i, instruction in enumerate(instructions):
            # Check if this instruction starts a new block
            block = instruction_to_block.get(i)
            
            if block and id(block) not in printed_blocks:
                # Print block summary before the first instruction in the block
                block_summary = self.format_block_summary(block)
                output_lines.append(block_summary)
                printed_blocks.add(id(block))
            
            # Format and print the instruction with its translation
            if i < len(translations):
                formatted_instr = self.format_instruction(instruction, translations[i], 
                                                         is_in_block=(block is not None))
                output_lines.append(formatted_instr)
            else:
                # Fallback if translation is missing
                formatted_instr = self.format_instruction(instruction, "", 
                                                         is_in_block=(block is not None))
                output_lines.append(formatted_instr)
        
        return "\n".join(output_lines)
    
    def format_instruction(self, instruction: Instruction, translation: str, 
                          is_in_block: bool = False) -> str:
        """
        Format a single instruction with its translation.
        
        Args:
            instruction: Instruction object to format
            translation: English translation of the instruction
            is_in_block: Whether this instruction is part of a logical block (for indentation)
            
        Returns:
            Formatted string for the instruction
        """
        parts = []
        
        # Add indentation if part of a block
        indent = "  " if is_in_block else ""
        
        # Build the instruction line
        instr_parts = []
        
        # Add address if present
        if instruction.address:
            instr_parts.append(instruction.address)
        
        # Add label if present
        if instruction.label:
            instr_parts.append(f"{instruction.label}:")
        
        # Add mnemonic and operands
        if instruction.mnemonic:
            mnemonic_str = instruction.mnemonic
            if instruction.operands:
                operands_str = ", ".join(instruction.operands)
                instr_parts.append(f"{mnemonic_str} {operands_str}")
            else:
                instr_parts.append(mnemonic_str)
        
        # Combine instruction parts
        instr_line = " ".join(instr_parts)
        
        # Add comment if present
        if instruction.comment:
            instr_line += f"  ; {instruction.comment}"
        
        # Format: instruction line followed by translation
        parts.append(f"{indent}{instr_line}")
        if translation:
            parts.append(f"{indent}  → {translation}")
        
        return "\n".join(parts)
    
    def format_block_summary(self, block: CodeBlock) -> str:
        """
        Create a block-level summary for a group of related instructions.
        
        Args:
            block: CodeBlock object to summarize
            
        Returns:
            Formatted block summary string
        """
        # Create a header based on block type
        block_type_headers = {
            'loop': '┌─ LOOP',
            'conditional': '┌─ CONDITIONAL',
            'function_prologue': '┌─ FUNCTION PROLOGUE',
            'function_epilogue': '┌─ FUNCTION EPILOGUE',
            'string_operation': '┌─ STRING OPERATION',
        }
        
        header = block_type_headers.get(block.block_type, f'┌─ {block.block_type.upper()}')
        
        # Add security flag if relevant
        if block.security_relevant:
            header += " ⚠ SECURITY"
        
        # Add description
        lines = [header]
        if block.description:
            lines.append(f"│ {block.description}")
        
        lines.append("└─")
        
        return "\n".join(lines)
    
    def _map_instructions_to_blocks(self, instructions: List[Instruction], 
                                   blocks: List[CodeBlock]) -> dict:
        """
        Create a mapping from instruction index to the block it belongs to.
        
        Only maps the first instruction of each block to avoid duplicate summaries.
        
        Args:
            instructions: List of all instructions
            blocks: List of code blocks
            
        Returns:
            Dictionary mapping instruction index to CodeBlock (only for first instruction in block)
        """
        mapping = {}
        
        for block in blocks:
            if not block.instructions:
                continue
            
            # Find the index of the first instruction in this block
            first_block_instr = block.instructions[0]
            
            for i, instr in enumerate(instructions):
                # Match by address or by object identity
                if first_block_instr.address and instr.address:
                    if first_block_instr.address == instr.address:
                        mapping[i] = block
                        break
                elif first_block_instr is instr:
                    mapping[i] = block
                    break
        
        return mapping
