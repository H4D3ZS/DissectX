"""
ROP Gadget Analyzer

This module provides ROP (Return-Oriented Programming) gadget discovery and analysis
capabilities for exploit development and binary analysis.

Requirements covered:
- 20.1: Find all useful ROP gadgets automatically
- 20.2: Assign quality scores based on usefulness
- 20.3: Provide chain generation assistance
- 20.4: Support pwntools format for exploit development
- 20.5: Allow filtering by operation type and register usage
"""

import os
import tempfile
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from enum import Enum
import re


class GadgetType(Enum):
    """Types of ROP gadgets based on their operations"""
    LOAD = "load"  # Load from memory (mov reg, [mem])
    STORE = "store"  # Store to memory (mov [mem], reg)
    ARITHMETIC = "arithmetic"  # add, sub, mul, div, etc.
    LOGIC = "logic"  # and, or, xor, not, etc.
    CONTROL = "control"  # jmp, call, ret
    STACK = "stack"  # push, pop
    SYSCALL = "syscall"  # syscall, int 0x80
    NOP = "nop"  # nop or equivalent
    UNKNOWN = "unknown"


@dataclass
class ROPGadget:
    """Represents a single ROP gadget"""
    address: int
    instructions: str  # Human-readable instruction sequence
    bytes: bytes  # Raw bytes of the gadget
    quality_score: float  # 0.0 to 1.0, higher is better
    gadget_type: GadgetType
    registers_read: Set[str]  # Registers read by this gadget
    registers_written: Set[str]  # Registers written by this gadget
    
    def __str__(self):
        return f"0x{self.address:08x}: {self.instructions} (score: {self.quality_score:.2f})"


@dataclass
class ChainSuggestion:
    """Represents a suggestion for building ROP chains"""
    goal: str  # What this chain achieves (e.g., "write to memory", "syscall")
    gadgets: List[ROPGadget]
    description: str


class ROPAnalyzer:
    """
    Analyzes binaries to find ROP gadgets and assist with chain generation.
    
    This class wraps the ROPgadget library and provides additional functionality
    for quality scoring, filtering, and chain generation assistance.
    """
    
    def __init__(self, binary_path: str, architecture: str = "x86"):
        """
        Initialize the ROP analyzer.
        
        Args:
            binary_path: Path to the binary file to analyze
            architecture: Target architecture (x86, x64, arm, mips)
        """
        self.binary_path = binary_path
        self.architecture = architecture.lower()
        self.gadgets: List[ROPGadget] = []
        self._raw_gadgets: List[Dict] = []
        
    def find_gadgets(self, depth: int = 10) -> List[ROPGadget]:
        """
        Find all ROP gadgets in the binary.
        
        Args:
            depth: Maximum instruction depth for gadgets
            
        Returns:
            List of discovered ROP gadgets
            
        Requirement 20.1: Find all useful ROP gadgets automatically
        """
        try:
            import subprocess
            import json
        except ImportError:
            raise ImportError("subprocess and json modules required")
        
        # Run ROPgadget as subprocess to get gadgets
        try:
            # Run ROPgadget with --dump option to get raw output
            cmd = [
                'ROPgadget',
                '--binary', self.binary_path,
                '--depth', str(depth),
                '--nojop'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                # ROPgadget might fail on some binaries, that's okay
                # We'll just return empty list
                self.gadgets = []
                return self.gadgets
            
            # Parse output
            self._raw_gadgets = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                # Look for lines like: 0x00000000 : pop rax ; ret
                if ':' in line and line[0:2] == '0x':
                    try:
                        parts = line.split(':', 1)
                        addr_str = parts[0].strip()
                        instr_str = parts[1].strip()
                        
                        # Parse address
                        address = int(addr_str, 16)
                        
                        self._raw_gadgets.append({
                            'vaddr': address,
                            'gadget': instr_str,
                            'bytes': b''  # We don't have bytes from text output
                        })
                    except (ValueError, IndexError):
                        continue
            
        except FileNotFoundError:
            raise ImportError(
                "ROPgadget command not found. Install with: pip install ROPGadget"
            )
        except subprocess.TimeoutExpired:
            # Timeout, return what we have
            pass
        
        # Convert to our ROPGadget format with quality scoring
        self.gadgets = []
        for raw_gadget in self._raw_gadgets:
            gadget = self._parse_gadget(raw_gadget)
            if gadget:
                self.gadgets.append(gadget)
        
        return self.gadgets
    
    def _parse_gadget(self, raw_gadget: Dict) -> Optional[ROPGadget]:
        """
        Parse a raw gadget from ROPgadget into our format.
        
        Args:
            raw_gadget: Raw gadget dictionary from ROPgadget
            
        Returns:
            Parsed ROPGadget or None if invalid
        """
        address = raw_gadget['vaddr']
        instructions = raw_gadget['gadget']
        gadget_bytes = raw_gadget.get('bytes', b'')
        
        # Classify gadget type
        gadget_type = self._classify_gadget(instructions)
        
        # Extract register usage
        registers_read, registers_written = self._extract_register_usage(instructions)
        
        # Calculate quality score
        quality_score = self._calculate_quality_score(
            instructions, gadget_type, registers_read, registers_written
        )
        
        return ROPGadget(
            address=address,
            instructions=instructions,
            bytes=gadget_bytes,
            quality_score=quality_score,
            gadget_type=gadget_type,
            registers_read=registers_read,
            registers_written=registers_written
        )
    
    def _classify_gadget(self, instructions: str) -> GadgetType:
        """
        Classify a gadget based on its instructions.
        
        Args:
            instructions: Instruction sequence as string
            
        Returns:
            GadgetType classification
        """
        instr_lower = instructions.lower()
        
        # Check for syscall
        if 'syscall' in instr_lower or 'int 0x80' in instr_lower:
            return GadgetType.SYSCALL
        
        # Check for control flow
        if any(x in instr_lower for x in ['jmp', 'call', 'ret']):
            return GadgetType.CONTROL
        
        # Check for stack operations
        if any(x in instr_lower for x in ['push', 'pop']):
            return GadgetType.STACK
        
        # Check for memory load
        if 'mov' in instr_lower and '[' in instr_lower:
            # Check if destination is register (load) or memory (store)
            if re.search(r'mov\s+\w+\s*,\s*\[', instr_lower):
                return GadgetType.LOAD
            elif re.search(r'mov\s+\[.*\]\s*,\s*\w+', instr_lower):
                return GadgetType.STORE
        
        # Check for arithmetic
        if any(x in instr_lower for x in ['add', 'sub', 'mul', 'div', 'inc', 'dec']):
            return GadgetType.ARITHMETIC
        
        # Check for logic
        if any(x in instr_lower for x in ['and', 'or', 'xor', 'not', 'shl', 'shr']):
            return GadgetType.LOGIC
        
        # Check for NOP
        if 'nop' in instr_lower:
            return GadgetType.NOP
        
        return GadgetType.UNKNOWN
    
    def _extract_register_usage(self, instructions: str) -> tuple[Set[str], Set[str]]:
        """
        Extract which registers are read and written by a gadget.
        
        Args:
            instructions: Instruction sequence as string
            
        Returns:
            Tuple of (registers_read, registers_written)
        """
        # Common x86/x64 registers
        x86_regs = {
            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'
        }
        
        registers_read = set()
        registers_written = set()
        
        # Split into individual instructions
        instr_list = [i.strip() for i in instructions.split(';')]
        
        for instr in instr_list:
            instr_lower = instr.lower()
            
            # Skip empty or control flow instructions
            if not instr_lower or instr_lower in ['ret', 'leave']:
                continue
            
            # Extract operands
            parts = instr_lower.split()
            if len(parts) < 2:
                continue
            
            opcode = parts[0]
            operands = ' '.join(parts[1:])
            
            # Find all registers in operands
            found_regs = [r for r in x86_regs if r in operands]
            
            # Determine read/write based on instruction type
            if opcode in ['mov', 'lea']:
                # mov dst, src - dst is written, src is read
                ops = operands.split(',')
                if len(ops) == 2:
                    dst, src = ops[0].strip(), ops[1].strip()
                    # Destination register is written
                    for reg in x86_regs:
                        if reg in dst and '[' not in dst:
                            registers_written.add(reg)
                    # Source register is read
                    for reg in x86_regs:
                        if reg in src:
                            registers_read.add(reg)
            
            elif opcode in ['push']:
                # push src - src is read
                for reg in found_regs:
                    registers_read.add(reg)
            
            elif opcode in ['pop']:
                # pop dst - dst is written
                for reg in found_regs:
                    registers_written.add(reg)
            
            elif opcode in ['add', 'sub', 'xor', 'or', 'and']:
                # op dst, src - dst is read and written, src is read
                ops = operands.split(',')
                if len(ops) == 2:
                    dst, src = ops[0].strip(), ops[1].strip()
                    for reg in x86_regs:
                        if reg in dst:
                            registers_read.add(reg)
                            registers_written.add(reg)
                        if reg in src:
                            registers_read.add(reg)
        
        return registers_read, registers_written
    
    def _calculate_quality_score(
        self,
        instructions: str,
        gadget_type: GadgetType,
        registers_read: Set[str],
        registers_written: Set[str]
    ) -> float:
        """
        Calculate a quality score for a gadget based on its usefulness.
        
        Args:
            instructions: Instruction sequence
            gadget_type: Type of gadget
            registers_read: Registers read by gadget
            registers_written: Registers written by gadget
            
        Returns:
            Quality score from 0.0 to 1.0
            
        Requirement 20.2: Assign quality scores based on usefulness
        """
        score = 0.5  # Base score
        
        # Count instructions
        instr_count = len([i for i in instructions.split(';') if i.strip()])
        
        # Prefer shorter gadgets (fewer side effects)
        if instr_count <= 2:
            score += 0.2
        elif instr_count <= 4:
            score += 0.1
        else:
            score -= 0.1
        
        # Bonus for useful gadget types
        type_bonuses = {
            GadgetType.SYSCALL: 0.3,
            GadgetType.LOAD: 0.2,
            GadgetType.STORE: 0.2,
            GadgetType.ARITHMETIC: 0.15,
            GadgetType.STACK: 0.15,
            GadgetType.LOGIC: 0.1,
            GadgetType.CONTROL: 0.05,
            GadgetType.NOP: -0.2,
            GadgetType.UNKNOWN: 0.0
        }
        score += type_bonuses.get(gadget_type, 0.0)
        
        # Bonus for writing to useful registers
        useful_regs = {'eax', 'rax', 'rdi', 'rsi', 'rdx', 'rcx'}
        if registers_written & useful_regs:
            score += 0.1
        
        # Penalty for clobbering many registers
        if len(registers_written) > 3:
            score -= 0.1
        
        # Penalty for bad instructions
        bad_patterns = ['leave', 'enter']
        if any(bad in instructions.lower() for bad in bad_patterns):
            score -= 0.15
        
        # Clamp to [0.0, 1.0]
        return max(0.0, min(1.0, score))
    
    def filter_gadgets(
        self,
        gadget_type: Optional[GadgetType] = None,
        min_quality: float = 0.0,
        registers_written: Optional[Set[str]] = None,
        registers_read: Optional[Set[str]] = None,
        max_instructions: Optional[int] = None
    ) -> List[ROPGadget]:
        """
        Filter gadgets based on various criteria.
        
        Args:
            gadget_type: Filter by gadget type
            min_quality: Minimum quality score
            registers_written: Must write to at least one of these registers
            registers_read: Must read from at least one of these registers
            max_instructions: Maximum number of instructions
            
        Returns:
            Filtered list of gadgets
            
        Requirement 20.5: Allow filtering by operation type and register usage
        """
        filtered = self.gadgets
        
        # Filter by type
        if gadget_type is not None:
            filtered = [g for g in filtered if g.gadget_type == gadget_type]
        
        # Filter by quality
        filtered = [g for g in filtered if g.quality_score >= min_quality]
        
        # Filter by registers written
        if registers_written:
            filtered = [
                g for g in filtered
                if g.registers_written & registers_written
            ]
        
        # Filter by registers read
        if registers_read:
            filtered = [
                g for g in filtered
                if g.registers_read & registers_read
            ]
        
        # Filter by instruction count
        if max_instructions is not None:
            filtered = [
                g for g in filtered
                if len([i for i in g.instructions.split(';') if i.strip()]) <= max_instructions
            ]
        
        return filtered
    
    def suggest_chains(self, goal: str) -> List[ChainSuggestion]:
        """
        Suggest gadget chains for common exploit goals.
        
        Args:
            goal: Exploit goal (e.g., "syscall", "write_memory", "stack_pivot")
            
        Returns:
            List of chain suggestions
            
        Requirement 20.3: Provide chain generation assistance
        """
        suggestions = []
        
        goal_lower = goal.lower()
        
        if 'syscall' in goal_lower or 'execve' in goal_lower:
            suggestions.extend(self._suggest_syscall_chain())
        
        if 'write' in goal_lower or 'memory' in goal_lower:
            suggestions.extend(self._suggest_write_memory_chain())
        
        if 'stack' in goal_lower or 'pivot' in goal_lower:
            suggestions.extend(self._suggest_stack_pivot_chain())
        
        if 'read' in goal_lower or 'load' in goal_lower:
            suggestions.extend(self._suggest_read_memory_chain())
        
        return suggestions
    
    def _suggest_syscall_chain(self) -> List[ChainSuggestion]:
        """Suggest chains for making a syscall"""
        suggestions = []
        
        # Find syscall gadgets
        syscall_gadgets = self.filter_gadgets(gadget_type=GadgetType.SYSCALL)
        
        if syscall_gadgets:
            # Find gadgets to set up registers (rax, rdi, rsi, rdx for x64)
            setup_gadgets = []
            
            # Look for pop rax; ret (to set syscall number)
            for g in self.gadgets:
                if 'pop' in g.instructions.lower() and 'rax' in g.registers_written:
                    setup_gadgets.append(g)
                    break
            
            # Look for pop rdi; ret (first argument)
            for g in self.gadgets:
                if 'pop' in g.instructions.lower() and 'rdi' in g.registers_written:
                    setup_gadgets.append(g)
                    break
            
            # Look for pop rsi; ret (second argument)
            for g in self.gadgets:
                if 'pop' in g.instructions.lower() and 'rsi' in g.registers_written:
                    setup_gadgets.append(g)
                    break
            
            if setup_gadgets:
                suggestions.append(ChainSuggestion(
                    goal="syscall",
                    gadgets=setup_gadgets + [syscall_gadgets[0]],
                    description="Set up registers and execute syscall"
                ))
        
        return suggestions
    
    def _suggest_write_memory_chain(self) -> List[ChainSuggestion]:
        """Suggest chains for writing to memory"""
        suggestions = []
        
        # Find store gadgets
        store_gadgets = self.filter_gadgets(gadget_type=GadgetType.STORE, min_quality=0.5)
        
        if store_gadgets:
            suggestions.append(ChainSuggestion(
                goal="write_memory",
                gadgets=store_gadgets[:3],  # Top 3 store gadgets
                description="Write value to memory location"
            ))
        
        return suggestions
    
    def _suggest_stack_pivot_chain(self) -> List[ChainSuggestion]:
        """Suggest chains for stack pivoting"""
        suggestions = []
        
        # Look for gadgets that modify ESP/RSP
        pivot_gadgets = [
            g for g in self.gadgets
            if any(reg in g.registers_written for reg in ['esp', 'rsp'])
            and g.quality_score >= 0.5
        ]
        
        if pivot_gadgets:
            suggestions.append(ChainSuggestion(
                goal="stack_pivot",
                gadgets=pivot_gadgets[:3],
                description="Pivot stack to controlled memory"
            ))
        
        return suggestions
    
    def _suggest_read_memory_chain(self) -> List[ChainSuggestion]:
        """Suggest chains for reading from memory"""
        suggestions = []
        
        # Find load gadgets
        load_gadgets = self.filter_gadgets(gadget_type=GadgetType.LOAD, min_quality=0.5)
        
        if load_gadgets:
            suggestions.append(ChainSuggestion(
                goal="read_memory",
                gadgets=load_gadgets[:3],
                description="Load value from memory into register"
            ))
        
        return suggestions
    
    def export_pwntools(self, output_file: Optional[str] = None) -> str:
        """
        Export gadgets in pwntools format.
        
        Args:
            output_file: Optional file path to write output
            
        Returns:
            Python code string for pwntools
            
        Requirement 20.4: Support pwntools format for exploit development
        """
        lines = []
        lines.append("#!/usr/bin/env python3")
        lines.append("# Generated by DissectX ROPAnalyzer")
        lines.append("from pwn import *")
        lines.append("")
        lines.append(f"# Binary: {os.path.basename(self.binary_path)}")
        lines.append(f"# Architecture: {self.architecture}")
        lines.append(f"# Total gadgets: {len(self.gadgets)}")
        lines.append("")
        lines.append("# ROP Gadgets")
        
        # Sort by quality score
        sorted_gadgets = sorted(self.gadgets, key=lambda g: g.quality_score, reverse=True)
        
        # Export top gadgets by category
        categories = {}
        for gadget in sorted_gadgets:
            cat = gadget.gadget_type.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(gadget)
        
        for category, gadgets in categories.items():
            lines.append(f"\n# {category.upper()} gadgets")
            for gadget in gadgets[:10]:  # Top 10 per category
                # Create a valid Python variable name
                var_name = f"{category}_{gadget.address:x}"
                lines.append(f"{var_name} = {gadget.address:#x}  # {gadget.instructions}")
        
        lines.append("\n# Example ROP chain")
        lines.append("rop = ROP(elf)")
        lines.append("# Add your gadgets here")
        lines.append("# rop.raw(gadget_address)")
        lines.append("")
        
        output = '\n'.join(lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
        
        return output
    
    def get_statistics(self) -> Dict:
        """
        Get statistics about discovered gadgets.
        
        Returns:
            Dictionary with gadget statistics
        """
        stats = {
            'total_gadgets': len(self.gadgets),
            'by_type': {},
            'avg_quality': 0.0,
            'high_quality_count': 0,  # quality >= 0.7
            'avg_instructions': 0.0
        }
        
        if not self.gadgets:
            return stats
        
        # Count by type
        for gadget in self.gadgets:
            gtype = gadget.gadget_type.value
            stats['by_type'][gtype] = stats['by_type'].get(gtype, 0) + 1
        
        # Calculate averages
        stats['avg_quality'] = sum(g.quality_score for g in self.gadgets) / len(self.gadgets)
        stats['high_quality_count'] = sum(1 for g in self.gadgets if g.quality_score >= 0.7)
        
        instr_counts = [
            len([i for i in g.instructions.split(';') if i.strip()])
            for g in self.gadgets
        ]
        stats['avg_instructions'] = sum(instr_counts) / len(instr_counts)
        
        return stats
