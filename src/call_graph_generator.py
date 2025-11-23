"""Call Graph Generation for analyzing function call relationships"""
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
import networkx as nx
from src.models import Instruction


@dataclass
class CallGraph:
    """
    Represents a call graph showing function call relationships.
    
    Attributes:
        graph: NetworkX directed graph where nodes are function addresses
               and edges represent calls
        entry_points: Set of function addresses that are entry points
        dead_code: Set of function addresses that are unreachable
        recursive_functions: Set of function addresses that are recursive
    """
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    entry_points: Set[int] = field(default_factory=set)
    dead_code: Set[int] = field(default_factory=set)
    recursive_functions: Set[int] = field(default_factory=set)
    
    def get_all_functions(self) -> Set[int]:
        """Get all function addresses in the call graph"""
        return set(self.graph.nodes())
    
    def get_callers(self, function_addr: int) -> List[int]:
        """Get all functions that call the specified function"""
        if function_addr not in self.graph:
            return []
        return list(self.graph.predecessors(function_addr))
    
    def get_callees(self, function_addr: int) -> List[int]:
        """Get all functions called by the specified function"""
        if function_addr not in self.graph:
            return []
        return list(self.graph.successors(function_addr))


class CallGraphGenerator:
    """
    Generates call graphs from assembly instructions.
    
    Analyzes function call relationships, detects recursion, identifies
    entry points and dead code, and provides multiple export formats.
    """
    
    def __init__(self):
        """Initialize the call graph generator"""
        self.call_graph = CallGraph()
        self._function_boundaries = {}  # address -> function_start_address
        self._current_function = None
    
    def build_graph(self, instructions: List[Instruction]) -> CallGraph:
        """
        Build a call graph from a list of instructions.
        
        Parses assembly for call instructions and builds a directed graph
        structure using networkx.
        
        Args:
            instructions: List of Instruction objects to analyze
            
        Returns:
            CallGraph object containing the complete call graph
        """
        if not instructions:
            return self.call_graph
        
        # First pass: identify function boundaries
        self._identify_function_boundaries(instructions)
        
        # Second pass: build the call graph
        for instr in instructions:
            # Update current function context
            if instr.address:
                addr = self._parse_address(instr.address)
                if addr in self._function_boundaries:
                    self._current_function = addr
                    # Add function as a node in the graph
                    if not self.call_graph.graph.has_node(addr):
                        self.call_graph.graph.add_node(addr)
            
            # Analyze call instructions
            if instr.mnemonic.lower() == 'call' and self._current_function is not None:
                self._process_call_instruction(instr)
        
        # Third pass: detect recursion
        self._detect_recursion()
        
        # Fourth pass: identify entry points and dead code
        self._identify_entry_points_and_dead_code()
        
        return self.call_graph
    
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
    
    def _process_call_instruction(self, instr: Instruction):
        """
        Process a call instruction and add edge to call graph.
        
        Args:
            instr: Call instruction to process
        """
        if not instr.operands or self._current_function is None:
            return
        
        # Parse the call target
        target = self._parse_operand_address(instr.operands[0])
        
        if target is not None:
            # Add target as a node if not already present
            if not self.call_graph.graph.has_node(target):
                self.call_graph.graph.add_node(target)
            
            # Add edge from current function to target
            self.call_graph.graph.add_edge(self._current_function, target)
    
    def detect_recursion(self) -> Set[int]:
        """
        Detect direct and indirect recursion in the call graph.
        
        Direct recursion: A function calls itself
        Indirect recursion: A function calls another function that eventually
                           calls back to the original function (cycle in graph)
        
        Returns:
            Set of function addresses that are recursive
        """
        self._detect_recursion()
        return self.call_graph.recursive_functions
    
    def _detect_recursion(self):
        """
        Internal method to detect and mark recursive functions.
        
        Uses cycle detection in the directed graph to find all functions
        that participate in recursive call chains.
        """
        # Find all cycles in the graph
        try:
            cycles = list(nx.simple_cycles(self.call_graph.graph))
        except:
            # If graph is too large or complex, fall back to simple check
            cycles = []
        
        # Mark all functions in cycles as recursive
        for cycle in cycles:
            for func_addr in cycle:
                self.call_graph.recursive_functions.add(func_addr)
        
        # Also check for direct recursion (self-loops)
        for node in self.call_graph.graph.nodes():
            if self.call_graph.graph.has_edge(node, node):
                self.call_graph.recursive_functions.add(node)
    
    def find_entry_points(self) -> Set[int]:
        """
        Identify main entry functions.
        
        Entry points are functions that are not called by any other function
        in the analyzed code (have no incoming edges).
        
        Returns:
            Set of entry point function addresses
        """
        self._identify_entry_points_and_dead_code()
        return self.call_graph.entry_points
    
    def find_dead_code(self) -> Set[int]:
        """
        Find unreachable code (dead code).
        
        Dead code consists of functions that cannot be reached from any
        entry point.
        
        Returns:
            Set of dead code function addresses
        """
        self._identify_entry_points_and_dead_code()
        return self.call_graph.dead_code
    
    def _identify_entry_points_and_dead_code(self):
        """
        Internal method to identify entry points and dead code.
        
        Entry points: Functions with no incoming edges (not called by anyone)
        Dead code: Functions not reachable from any entry point
        
        Strategy:
        1. Find all functions with no callers (potential entry points)
        2. Identify the "main" entry point (typically the first or labeled as main)
        3. Mark functions reachable from main as live code
        4. Functions with no callers that aren't reachable from main are dead code
        """
        # Clear previous results
        self.call_graph.entry_points.clear()
        self.call_graph.dead_code.clear()
        
        # Find all nodes with in-degree 0 (not called by anyone)
        potential_entries = set()
        for node in self.call_graph.graph.nodes():
            if self.call_graph.graph.in_degree(node) == 0:
                potential_entries.add(node)
        
        # If no potential entries found, all functions might be part of cycles
        # or we're analyzing a code fragment. Mark all as potential entry points.
        if not potential_entries:
            self.call_graph.entry_points = set(self.call_graph.graph.nodes())
            return
        
        # Identify the main entry point (lowest address, or first in list)
        # This is typically the actual program entry point
        main_entry = min(potential_entries)
        self.call_graph.entry_points.add(main_entry)
        
        # Find all nodes reachable from the main entry point
        reachable = set()
        try:
            descendants = nx.descendants(self.call_graph.graph, main_entry)
            reachable.add(main_entry)
            reachable.update(descendants)
        except:
            # If there's an issue, mark the entry point as reachable
            reachable.add(main_entry)
        
        # Other potential entries that aren't reachable from main are dead code
        # (they have no callers and can't be reached from the main entry)
        for node in potential_entries:
            if node not in reachable:
                self.call_graph.dead_code.add(node)
        
        # Also check for any other nodes not reachable from main
        all_nodes = set(self.call_graph.graph.nodes())
        unreachable = all_nodes - reachable
        self.call_graph.dead_code.update(unreachable)
    
    def export_dot(self) -> str:
        """
        Export call graph in Graphviz DOT format.
        
        Returns:
            DOT format string representation of the call graph
        """
        lines = []
        lines.append("digraph CallGraph {")
        lines.append("    rankdir=TB;")
        lines.append("    node [shape=box];")
        lines.append("")
        
        # Add nodes with styling based on properties
        for node in self.call_graph.graph.nodes():
            label = f"0x{node:x}"
            style_attrs = []
            
            if node in self.call_graph.entry_points:
                style_attrs.append('fillcolor=lightgreen')
                style_attrs.append('style=filled')
                label += "\\n(entry)"
            
            if node in self.call_graph.recursive_functions:
                style_attrs.append('fillcolor=yellow')
                style_attrs.append('style=filled')
                label += "\\n(recursive)"
            
            if node in self.call_graph.dead_code:
                style_attrs.append('fillcolor=lightgray')
                style_attrs.append('style=filled')
                label += "\\n(dead)"
            
            style_str = ', '.join(style_attrs) if style_attrs else ''
            if style_str:
                lines.append(f'    "0x{node:x}" [label="{label}", {style_str}];')
            else:
                lines.append(f'    "0x{node:x}" [label="{label}"];')
        
        lines.append("")
        
        # Add edges
        for source, target in self.call_graph.graph.edges():
            # Check if this is a recursive edge
            if source == target or (source in self.call_graph.recursive_functions and 
                                   target in self.call_graph.recursive_functions):
                lines.append(f'    "0x{source:x}" -> "0x{target:x}" [color=red];')
            else:
                lines.append(f'    "0x{source:x}" -> "0x{target:x}";')
        
        lines.append("}")
        
        return '\n'.join(lines)
    
    def export_mermaid(self) -> str:
        """
        Export call graph in Mermaid format.
        
        Returns:
            Mermaid format string representation of the call graph
        """
        lines = []
        lines.append("graph TD")
        
        # Add nodes with styling
        for node in self.call_graph.graph.nodes():
            node_id = f"F{node:x}"
            label = f"0x{node:x}"
            
            # Add annotations
            annotations = []
            if node in self.call_graph.entry_points:
                annotations.append("entry")
            if node in self.call_graph.recursive_functions:
                annotations.append("recursive")
            if node in self.call_graph.dead_code:
                annotations.append("dead")
            
            if annotations:
                label += f"<br/>({', '.join(annotations)})"
            
            # Apply styling based on properties
            if node in self.call_graph.entry_points:
                lines.append(f'    {node_id}["{label}"]')
                lines.append(f'    style {node_id} fill:#90EE90')
            elif node in self.call_graph.dead_code:
                lines.append(f'    {node_id}["{label}"]')
                lines.append(f'    style {node_id} fill:#D3D3D3')
            elif node in self.call_graph.recursive_functions:
                lines.append(f'    {node_id}["{label}"]')
                lines.append(f'    style {node_id} fill:#FFFF00')
            else:
                lines.append(f'    {node_id}["{label}"]')
        
        lines.append("")
        
        # Add edges
        for source, target in self.call_graph.graph.edges():
            source_id = f"F{source:x}"
            target_id = f"F{target:x}"
            
            # Use different arrow style for recursive calls
            if source == target or (source in self.call_graph.recursive_functions and 
                                   target in self.call_graph.recursive_functions):
                lines.append(f'    {source_id} -.->|recursive| {target_id}')
            else:
                lines.append(f'    {source_id} --> {target_id}')
        
        return '\n'.join(lines)
    
    def export_ascii(self) -> str:
        """
        Export call graph as ASCII tree.
        
        Returns:
            ASCII tree representation of the call graph
        """
        lines = []
        lines.append("=" * 80)
        lines.append("CALL GRAPH (ASCII Tree)")
        lines.append("=" * 80)
        lines.append("")
        
        # If no functions, return empty
        if not self.call_graph.graph.nodes():
            lines.append("No functions found in call graph.")
            return '\n'.join(lines)
        
        # Start from entry points
        if self.call_graph.entry_points:
            for entry_point in sorted(self.call_graph.entry_points):
                self._export_ascii_subtree(entry_point, lines, set(), "", True)
                lines.append("")
        else:
            # No clear entry points, show all nodes
            lines.append("No clear entry points found. Showing all functions:")
            lines.append("")
            for node in sorted(self.call_graph.graph.nodes()):
                self._export_ascii_node(node, lines, "")
        
        # Show dead code separately if any
        if self.call_graph.dead_code:
            lines.append("")
            lines.append("DEAD CODE (Unreachable):")
            lines.append("-" * 80)
            for dead_func in sorted(self.call_graph.dead_code):
                lines.append(f"  0x{dead_func:x}")
        
        lines.append("")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def _export_ascii_subtree(self, node: int, lines: List[str], visited: Set[int], 
                             prefix: str, is_last: bool):
        """
        Recursively export a subtree in ASCII format.
        
        Args:
            node: Current node to export
            lines: List to append output lines to
            visited: Set of already visited nodes (to avoid infinite recursion)
            prefix: Current line prefix for indentation
            is_last: Whether this is the last child of its parent
        """
        # Avoid infinite recursion
        if node in visited:
            self._export_ascii_node(node, lines, prefix, is_last, is_cycle=True)
            return
        
        visited.add(node)
        
        # Export current node
        self._export_ascii_node(node, lines, prefix, is_last)
        
        # Get children (callees)
        callees = sorted(self.call_graph.get_callees(node))
        
        if callees:
            # Prepare prefix for children
            if is_last:
                new_prefix = prefix + "    "
            else:
                new_prefix = prefix + "│   "
            
            # Export each child
            for i, callee in enumerate(callees):
                is_last_child = (i == len(callees) - 1)
                self._export_ascii_subtree(callee, lines, visited.copy(), new_prefix, is_last_child)
    
    def _export_ascii_node(self, node: int, lines: List[str], prefix: str = "", 
                          is_last: bool = True, is_cycle: bool = False):
        """
        Export a single node in ASCII format.
        
        Args:
            node: Node address to export
            lines: List to append output line to
            prefix: Line prefix for indentation
            is_last: Whether this is the last child
            is_cycle: Whether this node creates a cycle (already visited)
        """
        # Choose the connector
        if prefix:
            connector = "└── " if is_last else "├── "
        else:
            connector = ""
        
        # Build node label
        label = f"0x{node:x}"
        
        # Add annotations
        annotations = []
        if node in self.call_graph.entry_points:
            annotations.append("ENTRY")
        if node in self.call_graph.recursive_functions:
            annotations.append("RECURSIVE")
        if node in self.call_graph.dead_code:
            annotations.append("DEAD")
        if is_cycle:
            annotations.append("CYCLE")
        
        if annotations:
            label += f" [{', '.join(annotations)}]"
        
        lines.append(f"{prefix}{connector}{label}")
    
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
            address_str = address_str.strip()
            
            if address_str.startswith('0x') or address_str.startswith('0X'):
                return int(address_str, 16)
            else:
                try:
                    return int(address_str, 16)
                except ValueError:
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
    
    def generate_report(self) -> str:
        """
        Generate a comprehensive call graph report.
        
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("CALL GRAPH ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Statistics
        total_functions = len(self.call_graph.graph.nodes())
        total_calls = len(self.call_graph.graph.edges())
        num_entry_points = len(self.call_graph.entry_points)
        num_recursive = len(self.call_graph.recursive_functions)
        num_dead_code = len(self.call_graph.dead_code)
        
        lines.append("STATISTICS:")
        lines.append(f"  Total functions: {total_functions}")
        lines.append(f"  Total call edges: {total_calls}")
        lines.append(f"  Entry points: {num_entry_points}")
        lines.append(f"  Recursive functions: {num_recursive}")
        lines.append(f"  Dead code functions: {num_dead_code}")
        lines.append("")
        
        # Entry points
        if self.call_graph.entry_points:
            lines.append("ENTRY POINTS:")
            for entry in sorted(self.call_graph.entry_points):
                callees = self.call_graph.get_callees(entry)
                lines.append(f"  0x{entry:x} (calls {len(callees)} function(s))")
            lines.append("")
        
        # Recursive functions
        if self.call_graph.recursive_functions:
            lines.append("RECURSIVE FUNCTIONS:")
            for func in sorted(self.call_graph.recursive_functions):
                lines.append(f"  0x{func:x}")
            lines.append("")
        
        # Dead code
        if self.call_graph.dead_code:
            lines.append("DEAD CODE (Unreachable):")
            for dead in sorted(self.call_graph.dead_code):
                lines.append(f"  0x{dead:x}")
            lines.append("")
        
        # Most called functions
        if self.call_graph.graph.nodes():
            lines.append("TOP 10 MOST CALLED FUNCTIONS:")
            in_degrees = [(node, self.call_graph.graph.in_degree(node)) 
                         for node in self.call_graph.graph.nodes()]
            in_degrees.sort(key=lambda x: x[1], reverse=True)
            
            for node, degree in in_degrees[:10]:
                if degree > 0:
                    lines.append(f"  0x{node:x} - called by {degree} function(s)")
            lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
