"""Control Flow Graph Generation for analyzing program control flow"""
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
import networkx as nx
from src.models import Instruction


@dataclass
class BasicBlock:
    """
    Represents a basic block - a sequence of instructions with single entry and exit.
    
    A basic block is a straight-line code sequence with:
    - Single entry point (only the first instruction can be entered from outside)
    - Single exit point (only the last instruction can transfer control outside)
    
    Attributes:
        start_address: Address of the first instruction in the block
        end_address: Address of the last instruction in the block
        instructions: List of instructions in this basic block
        successors: List of addresses of successor basic blocks
        predecessors: List of addresses of predecessor basic blocks
    """
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    
    def __hash__(self):
        return hash(self.start_address)
    
    def __eq__(self, other):
        if not isinstance(other, BasicBlock):
            return False
        return self.start_address == other.start_address


@dataclass
class Loop:
    """
    Represents a loop structure detected in the control flow.
    
    Attributes:
        header: Address of the loop header (entry point)
        back_edge_source: Address where the back edge originates
        body_blocks: Set of basic block addresses that form the loop body
    """
    header: int
    back_edge_source: int
    body_blocks: Set[int] = field(default_factory=set)


@dataclass
class ControlFlowGraph:
    """
    Represents a control flow graph for a function.
    
    Attributes:
        function_address: Starting address of the function
        basic_blocks: Dictionary mapping start address to BasicBlock
        entry_block: Address of the entry basic block
        exit_blocks: List of addresses of exit basic blocks (blocks ending in ret)
        loops: List of detected loops
        graph: NetworkX directed graph for analysis
    """
    function_address: int
    basic_blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    entry_block: Optional[int] = None
    exit_blocks: List[int] = field(default_factory=list)
    loops: List[Loop] = field(default_factory=list)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)


class CFGGenerator:
    """
    Generates control flow graphs from assembly instructions.
    
    Analyzes basic blocks, branch instructions, and loop structures to build
    a complete control flow graph. Supports multiple export formats.
    """
    
    def __init__(self):
        """Initialize the CFG generator"""
        self._address_to_instruction = {}
        self._leaders = set()  # Addresses that start basic blocks
    
    def identify_basic_blocks(self, instructions: List[Instruction]) -> List[BasicBlock]:
        """
        Identify basic blocks in a sequence of instructions.
        
        A basic block is a maximal sequence of instructions with:
        - Single entry point (only first instruction can be entered)
        - Single exit point (only last instruction can exit)
        
        Algorithm:
        1. Identify leaders (instructions that start basic blocks):
           - First instruction
           - Target of any jump
           - Instruction immediately following a jump or branch
        2. Create basic blocks from leaders to next leader or end
        
        Args:
            instructions: List of Instruction objects to analyze
            
        Returns:
            List of BasicBlock objects
        """
        if not instructions:
            return []
        
        # Build address-to-instruction mapping
        self._address_to_instruction.clear()
        for instr in instructions:
            if instr.address:
                addr = self._parse_address(instr.address)
                if addr is not None:
                    self._address_to_instruction[addr] = instr
        
        # Step 1: Identify leaders
        self._identify_leaders(instructions)
        
        # Step 2: Create basic blocks
        basic_blocks = self._create_basic_blocks(instructions)
        
        return basic_blocks
    
    def _identify_leaders(self, instructions: List[Instruction]):
        """
        Identify leader instructions (those that start basic blocks).
        
        Leaders are:
        1. The first instruction
        2. Any instruction that is the target of a jump
        3. Any instruction immediately following a jump or conditional branch
        
        Args:
            instructions: List of instructions to analyze
        """
        self._leaders.clear()
        
        if not instructions:
            return
        
        # First instruction is always a leader
        first_addr = self._parse_address(instructions[0].address)
        if first_addr is not None:
            self._leaders.add(first_addr)
        
        # Scan for jump targets and instructions after branches
        for i, instr in enumerate(instructions):
            mnemonic = instr.mnemonic.lower()
            
            # Check if this is a branch/jump instruction
            if self._is_branch_instruction(instr):
                # Target of jump is a leader
                if instr.operands:
                    target_addr = self._parse_operand_address(instr.operands[0])
                    if target_addr is not None:
                        self._leaders.add(target_addr)
                
                # Instruction after branch is a leader (fall-through)
                if i + 1 < len(instructions):
                    next_addr = self._parse_address(instructions[i + 1].address)
                    if next_addr is not None:
                        self._leaders.add(next_addr)
            
            # Check if this is a return instruction (ends a block)
            elif mnemonic in ['ret', 'retn']:
                # Instruction after return is a leader (if any)
                if i + 1 < len(instructions):
                    next_addr = self._parse_address(instructions[i + 1].address)
                    if next_addr is not None:
                        self._leaders.add(next_addr)
    
    def _create_basic_blocks(self, instructions: List[Instruction]) -> List[BasicBlock]:
        """
        Create basic blocks from identified leaders.
        
        Args:
            instructions: List of instructions
            
        Returns:
            List of BasicBlock objects
        """
        basic_blocks = []
        current_block_instrs = []
        current_block_start = None
        
        for instr in instructions:
            addr = self._parse_address(instr.address)
            if addr is None:
                continue
            
            # Check if this address is a leader (starts a new block)
            if addr in self._leaders:
                # Save previous block if it exists
                if current_block_instrs and current_block_start is not None:
                    last_addr = self._parse_address(current_block_instrs[-1].address)
                    if last_addr is not None:
                        block = BasicBlock(
                            start_address=current_block_start,
                            end_address=last_addr,
                            instructions=current_block_instrs.copy()
                        )
                        basic_blocks.append(block)
                
                # Start new block
                current_block_start = addr
                current_block_instrs = [instr]
            else:
                # Continue current block
                current_block_instrs.append(instr)
        
        # Don't forget the last block
        if current_block_instrs and current_block_start is not None:
            last_addr = self._parse_address(current_block_instrs[-1].address)
            if last_addr is not None:
                block = BasicBlock(
                    start_address=current_block_start,
                    end_address=last_addr,
                    instructions=current_block_instrs.copy()
                )
                basic_blocks.append(block)
        
        return basic_blocks
    
    def build_cfg(self, basic_blocks: List[BasicBlock]) -> ControlFlowGraph:
        """
        Build a control flow graph from basic blocks.
        
        Analyzes branch instructions to determine successor/predecessor
        relationships between basic blocks.
        
        Args:
            basic_blocks: List of BasicBlock objects
            
        Returns:
            ControlFlowGraph object
        """
        if not basic_blocks:
            return ControlFlowGraph(function_address=0)
        
        # Create CFG
        cfg = ControlFlowGraph(function_address=basic_blocks[0].start_address)
        
        # Add all basic blocks to CFG
        for bb in basic_blocks:
            cfg.basic_blocks[bb.start_address] = bb
            cfg.graph.add_node(bb.start_address)
        
        # Set entry block
        cfg.entry_block = basic_blocks[0].start_address
        
        # Build edges by analyzing branch instructions
        self._analyze_branches(cfg)
        
        # Identify exit blocks (blocks ending in ret)
        self._identify_exit_blocks(cfg)
        
        # Detect loops
        cfg.loops = self.detect_loops(cfg)
        
        return cfg
    
    def _analyze_branches(self, cfg: ControlFlowGraph):
        """
        Analyze branch instructions and build CFG edges.
        
        For each basic block:
        - If it ends with an unconditional jump, add edge to target
        - If it ends with a conditional jump, add edges to target and fall-through
        - If it ends with ret, no outgoing edges
        - Otherwise, add edge to next sequential block
        
        Args:
            cfg: ControlFlowGraph to populate with edges
        """
        # Create address-to-block mapping for quick lookup
        addr_to_block = {}
        for addr, bb in cfg.basic_blocks.items():
            addr_to_block[addr] = bb
            # Also map all instruction addresses in the block
            for instr in bb.instructions:
                instr_addr = self._parse_address(instr.address)
                if instr_addr is not None:
                    addr_to_block[instr_addr] = bb
        
        # Analyze each basic block
        for bb in cfg.basic_blocks.values():
            if not bb.instructions:
                continue
            
            last_instr = bb.instructions[-1]
            mnemonic = last_instr.mnemonic.lower()
            
            # Handle different instruction types
            if mnemonic in ['ret', 'retn']:
                # Return instruction - no successors
                pass
            
            elif mnemonic == 'jmp':
                # Unconditional jump - single successor (the target)
                if last_instr.operands:
                    target_addr = self._parse_operand_address(last_instr.operands[0])
                    if target_addr is not None and target_addr in cfg.basic_blocks:
                        bb.successors.append(target_addr)
                        cfg.basic_blocks[target_addr].predecessors.append(bb.start_address)
                        cfg.graph.add_edge(bb.start_address, target_addr)
            
            elif self._is_conditional_jump(last_instr):
                # Conditional jump - two successors (target and fall-through)
                # 1. Jump target
                if last_instr.operands:
                    target_addr = self._parse_operand_address(last_instr.operands[0])
                    if target_addr is not None and target_addr in cfg.basic_blocks:
                        bb.successors.append(target_addr)
                        cfg.basic_blocks[target_addr].predecessors.append(bb.start_address)
                        cfg.graph.add_edge(bb.start_address, target_addr)
                
                # 2. Fall-through (next sequential block)
                fall_through = self._find_next_block(bb.end_address, cfg.basic_blocks)
                if fall_through is not None:
                    bb.successors.append(fall_through)
                    cfg.basic_blocks[fall_through].predecessors.append(bb.start_address)
                    cfg.graph.add_edge(bb.start_address, fall_through)
            
            else:
                # Regular instruction - fall through to next block
                fall_through = self._find_next_block(bb.end_address, cfg.basic_blocks)
                if fall_through is not None:
                    bb.successors.append(fall_through)
                    cfg.basic_blocks[fall_through].predecessors.append(bb.start_address)
                    cfg.graph.add_edge(bb.start_address, fall_through)
    
    def _identify_exit_blocks(self, cfg: ControlFlowGraph):
        """
        Identify exit blocks (blocks that end with return instructions).
        
        Args:
            cfg: ControlFlowGraph to update
        """
        for bb in cfg.basic_blocks.values():
            if bb.instructions:
                last_instr = bb.instructions[-1]
                if last_instr.mnemonic.lower() in ['ret', 'retn']:
                    cfg.exit_blocks.append(bb.start_address)
    
    def detect_loops(self, cfg: ControlFlowGraph) -> List[Loop]:
        """
        Detect loop structures in the control flow graph.
        
        A loop is identified by detecting back edges - edges that point to
        a block that dominates the source block (creating a cycle).
        
        Algorithm:
        1. Find all back edges (edges where target address < source address)
        2. For each back edge, identify the loop header and body
        
        Args:
            cfg: ControlFlowGraph to analyze
            
        Returns:
            List of Loop objects
        """
        loops = []
        
        # Find back edges (simple heuristic: target address < source address)
        for source_addr, bb in cfg.basic_blocks.items():
            for successor_addr in bb.successors:
                # Check if this is a back edge
                if successor_addr <= source_addr:
                    # This is likely a back edge (loop)
                    loop = Loop(
                        header=successor_addr,
                        back_edge_source=source_addr
                    )
                    
                    # Identify loop body (all blocks between header and back edge source)
                    loop.body_blocks = self._identify_loop_body(
                        cfg, successor_addr, source_addr
                    )
                    
                    loops.append(loop)
        
        return loops
    
    def _identify_loop_body(self, cfg: ControlFlowGraph, 
                           header: int, back_edge_source: int) -> Set[int]:
        """
        Identify all basic blocks that are part of a loop body.
        
        Uses a simple approach: all blocks reachable from header that can
        reach the back edge source are part of the loop.
        
        Args:
            cfg: ControlFlowGraph
            header: Address of loop header
            back_edge_source: Address of block with back edge
            
        Returns:
            Set of basic block addresses in the loop body
        """
        body = set()
        body.add(header)
        body.add(back_edge_source)
        
        # Find all blocks between header and back edge source
        # Simple approach: do BFS from header, stop at back_edge_source
        visited = set()
        queue = [header]
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            body.add(current)
            
            # Add successors (but don't go past the back edge source)
            if current in cfg.basic_blocks:
                for successor in cfg.basic_blocks[current].successors:
                    if successor not in visited:
                        # Include blocks up to and including back_edge_source
                        if successor <= back_edge_source or successor == header:
                            queue.append(successor)
        
        return body
    
    def _is_branch_instruction(self, instr: Instruction) -> bool:
        """
        Check if an instruction is a branch/jump instruction.
        
        Args:
            instr: Instruction to check
            
        Returns:
            True if instruction is a branch, False otherwise
        """
        mnemonic = instr.mnemonic.lower()
        branch_mnemonics = [
            'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
            'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
            'jp', 'jnp', 'jpe', 'jpo', 'jcxz', 'jecxz', 'jrcxz'
        ]
        return mnemonic in branch_mnemonics
    
    def _is_conditional_jump(self, instr: Instruction) -> bool:
        """
        Check if an instruction is a conditional jump.
        
        Args:
            instr: Instruction to check
            
        Returns:
            True if instruction is a conditional jump, False otherwise
        """
        mnemonic = instr.mnemonic.lower()
        conditional_jumps = [
            'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
            'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
            'jp', 'jnp', 'jpe', 'jpo', 'jcxz', 'jecxz', 'jrcxz'
        ]
        return mnemonic in conditional_jumps
    
    def _find_next_block(self, current_end_addr: int, 
                        basic_blocks: Dict[int, BasicBlock]) -> Optional[int]:
        """
        Find the next sequential basic block after the given address.
        
        Args:
            current_end_addr: End address of current block
            basic_blocks: Dictionary of all basic blocks
            
        Returns:
            Start address of next block, or None if not found
        """
        # Find the block with the smallest start address > current_end_addr
        next_addr = None
        min_distance = float('inf')
        
        for start_addr in basic_blocks.keys():
            if start_addr > current_end_addr:
                distance = start_addr - current_end_addr
                if distance < min_distance:
                    min_distance = distance
                    next_addr = start_addr
        
        return next_addr
    
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

    
    def export_dot(self, cfg: ControlFlowGraph) -> str:
        """
        Export control flow graph in Graphviz DOT format.
        
        Args:
            cfg: ControlFlowGraph to export
            
        Returns:
            DOT format string representation
        """
        lines = []
        lines.append("digraph CFG {")
        lines.append("    rankdir=TB;")
        lines.append("    node [shape=box];")
        lines.append("")
        
        # Add nodes
        for addr, bb in cfg.basic_blocks.items():
            label = f"Block 0x{addr:x}"
            
            # Add instruction count
            label += f"\\n({len(bb.instructions)} instructions)"
            
            # Styling based on block type
            style_attrs = []
            
            if addr == cfg.entry_block:
                style_attrs.append('fillcolor=lightgreen')
                style_attrs.append('style=filled')
                label += "\\n(entry)"
            
            if addr in cfg.exit_blocks:
                style_attrs.append('fillcolor=lightcoral')
                style_attrs.append('style=filled')
                label += "\\n(exit)"
            
            # Check if block is part of a loop
            in_loop = False
            for loop in cfg.loops:
                if addr in loop.body_blocks:
                    in_loop = True
                    break
            
            if in_loop:
                if not style_attrs:
                    style_attrs.append('fillcolor=lightyellow')
                    style_attrs.append('style=filled')
                label += "\\n(loop)"
            
            style_str = ', '.join(style_attrs) if style_attrs else ''
            if style_str:
                lines.append(f'    "0x{addr:x}" [label="{label}", {style_str}];')
            else:
                lines.append(f'    "0x{addr:x}" [label="{label}"];')
        
        lines.append("")
        
        # Add edges
        for addr, bb in cfg.basic_blocks.items():
            for successor in bb.successors:
                # Check if this is a back edge (loop)
                is_back_edge = False
                for loop in cfg.loops:
                    if addr == loop.back_edge_source and successor == loop.header:
                        is_back_edge = True
                        break
                
                if is_back_edge:
                    lines.append(f'    "0x{addr:x}" -> "0x{successor:x}" [color=red, label="back edge"];')
                else:
                    lines.append(f'    "0x{addr:x}" -> "0x{successor:x}";')
        
        lines.append("}")
        
        return '\n'.join(lines)
    
    def export_mermaid(self, cfg: ControlFlowGraph) -> str:
        """
        Export control flow graph in Mermaid format.
        
        Args:
            cfg: ControlFlowGraph to export
            
        Returns:
            Mermaid format string representation
        """
        lines = []
        lines.append("graph TD")
        
        # Add nodes
        for addr, bb in cfg.basic_blocks.items():
            node_id = f"B{addr:x}"
            label = f"Block 0x{addr:x}<br/>({len(bb.instructions)} instrs)"
            
            # Add annotations
            annotations = []
            if addr == cfg.entry_block:
                annotations.append("entry")
            if addr in cfg.exit_blocks:
                annotations.append("exit")
            
            # Check if in loop
            for loop in cfg.loops:
                if addr in loop.body_blocks:
                    annotations.append("loop")
                    break
            
            if annotations:
                label += f"<br/>({', '.join(annotations)})"
            
            lines.append(f'    {node_id}["{label}"]')
            
            # Apply styling
            if addr == cfg.entry_block:
                lines.append(f'    style {node_id} fill:#90EE90')
            elif addr in cfg.exit_blocks:
                lines.append(f'    style {node_id} fill:#FFB6C1')
            else:
                # Check if in loop
                in_loop = False
                for loop in cfg.loops:
                    if addr in loop.body_blocks:
                        in_loop = True
                        break
                if in_loop:
                    lines.append(f'    style {node_id} fill:#FFFFE0')
        
        lines.append("")
        
        # Add edges
        for addr, bb in cfg.basic_blocks.items():
            source_id = f"B{addr:x}"
            for successor in bb.successors:
                target_id = f"B{successor:x}"
                
                # Check if this is a back edge
                is_back_edge = False
                for loop in cfg.loops:
                    if addr == loop.back_edge_source and successor == loop.header:
                        is_back_edge = True
                        break
                
                if is_back_edge:
                    lines.append(f'    {source_id} -.->|back edge| {target_id}')
                else:
                    lines.append(f'    {source_id} --> {target_id}')
        
        return '\n'.join(lines)
    
    def export_ascii(self, cfg: ControlFlowGraph) -> str:
        """
        Export control flow graph as ASCII art.
        
        Args:
            cfg: ControlFlowGraph to export
            
        Returns:
            ASCII art representation
        """
        lines = []
        lines.append("=" * 80)
        lines.append("CONTROL FLOW GRAPH (ASCII)")
        lines.append("=" * 80)
        lines.append("")
        
        if not cfg.basic_blocks:
            lines.append("No basic blocks found.")
            return '\n'.join(lines)
        
        # Statistics
        lines.append("STATISTICS:")
        lines.append(f"  Total basic blocks: {len(cfg.basic_blocks)}")
        lines.append(f"  Entry block: 0x{cfg.entry_block:x}" if cfg.entry_block else "  Entry block: None")
        lines.append(f"  Exit blocks: {len(cfg.exit_blocks)}")
        lines.append(f"  Loops detected: {len(cfg.loops)}")
        lines.append("")
        
        # List all basic blocks
        lines.append("BASIC BLOCKS:")
        lines.append("-" * 80)
        
        for addr in sorted(cfg.basic_blocks.keys()):
            bb = cfg.basic_blocks[addr]
            
            # Block header
            header = f"Block 0x{addr:x}"
            annotations = []
            
            if addr == cfg.entry_block:
                annotations.append("ENTRY")
            if addr in cfg.exit_blocks:
                annotations.append("EXIT")
            
            # Check if in loop
            for loop in cfg.loops:
                if addr in loop.body_blocks:
                    if addr == loop.header:
                        annotations.append(f"LOOP HEADER")
                    else:
                        annotations.append("IN LOOP")
                    break
            
            if annotations:
                header += f" [{', '.join(annotations)}]"
            
            lines.append(header)
            lines.append("  " + "-" * 76)
            
            # Show first and last instruction
            if bb.instructions:
                first = bb.instructions[0]
                lines.append(f"  First: {first.mnemonic} {' '.join(first.operands)}")
                
                if len(bb.instructions) > 1:
                    last = bb.instructions[-1]
                    lines.append(f"  Last:  {last.mnemonic} {' '.join(last.operands)}")
                
                lines.append(f"  Instructions: {len(bb.instructions)}")
            
            # Show successors
            if bb.successors:
                succ_str = ", ".join([f"0x{s:x}" for s in bb.successors])
                lines.append(f"  Successors: {succ_str}")
            else:
                lines.append("  Successors: None")
            
            # Show predecessors
            if bb.predecessors:
                pred_str = ", ".join([f"0x{p:x}" for p in bb.predecessors])
                lines.append(f"  Predecessors: {pred_str}")
            else:
                lines.append("  Predecessors: None")
            
            lines.append("")
        
        # Show loops
        if cfg.loops:
            lines.append("")
            lines.append("DETECTED LOOPS:")
            lines.append("-" * 80)
            
            for i, loop in enumerate(cfg.loops, 1):
                lines.append(f"Loop {i}:")
                lines.append(f"  Header: 0x{loop.header:x}")
                lines.append(f"  Back edge from: 0x{loop.back_edge_source:x}")
                lines.append(f"  Body blocks: {len(loop.body_blocks)}")
                
                body_addrs = ", ".join([f"0x{addr:x}" for addr in sorted(loop.body_blocks)])
                lines.append(f"  Blocks: {body_addrs}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def generate_report(self, cfg: ControlFlowGraph) -> str:
        """
        Generate a comprehensive CFG analysis report.
        
        Args:
            cfg: ControlFlowGraph to report on
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("CONTROL FLOW GRAPH ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Statistics
        lines.append("STATISTICS:")
        lines.append(f"  Function address: 0x{cfg.function_address:x}")
        lines.append(f"  Total basic blocks: {len(cfg.basic_blocks)}")
        lines.append(f"  Total edges: {cfg.graph.number_of_edges()}")
        lines.append(f"  Entry block: 0x{cfg.entry_block:x}" if cfg.entry_block else "  Entry block: None")
        lines.append(f"  Exit blocks: {len(cfg.exit_blocks)}")
        lines.append(f"  Loops detected: {len(cfg.loops)}")
        lines.append("")
        
        # Complexity metrics
        if cfg.basic_blocks:
            # Cyclomatic complexity: E - N + 2 (for single entry/exit)
            edges = cfg.graph.number_of_edges()
            nodes = len(cfg.basic_blocks)
            complexity = edges - nodes + 2
            
            lines.append("COMPLEXITY METRICS:")
            lines.append(f"  Cyclomatic complexity: {complexity}")
            lines.append(f"  Average successors per block: {edges / nodes:.2f}" if nodes > 0 else "  Average successors per block: 0")
            lines.append("")
        
        # Entry and exit blocks
        if cfg.entry_block:
            lines.append("ENTRY BLOCK:")
            lines.append(f"  0x{cfg.entry_block:x}")
            lines.append("")
        
        if cfg.exit_blocks:
            lines.append("EXIT BLOCKS:")
            for addr in sorted(cfg.exit_blocks):
                lines.append(f"  0x{addr:x}")
            lines.append("")
        
        # Loops
        if cfg.loops:
            lines.append("LOOPS:")
            for i, loop in enumerate(cfg.loops, 1):
                lines.append(f"  Loop {i}:")
                lines.append(f"    Header: 0x{loop.header:x}")
                lines.append(f"    Back edge from: 0x{loop.back_edge_source:x}")
                lines.append(f"    Body size: {len(loop.body_blocks)} blocks")
            lines.append("")
        
        # Blocks with most predecessors (convergence points)
        if cfg.basic_blocks:
            lines.append("TOP CONVERGENCE POINTS (Most Predecessors):")
            pred_counts = [(addr, len(bb.predecessors)) 
                          for addr, bb in cfg.basic_blocks.items()]
            pred_counts.sort(key=lambda x: x[1], reverse=True)
            
            for addr, count in pred_counts[:5]:
                if count > 0:
                    lines.append(f"  0x{addr:x} - {count} predecessor(s)")
            lines.append("")
        
        # Blocks with most successors (branch points)
        if cfg.basic_blocks:
            lines.append("TOP BRANCH POINTS (Most Successors):")
            succ_counts = [(addr, len(bb.successors)) 
                          for addr, bb in cfg.basic_blocks.items()]
            succ_counts.sort(key=lambda x: x[1], reverse=True)
            
            for addr, count in succ_counts[:5]:
                if count > 0:
                    lines.append(f"  0x{addr:x} - {count} successor(s)")
            lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
