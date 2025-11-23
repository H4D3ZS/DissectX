"""Binary Diffing for comparing two binaries and identifying changes"""
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib


class ChangeType(Enum):
    """Type of change detected in binary diff"""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


@dataclass
class FunctionInfo:
    """Information about a function for diffing purposes"""
    address: int
    name: Optional[str] = None
    size: int = 0
    instructions: List[str] = field(default_factory=list)
    hash: Optional[str] = None
    calls: Set[int] = field(default_factory=set)  # Addresses of functions called
    called_by: Set[int] = field(default_factory=set)  # Addresses of callers
    
    def compute_hash(self) -> str:
        """
        Compute a hash of the function's instructions.
        
        Returns:
            SHA256 hash of the function's instructions
        """
        if self.hash:
            return self.hash
        
        # Normalize instructions for hashing (remove addresses)
        normalized = []
        for instr in self.instructions:
            # Remove address prefix if present
            parts = instr.split(maxsplit=1)
            if len(parts) > 1:
                normalized.append(parts[1])
            else:
                normalized.append(instr)
        
        # Compute hash
        content = '\n'.join(normalized).encode('utf-8')
        self.hash = hashlib.sha256(content).hexdigest()
        return self.hash
    
    def compute_structural_hash(self) -> str:
        """
        Compute a structural hash based on call graph and control flow.
        
        This is more resilient to minor code changes than instruction hash.
        
        Returns:
            SHA256 hash of structural features
        """
        # Combine structural features
        features = []
        features.append(f"size:{self.size}")
        features.append(f"calls:{len(self.calls)}")
        features.append(f"called_by:{len(self.called_by)}")
        
        # Add sorted call targets (relative structure)
        if self.calls:
            features.append(f"call_targets:{','.join(str(c) for c in sorted(self.calls))}")
        
        # Compute hash
        content = '|'.join(features).encode('utf-8')
        return hashlib.sha256(content).hexdigest()


@dataclass
class FunctionMatch:
    """Represents a match between functions in two binaries"""
    old_function: Optional[FunctionInfo]
    new_function: Optional[FunctionInfo]
    change_type: ChangeType
    confidence: float  # 0.0 to 1.0
    match_reason: str  # Why these functions were matched
    
    def is_security_relevant(self) -> bool:
        """
        Check if this change is security-relevant.
        
        Returns:
            True if the change affects security-critical code
        """
        # Check for security-relevant patterns
        security_keywords = [
            'auth', 'login', 'password', 'crypt', 'hash',
            'verify', 'check', 'validate', 'permission',
            'admin', 'root', 'privilege', 'token',
            'key', 'secret', 'secure'
        ]
        
        # Check function names
        if self.old_function and self.old_function.name:
            if any(kw in self.old_function.name.lower() for kw in security_keywords):
                return True
        
        if self.new_function and self.new_function.name:
            if any(kw in self.new_function.name.lower() for kw in security_keywords):
                return True
        
        # Check instructions for security-relevant operations
        security_instructions = [
            'cmp', 'test', 'je', 'jne',  # Comparison/branching (auth checks)
            'call', 'ret',  # Control flow changes
            'xor', 'rol', 'ror',  # Crypto operations
        ]
        
        if self.old_function:
            for instr in self.old_function.instructions:
                if any(op in instr.lower() for op in security_instructions):
                    return True
        
        if self.new_function:
            for instr in self.new_function.instructions:
                if any(op in instr.lower() for op in security_instructions):
                    return True
        
        return False


@dataclass
class DiffStatistics:
    """Statistics about the binary diff"""
    total_functions_old: int = 0
    total_functions_new: int = 0
    functions_added: int = 0
    functions_removed: int = 0
    functions_modified: int = 0
    functions_unchanged: int = 0
    security_relevant_changes: int = 0
    
    def get_change_percentage(self) -> float:
        """
        Calculate the percentage of functions that changed.
        
        Returns:
            Percentage of changed functions (0-100)
        """
        total = max(self.total_functions_old, self.total_functions_new)
        if total == 0:
            return 0.0
        
        changed = self.functions_added + self.functions_removed + self.functions_modified
        return (changed / total) * 100.0


class BinaryDiffer:
    """
    Compares two binaries and identifies changes.
    
    Implements function matching by hash and structural similarity,
    categorizes changes, and generates comparison reports.
    """
    
    def __init__(self):
        """Initialize the binary differ"""
        self.old_functions: Dict[int, FunctionInfo] = {}
        self.new_functions: Dict[int, FunctionInfo] = {}
        self.matches: List[FunctionMatch] = []
        self.statistics = DiffStatistics()
    
    def load_old_binary(self, functions: Dict[int, FunctionInfo]):
        """
        Load functions from the old (original) binary.
        
        Args:
            functions: Dictionary mapping addresses to FunctionInfo objects
        """
        self.old_functions = functions
        self.statistics.total_functions_old = len(functions)
        
        # Compute hashes for all functions
        for func in self.old_functions.values():
            func.compute_hash()
    
    def load_new_binary(self, functions: Dict[int, FunctionInfo]):
        """
        Load functions from the new (modified) binary.
        
        Args:
            functions: Dictionary mapping addresses to FunctionInfo objects
        """
        self.new_functions = functions
        self.statistics.total_functions_new = len(functions)
        
        # Compute hashes for all functions
        for func in self.new_functions.values():
            func.compute_hash()
    
    def compare(self) -> List[FunctionMatch]:
        """
        Compare the two binaries and identify changes.
        
        Implements function matching by hash and structural matching.
        
        Returns:
            List of FunctionMatch objects representing all changes
        """
        self.matches.clear()
        
        # Track which functions have been matched
        matched_old = set()
        matched_new = set()
        
        # Phase 1: Exact hash matching (unchanged functions)
        self._match_by_hash(matched_old, matched_new)
        
        # Phase 2: Structural matching (modified functions)
        self._match_by_structure(matched_old, matched_new)
        
        # Phase 3: Name matching (for functions with names)
        self._match_by_name(matched_old, matched_new)
        
        # Phase 4: Identify added and removed functions
        self._identify_added_removed(matched_old, matched_new)
        
        # Categorize changes and update statistics
        self._categorize_changes()
        
        return self.matches
    
    def _match_by_hash(self, matched_old: Set[int], matched_new: Set[int]):
        """
        Match functions by exact instruction hash.
        
        Args:
            matched_old: Set to track matched old function addresses
            matched_new: Set to track matched new function addresses
        """
        # Build hash -> function mapping for new functions
        new_hash_map: Dict[str, List[FunctionInfo]] = {}
        for func in self.new_functions.values():
            func_hash = func.compute_hash()
            if func_hash not in new_hash_map:
                new_hash_map[func_hash] = []
            new_hash_map[func_hash].append(func)
        
        # Match old functions by hash
        for old_func in self.old_functions.values():
            old_hash = old_func.compute_hash()
            
            if old_hash in new_hash_map:
                # Found exact match
                new_func = new_hash_map[old_hash][0]  # Take first match
                
                self.matches.append(FunctionMatch(
                    old_function=old_func,
                    new_function=new_func,
                    change_type=ChangeType.MODIFIED,  # Will be reclassified as unchanged
                    confidence=1.0,
                    match_reason="Exact instruction hash match"
                ))
                
                matched_old.add(old_func.address)
                matched_new.add(new_func.address)
                
                # Remove from hash map to avoid duplicate matches
                new_hash_map[old_hash].pop(0)
                if not new_hash_map[old_hash]:
                    del new_hash_map[old_hash]
    
    def _match_by_structure(self, matched_old: Set[int], matched_new: Set[int]):
        """
        Match functions by structural similarity.
        
        Uses call graph structure and function size to match functions
        that may have minor code changes.
        
        Args:
            matched_old: Set to track matched old function addresses
            matched_new: Set to track matched new function addresses
        """
        # Build structural hash -> function mapping for new functions
        new_struct_map: Dict[str, List[FunctionInfo]] = {}
        for func in self.new_functions.values():
            if func.address in matched_new:
                continue  # Already matched
            
            struct_hash = func.compute_structural_hash()
            if struct_hash not in new_struct_map:
                new_struct_map[struct_hash] = []
            new_struct_map[struct_hash].append(func)
        
        # Match old functions by structural hash
        for old_func in self.old_functions.values():
            if old_func.address in matched_old:
                continue  # Already matched
            
            struct_hash = old_func.compute_structural_hash()
            
            if struct_hash in new_struct_map:
                # Found structural match
                new_func = new_struct_map[struct_hash][0]  # Take first match
                
                # Calculate confidence based on size similarity
                size_diff = abs(old_func.size - new_func.size)
                max_size = max(old_func.size, new_func.size)
                confidence = 1.0 - (size_diff / max_size) if max_size > 0 else 0.5
                confidence = max(0.5, min(1.0, confidence))  # Clamp to [0.5, 1.0]
                
                self.matches.append(FunctionMatch(
                    old_function=old_func,
                    new_function=new_func,
                    change_type=ChangeType.MODIFIED,
                    confidence=confidence,
                    match_reason="Structural similarity (call graph and size)"
                ))
                
                matched_old.add(old_func.address)
                matched_new.add(new_func.address)
                
                # Remove from struct map to avoid duplicate matches
                new_struct_map[struct_hash].pop(0)
                if not new_struct_map[struct_hash]:
                    del new_struct_map[struct_hash]
    
    def _match_by_name(self, matched_old: Set[int], matched_new: Set[int]):
        """
        Match functions by name (for named functions).
        
        Args:
            matched_old: Set to track matched old function addresses
            matched_new: Set to track matched new function addresses
        """
        # Build name -> function mapping for new functions
        new_name_map: Dict[str, List[FunctionInfo]] = {}
        for func in self.new_functions.values():
            if func.address in matched_new or not func.name:
                continue  # Already matched or no name
            
            if func.name not in new_name_map:
                new_name_map[func.name] = []
            new_name_map[func.name].append(func)
        
        # Match old functions by name
        for old_func in self.old_functions.values():
            if old_func.address in matched_old or not old_func.name:
                continue  # Already matched or no name
            
            if old_func.name in new_name_map:
                # Found name match
                new_func = new_name_map[old_func.name][0]  # Take first match
                
                self.matches.append(FunctionMatch(
                    old_function=old_func,
                    new_function=new_func,
                    change_type=ChangeType.MODIFIED,
                    confidence=0.8,  # Name match is good but not perfect
                    match_reason=f"Function name match: {old_func.name}"
                ))
                
                matched_old.add(old_func.address)
                matched_new.add(new_func.address)
                
                # Remove from name map to avoid duplicate matches
                new_name_map[old_func.name].pop(0)
                if not new_name_map[old_func.name]:
                    del new_name_map[old_func.name]
    
    def _identify_added_removed(self, matched_old: Set[int], matched_new: Set[int]):
        """
        Identify functions that were added or removed.
        
        Args:
            matched_old: Set of matched old function addresses
            matched_new: Set of matched new function addresses
        """
        # Removed functions (in old but not matched)
        for addr, func in self.old_functions.items():
            if addr not in matched_old:
                self.matches.append(FunctionMatch(
                    old_function=func,
                    new_function=None,
                    change_type=ChangeType.REMOVED,
                    confidence=1.0,
                    match_reason="Function not found in new binary"
                ))
        
        # Added functions (in new but not matched)
        for addr, func in self.new_functions.items():
            if addr not in matched_new:
                self.matches.append(FunctionMatch(
                    old_function=None,
                    new_function=func,
                    change_type=ChangeType.ADDED,
                    confidence=1.0,
                    match_reason="Function not found in old binary"
                ))
    
    def _categorize_changes(self):
        """
        Categorize changes and update statistics.
        
        Determines if matched functions are actually unchanged or modified,
        and counts security-relevant changes.
        """
        self.statistics.functions_added = 0
        self.statistics.functions_removed = 0
        self.statistics.functions_modified = 0
        self.statistics.functions_unchanged = 0
        self.statistics.security_relevant_changes = 0
        
        for match in self.matches:
            # Categorize by change type
            if match.change_type == ChangeType.ADDED:
                self.statistics.functions_added += 1
            elif match.change_type == ChangeType.REMOVED:
                self.statistics.functions_removed += 1
            elif match.change_type == ChangeType.MODIFIED:
                # Check if actually unchanged (exact hash match)
                if (match.old_function and match.new_function and
                    match.old_function.hash == match.new_function.hash):
                    self.statistics.functions_unchanged += 1
                else:
                    self.statistics.functions_modified += 1
            
            # Check for security relevance
            if match.is_security_relevant():
                self.statistics.security_relevant_changes += 1
    
    def get_statistics(self) -> DiffStatistics:
        """
        Get diff statistics.
        
        Returns:
            DiffStatistics object with summary information
        """
        return self.statistics
    
    def generate_report(self) -> str:
        """
        Generate a comprehensive diff report.
        
        Returns:
            Formatted diff report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("BINARY DIFF REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Statistics
        lines.append("STATISTICS:")
        lines.append(f"  Functions in old binary: {self.statistics.total_functions_old}")
        lines.append(f"  Functions in new binary: {self.statistics.total_functions_new}")
        lines.append(f"  Functions added: {self.statistics.functions_added}")
        lines.append(f"  Functions removed: {self.statistics.functions_removed}")
        lines.append(f"  Functions modified: {self.statistics.functions_modified}")
        lines.append(f"  Functions unchanged: {self.statistics.functions_unchanged}")
        lines.append(f"  Security-relevant changes: {self.statistics.security_relevant_changes}")
        lines.append(f"  Change percentage: {self.statistics.get_change_percentage():.1f}%")
        lines.append("")
        
        # Added functions
        added = [m for m in self.matches if m.change_type == ChangeType.ADDED]
        if added:
            lines.append("ADDED FUNCTIONS:")
            lines.append("-" * 80)
            for match in sorted(added, key=lambda m: m.new_function.address if m.new_function else 0):
                func = match.new_function
                name = func.name if func.name else "<unnamed>"
                security = " [SECURITY]" if match.is_security_relevant() else ""
                lines.append(f"  + 0x{func.address:x} {name} (size: {func.size}){security}")
            lines.append("")
        
        # Removed functions
        removed = [m for m in self.matches if m.change_type == ChangeType.REMOVED]
        if removed:
            lines.append("REMOVED FUNCTIONS:")
            lines.append("-" * 80)
            for match in sorted(removed, key=lambda m: m.old_function.address if m.old_function else 0):
                func = match.old_function
                name = func.name if func.name else "<unnamed>"
                security = " [SECURITY]" if match.is_security_relevant() else ""
                lines.append(f"  - 0x{func.address:x} {name} (size: {func.size}){security}")
            lines.append("")
        
        # Modified functions
        modified = [m for m in self.matches 
                   if m.change_type == ChangeType.MODIFIED and 
                   m.old_function and m.new_function and
                   m.old_function.hash != m.new_function.hash]
        if modified:
            lines.append("MODIFIED FUNCTIONS:")
            lines.append("-" * 80)
            for match in sorted(modified, key=lambda m: m.old_function.address if m.old_function else 0):
                old_func = match.old_function
                new_func = match.new_function
                old_name = old_func.name if old_func.name else "<unnamed>"
                new_name = new_func.name if new_func.name else "<unnamed>"
                security = " [SECURITY]" if match.is_security_relevant() else ""
                
                lines.append(f"  ~ 0x{old_func.address:x} -> 0x{new_func.address:x}")
                lines.append(f"    Old: {old_name} (size: {old_func.size})")
                lines.append(f"    New: {new_name} (size: {new_func.size})")
                lines.append(f"    Confidence: {match.confidence:.2f}")
                lines.append(f"    Reason: {match.match_reason}{security}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def generate_side_by_side_comparison(self, match: FunctionMatch) -> str:
        """
        Generate a side-by-side comparison view for a specific function match.
        
        Args:
            match: FunctionMatch to generate comparison for
            
        Returns:
            Formatted side-by-side comparison string
        """
        lines = []
        lines.append("=" * 120)
        lines.append("SIDE-BY-SIDE FUNCTION COMPARISON")
        lines.append("=" * 120)
        lines.append("")
        
        # Header
        if match.old_function and match.new_function:
            old_name = match.old_function.name or f"0x{match.old_function.address:x}"
            new_name = match.new_function.name or f"0x{match.new_function.address:x}"
            lines.append(f"OLD: {old_name:<50} | NEW: {new_name}")
        elif match.old_function:
            old_name = match.old_function.name or f"0x{match.old_function.address:x}"
            lines.append(f"OLD: {old_name:<50} | NEW: <removed>")
        elif match.new_function:
            new_name = match.new_function.name or f"0x{match.new_function.address:x}"
            lines.append(f"OLD: <added>                                       | NEW: {new_name}")
        
        lines.append("-" * 120)
        
        # Instructions side-by-side
        old_instrs = match.old_function.instructions if match.old_function else []
        new_instrs = match.new_function.instructions if match.new_function else []
        
        max_lines = max(len(old_instrs), len(new_instrs))
        
        for i in range(max_lines):
            old_line = old_instrs[i] if i < len(old_instrs) else ""
            new_line = new_instrs[i] if i < len(new_instrs) else ""
            
            # Truncate long lines
            old_line = old_line[:55] if len(old_line) > 55 else old_line
            new_line = new_line[:55] if len(new_line) > 55 else new_line
            
            # Highlight differences
            marker = " "
            if old_line != new_line:
                if not old_line:
                    marker = "+"
                elif not new_line:
                    marker = "-"
                else:
                    marker = "~"
            
            lines.append(f"{marker} {old_line:<55} | {new_line}")
        
        lines.append("")
        lines.append("=" * 120)
        
        return '\n'.join(lines)
    
    def highlight_security_changes(self) -> List[FunctionMatch]:
        """
        Identify and highlight security-relevant changes.
        
        Returns:
            List of FunctionMatch objects that are security-relevant
        """
        security_changes = []
        
        for match in self.matches:
            if match.is_security_relevant():
                security_changes.append(match)
        
        return security_changes
    
    def generate_security_report(self) -> str:
        """
        Generate a report focused on security-relevant changes.
        
        Returns:
            Formatted security-focused report string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("SECURITY-RELEVANT CHANGES REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        security_changes = self.highlight_security_changes()
        
        if not security_changes:
            lines.append("No security-relevant changes detected.")
            lines.append("")
            lines.append("=" * 80)
            return '\n'.join(lines)
        
        lines.append(f"Total security-relevant changes: {len(security_changes)}")
        lines.append("")
        
        # Group by change type
        added = [m for m in security_changes if m.change_type == ChangeType.ADDED]
        removed = [m for m in security_changes if m.change_type == ChangeType.REMOVED]
        modified = [m for m in security_changes if m.change_type == ChangeType.MODIFIED]
        
        if added:
            lines.append("ADDED SECURITY FUNCTIONS:")
            lines.append("-" * 80)
            for match in added:
                func = match.new_function
                name = func.name if func.name else "<unnamed>"
                lines.append(f"  + 0x{func.address:x} {name}")
                lines.append(f"    Size: {func.size} bytes")
                lines.append(f"    Reason: {match.match_reason}")
                lines.append("")
        
        if removed:
            lines.append("REMOVED SECURITY FUNCTIONS:")
            lines.append("-" * 80)
            for match in removed:
                func = match.old_function
                name = func.name if func.name else "<unnamed>"
                lines.append(f"  - 0x{func.address:x} {name}")
                lines.append(f"    Size: {func.size} bytes")
                lines.append(f"    WARNING: Security function removed!")
                lines.append("")
        
        if modified:
            lines.append("MODIFIED SECURITY FUNCTIONS:")
            lines.append("-" * 80)
            for match in modified:
                old_func = match.old_function
                new_func = match.new_function
                old_name = old_func.name if old_func and old_func.name else "<unnamed>"
                new_name = new_func.name if new_func and new_func.name else "<unnamed>"
                
                if old_func and new_func:
                    lines.append(f"  ~ 0x{old_func.address:x} -> 0x{new_func.address:x}")
                    lines.append(f"    Old: {old_name} (size: {old_func.size})")
                    lines.append(f"    New: {new_name} (size: {new_func.size})")
                    lines.append(f"    Confidence: {match.confidence:.2f}")
                    lines.append(f"    WARNING: Security-critical function modified!")
                    lines.append("")
        
        lines.append("=" * 80)
        lines.append("RECOMMENDATION: Carefully review all security-relevant changes")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
