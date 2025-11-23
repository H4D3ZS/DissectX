"""
Radare2 Integration for DissectX

This module provides integration with Radare2 reverse engineering framework,
allowing bidirectional communication via r2pipe for data exchange between
DissectX and Radare2.
"""
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import json
from enum import Enum

# Import naming convention adapters
try:
    from .naming_conventions import (
        Radare2NamingAdapter, NamedEntity, EntityType, ToolType
    )
except ImportError:
    # Fallback if running standalone
    from naming_conventions import (
        Radare2NamingAdapter, NamedEntity, EntityType, ToolType
    )


class R2DataType(Enum):
    """Radare2 data types"""
    BYTE = "b"
    WORD = "w"
    DWORD = "d"
    QWORD = "q"
    STRING = "s"
    ARRAY = "a"
    STRUCT = "struct"
    UNKNOWN = "?"


@dataclass
class R2Function:
    """Represents a function in Radare2 format"""
    address: int
    name: str
    size: int = 0
    offset: Optional[int] = None
    signature: Optional[str] = None
    comment: Optional[str] = None
    calls: List[int] = field(default_factory=list)
    callrefs: List[int] = field(default_factory=list)
    datarefs: List[int] = field(default_factory=list)
    codexrefs: List[int] = field(default_factory=list)
    is_import: bool = False
    is_pure: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'size': self.size,
            'offset': self.offset,
            'signature': self.signature,
            'comment': self.comment,
            'calls': [hex(c) for c in self.calls],
            'callrefs': [hex(c) for c in self.callrefs],
            'datarefs': [hex(d) for d in self.datarefs],
            'codexrefs': [hex(c) for c in self.codexrefs],
            'is_import': self.is_import,
            'is_pure': self.is_pure
        }


@dataclass
class R2Flag:
    """Represents a flag (label/symbol) in Radare2"""
    address: int
    name: str
    size: int = 1
    realname: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'size': self.size,
            'realname': self.realname
        }


@dataclass
class R2String:
    """Represents a string in Radare2"""
    address: int
    string: str
    length: int
    size: int
    section: Optional[str] = None
    type: str = "ascii"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'string': self.string,
            'length': self.length,
            'size': self.size,
            'section': self.section,
            'type': self.type
        }


@dataclass
class R2XRef:
    """Represents a cross-reference in Radare2"""
    from_address: int
    to_address: int
    xref_type: str  # 'CALL', 'DATA', 'STRING', 'CODE'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'from': hex(self.from_address),
            'to': hex(self.to_address),
            'type': self.xref_type
        }


@dataclass
class R2Section:
    """Represents a section in Radare2"""
    name: str
    vaddr: int
    vsize: int
    paddr: int
    size: int
    permissions: str  # e.g., "r-x", "rw-"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'vaddr': hex(self.vaddr),
            'vsize': self.vsize,
            'paddr': hex(self.paddr),
            'size': self.size,
            'permissions': self.permissions
        }


class Radare2Integration:
    """
    Integration with Radare2 reverse engineering framework.
    
    Provides functionality to:
    - Communicate with Radare2 via r2pipe
    - Import Radare2 analysis data (functions, flags, strings, xrefs)
    - Export DissectX analysis to Radare2
    - Support bidirectional data exchange
    - Execute Radare2 commands programmatically
    """
    
    def __init__(self, binary_path: Optional[str] = None):
        """
        Initialize Radare2 integration.
        
        Args:
            binary_path: Optional path to binary file to open in Radare2
        """
        self.r2 = None
        self.binary_path = binary_path
        self.functions: Dict[int, R2Function] = {}
        self.flags: Dict[int, R2Flag] = {}
        self.strings: List[R2String] = []
        self.xrefs: List[R2XRef] = []
        self.sections: List[R2Section] = []
        self.info: Dict[str, Any] = {}
        self.is_connected = False
        self.naming_adapter = Radare2NamingAdapter()
        self.preserved_annotations: Dict[int, Dict[str, Any]] = {}  # For annotation preservation
    
    def connect(self, binary_path: Optional[str] = None, 
                flags: Optional[List[str]] = None) -> bool:
        """
        Connect to Radare2 via r2pipe.
        
        Opens a binary in Radare2 and establishes r2pipe communication.
        
        Args:
            binary_path: Path to binary file (uses self.binary_path if not provided)
            flags: Optional list of r2 flags (e.g., ['-2', '-A'] for analysis)
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            import r2pipe
            
            # Use provided path or stored path
            path = binary_path or self.binary_path
            if not path:
                print("Error: No binary path provided")
                return False
            
            # Default flags: -2 for stderr output, -A for auto-analysis
            if flags is None:
                flags = ['-2']
            
            # Open binary with r2pipe
            self.r2 = r2pipe.open(path, flags=flags)
            self.binary_path = path
            self.is_connected = True
            
            print(f"Connected to Radare2 with binary: {path}")
            return True
            
        except ImportError:
            print("Error: r2pipe library not available.")
            print("Please install it with: pip install r2pipe")
            return False
        except Exception as e:
            print(f"Error connecting to Radare2: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Radare2 and cleanup"""
        if self.r2:
            try:
                self.r2.quit()
            except:
                pass
            self.r2 = None
            self.is_connected = False
    
    def execute_command(self, command: str) -> Optional[str]:
        """
        Execute a Radare2 command and return the output.
        
        Args:
            command: Radare2 command to execute
            
        Returns:
            Command output as string, or None if error
        """
        if not self.is_connected or not self.r2:
            print("Error: Not connected to Radare2")
            return None
        
        try:
            result = self.r2.cmd(command)
            return result
        except Exception as e:
            print(f"Error executing command '{command}': {e}")
            return None
    
    def execute_json_command(self, command: str) -> Optional[Any]:
        """
        Execute a Radare2 command that returns JSON output.
        
        Args:
            command: Radare2 command to execute (typically ends with 'j')
            
        Returns:
            Parsed JSON data, or None if error
        """
        if not self.is_connected or not self.r2:
            print("Error: Not connected to Radare2")
            return None
        
        try:
            result = self.r2.cmdj(command)
            return result
        except Exception as e:
            print(f"Error executing JSON command '{command}': {e}")
            return None
    
    def analyze(self, level: str = 'aa') -> bool:
        """
        Run Radare2 analysis on the binary.
        
        Args:
            level: Analysis level
                   'aa' - basic analysis
                   'aaa' - more analysis
                   'aaaa' - even more analysis
                   'aaaaa' - experimental analysis
                   
        Returns:
            True if analysis successful, False otherwise
        """
        if not self.is_connected:
            print("Error: Not connected to Radare2")
            return False
        
        try:
            print(f"Running Radare2 analysis: {level}")
            self.execute_command(level)
            print("Analysis complete")
            return True
        except Exception as e:
            print(f"Error during analysis: {e}")
            return False
    
    def import_analysis(self) -> bool:
        """
        Import all analysis data from Radare2.
        
        Imports functions, flags, strings, xrefs, sections, and binary info.
        
        Returns:
            True if import successful, False otherwise
        """
        if not self.is_connected:
            print("Error: Not connected to Radare2")
            return False
        
        try:
            # Import binary info
            self.info = self.execute_json_command('ij') or {}
            
            # Import sections
            sections_data = self.execute_json_command('iSj')
            if sections_data:
                self.sections = []
                for sec in sections_data:
                    section = R2Section(
                        name=sec.get('name', ''),
                        vaddr=sec.get('vaddr', 0),
                        vsize=sec.get('vsize', 0),
                        paddr=sec.get('paddr', 0),
                        size=sec.get('size', 0),
                        permissions=sec.get('perm', '---')
                    )
                    self.sections.append(section)
            
            # Import functions
            functions_data = self.execute_json_command('aflj')
            if functions_data:
                self.functions = {}
                for func in functions_data:
                    address = func.get('offset', 0)
                    r2_func = R2Function(
                        address=address,
                        name=func.get('name', f'fcn.{address:08x}'),
                        size=func.get('size', 0),
                        offset=func.get('offset'),
                        signature=func.get('signature'),
                        is_import=func.get('is-import', False),
                        is_pure=func.get('is-pure', False)
                    )
                    
                    # Get function calls
                    if 'callrefs' in func:
                        r2_func.callrefs = [ref.get('addr', 0) for ref in func['callrefs']]
                    if 'codexrefs' in func:
                        r2_func.codexrefs = [ref.get('addr', 0) for ref in func['codexrefs']]
                    if 'datarefs' in func:
                        r2_func.datarefs = [ref.get('addr', 0) for ref in func['datarefs']]
                    
                    self.functions[address] = r2_func
                    
                    # Preserve function metadata as annotations
                    if func.get('signature') or func.get('comment'):
                        self.preserve_annotations(address, {
                            'signature': func.get('signature'),
                            'comment': func.get('comment'),
                            'source': 'radare2'
                        })
            
            # Import flags (symbols/labels)
            flags_data = self.execute_json_command('fj')
            if flags_data:
                self.flags = {}
                for flag in flags_data:
                    address = flag.get('offset', 0)
                    r2_flag = R2Flag(
                        address=address,
                        name=flag.get('name', f'flag_{address:08x}'),
                        size=flag.get('size', 1),
                        realname=flag.get('realname')
                    )
                    self.flags[address] = r2_flag
            
            # Import strings
            strings_data = self.execute_json_command('izj')
            if strings_data:
                self.strings = []
                for string in strings_data:
                    r2_string = R2String(
                        address=string.get('vaddr', 0),
                        string=string.get('string', ''),
                        length=string.get('length', 0),
                        size=string.get('size', 0),
                        section=string.get('section'),
                        type=string.get('type', 'ascii')
                    )
                    self.strings.append(r2_string)
            
            # Import cross-references
            # Note: r2 xrefs are per-function, so we collect them all
            self.xrefs = []
            for func_addr in self.functions.keys():
                xrefs_data = self.execute_json_command(f'axtj @ {func_addr}')
                if xrefs_data:
                    for xref in xrefs_data:
                        r2_xref = R2XRef(
                            from_address=xref.get('from', 0),
                            to_address=xref.get('to', func_addr),
                            xref_type=xref.get('type', 'UNKNOWN')
                        )
                        self.xrefs.append(r2_xref)
            
            print("Successfully imported Radare2 analysis data")
            return True
            
        except Exception as e:
            print(f"Error importing analysis: {e}")
            return False
    
    def export_to_radare2(self, functions: Optional[Dict[int, Any]] = None,
                          flags: Optional[Dict[int, Any]] = None,
                          comments: Optional[Dict[int, str]] = None) -> bool:
        """
        Export DissectX analysis data to Radare2.
        
        Sends function names, flags, and comments to Radare2 via r2pipe.
        
        Args:
            functions: Dictionary of function data to export
            flags: Dictionary of flag/symbol data to export
            comments: Dictionary of comments to export (address -> comment)
            
        Returns:
            True if export successful, False otherwise
        """
        if not self.is_connected:
            print("Error: Not connected to Radare2")
            return False
        
        try:
            # Export functions
            if functions:
                print("Exporting functions to Radare2...")
                for addr, func_data in functions.items():
                    name = func_data.get('name', f'fcn_{addr:08x}')
                    
                    # Create function if it doesn't exist
                    self.execute_command(f'af @ {addr}')
                    
                    # Rename function
                    self.execute_command(f'afn {name} @ {addr}')
                    
                    # Add function comment if present
                    if 'comment' in func_data and func_data['comment']:
                        comment = func_data['comment'].replace('"', '\\"')
                        self.execute_command(f'CCu "{comment}" @ {addr}')
            
            # Export flags/symbols
            if flags:
                print("Exporting flags to Radare2...")
                for addr, flag_data in flags.items():
                    name = flag_data.get('name', f'flag_{addr:08x}')
                    size = flag_data.get('size', 1)
                    
                    # Create flag
                    self.execute_command(f'f {name} {size} @ {addr}')
            
            # Export comments
            if comments:
                print("Exporting comments to Radare2...")
                for addr, comment_text in comments.items():
                    comment = comment_text.replace('"', '\\"')
                    self.execute_command(f'CCu "{comment}" @ {addr}')
            
            print("Export to Radare2 complete")
            return True
            
        except Exception as e:
            print(f"Error exporting to Radare2: {e}")
            return False
    
    def import_from_json(self, json_path: str) -> bool:
        """
        Import Radare2 analysis data from JSON file.
        
        Args:
            json_path: Path to JSON file with Radare2 data
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Import info
            if 'info' in data:
                self.info = data['info']
            
            # Import sections
            if 'sections' in data:
                self.sections = []
                for sec_data in data['sections']:
                    section = R2Section(
                        name=sec_data['name'],
                        vaddr=int(sec_data['vaddr'], 16) if isinstance(sec_data['vaddr'], str) else sec_data['vaddr'],
                        vsize=sec_data['vsize'],
                        paddr=int(sec_data['paddr'], 16) if isinstance(sec_data['paddr'], str) else sec_data['paddr'],
                        size=sec_data['size'],
                        permissions=sec_data['permissions']
                    )
                    self.sections.append(section)
            
            # Import functions
            if 'functions' in data:
                self.functions = {}
                for func_data in data['functions']:
                    address = int(func_data['address'], 16) if isinstance(func_data['address'], str) else func_data['address']
                    
                    func = R2Function(
                        address=address,
                        name=func_data['name'],
                        size=func_data.get('size', 0),
                        offset=func_data.get('offset'),
                        signature=func_data.get('signature'),
                        comment=func_data.get('comment'),
                        is_import=func_data.get('is_import', False),
                        is_pure=func_data.get('is_pure', False)
                    )
                    
                    # Parse hex addresses in lists
                    if 'calls' in func_data:
                        func.calls = [int(c, 16) if isinstance(c, str) else c for c in func_data['calls']]
                    if 'callrefs' in func_data:
                        func.callrefs = [int(c, 16) if isinstance(c, str) else c for c in func_data['callrefs']]
                    if 'datarefs' in func_data:
                        func.datarefs = [int(d, 16) if isinstance(d, str) else d for d in func_data['datarefs']]
                    if 'codexrefs' in func_data:
                        func.codexrefs = [int(c, 16) if isinstance(c, str) else c for c in func_data['codexrefs']]
                    
                    self.functions[address] = func
            
            # Import flags
            if 'flags' in data:
                self.flags = {}
                for flag_data in data['flags']:
                    address = int(flag_data['address'], 16) if isinstance(flag_data['address'], str) else flag_data['address']
                    
                    flag = R2Flag(
                        address=address,
                        name=flag_data['name'],
                        size=flag_data.get('size', 1),
                        realname=flag_data.get('realname')
                    )
                    self.flags[address] = flag
            
            # Import strings
            if 'strings' in data:
                self.strings = []
                for string_data in data['strings']:
                    address = int(string_data['address'], 16) if isinstance(string_data['address'], str) else string_data['address']
                    
                    string = R2String(
                        address=address,
                        string=string_data['string'],
                        length=string_data['length'],
                        size=string_data['size'],
                        section=string_data.get('section'),
                        type=string_data.get('type', 'ascii')
                    )
                    self.strings.append(string)
            
            # Import xrefs
            if 'xrefs' in data:
                self.xrefs = []
                for xref_data in data['xrefs']:
                    from_addr = int(xref_data['from'], 16) if isinstance(xref_data['from'], str) else xref_data['from']
                    to_addr = int(xref_data['to'], 16) if isinstance(xref_data['to'], str) else xref_data['to']
                    
                    xref = R2XRef(
                        from_address=from_addr,
                        to_address=to_addr,
                        xref_type=xref_data['type']
                    )
                    self.xrefs.append(xref)
            
            print(f"Successfully imported Radare2 data from {json_path}")
            return True
            
        except Exception as e:
            print(f"Error importing from JSON: {e}")
            return False
    
    def export_to_json(self, output_path: str) -> bool:
        """
        Export current Radare2 data to JSON format.
        
        Args:
            output_path: Path to write JSON file
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            data = {
                'info': self.info,
                'sections': [sec.to_dict() for sec in self.sections],
                'functions': [func.to_dict() for func in self.functions.values()],
                'flags': [flag.to_dict() for flag in self.flags.values()],
                'strings': [string.to_dict() for string in self.strings],
                'xrefs': [xref.to_dict() for xref in self.xrefs]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            print(f"Successfully exported to {output_path}")
            return True
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
    
    def get_function(self, address: int) -> Optional[R2Function]:
        """
        Get function at specified address.
        
        Args:
            address: Function address
            
        Returns:
            R2Function if found, None otherwise
        """
        return self.functions.get(address)
    
    def get_flag(self, address: int) -> Optional[R2Flag]:
        """
        Get flag at specified address.
        
        Args:
            address: Flag address
            
        Returns:
            R2Flag if found, None otherwise
        """
        return self.flags.get(address)
    
    def get_strings(self) -> List[R2String]:
        """
        Get all imported strings.
        
        Returns:
            List of R2String objects
        """
        return self.strings
    
    def get_xrefs_to(self, address: int) -> List[R2XRef]:
        """
        Get all cross-references to specified address.
        
        Args:
            address: Target address
            
        Returns:
            List of R2XRef objects pointing to address
        """
        return [xref for xref in self.xrefs if xref.to_address == address]
    
    def get_xrefs_from(self, address: int) -> List[R2XRef]:
        """
        Get all cross-references from specified address.
        
        Args:
            address: Source address
            
        Returns:
            List of R2XRef objects originating from address
        """
        return [xref for xref in self.xrefs if xref.from_address == address]
    
    def get_all_functions(self) -> List[R2Function]:
        """
        Get all imported functions.
        
        Returns:
            List of all R2Function objects
        """
        return list(self.functions.values())
    
    def get_all_flags(self) -> List[R2Flag]:
        """
        Get all imported flags.
        
        Returns:
            List of all R2Flag objects
        """
        return list(self.flags.values())
    
    def get_binary_info(self) -> Dict[str, Any]:
        """
        Get binary information from Radare2.
        
        Returns:
            Dictionary with binary info (architecture, format, etc.)
        """
        return self.info
    
    def disassemble_at(self, address: int, count: int = 10) -> Optional[str]:
        """
        Disassemble instructions at specified address.
        
        Args:
            address: Address to disassemble
            count: Number of instructions to disassemble
            
        Returns:
            Disassembly output as string, or None if error
        """
        if not self.is_connected:
            print("Error: Not connected to Radare2")
            return None
        
        return self.execute_command(f'pd {count} @ {address}')
    
    def seek(self, address: int) -> bool:
        """
        Seek to specified address in Radare2.
        
        Args:
            address: Address to seek to
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected:
            print("Error: Not connected to Radare2")
            return False
        
        result = self.execute_command(f's {address}')
        return result is not None
    
    def generate_radare2_naming_convention(self, name: str, address: int,
                                          entity_type: str = 'function',
                                          metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a name following Radare2 naming conventions.
        
        Uses the unified naming convention adapter for consistent naming.
        
        Radare2 uses specific naming patterns:
        - Functions: fcn.<address>, sym.<name>
        - Flags: flag.<address>
        - Strings: str.<content>
        - Imports: sym.imp.<name>
        
        Args:
            name: Original name
            address: Entity address
            entity_type: Type of entity ('function', 'flag', 'string', 'import')
            metadata: Optional metadata about the entity
            
        Returns:
            Radare2-compatible name
        """
        # Map string entity type to EntityType enum
        entity_type_map = {
            'function': EntityType.FUNCTION,
            'flag': EntityType.LABEL,
            'label': EntityType.LABEL,
            'string': EntityType.STRING,
            'import': EntityType.IMPORT
        }
        
        enum_type = entity_type_map.get(entity_type, EntityType.FUNCTION)
        
        # Create NamedEntity
        entity = NamedEntity(
            address=address,
            name=name,
            entity_type=enum_type,
            metadata=metadata or {}
        )
        
        # Use naming adapter
        return self.naming_adapter.to_tool_name(entity)
    
    def preserve_annotations(self, address: int, annotations: Dict[str, Any]):
        """
        Preserve annotations from external tool during import.
        
        This ensures that user-defined comments, bookmarks, and other
        annotations are maintained when importing from Radare2.
        
        Args:
            address: Address of the annotated entity
            annotations: Dictionary of annotations to preserve
        """
        if address not in self.preserved_annotations:
            self.preserved_annotations[address] = {}
        self.preserved_annotations[address].update(annotations)
    
    def get_preserved_annotations(self, address: int) -> Dict[str, Any]:
        """
        Get preserved annotations for an address.
        
        Args:
            address: Address to get annotations for
            
        Returns:
            Dictionary of preserved annotations
        """
        return self.preserved_annotations.get(address, {})
    
    def merge_annotations(self, address: int, new_annotations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge new annotations with preserved annotations.
        
        Preserved annotations take precedence over new ones to maintain
        user-defined data from external tools.
        
        Args:
            address: Address of the entity
            new_annotations: New annotations to merge
            
        Returns:
            Merged annotations dictionary
        """
        preserved = self.preserved_annotations.get(address, {})
        merged = new_annotations.copy()
        merged.update(preserved)  # Preserved takes precedence
        return merged
    
    def clear(self):
        """Clear all imported data"""
        self.functions.clear()
        self.flags.clear()
        self.strings.clear()
        self.xrefs.clear()
        self.sections.clear()
        self.info.clear()
        self.preserved_annotations.clear()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup connection"""
        self.disconnect()
        return False
