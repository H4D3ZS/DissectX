"""
Ghidra Integration for DissectX

This module provides integration with Ghidra reverse engineering tool,
allowing import of Ghidra decompilation results and export of DissectX
analysis as Ghidra scripts.
"""
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from enum import Enum

# Import naming convention adapters
try:
    from .naming_conventions import (
        GhidraNamingAdapter, NamedEntity, EntityType, ToolType
    )
except ImportError:
    # Fallback if running standalone
    from naming_conventions import (
        GhidraNamingAdapter, NamedEntity, EntityType, ToolType
    )


class GhidraDataType(Enum):
    """Ghidra data types"""
    BYTE = "byte"
    WORD = "word"
    DWORD = "dword"
    QWORD = "qword"
    POINTER = "pointer"
    STRING = "string"
    STRUCT = "struct"
    ARRAY = "array"
    UNDEFINED = "undefined"


@dataclass
class GhidraFunction:
    """Represents a function in Ghidra format"""
    address: int
    name: str
    signature: Optional[str] = None
    decompiled_code: Optional[str] = None
    comment: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    local_variables: List[Dict[str, Any]] = field(default_factory=list)
    return_type: Optional[str] = None
    calling_convention: Optional[str] = None
    is_thunk: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'signature': self.signature,
            'decompiled_code': self.decompiled_code,
            'comment': self.comment,
            'parameters': self.parameters,
            'local_variables': self.local_variables,
            'return_type': self.return_type,
            'calling_convention': self.calling_convention,
            'is_thunk': self.is_thunk
        }


@dataclass
class GhidraSymbol:
    """Represents a symbol (label) in Ghidra"""
    address: int
    name: str
    symbol_type: str  # 'function', 'label', 'data', etc.
    namespace: Optional[str] = None
    is_external: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'type': self.symbol_type,
            'namespace': self.namespace,
            'is_external': self.is_external
        }


@dataclass
class GhidraComment:
    """Represents a comment in Ghidra"""
    address: int
    comment_type: str  # 'EOL', 'PRE', 'POST', 'PLATE', 'REPEATABLE'
    text: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'type': self.comment_type,
            'text': self.text
        }


@dataclass
class GhidraDataDefinition:
    """Represents a data definition in Ghidra"""
    address: int
    data_type: GhidraDataType
    size: int
    name: Optional[str] = None
    value: Optional[Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'data_type': self.data_type.value,
            'size': self.size,
            'name': self.name,
            'value': str(self.value) if self.value is not None else None
        }


@dataclass
class GhidraXRef:
    """Represents a cross-reference in Ghidra"""
    from_address: int
    to_address: int
    xref_type: str  # 'CALL', 'JUMP', 'READ', 'WRITE', 'DATA'
    is_user_defined: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'from': hex(self.from_address),
            'to': hex(self.to_address),
            'type': self.xref_type,
            'user_defined': self.is_user_defined
        }


class GhidraIntegration:
    """
    Integration with Ghidra reverse engineering tool.
    
    Provides functionality to:
    - Import Ghidra decompilation results
    - Import Ghidra analysis data (functions, symbols, comments, xrefs)
    - Export DissectX analysis as Ghidra Python scripts
    - Generate Ghidra-compatible naming conventions
    """
    
    def __init__(self):
        """Initialize Ghidra integration"""
        self.functions: Dict[int, GhidraFunction] = {}
        self.symbols: Dict[int, GhidraSymbol] = {}
        self.comments: Dict[int, List[GhidraComment]] = {}
        self.data_definitions: Dict[int, GhidraDataDefinition] = {}
        self.xrefs: List[GhidraXRef] = []
        self.program_name: Optional[str] = None
        self.base_address: int = 0
        self.naming_adapter = GhidraNamingAdapter()
        self.preserved_annotations: Dict[int, Dict[str, Any]] = {}  # For annotation preservation
    
    def import_from_json(self, json_path: str) -> bool:
        """
        Import Ghidra analysis data from JSON export.
        
        Ghidra can export analysis data to JSON format using custom scripts.
        This method imports that data into DissectX format.
        
        Args:
            json_path: Path to JSON file exported from Ghidra
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Import program metadata
            if 'program' in data:
                self.program_name = data['program'].get('name')
                base_addr_str = data['program'].get('base_address', '0x0')
                self.base_address = int(base_addr_str, 16) if isinstance(base_addr_str, str) else base_addr_str
            
            # Import functions
            if 'functions' in data:
                for func_data in data['functions']:
                    func = self._parse_function_from_json(func_data)
                    if func:
                        self.functions[func.address] = func
            
            # Import symbols
            if 'symbols' in data:
                for sym_data in data['symbols']:
                    sym = self._parse_symbol_from_json(sym_data)
                    if sym:
                        self.symbols[sym.address] = sym
            
            # Import comments
            if 'comments' in data:
                for comment_data in data['comments']:
                    comment = self._parse_comment_from_json(comment_data)
                    if comment:
                        if comment.address not in self.comments:
                            self.comments[comment.address] = []
                        self.comments[comment.address].append(comment)
                        
                        # Preserve comment as annotation
                        self.preserve_annotations(comment.address, {
                            'comment': comment.text,
                            'comment_type': comment.comment_type,
                            'source': 'ghidra'
                        })
            
            # Import data definitions
            if 'data' in data:
                for data_def in data['data']:
                    dd = self._parse_data_definition_from_json(data_def)
                    if dd:
                        self.data_definitions[dd.address] = dd
            
            # Import cross-references
            if 'xrefs' in data:
                for xref_data in data['xrefs']:
                    xref = self._parse_xref_from_json(xref_data)
                    if xref:
                        self.xrefs.append(xref)
            
            return True
            
        except Exception as e:
            print(f"Error importing Ghidra JSON: {e}")
            return False
    
    def _parse_function_from_json(self, data: Dict[str, Any]) -> Optional[GhidraFunction]:
        """Parse function from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            return GhidraFunction(
                address=address,
                name=data.get('name', f'FUN_{address:08x}'),
                signature=data.get('signature'),
                decompiled_code=data.get('decompiled_code'),
                comment=data.get('comment'),
                parameters=data.get('parameters', []),
                local_variables=data.get('local_variables', []),
                return_type=data.get('return_type'),
                calling_convention=data.get('calling_convention'),
                is_thunk=data.get('is_thunk', False)
            )
        except Exception as e:
            print(f"Error parsing function: {e}")
            return None
    
    def _parse_symbol_from_json(self, data: Dict[str, Any]) -> Optional[GhidraSymbol]:
        """Parse symbol from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            return GhidraSymbol(
                address=address,
                name=data['name'],
                symbol_type=data.get('type', 'label'),
                namespace=data.get('namespace'),
                is_external=data.get('is_external', False)
            )
        except Exception as e:
            print(f"Error parsing symbol: {e}")
            return None
    
    def _parse_comment_from_json(self, data: Dict[str, Any]) -> Optional[GhidraComment]:
        """Parse comment from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            return GhidraComment(
                address=address,
                comment_type=data.get('type', 'EOL'),
                text=data['text']
            )
        except Exception as e:
            print(f"Error parsing comment: {e}")
            return None
    
    def _parse_data_definition_from_json(self, data: Dict[str, Any]) -> Optional[GhidraDataDefinition]:
        """Parse data definition from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            # Parse data type
            data_type_str = data.get('data_type', 'undefined')
            try:
                data_type = GhidraDataType(data_type_str)
            except ValueError:
                data_type = GhidraDataType.UNDEFINED
            
            return GhidraDataDefinition(
                address=address,
                data_type=data_type,
                size=data.get('size', 1),
                name=data.get('name'),
                value=data.get('value')
            )
        except Exception as e:
            print(f"Error parsing data definition: {e}")
            return None
    
    def _parse_xref_from_json(self, data: Dict[str, Any]) -> Optional[GhidraXRef]:
        """Parse cross-reference from JSON data"""
        try:
            from_addr = int(data['from'], 16) if isinstance(data['from'], str) else data['from']
            to_addr = int(data['to'], 16) if isinstance(data['to'], str) else data['to']
            
            return GhidraXRef(
                from_address=from_addr,
                to_address=to_addr,
                xref_type=data.get('type', 'DATA'),
                is_user_defined=data.get('user_defined', False)
            )
        except Exception as e:
            print(f"Error parsing xref: {e}")
            return None

    def import_from_xml(self, xml_path: str) -> bool:
        """
        Import Ghidra analysis data from XML export.
        
        Ghidra can export program data to XML format.
        This method imports that data into DissectX format.
        
        Args:
            xml_path: Path to XML file exported from Ghidra
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            # Import program metadata
            program_elem = root.find('PROGRAM')
            if program_elem is not None:
                self.program_name = program_elem.get('NAME')
                base_addr_str = program_elem.get('IMAGE_BASE', '0x0')
                self.base_address = int(base_addr_str, 16)
            
            # Import functions
            functions_elem = root.find('FUNCTIONS')
            if functions_elem is not None:
                for func_elem in functions_elem.findall('FUNCTION'):
                    func = self._parse_function_from_xml(func_elem)
                    if func:
                        self.functions[func.address] = func
            
            # Import symbols
            symbols_elem = root.find('SYMBOLS')
            if symbols_elem is not None:
                for sym_elem in symbols_elem.findall('SYMBOL'):
                    sym = self._parse_symbol_from_xml(sym_elem)
                    if sym:
                        self.symbols[sym.address] = sym
            
            # Import comments
            comments_elem = root.find('COMMENTS')
            if comments_elem is not None:
                for comment_elem in comments_elem.findall('COMMENT'):
                    comment = self._parse_comment_from_xml(comment_elem)
                    if comment:
                        if comment.address not in self.comments:
                            self.comments[comment.address] = []
                        self.comments[comment.address].append(comment)
            
            return True
            
        except Exception as e:
            print(f"Error importing Ghidra XML: {e}")
            return False
    
    def _parse_function_from_xml(self, elem: ET.Element) -> Optional[GhidraFunction]:
        """Parse function from XML element"""
        try:
            address = int(elem.get('ENTRY_POINT', '0'), 16)
            name = elem.get('NAME', f'FUN_{address:08x}')
            
            return GhidraFunction(
                address=address,
                name=name,
                signature=elem.get('SIGNATURE'),
                comment=elem.get('COMMENT'),
                return_type=elem.get('RETURN_TYPE'),
                calling_convention=elem.get('CALLING_CONVENTION'),
                is_thunk=elem.get('THUNK', 'false').lower() == 'true'
            )
        except Exception as e:
            print(f"Error parsing function from XML: {e}")
            return None
    
    def _parse_symbol_from_xml(self, elem: ET.Element) -> Optional[GhidraSymbol]:
        """Parse symbol from XML element"""
        try:
            address = int(elem.get('ADDRESS', '0'), 16)
            name = elem.get('NAME', '')
            
            return GhidraSymbol(
                address=address,
                name=name,
                symbol_type=elem.get('TYPE', 'label'),
                namespace=elem.get('NAMESPACE'),
                is_external=elem.get('EXTERNAL', 'false').lower() == 'true'
            )
        except Exception as e:
            print(f"Error parsing symbol from XML: {e}")
            return None
    
    def _parse_comment_from_xml(self, elem: ET.Element) -> Optional[GhidraComment]:
        """Parse comment from XML element"""
        try:
            address = int(elem.get('ADDRESS', '0'), 16)
            
            return GhidraComment(
                address=address,
                comment_type=elem.get('TYPE', 'EOL'),
                text=elem.text or ''
            )
        except Exception as e:
            print(f"Error parsing comment from XML: {e}")
            return None
    
    def export_to_python_script(self, output_path: str, 
                                 functions: Optional[Dict[int, Any]] = None,
                                 symbols: Optional[Dict[int, Any]] = None,
                                 comments: Optional[Dict[int, List[str]]] = None,
                                 xrefs: Optional[List[Dict[str, Any]]] = None) -> bool:
        """
        Export DissectX analysis as a Ghidra Python script.
        
        Generates a Python script that can be run in Ghidra to apply
        DissectX analysis results (function names, comments, etc.).
        
        Args:
            output_path: Path to write the Python script
            functions: Dictionary of function data to export
            symbols: Dictionary of symbol data to export
            comments: Dictionary of comments to export
            xrefs: List of cross-references to export
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            lines = []
            
            # Script header
            lines.append("# Ghidra Python Script - Generated by DissectX")
            lines.append("# This script applies DissectX analysis results to the current program")
            lines.append("")
            lines.append("from ghidra.program.model.symbol import SourceType")
            lines.append("from ghidra.program.model.listing import CodeUnit")
            lines.append("")
            lines.append("# Get current program")
            lines.append("program = getCurrentProgram()")
            lines.append("listing = program.getListing()")
            lines.append("symbolTable = program.getSymbolTable()")
            lines.append("functionManager = program.getFunctionManager()")
            lines.append("")
            lines.append("# Start transaction")
            lines.append("transaction = program.startTransaction('Apply DissectX Analysis')")
            lines.append("try:")
            lines.append("")
            
            # Export functions
            if functions:
                lines.append("    # Create/rename functions")
                for addr, func_data in sorted(functions.items()):
                    name = func_data.get('name', f'FUN_{addr:08x}')
                    lines.append(f"    # Function at 0x{addr:x}")
                    lines.append(f"    addr = toAddr(0x{addr:x})")
                    lines.append(f"    func = functionManager.getFunctionAt(addr)")
                    lines.append(f"    if func is None:")
                    lines.append(f"        func = createFunction(addr, '{name}')")
                    lines.append(f"    else:")
                    lines.append(f"        func.setName('{name}', SourceType.USER_DEFINED)")
                    
                    # Add function comment if present
                    if 'comment' in func_data and func_data['comment']:
                        comment_text = func_data['comment'].replace("'", "\\'")
                        lines.append(f"        func.setComment('{comment_text}')")
                    
                    lines.append("")
            
            # Export symbols/labels
            if symbols:
                lines.append("    # Create symbols/labels")
                for addr, sym_data in sorted(symbols.items()):
                    name = sym_data.get('name', f'LAB_{addr:08x}')
                    lines.append(f"    # Symbol at 0x{addr:x}")
                    lines.append(f"    addr = toAddr(0x{addr:x})")
                    lines.append(f"    symbolTable.createLabel(addr, '{name}', SourceType.USER_DEFINED)")
                    lines.append("")
            
            # Export comments
            if comments:
                lines.append("    # Add comments")
                for addr, comment_list in sorted(comments.items()):
                    for comment_text in comment_list:
                        comment_text = comment_text.replace("'", "\\'")
                        lines.append(f"    # Comment at 0x{addr:x}")
                        lines.append(f"    addr = toAddr(0x{addr:x})")
                        lines.append(f"    codeUnit = listing.getCodeUnitAt(addr)")
                        lines.append(f"    if codeUnit is not None:")
                        lines.append(f"        codeUnit.setComment(CodeUnit.EOL_COMMENT, '{comment_text}')")
                        lines.append("")
            
            # Export cross-references (if provided)
            if xrefs:
                lines.append("    # Add cross-references")
                lines.append("    refManager = program.getReferenceManager()")
                for xref in xrefs:
                    from_addr = xref.get('from_address', 0)
                    to_addr = xref.get('to_address', 0)
                    xref_type = xref.get('type', 'DATA')
                    
                    lines.append(f"    # XRef from 0x{from_addr:x} to 0x{to_addr:x}")
                    lines.append(f"    fromAddr = toAddr(0x{from_addr:x})")
                    lines.append(f"    toAddr = toAddr(0x{to_addr:x})")
                    lines.append(f"    # refManager.addMemoryReference(fromAddr, toAddr, ...)")
                    lines.append("")
            
            # Script footer
            lines.append("    # Commit transaction")
            lines.append("    program.endTransaction(transaction, True)")
            lines.append("    print('DissectX analysis applied successfully!')")
            lines.append("")
            lines.append("except Exception as e:")
            lines.append("    # Rollback on error")
            lines.append("    program.endTransaction(transaction, False)")
            lines.append("    print('Error applying analysis: ' + str(e))")
            lines.append("    raise")
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            return True
            
        except Exception as e:
            print(f"Error exporting Ghidra Python script: {e}")
            return False
    
    def export_to_json(self, output_path: str) -> bool:
        """
        Export current Ghidra data to JSON format.
        
        Args:
            output_path: Path to write JSON file
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            data = {
                'program': {
                    'name': self.program_name,
                    'base_address': hex(self.base_address)
                },
                'functions': [func.to_dict() for func in self.functions.values()],
                'symbols': [sym.to_dict() for sym in self.symbols.values()],
                'comments': [
                    comment.to_dict() 
                    for comment_list in self.comments.values() 
                    for comment in comment_list
                ],
                'data': [dd.to_dict() for dd in self.data_definitions.values()],
                'xrefs': [xref.to_dict() for xref in self.xrefs]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
    
    def get_function(self, address: int) -> Optional[GhidraFunction]:
        """
        Get function at specified address.
        
        Args:
            address: Function address
            
        Returns:
            GhidraFunction if found, None otherwise
        """
        return self.functions.get(address)
    
    def get_symbol(self, address: int) -> Optional[GhidraSymbol]:
        """
        Get symbol at specified address.
        
        Args:
            address: Symbol address
            
        Returns:
            GhidraSymbol if found, None otherwise
        """
        return self.symbols.get(address)
    
    def get_comments(self, address: int) -> List[GhidraComment]:
        """
        Get all comments at specified address.
        
        Args:
            address: Address to get comments for
            
        Returns:
            List of GhidraComment objects
        """
        return self.comments.get(address, [])
    
    def get_decompiled_code(self, address: int) -> Optional[str]:
        """
        Get decompiled code for function at address.
        
        Args:
            address: Function address
            
        Returns:
            Decompiled code string if available, None otherwise
        """
        func = self.functions.get(address)
        return func.decompiled_code if func else None
    
    def get_all_functions(self) -> List[GhidraFunction]:
        """
        Get all imported functions.
        
        Returns:
            List of all GhidraFunction objects
        """
        return list(self.functions.values())
    
    def get_all_symbols(self) -> List[GhidraSymbol]:
        """
        Get all imported symbols.
        
        Returns:
            List of all GhidraSymbol objects
        """
        return list(self.symbols.values())
    
    def get_xrefs_from(self, address: int) -> List[GhidraXRef]:
        """
        Get all cross-references from specified address.
        
        Args:
            address: Source address
            
        Returns:
            List of GhidraXRef objects originating from address
        """
        return [xref for xref in self.xrefs if xref.from_address == address]
    
    def get_xrefs_to(self, address: int) -> List[GhidraXRef]:
        """
        Get all cross-references to specified address.
        
        Args:
            address: Target address
            
        Returns:
            List of GhidraXRef objects pointing to address
        """
        return [xref for xref in self.xrefs if xref.to_address == address]
    
    def generate_ghidra_naming_convention(self, name: str, address: int, 
                                         entity_type: str = 'function',
                                         metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a name following Ghidra naming conventions.
        
        Uses the unified naming convention adapter for consistent naming.
        
        Ghidra uses specific naming patterns:
        - Functions: FUN_<address>
        - Labels: LAB_<address>
        - Data: DAT_<address>
        - Strings: s_<content>_<address>
        
        Args:
            name: Original name
            address: Entity address
            entity_type: Type of entity ('function', 'label', 'data', 'string')
            metadata: Optional metadata about the entity
            
        Returns:
            Ghidra-compatible name
        """
        # Map string entity type to EntityType enum
        entity_type_map = {
            'function': EntityType.FUNCTION,
            'label': EntityType.LABEL,
            'data': EntityType.DATA,
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
    
    def generate_import_script(self, output_path: str) -> bool:
        """
        Generate a Ghidra script to import DissectX analysis.
        
        This creates a comprehensive script that imports all analysis data.
        
        Args:
            output_path: Path to write the import script
            
        Returns:
            True if successful, False otherwise
        """
        # Convert internal data to export format
        functions_dict = {addr: func.to_dict() for addr, func in self.functions.items()}
        symbols_dict = {addr: sym.to_dict() for addr, sym in self.symbols.items()}
        comments_dict = {addr: [c.text for c in comments] 
                        for addr, comments in self.comments.items()}
        xrefs_list = [xref.to_dict() for xref in self.xrefs]
        
        return self.export_to_python_script(
            output_path,
            functions=functions_dict,
            symbols=symbols_dict,
            comments=comments_dict,
            xrefs=xrefs_list
        )
    
    def preserve_annotations(self, address: int, annotations: Dict[str, Any]):
        """
        Preserve annotations from external tool during import.
        
        This ensures that user-defined comments, bookmarks, and other
        annotations are maintained when importing from Ghidra.
        
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
        self.symbols.clear()
        self.comments.clear()
        self.data_definitions.clear()
        self.xrefs.clear()
        self.preserved_annotations.clear()
        self.program_name = None
        self.base_address = 0
