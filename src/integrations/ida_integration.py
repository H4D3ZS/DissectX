"""
IDA Pro Integration for DissectX

This module provides integration with IDA Pro reverse engineering tool,
allowing import of IDA database (.idb/.i64) data and export of DissectX
analysis as IDA Python scripts.
"""
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import json
import struct
from enum import Enum

# Import naming convention adapters
try:
    from .naming_conventions import (
        IDANamingAdapter, NamedEntity, EntityType, ToolType
    )
except ImportError:
    # Fallback if running standalone
    from naming_conventions import (
        IDANamingAdapter, NamedEntity, EntityType, ToolType
    )


class IDADataType(Enum):
    """IDA Pro data types"""
    BYTE = "db"
    WORD = "dw"
    DWORD = "dd"
    QWORD = "dq"
    OWORD = "do"
    FLOAT = "float"
    DOUBLE = "double"
    TBYTE = "dt"
    POINTER = "ptr"
    STRING = "string"
    STRUCT = "struct"
    ARRAY = "array"
    ALIGN = "align"
    UNKNOWN = "unknown"


class IDASegmentType(Enum):
    """IDA Pro segment types"""
    CODE = "CODE"
    DATA = "DATA"
    BSS = "BSS"
    CONST = "CONST"
    EXTERN = "EXTERN"
    UNKNOWN = "UNKNOWN"


@dataclass
class IDAFunction:
    """Represents a function in IDA Pro format"""
    address: int
    name: str
    end_address: Optional[int] = None
    flags: int = 0
    comment: Optional[str] = None
    repeatable_comment: Optional[str] = None
    decompiled_code: Optional[str] = None
    frame_size: int = 0
    local_vars: List[Dict[str, Any]] = field(default_factory=list)
    arguments: List[Dict[str, Any]] = field(default_factory=list)
    return_type: Optional[str] = None
    calling_convention: Optional[str] = None
    is_library: bool = False
    is_thunk: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'end_address': hex(self.end_address) if self.end_address else None,
            'flags': self.flags,
            'comment': self.comment,
            'repeatable_comment': self.repeatable_comment,
            'decompiled_code': self.decompiled_code,
            'frame_size': self.frame_size,
            'local_vars': self.local_vars,
            'arguments': self.arguments,
            'return_type': self.return_type,
            'calling_convention': self.calling_convention,
            'is_library': self.is_library,
            'is_thunk': self.is_thunk
        }


@dataclass
class IDAName:
    """Represents a named location in IDA Pro"""
    address: int
    name: str
    flags: int = 0
    is_public: bool = False
    is_weak: bool = False
    is_code: bool = False
    is_data: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'name': self.name,
            'flags': self.flags,
            'is_public': self.is_public,
            'is_weak': self.is_weak,
            'is_code': self.is_code,
            'is_data': self.is_data
        }


@dataclass
class IDAComment:
    """Represents a comment in IDA Pro"""
    address: int
    comment_type: str  # 'regular', 'repeatable', 'anterior', 'posterior'
    text: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'address': hex(self.address),
            'type': self.comment_type,
            'text': self.text
        }


@dataclass
class IDASegment:
    """Represents a segment in IDA Pro"""
    name: str
    start_address: int
    end_address: int
    segment_type: IDASegmentType
    permissions: str  # e.g., "rwx", "r-x", "rw-"
    bitness: int = 32  # 32 or 64
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'start_address': hex(self.start_address),
            'end_address': hex(self.end_address),
            'type': self.segment_type.value,
            'permissions': self.permissions,
            'bitness': self.bitness
        }


@dataclass
class IDAXRef:
    """Represents a cross-reference in IDA Pro"""
    from_address: int
    to_address: int
    xref_type: str  # 'Code_Near_Call', 'Code_Near_Jump', 'Data_Read', 'Data_Write', etc.
    is_user_defined: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'from': hex(self.from_address),
            'to': hex(self.to_address),
            'type': self.xref_type,
            'user_defined': self.is_user_defined
        }


@dataclass
class IDAStruct:
    """Represents a structure definition in IDA Pro"""
    name: str
    size: int
    members: List[Dict[str, Any]] = field(default_factory=list)
    comment: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'size': self.size,
            'members': self.members,
            'comment': self.comment
        }


@dataclass
class IDAEnum:
    """Represents an enumeration in IDA Pro"""
    name: str
    members: Dict[str, int] = field(default_factory=dict)
    bitfield: bool = False
    comment: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'members': self.members,
            'bitfield': self.bitfield,
            'comment': self.comment
        }


class IDAIntegration:
    """
    Integration with IDA Pro reverse engineering tool.
    
    Provides functionality to:
    - Import IDA database (.idb/.i64) data via JSON export
    - Import IDA analysis data (functions, names, comments, xrefs)
    - Export DissectX analysis as IDA Python scripts
    - Generate IDA-compatible naming conventions
    
    Note: Direct .idb/.i64 parsing requires proprietary libraries.
    This implementation supports JSON-based import/export workflow.
    """
    
    def __init__(self):
        """Initialize IDA Pro integration"""
        self.functions: Dict[int, IDAFunction] = {}
        self.names: Dict[int, IDAName] = {}
        self.comments: Dict[int, List[IDAComment]] = {}
        self.segments: List[IDASegment] = []
        self.xrefs: List[IDAXRef] = []
        self.structs: Dict[str, IDAStruct] = {}
        self.enums: Dict[str, IDAEnum] = {}
        self.database_name: Optional[str] = None
        self.base_address: int = 0
        self.bitness: int = 32  # 32 or 64
        self.processor: Optional[str] = None  # 'metapc', 'ARM', 'MIPS', etc.
        self.naming_adapter = IDANamingAdapter()
        self.preserved_annotations: Dict[int, Dict[str, Any]] = {}  # For annotation preservation
    
    def import_from_json(self, json_path: str) -> bool:
        """
        Import IDA Pro analysis data from JSON export.
        
        IDA Pro can export analysis data to JSON format using IDAPython scripts.
        This method imports that data into DissectX format.
        
        Args:
            json_path: Path to JSON file exported from IDA Pro
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Import database metadata
            if 'database' in data:
                db_info = data['database']
                self.database_name = db_info.get('name')
                base_addr_str = db_info.get('base_address', '0x0')
                self.base_address = int(base_addr_str, 16) if isinstance(base_addr_str, str) else base_addr_str
                self.bitness = db_info.get('bitness', 32)
                self.processor = db_info.get('processor')
            
            # Import segments
            if 'segments' in data:
                for seg_data in data['segments']:
                    seg = self._parse_segment_from_json(seg_data)
                    if seg:
                        self.segments.append(seg)
            
            # Import functions
            if 'functions' in data:
                for func_data in data['functions']:
                    func = self._parse_function_from_json(func_data)
                    if func:
                        self.functions[func.address] = func
            
            # Import names
            if 'names' in data:
                for name_data in data['names']:
                    name = self._parse_name_from_json(name_data)
                    if name:
                        self.names[name.address] = name
            
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
                            'source': 'ida'
                        })
            
            # Import cross-references
            if 'xrefs' in data:
                for xref_data in data['xrefs']:
                    xref = self._parse_xref_from_json(xref_data)
                    if xref:
                        self.xrefs.append(xref)
            
            # Import structures
            if 'structs' in data:
                for struct_data in data['structs']:
                    struct = self._parse_struct_from_json(struct_data)
                    if struct:
                        self.structs[struct.name] = struct
            
            # Import enumerations
            if 'enums' in data:
                for enum_data in data['enums']:
                    enum = self._parse_enum_from_json(enum_data)
                    if enum:
                        self.enums[enum.name] = enum
            
            return True
            
        except Exception as e:
            print(f"Error importing IDA JSON: {e}")
            return False
    
    def _parse_segment_from_json(self, data: Dict[str, Any]) -> Optional[IDASegment]:
        """Parse segment from JSON data"""
        try:
            start_addr = int(data['start_address'], 16) if isinstance(data['start_address'], str) else data['start_address']
            end_addr = int(data['end_address'], 16) if isinstance(data['end_address'], str) else data['end_address']
            
            # Parse segment type
            seg_type_str = data.get('type', 'UNKNOWN')
            try:
                seg_type = IDASegmentType(seg_type_str)
            except ValueError:
                seg_type = IDASegmentType.UNKNOWN
            
            return IDASegment(
                name=data['name'],
                start_address=start_addr,
                end_address=end_addr,
                segment_type=seg_type,
                permissions=data.get('permissions', 'r--'),
                bitness=data.get('bitness', 32)
            )
        except Exception as e:
            print(f"Error parsing segment: {e}")
            return None
    
    def _parse_function_from_json(self, data: Dict[str, Any]) -> Optional[IDAFunction]:
        """Parse function from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            end_addr = None
            if 'end_address' in data and data['end_address']:
                end_addr = int(data['end_address'], 16) if isinstance(data['end_address'], str) else data['end_address']
            
            return IDAFunction(
                address=address,
                name=data.get('name', f'sub_{address:X}'),
                end_address=end_addr,
                flags=data.get('flags', 0),
                comment=data.get('comment'),
                repeatable_comment=data.get('repeatable_comment'),
                decompiled_code=data.get('decompiled_code'),
                frame_size=data.get('frame_size', 0),
                local_vars=data.get('local_vars', []),
                arguments=data.get('arguments', []),
                return_type=data.get('return_type'),
                calling_convention=data.get('calling_convention'),
                is_library=data.get('is_library', False),
                is_thunk=data.get('is_thunk', False)
            )
        except Exception as e:
            print(f"Error parsing function: {e}")
            return None
    
    def _parse_name_from_json(self, data: Dict[str, Any]) -> Optional[IDAName]:
        """Parse name from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            return IDAName(
                address=address,
                name=data['name'],
                flags=data.get('flags', 0),
                is_public=data.get('is_public', False),
                is_weak=data.get('is_weak', False),
                is_code=data.get('is_code', False),
                is_data=data.get('is_data', False)
            )
        except Exception as e:
            print(f"Error parsing name: {e}")
            return None
    
    def _parse_comment_from_json(self, data: Dict[str, Any]) -> Optional[IDAComment]:
        """Parse comment from JSON data"""
        try:
            address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
            
            return IDAComment(
                address=address,
                comment_type=data.get('type', 'regular'),
                text=data['text']
            )
        except Exception as e:
            print(f"Error parsing comment: {e}")
            return None
    
    def _parse_xref_from_json(self, data: Dict[str, Any]) -> Optional[IDAXRef]:
        """Parse cross-reference from JSON data"""
        try:
            from_addr = int(data['from'], 16) if isinstance(data['from'], str) else data['from']
            to_addr = int(data['to'], 16) if isinstance(data['to'], str) else data['to']
            
            return IDAXRef(
                from_address=from_addr,
                to_address=to_addr,
                xref_type=data.get('type', 'Data_Unknown'),
                is_user_defined=data.get('user_defined', False)
            )
        except Exception as e:
            print(f"Error parsing xref: {e}")
            return None
    
    def _parse_struct_from_json(self, data: Dict[str, Any]) -> Optional[IDAStruct]:
        """Parse structure from JSON data"""
        try:
            return IDAStruct(
                name=data['name'],
                size=data['size'],
                members=data.get('members', []),
                comment=data.get('comment')
            )
        except Exception as e:
            print(f"Error parsing struct: {e}")
            return None
    
    def _parse_enum_from_json(self, data: Dict[str, Any]) -> Optional[IDAEnum]:
        """Parse enumeration from JSON data"""
        try:
            return IDAEnum(
                name=data['name'],
                members=data.get('members', {}),
                bitfield=data.get('bitfield', False),
                comment=data.get('comment')
            )
        except Exception as e:
            print(f"Error parsing enum: {e}")
            return None

    def import_from_idb(self, idb_path: str) -> bool:
        """
        Import IDA Pro database (.idb/.i64) file.
        
        Note: Direct .idb parsing requires specialized libraries.
        This method provides a placeholder for future implementation
        or integration with tools like idb-rs or python-idb.
        
        For now, users should export IDA data to JSON format using
        an IDAPython script and use import_from_json() instead.
        
        Args:
            idb_path: Path to .idb or .i64 file
            
        Returns:
            True if import successful, False otherwise
        """
        try:
            # Check file extension
            path = Path(idb_path)
            if path.suffix not in ['.idb', '.i64', '.til', '.id0', '.id1', '.id2', '.nam']:
                print(f"Warning: File {idb_path} may not be an IDA database file")
            
            # Attempt to use python-idb if available
            try:
                import idb
                
                with idb.from_file(idb_path) as db:
                    # Extract database metadata
                    api = idb.IDAPython(db)
                    
                    # Get base address
                    self.base_address = api.get_imagebase()
                    
                    # Get processor type
                    self.processor = api.get_processor_name()
                    
                    # Import functions
                    for func_ea in api.Functions():
                        func_name = api.get_func_name(func_ea)
                        func_end = api.get_func_attr(func_ea, idb.FUNCATTR_END)
                        
                        func = IDAFunction(
                            address=func_ea,
                            name=func_name,
                            end_address=func_end,
                            comment=api.get_func_cmt(func_ea, False),
                            repeatable_comment=api.get_func_cmt(func_ea, True)
                        )
                        self.functions[func_ea] = func
                    
                    # Import names
                    for name_ea, name in api.Names():
                        ida_name = IDAName(
                            address=name_ea,
                            name=name,
                            is_code=api.is_code(api.get_flags(name_ea)),
                            is_data=api.is_data(api.get_flags(name_ea))
                        )
                        self.names[name_ea] = ida_name
                    
                    # Import segments
                    for seg_ea in api.Segments():
                        seg_name = api.get_segm_name(seg_ea)
                        seg_start = api.get_segm_start(seg_ea)
                        seg_end = api.get_segm_end(seg_ea)
                        
                        segment = IDASegment(
                            name=seg_name,
                            start_address=seg_start,
                            end_address=seg_end,
                            segment_type=IDASegmentType.UNKNOWN,
                            permissions="r--"
                        )
                        self.segments.append(segment)
                    
                    print(f"Successfully imported IDB file: {idb_path}")
                    return True
                    
            except ImportError:
                print("python-idb library not available.")
                print("Please install it with: pip install python-idb")
                print("Or export IDA data to JSON and use import_from_json() instead.")
                return False
            except Exception as e:
                print(f"Error using python-idb: {e}")
                print("Consider exporting IDA data to JSON format instead.")
                return False
                
        except Exception as e:
            print(f"Error importing IDB file: {e}")
            return False
    
    def export_to_python_script(self, output_path: str,
                                 functions: Optional[Dict[int, Any]] = None,
                                 names: Optional[Dict[int, Any]] = None,
                                 comments: Optional[Dict[int, List[str]]] = None,
                                 xrefs: Optional[List[Dict[str, Any]]] = None,
                                 structs: Optional[Dict[str, Any]] = None) -> bool:
        """
        Export DissectX analysis as an IDA Python script.
        
        Generates an IDAPython script that can be run in IDA Pro to apply
        DissectX analysis results (function names, comments, structures, etc.).
        
        Args:
            output_path: Path to write the Python script
            functions: Dictionary of function data to export
            names: Dictionary of name data to export
            comments: Dictionary of comments to export
            xrefs: List of cross-references to export
            structs: Dictionary of structure definitions to export
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            lines = []
            
            # Script header
            lines.append("# IDAPython Script - Generated by DissectX")
            lines.append("# This script applies DissectX analysis results to the current database")
            lines.append("#")
            lines.append("# Usage: File -> Script file... -> Select this script")
            lines.append("# Or: Alt+F7 -> Select this script")
            lines.append("")
            lines.append("import ida_bytes")
            lines.append("import ida_funcs")
            lines.append("import ida_name")
            lines.append("import ida_segment")
            lines.append("import ida_struct")
            lines.append("import ida_enum")
            lines.append("import ida_xref")
            lines.append("import idaapi")
            lines.append("import idc")
            lines.append("")
            lines.append("print('Applying DissectX analysis...')")
            lines.append("")
            
            # Export functions
            if functions:
                lines.append("# Create/rename functions")
                lines.append("print('Processing functions...')")
                for addr, func_data in sorted(functions.items()):
                    name = func_data.get('name', f'sub_{addr:X}')
                    lines.append(f"")
                    lines.append(f"# Function at 0x{addr:X}")
                    lines.append(f"ea = 0x{addr:X}")
                    
                    # Create function if it doesn't exist
                    lines.append(f"if not ida_funcs.get_func(ea):")
                    lines.append(f"    ida_funcs.add_func(ea)")
                    
                    # Set function name
                    lines.append(f"ida_name.set_name(ea, '{name}', ida_name.SN_NOWARN)")
                    
                    # Add function comment if present
                    if 'comment' in func_data and func_data['comment']:
                        comment_text = func_data['comment'].replace("'", "\\'").replace('"', '\\"')
                        lines.append(f"ida_funcs.set_func_cmt(ida_funcs.get_func(ea), '{comment_text}', False)")
                    
                    # Add repeatable comment if present
                    if 'repeatable_comment' in func_data and func_data['repeatable_comment']:
                        rep_comment = func_data['repeatable_comment'].replace("'", "\\'").replace('"', '\\"')
                        lines.append(f"ida_funcs.set_func_cmt(ida_funcs.get_func(ea), '{rep_comment}', True)")
            
            # Export names/labels
            if names:
                lines.append("")
                lines.append("# Create names/labels")
                lines.append("print('Processing names...')")
                for addr, name_data in sorted(names.items()):
                    name = name_data.get('name', f'loc_{addr:X}')
                    lines.append(f"")
                    lines.append(f"# Name at 0x{addr:X}")
                    lines.append(f"ida_name.set_name(0x{addr:X}, '{name}', ida_name.SN_NOWARN)")
            
            # Export comments
            if comments:
                lines.append("")
                lines.append("# Add comments")
                lines.append("print('Processing comments...')")
                for addr, comment_list in sorted(comments.items()):
                    for comment_text in comment_list:
                        comment_text = comment_text.replace("'", "\\'").replace('"', '\\"')
                        lines.append(f"")
                        lines.append(f"# Comment at 0x{addr:X}")
                        lines.append(f"idc.set_cmt(0x{addr:X}, '{comment_text}', 0)  # Regular comment")
            
            # Export structures
            if structs:
                lines.append("")
                lines.append("# Create structures")
                lines.append("print('Processing structures...')")
                for struct_name, struct_data in structs.items():
                    lines.append(f"")
                    lines.append(f"# Structure: {struct_name}")
                    lines.append(f"sid = ida_struct.get_struc_id('{struct_name}')")
                    lines.append(f"if sid == idaapi.BADADDR:")
                    lines.append(f"    sid = ida_struct.add_struc(idaapi.BADADDR, '{struct_name}')")
                    lines.append(f"if sid != idaapi.BADADDR:")
                    lines.append(f"    sptr = ida_struct.get_struc(sid)")
                    
                    # Add structure members
                    if 'members' in struct_data:
                        for member in struct_data['members']:
                            member_name = member.get('name', 'field')
                            member_offset = member.get('offset', 0)
                            member_size = member.get('size', 1)
                            lines.append(f"    ida_struct.add_struc_member(sptr, '{member_name}', {member_offset}, "
                                       f"ida_bytes.FF_DATA, None, {member_size})")
            
            # Export cross-references (if provided)
            if xrefs:
                lines.append("")
                lines.append("# Add cross-references")
                lines.append("print('Processing cross-references...')")
                for xref in xrefs:
                    from_addr = xref.get('from_address', 0)
                    to_addr = xref.get('to_address', 0)
                    xref_type = xref.get('type', 'Data_Unknown')
                    
                    lines.append(f"")
                    lines.append(f"# XRef from 0x{from_addr:X} to 0x{to_addr:X}")
                    lines.append(f"# Type: {xref_type}")
                    lines.append(f"# ida_xref.add_cref(0x{from_addr:X}, 0x{to_addr:X}, ida_xref.fl_CN)")
            
            # Script footer
            lines.append("")
            lines.append("print('DissectX analysis applied successfully!')")
            lines.append("print('Please review the changes and save the database.')")
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            return True
            
        except Exception as e:
            print(f"Error exporting IDA Python script: {e}")
            return False
    
    def export_to_json(self, output_path: str) -> bool:
        """
        Export current IDA data to JSON format.
        
        Args:
            output_path: Path to write JSON file
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            data = {
                'database': {
                    'name': self.database_name,
                    'base_address': hex(self.base_address),
                    'bitness': self.bitness,
                    'processor': self.processor
                },
                'segments': [seg.to_dict() for seg in self.segments],
                'functions': [func.to_dict() for func in self.functions.values()],
                'names': [name.to_dict() for name in self.names.values()],
                'comments': [
                    comment.to_dict()
                    for comment_list in self.comments.values()
                    for comment in comment_list
                ],
                'xrefs': [xref.to_dict() for xref in self.xrefs],
                'structs': [struct.to_dict() for struct in self.structs.values()],
                'enums': [enum.to_dict() for enum in self.enums.values()]
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
    
    def get_function(self, address: int) -> Optional[IDAFunction]:
        """
        Get function at specified address.
        
        Args:
            address: Function address
            
        Returns:
            IDAFunction if found, None otherwise
        """
        return self.functions.get(address)
    
    def get_name(self, address: int) -> Optional[IDAName]:
        """
        Get name at specified address.
        
        Args:
            address: Address
            
        Returns:
            IDAName if found, None otherwise
        """
        return self.names.get(address)
    
    def get_comments(self, address: int) -> List[IDAComment]:
        """
        Get all comments at specified address.
        
        Args:
            address: Address to get comments for
            
        Returns:
            List of IDAComment objects
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
    
    def get_all_functions(self) -> List[IDAFunction]:
        """
        Get all imported functions.
        
        Returns:
            List of all IDAFunction objects
        """
        return list(self.functions.values())
    
    def get_all_names(self) -> List[IDAName]:
        """
        Get all imported names.
        
        Returns:
            List of all IDAName objects
        """
        return list(self.names.values())
    
    def get_all_segments(self) -> List[IDASegment]:
        """
        Get all imported segments.
        
        Returns:
            List of all IDASegment objects
        """
        return self.segments
    
    def get_xrefs_from(self, address: int) -> List[IDAXRef]:
        """
        Get all cross-references from specified address.
        
        Args:
            address: Source address
            
        Returns:
            List of IDAXRef objects originating from address
        """
        return [xref for xref in self.xrefs if xref.from_address == address]
    
    def get_xrefs_to(self, address: int) -> List[IDAXRef]:
        """
        Get all cross-references to specified address.
        
        Args:
            address: Target address
            
        Returns:
            List of IDAXRef objects pointing to address
        """
        return [xref for xref in self.xrefs if xref.to_address == address]
    
    def get_struct(self, name: str) -> Optional[IDAStruct]:
        """
        Get structure definition by name.
        
        Args:
            name: Structure name
            
        Returns:
            IDAStruct if found, None otherwise
        """
        return self.structs.get(name)
    
    def get_enum(self, name: str) -> Optional[IDAEnum]:
        """
        Get enumeration by name.
        
        Args:
            name: Enumeration name
            
        Returns:
            IDAEnum if found, None otherwise
        """
        return self.enums.get(name)
    
    def generate_ida_naming_convention(self, name: str, address: int,
                                      entity_type: str = 'function',
                                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a name following IDA Pro naming conventions.
        
        Uses the unified naming convention adapter for consistent naming.
        
        IDA Pro uses specific naming patterns:
        - Functions: sub_<address>
        - Labels: loc_<address>, locret_<address>
        - Data: byte_<address>, word_<address>, dword_<address>, qword_<address>
        - Strings: a<Content>_<address> (e.g., aHelloWorld_401000)
        - Imports: __imp_<name>
        
        Args:
            name: Original name
            address: Entity address
            entity_type: Type of entity ('function', 'label', 'data', 'string', 'import')
            metadata: Optional metadata about the entity
            
        Returns:
            IDA-compatible name
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
    
    def generate_export_script(self, output_path: str) -> bool:
        """
        Generate an IDAPython script to export IDA data to JSON.
        
        This creates a script that can be run in IDA Pro to export
        analysis data in a format compatible with import_from_json().
        
        Args:
            output_path: Path to write the export script
            
        Returns:
            True if successful, False otherwise
        """
        try:
            lines = []
            
            # Script header
            lines.append("# IDAPython Export Script - Generated by DissectX")
            lines.append("# This script exports IDA Pro analysis data to JSON format")
            lines.append("#")
            lines.append("# Usage: File -> Script file... -> Select this script")
            lines.append("# The script will create a JSON file in the same directory as the IDB")
            lines.append("")
            lines.append("import json")
            lines.append("import ida_bytes")
            lines.append("import ida_funcs")
            lines.append("import ida_name")
            lines.append("import ida_segment")
            lines.append("import ida_struct")
            lines.append("import ida_enum")
            lines.append("import ida_xref")
            lines.append("import idaapi")
            lines.append("import idc")
            lines.append("from pathlib import Path")
            lines.append("")
            lines.append("def export_ida_to_json():")
            lines.append("    \"\"\"Export IDA Pro analysis to JSON format\"\"\"")
            lines.append("    ")
            lines.append("    data = {")
            lines.append("        'database': {")
            lines.append("            'name': idc.get_root_filename(),")
            lines.append("            'base_address': hex(idaapi.get_imagebase()),")
            lines.append("            'bitness': 64 if idaapi.get_inf_structure().is_64bit() else 32,")
            lines.append("            'processor': idaapi.get_inf_structure().procname")
            lines.append("        },")
            lines.append("        'segments': [],")
            lines.append("        'functions': [],")
            lines.append("        'names': [],")
            lines.append("        'comments': [],")
            lines.append("        'xrefs': [],")
            lines.append("        'structs': [],")
            lines.append("        'enums': []")
            lines.append("    }")
            lines.append("    ")
            lines.append("    # Export segments")
            lines.append("    print('Exporting segments...')")
            lines.append("    for seg_ea in idautils.Segments():")
            lines.append("        seg = idaapi.getseg(seg_ea)")
            lines.append("        data['segments'].append({")
            lines.append("            'name': idc.get_segm_name(seg_ea),")
            lines.append("            'start_address': hex(seg.start_ea),")
            lines.append("            'end_address': hex(seg.end_ea),")
            lines.append("            'type': 'CODE' if seg.type == idaapi.SEG_CODE else 'DATA',")
            lines.append("            'permissions': 'rwx',  # Simplified")
            lines.append("            'bitness': data['database']['bitness']")
            lines.append("        })")
            lines.append("    ")
            lines.append("    # Export functions")
            lines.append("    print('Exporting functions...')")
            lines.append("    for func_ea in idautils.Functions():")
            lines.append("        func = ida_funcs.get_func(func_ea)")
            lines.append("        data['functions'].append({")
            lines.append("            'address': hex(func_ea),")
            lines.append("            'name': idc.get_func_name(func_ea),")
            lines.append("            'end_address': hex(func.end_ea) if func else None,")
            lines.append("            'comment': idc.get_func_cmt(func_ea, 0),")
            lines.append("            'repeatable_comment': idc.get_func_cmt(func_ea, 1)")
            lines.append("        })")
            lines.append("    ")
            lines.append("    # Export names")
            lines.append("    print('Exporting names...')")
            lines.append("    for name_ea, name in idautils.Names():")
            lines.append("        data['names'].append({")
            lines.append("            'address': hex(name_ea),")
            lines.append("            'name': name,")
            lines.append("            'is_code': idc.is_code(idc.get_full_flags(name_ea)),")
            lines.append("            'is_data': idc.is_data(idc.get_full_flags(name_ea))")
            lines.append("        })")
            lines.append("    ")
            lines.append("    # Export comments")
            lines.append("    print('Exporting comments...')")
            lines.append("    for func_ea in idautils.Functions():")
            lines.append("        func = ida_funcs.get_func(func_ea)")
            lines.append("        if func:")
            lines.append("            for ea in range(func.start_ea, func.end_ea):")
            lines.append("                cmt = idc.get_cmt(ea, 0)")
            lines.append("                if cmt:")
            lines.append("                    data['comments'].append({")
            lines.append("                        'address': hex(ea),")
            lines.append("                        'type': 'regular',")
            lines.append("                        'text': cmt")
            lines.append("                    })")
            lines.append("    ")
            lines.append("    # Write to JSON file")
            lines.append("    idb_path = idc.get_idb_path()")
            lines.append("    json_path = Path(idb_path).with_suffix('.json')")
            lines.append("    ")
            lines.append("    with open(json_path, 'w', encoding='utf-8') as f:")
            lines.append("        json.dump(data, f, indent=2)")
            lines.append("    ")
            lines.append("    print(f'Export complete: {json_path}')")
            lines.append("    return str(json_path)")
            lines.append("")
            lines.append("# Run the export")
            lines.append("if __name__ == '__main__':")
            lines.append("    import idautils")
            lines.append("    output_file = export_ida_to_json()")
            lines.append("    print(f'IDA data exported to: {output_file}')")
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            return True
            
        except Exception as e:
            print(f"Error generating export script: {e}")
            return False
    
    def preserve_annotations(self, address: int, annotations: Dict[str, Any]):
        """
        Preserve annotations from external tool during import.
        
        This ensures that user-defined comments, bookmarks, and other
        annotations are maintained when importing from IDA Pro.
        
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
        self.names.clear()
        self.comments.clear()
        self.segments.clear()
        self.xrefs.clear()
        self.structs.clear()
        self.enums.clear()
        self.preserved_annotations.clear()
        self.database_name = None
        self.base_address = 0
        self.bitness = 32
        self.processor = None
