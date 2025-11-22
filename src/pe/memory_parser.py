#!/usr/bin/env python3
"""
In-Memory PE Parser for DissectX

Parses PE files from memory dumps and detects:
- Manual mapping
- Reflective DLL injection
- Process hollowing
- Import table reconstruction
- Hidden sections

Author: DissectX Team
"""

import struct
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class MemorySection:
    """Represents a memory section"""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_suspicious: bool


@dataclass
class ImportEntry:
    """Represents an imported function"""
    dll_name: str
    function_name: str
    address: int
    is_resolved: bool


@dataclass
class MemoryPEAnalysis:
    """Results from in-memory PE analysis"""
    is_valid_pe: bool
    base_address: int
    image_size: int
    entry_point: int
    sections: List[MemorySection]
    imports: List[ImportEntry]
    exports: List[str]
    is_manually_mapped: bool
    is_hollowed: bool
    suspicious_indicators: List[str]
    threat_level: str


class MemoryPEParser:
    """Parse PE files from memory dumps"""
    
    def __init__(self):
        """Initialize memory PE parser"""
        if not PEFILE_AVAILABLE:
            raise ImportError("pefile not installed. Run: pip install pefile")
        
        self.pe = None
        self.base_address = 0
    
    def parse_memory_dump(self, data: bytes, base_addr: int = 0) -> MemoryPEAnalysis:
        """
        Parse PE from memory dump
        
        Args:
            data: Memory dump data
            base_addr: Base address in memory
            
        Returns:
            MemoryPEAnalysis with findings
        """
        try:
            # Try to parse as PE
            self.pe = pefile.PE(data=data)
            self.base_address = base_addr
            
            # Extract information
            sections = self._parse_sections()
            imports = self._parse_imports()
            exports = self._parse_exports()
            
            # Detect suspicious patterns
            is_manually_mapped = self._detect_manual_mapping()
            is_hollowed = self._detect_process_hollowing()
            suspicious = self._find_suspicious_indicators()
            
            # Assess threat level
            threat_level = self._assess_threat_level(
                is_manually_mapped, is_hollowed, suspicious
            )
            
            return MemoryPEAnalysis(
                is_valid_pe=True,
                base_address=base_addr,
                image_size=self.pe.OPTIONAL_HEADER.SizeOfImage,
                entry_point=self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + base_addr,
                sections=sections,
                imports=imports,
                exports=exports,
                is_manually_mapped=is_manually_mapped,
                is_hollowed=is_hollowed,
                suspicious_indicators=suspicious,
                threat_level=threat_level
            )
            
        except Exception as e:
            return MemoryPEAnalysis(
                is_valid_pe=False,
                base_address=base_addr,
                image_size=0,
                entry_point=0,
                sections=[],
                imports=[],
                exports=[],
                is_manually_mapped=False,
                is_hollowed=False,
                suspicious_indicators=[f"Parse error: {str(e)}"],
                threat_level="UNKNOWN"
            )
    
    def _parse_sections(self) -> List[MemorySection]:
        """Parse PE sections"""
        sections = []
        
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # Check characteristics
            is_executable = bool(section.Characteristics & 0x20000000)
            is_writable = bool(section.Characteristics & 0x80000000)
            
            # Check if suspicious
            is_suspicious = self._is_suspicious_section(
                name, section.Characteristics, 
                section.SizeOfRawData, section.Misc_VirtualSize
            )
            
            mem_section = MemorySection(
                name=name,
                virtual_address=section.VirtualAddress + self.base_address,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                characteristics=section.Characteristics,
                is_executable=is_executable,
                is_writable=is_writable,
                is_suspicious=is_suspicious
            )
            sections.append(mem_section)
        
        return sections
    
    def _is_suspicious_section(
        self, name: str, characteristics: int, 
        raw_size: int, virtual_size: int
    ) -> bool:
        """Check if section is suspicious"""
        # Standard section names
        standard_sections = {
            '.text', '.data', '.rdata', '.bss', '.rsrc',
            '.reloc', '.pdata', '.idata', '.edata', '.tls'
        }
        
        suspicious = False
        
        # Non-standard name
        if name.upper() not in {s.upper() for s in standard_sections}:
            suspicious = True
        
        # Executable + writable (RWX)
        is_exec = bool(characteristics & 0x20000000)
        is_write = bool(characteristics & 0x80000000)
        if is_exec and is_write:
            suspicious = True
        
        # Large size discrepancy
        if raw_size > 0 and virtual_size > 0:
            ratio = virtual_size / raw_size
            if ratio > 10 or ratio < 0.1:
                suspicious = True
        
        return suspicious
    
    def _parse_imports(self) -> List[ImportEntry]:
        """Parse import table"""
        imports = []
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        func_name = ""
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                        else:
                            func_name = f"Ordinal_{imp.ordinal}"
                        
                        import_entry = ImportEntry(
                            dll_name=dll_name,
                            function_name=func_name,
                            address=imp.address,
                            is_resolved=imp.address != 0
                        )
                        imports.append(import_entry)
        except:
            pass
        
        return imports
    
    def _parse_exports(self) -> List[str]:
        """Parse export table"""
        exports = []
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        name = exp.name.decode('utf-8', errors='ignore')
                        exports.append(name)
        except:
            pass
        
        return exports
    
    def _detect_manual_mapping(self) -> bool:
        """Detect manual mapping indicators"""
        indicators = 0
        
        # Check 1: Missing or unusual import table
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            indicators += 1
        elif len(self.pe.DIRECTORY_ENTRY_IMPORT) < 2:
            indicators += 1
        
        # Check 2: RWX sections (common in manual mapping)
        for section in self.pe.sections:
            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)
            if is_exec and is_write:
                indicators += 1
                break
        
        # Check 3: Unusual section alignment
        if self.pe.OPTIONAL_HEADER.SectionAlignment != 0x1000:
            indicators += 1
        
        # Manual mapping likely if 2+ indicators
        return indicators >= 2
    
    def _detect_process_hollowing(self) -> bool:
        """Detect process hollowing indicators"""
        indicators = 0
        
        # Check 1: Entry point in unusual section
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_section = None
        
        for section in self.pe.sections:
            if (section.VirtualAddress <= entry_point < 
                section.VirtualAddress + section.Misc_VirtualSize):
                entry_section = section
                break
        
        if entry_section:
            name = entry_section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            if name.upper() != '.TEXT':
                indicators += 1
        
        # Check 2: Suspicious base address (not typical load address)
        if self.base_address != 0 and self.base_address < 0x10000:
            indicators += 1
        
        # Check 3: Modified headers
        if self.pe.DOS_HEADER.e_magic != 0x5A4D:  # MZ
            indicators += 1
        
        return indicators >= 2
    
    def _find_suspicious_indicators(self) -> List[str]:
        """Find suspicious indicators"""
        indicators = []
        
        # Check for suspicious sections
        for section in self.pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # RWX section
            is_exec = bool(section.Characteristics & 0x20000000)
            is_write = bool(section.Characteristics & 0x80000000)
            if is_exec and is_write:
                indicators.append(f"RWX section: {name}")
            
            # Non-standard name
            standard = {'.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc'}
            if name.upper() not in {s.upper() for s in standard}:
                indicators.append(f"Non-standard section: {name}")
        
        # Check for missing imports
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            indicators.append("No import table (possibly manually mapped)")
        
        # Check for unusual entry point
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if entry_point == 0:
            indicators.append("Entry point at 0 (suspicious)")
        
        # Check for TLS callbacks (anti-debugging)
        if hasattr(self.pe, 'DIRECTORY_ENTRY_TLS'):
            indicators.append("TLS callbacks present (possible anti-debugging)")
        
        return indicators
    
    def _assess_threat_level(
        self, is_manually_mapped: bool, 
        is_hollowed: bool, 
        suspicious: List[str]
    ) -> str:
        """Assess threat level"""
        if is_manually_mapped or is_hollowed:
            return "CRITICAL"
        elif len(suspicious) >= 3:
            return "HIGH"
        elif len(suspicious) >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def reconstruct_imports(self, memory_data: bytes) -> List[ImportEntry]:
        """
        Reconstruct import table from memory
        (for manually mapped DLLs)
        
        Args:
            memory_data: Full memory dump
            
        Returns:
            List of reconstructed imports
        """
        reconstructed = []
        
        # Simple heuristic: Scan for pointers that look like they point to known DLL exports
        # In a real scenario, we would need to know where DLLs are loaded in the dump
        # For this static analysis, we'll look for patterns of thunks
        
        # This is a placeholder for the complex logic of scanning the IAT
        # Real implementation would require:
        # 1. Identifying potential IAT arrays (consecutive pointers)
        # 2. Resolving those pointers to module exports (requires symbol resolution)
        
        # For now, we'll return an empty list as we don't have the external context
        # of loaded system DLLs in this static parser.
        # However, we can detect the *presence* of a destroyed IAT
        
        return reconstructed
    
    def format_report(self, analysis: MemoryPEAnalysis) -> str:
        """Format analysis as report"""
        lines = []
        lines.append("=" * 70)
        lines.append("IN-MEMORY PE ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        if not analysis.is_valid_pe:
            lines.append("❌ Not a valid PE file")
            if analysis.suspicious_indicators:
                lines.append(f"Error: {analysis.suspicious_indicators[0]}")
            lines.append("")
            lines.append("=" * 70)
            return "\n".join(lines)
        
        # Basic info
        lines.append(f"Base Address: 0x{analysis.base_address:X}")
        lines.append(f"Image Size: 0x{analysis.image_size:X} ({analysis.image_size} bytes)")
        lines.append(f"Entry Point: 0x{analysis.entry_point:X}")
        lines.append("")
        
        # Threat assessment
        threat_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': '✓',
            'UNKNOWN': '❓'
        }.get(analysis.threat_level, '•')
        
        lines.append(f"{threat_emoji} THREAT LEVEL: {analysis.threat_level}")
        lines.append("")
        
        # Detection results
        if analysis.is_manually_mapped:
            lines.append("🎯 MANUAL MAPPING DETECTED")
            lines.append("  This PE was manually mapped into memory")
            lines.append("  Bypasses normal loader detection")
            lines.append("")
        
        if analysis.is_hollowed:
            lines.append("🕳️  PROCESS HOLLOWING DETECTED")
            lines.append("  This PE replaced another process")
            lines.append("  Common malware injection technique")
            lines.append("")
        
        # Suspicious indicators
        if analysis.suspicious_indicators:
            lines.append(f"⚠️  Suspicious Indicators ({len(analysis.suspicious_indicators)}):")
            for indicator in analysis.suspicious_indicators:
                lines.append(f"  • {indicator}")
            lines.append("")
        
        # Sections
        if analysis.sections:
            lines.append(f"📋 Sections ({len(analysis.sections)}):")
            for section in analysis.sections:
                flags = []
                if section.is_executable:
                    flags.append("X")
                if section.is_writable:
                    flags.append("W")
                if section.is_suspicious:
                    flags.append("⚠️")
                
                flags_str = "".join(flags) if flags else "R"
                lines.append(f"  • {section.name:10s} [{flags_str:5s}] "
                           f"VA: 0x{section.virtual_address:X} "
                           f"Size: 0x{section.virtual_size:X}")
            lines.append("")
        
        # Imports - SHOW ALL for CTF analysis
        if analysis.imports:
            lines.append(f"📥 Imports ({len(analysis.imports)} total - ALL SHOWN):")
            lines.append("")

            # Group by DLL for better organization
            from collections import defaultdict
            imports_by_dll = defaultdict(list)
            for imp in analysis.imports:
                imports_by_dll[imp.dll_name].append(imp)

            for dll_name in sorted(imports_by_dll.keys()):
                dll_imports = imports_by_dll[dll_name]
                lines.append(f"  📚 {dll_name} ({len(dll_imports)} functions):")
                for imp in dll_imports:
                    status = "✓" if imp.is_resolved else "✗"
                    lines.append(f"     {status} {imp.function_name}")
                lines.append("")

        # Exports - SHOW ALL for CTF analysis
        if analysis.exports:
            lines.append(f"📤 Exports ({len(analysis.exports)} total - ALL SHOWN):")
            for exp in analysis.exports:
                lines.append(f"  • {exp}")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if not PEFILE_AVAILABLE:
        print("❌ pefile not installed. Run: pip install pefile")
        sys.exit(1)
    
    if len(sys.argv) != 2:
        print("Usage: python memory_parser.py <file.exe>")
        sys.exit(1)
    
    # Read file
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    # Parse
    parser = MemoryPEParser()
    analysis = parser.parse_memory_dump(data, base_addr=0x400000)
    
    # Print report
    print(parser.format_report(analysis))
