#!/usr/bin/env python3
"""
Direct Syscall Detection & SSN Table Extraction for DissectX

Detects and analyzes direct syscall patterns used to bypass user-mode hooks:
- Hell's Gate / Tartarus' Gate
- SysWhispers2/3
- FreshRE
- Custom syscall stubs

Author: DissectX Team
"""

import re
import struct
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SyscallStub:
    """Represents a detected syscall stub"""
    rva: int
    va: int
    ssn: int
    description: str
    confidence: str  # 'high', 'medium', 'low'


class SyscallDetector:
    """Detects direct syscall usage and extracts SSN tables"""
    
    # Known syscall stub signatures (2020–2025)
    SYSCALL_PATTERNS = {
        'hells_gate': rb'\x4C\x8B\xD1\xB8(....)\x0F\x05\xC3',  # mov r10,rcx; mov eax,SSN; syscall; ret
        'hells_gate_no_ret': rb'\x4C\x8B\xD1\xB8(....)\x0F\x05',  # same without ret
        'syswhispers': rb'\x49\x89\xCA\xB8(....)\x0F\x05',  # mov r10,rcx; mov eax,SSN; syscall
        'simple_stub': rb'\xB8(....)\x0F\x05\xC3',  # mov eax,SSN; syscall; ret
        'dynamic_ssn': rb'\x8B\x05(....)\x0F\x05',  # mov eax,[rip+offset]; syscall
        'freshre': rb'\x4C\x8B\xD1\xB8(....)\x4C\x8B\xC1\x0F\x05',  # FreshRE variant
    }
    
    # Common SSN table addresses seen in the wild
    KNOWN_SSN_TABLE_ADDRESSES = [
        0x140007000, 0x140008000, 0x140009000, 0x14000A000,
        0x180007000, 0x180008000, 0x180009000,
        0x1C0007000, 0x1C0008000,
    ]
    
    # SSN to API name mapping (Windows 10/11 2024-2025)
    # Source: Compiled from ntdll.dll analysis
    SSN_TO_NAME = {
        0x000: "NtAccessCheck",
        0x001: "NtWorkerFactoryWorkerReady",
        0x002: "NtAcceptConnectPort",
        0x003: "NtMapUserPhysicalPagesScatter",
        0x004: "NtWaitForSingleObject",
        0x005: "NtCallbackReturn",
        0x006: "NtReadFile",
        0x007: "NtDeviceIoControlFile",
        0x008: "NtWriteFile",
        0x009: "NtRemoveIoCompletion",
        0x00A: "NtReleaseSemaphore",
        0x00B: "NtReplyWaitReceivePort",
        0x00C: "NtReplyPort",
        0x00D: "NtSetInformationThread",
        0x00E: "NtSetEvent",
        0x00F: "NtClose",
        0x010: "NtQueryObject",
        0x011: "NtQueryInformationFile",
        0x012: "NtOpenKey",
        0x013: "NtEnumerateValueKey",
        0x014: "NtFindAtom",
        0x015: "NtQueryDefaultLocale",
        0x016: "NtQueryKey",
        0x017: "NtQueryValueKey",
        0x018: "NtAllocateVirtualMemory",
        0x019: "NtQueryInformationProcess",
        0x01A: "NtWaitForMultipleObjects32",
        0x01B: "NtWriteFileGather",
        0x01C: "NtCreateKey",
        0x01D: "NtFreeVirtualMemory",
        0x01E: "NtImpersonateClientOfPort",
        0x01F: "NtReleaseMutant",
        0x020: "NtQueryInformationToken",
        0x021: "NtRequestWaitReplyPort",
        0x022: "NtQueryVirtualMemory",
        0x023: "NtOpenThreadToken",
        0x024: "NtQueryInformationThread",
        0x025: "NtOpenProcess",
        0x026: "NtSetInformationFile",
        0x027: "NtMapViewOfSection",
        0x028: "NtAccessCheckAndAuditAlarm",
        0x029: "NtUnmapViewOfSection",
        0x02A: "NtReplyWaitReceivePortEx",
        0x02B: "NtTerminateProcess",
        0x02C: "NtSetEventBoostPriority",
        0x02D: "NtReadFileScatter",
        0x02E: "NtOpenThreadTokenEx",
        0x02F: "NtOpenProcessTokenEx",
        0x030: "NtQueryPerformanceCounter",
        0x031: "NtEnumerateKey",
        0x032: "NtOpenFile",
        0x033: "NtDelayExecution",
        0x034: "NtQueryDirectoryFile",
        0x035: "NtQuerySystemInformation",
        0x036: "NtOpenSection",
        0x037: "NtQueryTimer",
        0x038: "NtFsControlFile",
        0x039: "NtWriteVirtualMemory",
        0x03A: "NtCloseObjectAuditAlarm",
        0x03B: "NtDuplicateObject",
        0x03C: "NtQueryAttributesFile",
        0x03D: "NtClearEvent",
        0x03E: "NtReadVirtualMemory",
        0x03F: "NtOpenEvent",
        0x040: "NtAdjustPrivilegesToken",
        0x041: "NtDuplicateToken",
        0x042: "NtContinue",
        0x043: "NtQueryDefaultUILanguage",
        0x044: "NtQueueApcThread",
        0x045: "NtCreateProcessEx",
        0x046: "NtCreateThread",
        0x047: "NtIsProcessInJob",
        0x048: "NtProtectVirtualMemory",
        0x049: "NtQuerySection",
        0x04A: "NtResumeThread",
        0x04B: "NtTerminateThread",
        0x04C: "NtReadRequestData",
        0x04D: "NtCreateFile",
        0x04E: "NtQueryEvent",
        0x04F: "NtWriteRequestData",
        0x050: "NtOpenDirectoryObject",
        0x055: "NtCreateSection",
        0x0A2: "NtCreateUserProcess",
        0x0B4: "NtSetInformationProcess",
        0x118: "NtCreateThreadEx",
    }
    
    def __init__(self, image_base: int = 0x140000000):
        """
        Initialize syscall detector
        
        Args:
            image_base: Base address of the binary (default: 0x140000000)
        """
        self.image_base = image_base
        self.detected_stubs: List[SyscallStub] = []
        self.ssn_table: Dict[int, int] = {}
    
    def find_syscall_stubs(self, data: bytes) -> List[SyscallStub]:
        """
        Find all syscall stubs in binary data
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of detected syscall stubs
        """
        stubs = []
        
        for pattern_name, pattern in self.SYSCALL_PATTERNS.items():
            for match in re.finditer(pattern, data, re.DOTALL):
                rva = match.start()
                va = self.image_base + rva
                
                # Extract SSN based on pattern type
                ssn = self._extract_ssn(match, pattern_name)
                
                if ssn is not None:
                    confidence = self._determine_confidence(pattern_name, ssn)
                    description = self._get_pattern_description(pattern_name)
                    
                    stub = SyscallStub(
                        rva=rva,
                        va=va,
                        ssn=ssn,
                        description=description,
                        confidence=confidence
                    )
                    stubs.append(stub)
        
        self.detected_stubs = stubs
        return stubs
    
    def _extract_ssn(self, match: re.Match, pattern_name: str) -> Optional[int]:
        """Extract SSN from regex match"""
        try:
            if pattern_name in ['hells_gate', 'hells_gate_no_ret', 'syswhispers', 'simple_stub', 'freshre']:
                # SSN is in the captured group
                ssn_bytes = match.group(1)
                return struct.unpack("<I", ssn_bytes)[0]
            elif pattern_name == 'dynamic_ssn':
                # For dynamic SSN, we can't extract the value statically
                return None
        except (struct.error, IndexError):
            return None
        return None
    
    def _determine_confidence(self, pattern_name: str, ssn: int) -> str:
        """Determine confidence level of detection"""
        if pattern_name in ['hells_gate', 'hells_gate_no_ret']:
            return 'high'
        elif pattern_name in ['syswhispers', 'freshre']:
            return 'high'
        elif pattern_name == 'simple_stub' and 0 < ssn < 0x500:
            return 'medium'
        elif pattern_name == 'dynamic_ssn':
            return 'medium'
        return 'low'
    
    def _get_pattern_description(self, pattern_name: str) -> str:
        """Get human-readable description of pattern"""
        descriptions = {
            'hells_gate': "Hell's Gate / Tartarus' Gate pattern",
            'hells_gate_no_ret': "Hell's Gate variant (no ret)",
            'syswhispers': "SysWhispers2/3 pattern",
            'simple_stub': "Simple direct syscall stub",
            'dynamic_ssn': "Dynamic SSN loading",
            'freshre': "FreshRE pattern",
        }
        return descriptions.get(pattern_name, "Unknown pattern")
    
    def extract_ssn_table(self, data: bytes) -> Dict[int, int]:
        """
        Extract SSN table from binary data
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Dictionary mapping address to SSN value
        """
        table = {}
        
        for candidate_addr in self.KNOWN_SSN_TABLE_ADDRESSES:
            offset = candidate_addr - self.image_base
            
            if offset < 0 or offset + 1024 >= len(data):
                continue
            
            # Try to parse as DWORD array
            try:
                chunk = data[offset:offset + 400]
                values = struct.unpack("<100I", chunk[:400])
                
                valid_count = 0
                prev = 0
                temp_table = {}
                
                for i, ssn in enumerate(values):
                    if ssn == 0:
                        break
                    # Reasonable SSN range: 0x10 to 0x500
                    if 0x10 <= ssn < 0x500 and ssn >= prev:
                        addr = candidate_addr + i * 4
                        temp_table[addr] = ssn
                        prev = ssn
                        valid_count += 1
                    else:
                        break
                
                # If we found at least 20 consecutive valid SSNs, it's likely a table
                if valid_count >= 20:
                    table.update(temp_table)
                    
            except struct.error:
                continue
        
        self.ssn_table = table
        return table
    
    def resolve_ssn_to_name(self, ssn: int) -> str:
        """
        Resolve SSN to API name
        
        Args:
            ssn: System Service Number
            
        Returns:
            API name or "Unknown_XXXX"
        """
        return self.SSN_TO_NAME.get(ssn, f"Unknown_{ssn:04X}")
    
    def analyze(self, data: bytes) -> Dict:
        """
        Perform complete syscall analysis
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        stubs = self.find_syscall_stubs(data)
        table = self.extract_ssn_table(data)
        
        # Build results
        results = {
            'stubs_found': len(stubs),
            'stubs': [],
            'ssn_table_found': len(table) > 0,
            'ssn_table_size': len(table),
            'ssn_table': [],
            'threat_level': self._assess_threat_level(stubs, table),
            'bypass_techniques': self._identify_bypass_techniques(stubs),
        }
        
        # Add stub details
        for stub in stubs:
            api_name = self.resolve_ssn_to_name(stub.ssn)
            results['stubs'].append({
                'address': f"0x{stub.va:X}",
                'rva': f"0x{stub.rva:X}",
                'ssn': f"0x{stub.ssn:04X}",
                'api_name': api_name,
                'description': stub.description,
                'confidence': stub.confidence,
            })
        
        # Add SSN table details (limit to first 50)
        for addr, ssn in sorted(table.items())[:50]:
            api_name = self.resolve_ssn_to_name(ssn)
            results['ssn_table'].append({
                'address': f"0x{addr:X}",
                'ssn': f"0x{ssn:04X}",
                'api_name': api_name,
            })
        
        return results
    
    def _assess_threat_level(self, stubs: List[SyscallStub], table: Dict) -> str:
        """Assess threat level based on findings"""
        if len(stubs) > 10 or len(table) > 30:
            return 'CRITICAL'
        elif len(stubs) > 5 or len(table) > 15:
            return 'HIGH'
        elif len(stubs) > 0 or len(table) > 0:
            return 'MEDIUM'
        return 'NONE'
    
    def _identify_bypass_techniques(self, stubs: List[SyscallStub]) -> List[str]:
        """Identify specific bypass techniques used"""
        techniques = set()
        
        for stub in stubs:
            if "Hell's Gate" in stub.description:
                techniques.add("Hell's Gate / Tartarus' Gate")
            elif "SysWhispers" in stub.description:
                techniques.add("SysWhispers2/3")
            elif "FreshRE" in stub.description:
                techniques.add("FreshRE")
            elif "Dynamic" in stub.description:
                techniques.add("Dynamic SSN Resolution")
        
        return sorted(list(techniques))
    
    def format_report(self, results: Dict) -> str:
        """
        Format analysis results as human-readable report
        
        Args:
            results: Analysis results from analyze()
            
        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 70)
        lines.append("DIRECT SYSCALL ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Threat assessment
        threat = results['threat_level']
        if threat != 'NONE':
            lines.append(f"⚠️  THREAT LEVEL: {threat}")
            lines.append("")
        
        # Syscall stubs
        if results['stubs_found'] > 0:
            lines.append(f"🔍 Found {results['stubs_found']} direct syscall stub(s):")
            lines.append("")
            
            for stub in results['stubs']:
                lines.append(f"  Address: {stub['address']}")
                lines.append(f"  SSN:     {stub['ssn']} → {stub['api_name']}")
                lines.append(f"  Pattern: {stub['description']}")
                lines.append(f"  Confidence: {stub['confidence'].upper()}")
                lines.append("")
        else:
            lines.append("✓ No direct syscall stubs detected")
            lines.append("")
        
        # SSN table
        if results['ssn_table_found']:
            lines.append(f"📊 SSN Table Found ({results['ssn_table_size']} entries):")
            lines.append("")
            
            for entry in results['ssn_table'][:20]:  # Show first 20
                lines.append(f"  {entry['address']} → {entry['ssn']} {entry['api_name']}")
            
            if results['ssn_table_size'] > 20:
                lines.append(f"  ... and {results['ssn_table_size'] - 20} more entries")
            lines.append("")
        
        # Bypass techniques
        if results['bypass_techniques']:
            lines.append("🛡️  Detected Bypass Techniques:")
            for technique in results['bypass_techniques']:
                lines.append(f"  • {technique}")
            lines.append("")
        
        # Warning
        if threat != 'NONE':
            lines.append("⚠️  WARNING:")
            lines.append("  This binary bypasses ALL user-mode API monitoring:")
            lines.append("  • ETW (Event Tracing for Windows)")
            lines.append("  • User-mode hooks (AV/EDR)")
            lines.append("  • API logging tools")
            lines.append("")
            lines.append("  Only kernel-mode monitoring can detect this behavior.")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python syscall_detector.py <binary.exe>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    
    detector = SyscallDetector()
    results = detector.analyze(data)
    print(detector.format_report(results))
