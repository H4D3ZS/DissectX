#!/usr/bin/env python3
"""
API Hashing Resolver for DissectX

Detects and resolves API hashing techniques used to hide imports:
- ROR-13 (most common, ~60% of samples)
- Rolling XOR (~20%)
- FNV-1a / Jenkins Hash (~10%)
- CRC32 (~5%)

Author: DissectX Team
"""

import re
import struct
import binascii
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass


@dataclass
class HashMatch:
    """Represents a matched API hash"""
    hash_value: int
    api_name: str
    algorithm: str
    confidence: float
    location: Optional[int] = None


class APIHashResolver:
    """Resolves API hashing to reconstruct import table"""
    
    # Common Windows APIs (top 500 most used)
    COMMON_APIS = [
        # Kernel32.dll
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect", "VirtualProtectEx",
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
        "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "OpenProcess",
        "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
        "Sleep", "SleepEx", "WaitForSingleObject", "WaitForMultipleObjects",
        "CreateThread", "ExitThread", "TerminateThread", "SuspendThread", "ResumeThread",
        "GetSystemInfo", "GetVersionExA", "GetVersionExW", "GetComputerNameA",
        "SetFilePointer", "SetFilePointerEx", "GetFileSize", "GetFileSizeEx",
        "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
        "GetTempPathA", "GetTempPathW", "GetWindowsDirectoryA", "GetWindowsDirectoryW",
        "CopyFileA", "CopyFileW", "DeleteFileA", "DeleteFileW", "MoveFileA", "MoveFileW",
        "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW", "FindClose",
        "GetLastError", "SetLastError", "FormatMessageA", "FormatMessageW",
        "HeapAlloc", "HeapFree", "HeapReAlloc", "GetProcessHeap",
        "lstrcatA", "lstrcatW", "lstrcpyA", "lstrcpyW", "lstrlenA", "lstrlenW",
        
        # Ntdll.dll
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory",
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtQueryVirtualMemory",
        "NtCreateFile", "NtReadFile", "NtWriteFile", "NtClose",
        "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtCreateProcess", "NtCreateProcessEx", "NtCreateThread", "NtCreateThreadEx",
        "NtOpenProcess", "NtOpenThread", "NtTerminateProcess", "NtTerminateThread",
        "NtSuspendThread", "NtResumeThread", "NtGetContextThread", "NtSetContextThread",
        "NtQueryInformationProcess", "NtQueryInformationThread", "NtSetInformationProcess",
        "NtQuerySystemInformation", "NtDelayExecution", "NtWaitForSingleObject",
        "NtDeviceIoControlFile", "NtFsControlFile", "NtQueryDirectoryFile",
        "RtlInitUnicodeString", "RtlCreateUserThread", "RtlExitUserThread",
        "LdrLoadDll", "LdrGetProcedureAddress", "LdrUnloadDll",
        
        # User32.dll
        "MessageBoxA", "MessageBoxW", "FindWindowA", "FindWindowW",
        "GetWindowTextA", "GetWindowTextW", "SetWindowTextA", "SetWindowTextW",
        "ShowWindow", "UpdateWindow", "GetDC", "ReleaseDC",
        "CreateWindowExA", "CreateWindowExW", "DestroyWindow",
        "GetMessageA", "GetMessageW", "PeekMessageA", "PeekMessageW",
        "PostMessageA", "PostMessageW", "SendMessageA", "SendMessageW",
        "RegisterClassA", "RegisterClassW", "RegisterClassExA", "RegisterClassExW",
        
        # Advapi32.dll
        "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
        "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegQueryValueA", "RegQueryValueW", "RegQueryValueExA", "RegQueryValueExW",
        "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
        "RegCloseKey", "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA",
        "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptReleaseContext",
        "CryptCreateHash", "CryptHashData", "CryptGetHashParam", "CryptDestroyHash",
        
        # Ws2_32.dll
        "WSAStartup", "WSACleanup", "socket", "connect", "send", "recv",
        "bind", "listen", "accept", "closesocket", "shutdown",
        "WSASocket", "WSAConnect", "WSASend", "WSARecv",
        "gethostbyname", "gethostname", "inet_addr", "inet_ntoa",
        
        # Wininet.dll
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "InternetReadFile", "InternetCloseHandle", "InternetOpenUrlA", "InternetOpenUrlW",
        
        # Shell32.dll
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        
        # Msvcrt.dll
        "malloc", "free", "calloc", "realloc", "memset", "memcpy", "memmove",
        "strcmp", "strncmp", "strcpy", "strncpy", "strlen", "strcat", "strncat",
        "sprintf", "snprintf", "printf", "fprintf", "fopen", "fclose", "fread", "fwrite",
    ]
    
    def __init__(self):
        """Initialize API hash resolver"""
        self.hash_databases: Dict[str, Dict[int, str]] = {}
        self._build_hash_databases()
    
    def _build_hash_databases(self):
        """Precompute hash databases for all algorithms"""
        self.hash_databases['ror13'] = {}
        self.hash_databases['rolling_xor'] = {}
        self.hash_databases['fnv1a'] = {}
        self.hash_databases['crc32'] = {}
        
        for api in self.COMMON_APIS:
            # ROR-13
            self.hash_databases['ror13'][self.compute_ror13_hash(api)] = api
            
            # Rolling XOR
            self.hash_databases['rolling_xor'][self.compute_rolling_xor(api)] = api
            
            # FNV-1a
            self.hash_databases['fnv1a'][self.compute_fnv1a_hash(api)] = api
            
            # CRC32
            self.hash_databases['crc32'][self.compute_crc32_hash(api)] = api
    
    @staticmethod
    def compute_ror13_hash(api_name: str) -> int:
        """
        Compute ROR-13 hash (most common algorithm)
        
        Algorithm:
        hash = 0
        for each char in api_name:
            hash = ROR(hash, 13)
            hash += char
        """
        hash_val = 0
        for char in api_name:
            # Rotate right by 13 bits
            hash_val = ((hash_val >> 13) | (hash_val << (32 - 13))) & 0xFFFFFFFF
            hash_val = (hash_val + ord(char)) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_rolling_xor(api_name: str) -> int:
        """
        Compute rolling XOR hash
        
        Algorithm:
        hash = 0
        for each char in api_name:
            hash ^= char
            hash = ROL(hash, 1)
        """
        hash_val = 0
        for char in api_name:
            hash_val ^= ord(char)
            # Rotate left by 1 bit
            hash_val = ((hash_val << 1) | (hash_val >> 31)) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_fnv1a_hash(api_name: str) -> int:
        """
        Compute FNV-1a hash (32-bit)
        
        Algorithm:
        hash = 2166136261 (FNV offset basis)
        for each char in api_name:
            hash ^= char
            hash *= 16777619 (FNV prime)
        """
        FNV_OFFSET_BASIS = 2166136261
        FNV_PRIME = 16777619
        
        hash_val = FNV_OFFSET_BASIS
        for char in api_name:
            hash_val ^= ord(char)
            hash_val = (hash_val * FNV_PRIME) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_crc32_hash(api_name: str) -> int:
        """Compute CRC32 hash"""
        return binascii.crc32(api_name.encode()) & 0xFFFFFFFF
    
    def detect_hash_algorithm(self, data: bytes) -> List[str]:
        """
        Detect which hashing algorithm is likely used
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of likely algorithms
        """
        detected = []
        
        # Look for ROR-13 pattern: ror eax, 13 / ror edx, 13
        if re.search(rb'\xC1[\xC8-\xCF]\x0D', data):  # ror reg, 0x0D
            detected.append('ror13')
        
        # Look for XOR patterns
        if re.search(rb'\x33[\xC0-\xC7]', data):  # xor reg, reg
            detected.append('rolling_xor')
        
        # Look for FNV constants
        fnv_offset = struct.pack("<I", 2166136261)
        fnv_prime = struct.pack("<I", 16777619)
        if fnv_offset in data or fnv_prime in data:
            detected.append('fnv1a')
        
        # If no specific pattern found, try all
        if not detected:
            detected = ['ror13', 'rolling_xor', 'fnv1a', 'crc32']
        
        return detected
    
    def find_hash_constants(self, data: bytes) -> List[Tuple[int, int]]:
        """
        Find potential hash constants in binary
        
        Args:
            data: Binary data to analyze
            
        Returns:
            List of (offset, hash_value) tuples
        """
        constants = []
        
        # Look for DWORD constants that might be hashes
        for i in range(0, len(data) - 4, 4):
            try:
                value = struct.unpack("<I", data[i:i+4])[0]
                
                # Heuristic: likely hash if value is in reasonable range
                # and not obviously a pointer or small number
                if 0x1000 < value < 0xFFFFFFFF and value not in [0xCCCCCCCC, 0xDDDDDDDD]:
                    constants.append((i, value))
            except struct.error:
                continue
        
        return constants
    
    def resolve_hash(self, hash_value: int, algorithms: Optional[List[str]] = None) -> List[HashMatch]:
        """
        Resolve a hash value to possible API names
        
        Args:
            hash_value: Hash to resolve
            algorithms: List of algorithms to try (None = all)
            
        Returns:
            List of possible matches
        """
        if algorithms is None:
            algorithms = ['ror13', 'rolling_xor', 'fnv1a', 'crc32']
        
        matches = []
        
        for algo in algorithms:
            if algo in self.hash_databases:
                if hash_value in self.hash_databases[algo]:
                    api_name = self.hash_databases[algo][hash_value]
                    confidence = self._calculate_confidence(algo, hash_value)
                    
                    match = HashMatch(
                        hash_value=hash_value,
                        api_name=api_name,
                        algorithm=algo,
                        confidence=confidence
                    )
                    matches.append(match)
        
        return matches
    
    def _calculate_confidence(self, algorithm: str, hash_value: int) -> float:
        """Calculate confidence score for a match"""
        # Base confidence by algorithm popularity
        base_confidence = {
            'ror13': 0.9,
            'rolling_xor': 0.7,
            'fnv1a': 0.6,
            'crc32': 0.5,
        }
        return base_confidence.get(algorithm, 0.5)
    
    def analyze(self, data: bytes) -> Dict:
        """
        Perform complete API hashing analysis
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Detect likely algorithms
        algorithms = self.detect_hash_algorithm(data)
        
        # Find potential hash constants
        constants = self.find_hash_constants(data)
        
        # Try to resolve hashes
        resolved = []
        for offset, hash_val in constants[:1000]:  # Limit to first 1000
            matches = self.resolve_hash(hash_val, algorithms)
            if matches:
                for match in matches:
                    match.location = offset
                    resolved.append(match)
        
        # Build results
        results = {
            'detected_algorithms': algorithms,
            'total_constants': len(constants),
            'resolved_count': len(resolved),
            'resolved_apis': [],
            'unique_apis': set(),
        }
        
        # Add resolved API details
        for match in resolved:
            results['resolved_apis'].append({
                'offset': f"0x{match.location:X}" if match.location else "N/A",
                'hash': f"0x{match.hash_value:08X}",
                'api_name': match.api_name,
                'algorithm': match.algorithm.upper(),
                'confidence': f"{match.confidence:.0%}",
            })
            results['unique_apis'].add(match.api_name)
        
        results['unique_api_count'] = len(results['unique_apis'])
        
        return results
    
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
        lines.append("API HASHING ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Detected algorithms
        if results['detected_algorithms']:
            lines.append("🔍 Detected Hashing Algorithms:")
            for algo in results['detected_algorithms']:
                lines.append(f"  • {algo.upper()}")
            lines.append("")
        
        # Statistics
        lines.append(f"📊 Statistics:")
        lines.append(f"  Total constants analyzed: {results['total_constants']}")
        lines.append(f"  Resolved API hashes: {results['resolved_count']}")
        lines.append(f"  Unique APIs found: {results['unique_api_count']}")
        lines.append("")
        
        # Resolved APIs
        if results['resolved_count'] > 0:
            lines.append(f"🎯 Resolved API Calls (showing first 30):")
            lines.append("")
            
            for i, api in enumerate(results['resolved_apis'][:30]):
                lines.append(f"  [{api['algorithm']}] {api['api_name']}")
                lines.append(f"    Hash: {api['hash']} | Offset: {api['offset']} | Confidence: {api['confidence']}")
                lines.append("")
            
            if results['resolved_count'] > 30:
                lines.append(f"  ... and {results['resolved_count'] - 30} more")
                lines.append("")
            
            # Unique APIs summary
            lines.append("📋 Unique APIs Detected:")
            for api in sorted(results['unique_apis'])[:50]:
                lines.append(f"  • {api}")
            if results['unique_api_count'] > 50:
                lines.append(f"  ... and {results['unique_api_count'] - 50} more")
            lines.append("")
        
        # Warning
        if results['resolved_count'] > 0:
            lines.append("⚠️  WARNING:")
            lines.append("  This binary uses API hashing to hide imports.")
            lines.append("  This technique is commonly used by:")
            lines.append("  • Malware and ransomware")
            lines.append("  • Rootkits and bootkits")
            lines.append("  • Commercial protectors (VMProtect, Themida)")
            lines.append("  • Red team implants")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# Standalone test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python api_hash_resolver.py <binary.exe>")
        sys.exit(1)
    
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    
    resolver = APIHashResolver()
    results = resolver.analyze(data)
    print(resolver.format_report(results))
