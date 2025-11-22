#!/usr/bin/env python3
"""
Demo script showing advanced detection capabilities

Demonstrates:
- Direct syscall detection
- API hashing resolution
- Junk code and anti-analysis detection
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.detectors.syscall_detector import SyscallDetector
from src.detectors.api_hash_resolver import APIHashResolver
from src.detectors.junk_detector import JunkDetector


def demo_syscall_detection():
    """Demonstrate syscall detection"""
    print("=" * 80)
    print("DEMO 1: Direct Syscall Detection")
    print("=" * 80)
    print()
    
    # Create sample binary data with Hell's Gate pattern
    # mov r10, rcx; mov eax, 0x0018; syscall; ret
    sample_data = b'\x4C\x8B\xD1\xB8\x18\x00\x00\x00\x0F\x05\xC3'
    sample_data += b'\x00' * 1000  # Padding
    
    detector = SyscallDetector()
    results = detector.analyze(sample_data)
    
    print(detector.format_report(results))
    print()


def demo_api_hashing():
    """Demonstrate API hash resolution"""
    print("=" * 80)
    print("DEMO 2: API Hash Resolution")
    print("=" * 80)
    print()
    
    resolver = APIHashResolver()
    
    # Show some example hashes
    print("Example API Hashes:")
    print()
    
    test_apis = ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc', 'CreateThread']
    
    for api in test_apis:
        ror13 = resolver.compute_ror13_hash(api)
        xor = resolver.compute_rolling_xor(api)
        fnv = resolver.compute_fnv1a_hash(api)
        
        print(f"API: {api}")
        print(f"  ROR-13:      0x{ror13:08X}")
        print(f"  Rolling XOR: 0x{xor:08X}")
        print(f"  FNV-1a:      0x{fnv:08X}")
        print()
    
    print("Resolver can detect and match these hashes in binaries!")
    print()


def demo_junk_detection():
    """Demonstrate junk code detection"""
    print("=" * 80)
    print("DEMO 3: Junk Code & Anti-Analysis Detection")
    print("=" * 80)
    print()
    
    # Create sample data with opaque predicates
    # cmp eax, eax (always equal)
    sample_data = b'\x39\xC0' * 10
    # xor eax, eax; test eax, eax
    sample_data += b'\x31\xC0\x85\xC0' * 5
    sample_data += b'\x00' * 1000
    
    detector = JunkDetector()
    results = detector.analyze(sample_data)
    
    print(detector.format_report(results))
    print()


def main():
    """Run all demos"""
    print()
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "DISSECTX ADVANCED DETECTION DEMO" + " " * 26 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    demo_syscall_detection()
    demo_api_hashing()
    demo_junk_detection()
    
    print("=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print()
    print("To use these features on real binaries:")
    print("  python main.py <binary> --advanced")
    print("  python main.py <binary> --detect-syscalls")
    print("  python main.py <binary> --resolve-hashes")
    print("  python main.py <binary> --detect-junk")
    print()


if __name__ == "__main__":
    main()
