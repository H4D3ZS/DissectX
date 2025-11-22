#!/usr/bin/env python3
"""
Demo script for memory analysis features

Demonstrates:
- In-memory PE parsing
- Manual mapping detection
- Process hollowing detection
- Memory dump analysis
- Hidden PE detection

Author: DissectX Team
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

print("=" * 80)
print("DISSECTX MEMORY ANALYSIS DEMO")
print("=" * 80)
print()

# Check dependencies
try:
    from src.pe.memory_parser import MemoryPEParser, PEFILE_AVAILABLE
    from src.pe.memory_dump_analyzer import MemoryDumpAnalyzer
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\n💡 Install dependencies:")
    print("   pip install pefile")
    sys.exit(1)

if not PEFILE_AVAILABLE:
    print("❌ pefile not installed!")
    print("\n💡 Install with:")
    print("   pip install pefile")
    sys.exit(1)

print("✅ pefile available!\n")

# Demo 1: In-Memory PE Parsing
print("-" * 80)
print("DEMO 1: In-Memory PE Parsing")
print("-" * 80)
print()

# Load a sample PE
import os
sample_files = ['ch1.exe', 'ch3.exe', 'bininst2.exe']
sample_file = None

for f in sample_files:
    if os.path.exists(f):
        sample_file = f
        break

if not sample_file:
    print("⚠️  No sample files found. Skipping PE parsing demo.")
else:
    with open(sample_file, 'rb') as f:
        data = f.read()
    
    print(f"Analyzing: {sample_file}")
    print(f"Size: {len(data)} bytes")
    print()
    
    parser = MemoryPEParser()
    analysis = parser.parse_memory_dump(data, base_addr=0x400000)
    
    print(parser.format_report(analysis))

# Demo 2: Memory Dump Analysis
print("-" * 80)
print("DEMO 2: Memory Dump Analysis")
print("-" * 80)
print()

if sample_file:
    analyzer = MemoryDumpAnalyzer()
    results = analyzer.analyze_dump(data, base_addr=0x400000)
    
    print(analyzer.format_report(results))

# Demo 3: Detection Capabilities
print("-" * 80)
print("DEMO 3: Detection Capabilities Summary")
print("-" * 80)
print()

print("✅ Implemented Features:")
print("  • In-memory PE parsing")
print("  • Manual mapping detection")
print("  • Process hollowing detection")
print("  • Hidden PE file discovery")
print("  • Shellcode pattern matching")
print("  • Entropy analysis")
print("  • Suspicious string extraction")
print("  • Import/Export table parsing")
print("  • Section analysis (RWX detection)")
print()

print("🎯 Detection Techniques:")
print("  • RWX sections (manual mapping indicator)")
print("  • Missing import tables")
print("  • Unusual entry points")
print("  • Non-standard section names")
print("  • TLS callbacks (anti-debugging)")
print("  • High entropy regions (encryption)")
print("  • Shellcode patterns (GetPC, PEB access)")
print()

print("=" * 80)
print("DEMO COMPLETE")
print("=" * 80)
print()
print("💡 Use these features to:")
print("  • Analyze memory dumps from malware")
print("  • Detect injected code")
print("  • Find hidden PE files")
print("  • Identify manual mapping")
print("  • Discover process hollowing")
print()
