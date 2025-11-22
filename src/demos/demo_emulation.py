#!/usr/bin/env python3
"""
Demo script for Unicorn emulation features

Demonstrates:
- CPU emulation
- String decryption
- Memory operations
- Register manipulation

Author: DissectX Team
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

print("=" * 80)
print("DISSECTX EMULATION DEMO")
print("=" * 80)
print()

# Check if Unicorn is available
try:
    from src.emulation.unicorn_emulator import UnicornEmulator, UNICORN_AVAILABLE
    from src.emulation.string_decryptor import StringDecryptor
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("\n💡 Install dependencies:")
    print("   pip install unicorn capstone")
    sys.exit(1)

if not UNICORN_AVAILABLE:
    print("❌ Unicorn engine not installed!")
    print("\n💡 Install with:")
    print("   pip install unicorn capstone")
    sys.exit(1)

print("✅ Unicorn engine available!\n")

# Demo 1: Basic CPU Emulation
print("-" * 80)
print("DEMO 1: Basic CPU Emulation")
print("-" * 80)
print()

# Simple arithmetic: mov eax, 5; add eax, 10; ret
code = b'\xB8\x05\x00\x00\x00'  # mov eax, 5
code += b'\x83\xC0\x0A'          # add eax, 10
code += b'\xC3'                   # ret

print("Code: mov eax, 5; add eax, 10; ret")
print(f"Bytes: {code.hex()}")
print()

emu = UnicornEmulator(arch='x64')
addr = emu.load_code(code)

result = emu.emulate(addr, max_instructions=100)

if result.success:
    print(f"✓ Emulation successful!")
    print(f"  Instructions executed: {result.instructions_executed}")
    print(f"  Final RAX: {result.final_registers.get('rax', 0)} (expected: 15)")
else:
    print(f"✗ Emulation failed: {result.error}")

print()

# Demo 2: String Decryption
print("-" * 80)
print("DEMO 2: String Decryption (XOR)")
print("-" * 80)
print()

decryptor = StringDecryptor()

# Example encrypted strings
test_strings = [
    ("flag{test_emulation}", 0x55),
    ("secret_password", 0x42),
    ("hidden_api_key", 0xAA),
]

for plaintext, key in test_strings:
    encrypted = bytes([ord(c) ^ key for c in plaintext])
    decrypted = decryptor.decrypt_xor_loop(encrypted, bytes([key]))
    
    print(f"Original:  {plaintext}")
    print(f"Key:       0x{key:02X}")
    print(f"Encrypted: {encrypted.hex()[:40]}...")
    print(f"Decrypted: {decrypted}")
    print()

# Demo 3: Memory Operations
print("-" * 80)
print("DEMO 3: Memory Operations")
print("-" * 80)
print()

emu2 = UnicornEmulator(arch='x64')

# Write a string to memory
test_string = "Hello from Unicorn!"
string_addr = emu2.HEAP_BASE
emu2.write_string(string_addr, test_string)

# Read it back
read_string = emu2.read_string(string_addr)

print(f"Written:  {test_string}")
print(f"Address:  0x{string_addr:X}")
print(f"Read back: {read_string}")
print(f"✓ Match: {test_string == read_string}")
print()

# Demo 4: Register Manipulation
print("-" * 80)
print("DEMO 4: Register Manipulation")
print("-" * 80)
print()

emu3 = UnicornEmulator(arch='x64')

# Set registers
emu3.set_register('rax', 0x1337)
emu3.set_register('rbx', 0xDEADBEEF)
emu3.set_register('rcx', 0xCAFEBABE)

# Read them back
rax = emu3.get_register('rax')
rbx = emu3.get_register('rbx')
rcx = emu3.get_register('rcx')

print(f"RAX: 0x{rax:X} (expected: 0x1337)")
print(f"RBX: 0x{rbx:X} (expected: 0xDEADBEEF)")
print(f"RCX: 0x{rcx:X} (expected: 0xCAFEBABE)")
print()

print("=" * 80)
print("DEMO COMPLETE")
print("=" * 80)
print()
print("💡 Emulation features:")
print("  • Safe, sandboxed code execution")
print("  • String decryption (XOR, RC4, custom)")
print("  • Memory read/write operations")
print("  • Register manipulation")
print("  • Instruction counting and limits")
print()
print("🚀 Use these features to:")
print("  • Decrypt obfuscated strings")
print("  • Resolve API hashes dynamically")
print("  • Extract runtime-only flags")
print("  • Analyze malware behavior safely")
print()
