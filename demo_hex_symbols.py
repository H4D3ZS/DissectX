#!/usr/bin/env python3
"""Demo script for hexadecimal and symbol handling features"""

from src.parser import AssemblyParser
from src.translator import InstructionTranslator
from src.formatter import OutputFormatter

def main():
    """Demonstrate hex value interpretation and symbol handling"""
    
    # Sample assembly with hex values and symbolic names
    assembly_code = """
140001000 mov rax, 0x1000
140001007 lea rdx, [rsp+0x20]
14000100e call _Z10my_functionii
140001013 cmp rax, 0x0
140001016 jne 0x140001030
14000101b mov rbx, 0x7FFFFFFF
140001022 call ?myFunc@@YAXXZ
140001027 add rsp, 0x8
14000102b ret
"""
    
    print("=" * 80)
    print("Assembly to English Translator - Hex & Symbol Handling Demo")
    print("=" * 80)
    print()
    
    # Parse the assembly
    parser = AssemblyParser()
    instructions = parser.parse(assembly_code)
    
    print(f"Parsed {len(instructions)} instructions")
    print()
    
    # Translate instructions
    translator = InstructionTranslator()
    translations = {}
    
    print("INSTRUCTION-LEVEL TRANSLATIONS:")
    print("-" * 80)
    
    for instr in instructions:
        translation = translator.translate(instr)
        translations[id(instr)] = translation
        
        # Format instruction display
        addr = instr.address if instr.address else "        "
        mnemonic = instr.mnemonic.ljust(8)
        operands = ", ".join(instr.operands)
        
        print(f"{addr}  {mnemonic} {operands}")
        print(f"         → {translation}")
        print()
    
    print()
    print("=" * 80)
    print("FEATURE DEMONSTRATIONS:")
    print("=" * 80)
    print()
    
    # Demonstrate hex value interpretation
    print("1. Hexadecimal Value Interpretation:")
    print("-" * 40)
    test_values = [0, 4, 0x50, 0x1000, 0x140001000]
    for val in test_values:
        explanation = translator._explain_hex_value(val)
        print(f"   {hex(val):15s} → {explanation}")
    print()
    
    # Demonstrate address type identification
    print("2. Address Type Identification:")
    print("-" * 40)
    test_addresses = ["0x140001000", "0x400000", "0x100", "0x7FFFFFFF"]
    for addr in test_addresses:
        addr_type = translator._identify_address_type(addr)
        print(f"   {addr:15s} → {addr_type}")
    print()
    
    # Demonstrate hex address detection
    print("3. Hex Address Detection:")
    print("-" * 40)
    test_strings = ["0x140001000", "140001000", "sub_140001", "rax", "_Z3foov"]
    for s in test_strings:
        is_hex = translator._is_hex_address(s)
        print(f"   {s:20s} → {'Yes' if is_hex else 'No'}")
    print()
    
    # Demonstrate mangled name detection
    print("4. C++ Mangled Name Detection:")
    print("-" * 40)
    test_names = [
        "_Z3foov",
        "_Z10my_functionii",
        "?myFunc@@YAXXZ",
        "??0MyClass@@QEAA@XZ",
        "main",
        "sub_140001000"
    ]
    for name in test_names:
        is_mangled = translator._is_mangled_name(name)
        demangled = translator._demangle_name(name) if is_mangled else None
        status = f"Mangled → {demangled}" if demangled else ("Mangled (no demangle)" if is_mangled else "Not mangled")
        print(f"   {name:25s} → {status}")
    print()
    
    print("=" * 80)
    print("Demo complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()
