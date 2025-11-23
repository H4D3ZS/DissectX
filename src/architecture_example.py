"""
Example usage of the Architecture Abstraction Layer

This module demonstrates how to use the architecture abstraction layer
to work with different CPU architectures in DissectX.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.architecture import (
    Architecture,
    X86Architecture,
    ARMArchitecture,
    MIPSArchitecture,
)


def example_x86_usage():
    """Example: Using X86Architecture"""
    print("=== X86-64 Architecture Example ===\n")
    
    # Create x86-64 architecture instance
    arch = X86Architecture(is_64bit=True)
    
    # Get architecture info
    print(f"Architecture: {arch.get_architecture_name()}")
    
    # Get calling convention
    cc = arch.get_calling_convention()
    print(f"Calling Convention: {cc.name}")
    print(f"Integer Arguments: {cc.integer_args}")
    print(f"Return Register: {cc.return_reg}")
    
    # Translate instructions
    print("\nInstruction Translation:")
    print(f"  mov rax, rbx  ->  {arch.translate_instruction('mov', ['rax', 'rbx'])}")
    print(f"  add rax, 5    ->  {arch.translate_instruction('add', ['rax', '5'])}")
    print(f"  call func     ->  {arch.translate_instruction('call', ['func'])}")
    
    # Check instruction types
    print("\nInstruction Type Detection:")
    print(f"  'jmp' is branch: {arch.is_branch_instruction('jmp')}")
    print(f"  'call' is call: {arch.is_call_instruction('call')}")
    print(f"  'ret' is return: {arch.is_return_instruction('ret')}")
    
    # Get register info
    print("\nRegister Information:")
    reg_info = arch.get_register_info('rax')
    print(f"  Register: {reg_info.name}")
    print(f"  Size: {reg_info.size} bits")
    print(f"  Description: {reg_info.description}")
    print(f"  Aliases: {reg_info.aliases}")


def example_arm_usage():
    """Example: Using ARMArchitecture"""
    print("\n\n=== ARM64 Architecture Example ===\n")
    
    # Create ARM64 architecture instance
    arch = ARMArchitecture(is_64bit=True)
    
    # Get architecture info
    print(f"Architecture: {arch.get_architecture_name()}")
    
    # Get calling convention
    cc = arch.get_calling_convention()
    print(f"Calling Convention: {cc.name}")
    print(f"Integer Arguments: {cc.integer_args}")
    print(f"Return Register: {cc.return_reg}")
    
    # Translate instructions
    print("\nInstruction Translation:")
    print(f"  mov x0, x1       ->  {arch.translate_instruction('mov', ['x0', 'x1'])}")
    print(f"  add x0, x1, x2   ->  {arch.translate_instruction('add', ['x0', 'x1', 'x2'])}")
    print(f"  bl func          ->  {arch.translate_instruction('bl', ['func'])}")
    
    # Check instruction types
    print("\nInstruction Type Detection:")
    print(f"  'b' is branch: {arch.is_branch_instruction('b')}")
    print(f"  'bl' is call: {arch.is_call_instruction('bl')}")
    print(f"  'ret' is return: {arch.is_return_instruction('ret')}")


def example_mips_usage():
    """Example: Using MIPSArchitecture"""
    print("\n\n=== MIPS32 Architecture Example ===\n")
    
    # Create MIPS32 architecture instance
    arch = MIPSArchitecture(is_64bit=False)
    
    # Get architecture info
    print(f"Architecture: {arch.get_architecture_name()}")
    
    # Get calling convention
    cc = arch.get_calling_convention()
    print(f"Calling Convention: {cc.name}")
    print(f"Integer Arguments: {cc.integer_args}")
    print(f"Return Register: {cc.return_reg}")
    
    # Translate instructions
    print("\nInstruction Translation:")
    print(f"  move $t0, $t1       ->  {arch.translate_instruction('move', ['$t0', '$t1'])}")
    print(f"  add $t0, $t1, $t2   ->  {arch.translate_instruction('add', ['$t0', '$t1', '$t2'])}")
    print(f"  jal func            ->  {arch.translate_instruction('jal', ['func'])}")
    
    # Check instruction types
    print("\nInstruction Type Detection:")
    print(f"  'j' is branch: {arch.is_branch_instruction('j')}")
    print(f"  'jal' is call: {arch.is_call_instruction('jal')}")


def example_architecture_factory():
    """Example: Creating architecture instances based on detection"""
    print("\n\n=== Architecture Factory Pattern ===\n")
    
    def create_architecture(arch_type: Architecture, is_64bit: bool = True):
        """Factory function to create architecture instances"""
        if arch_type in [Architecture.X86, Architecture.X86_64]:
            return X86Architecture(is_64bit=is_64bit)
        elif arch_type in [Architecture.ARM, Architecture.ARM64]:
            return ARMArchitecture(is_64bit=is_64bit)
        elif arch_type in [Architecture.MIPS, Architecture.MIPS64]:
            return MIPSArchitecture(is_64bit=is_64bit)
        else:
            raise ValueError(f"Unsupported architecture: {arch_type}")
    
    # Create different architectures
    architectures = [
        (Architecture.X86_64, True),
        (Architecture.ARM64, True),
        (Architecture.MIPS, False),
    ]
    
    for arch_type, is_64bit in architectures:
        arch = create_architecture(arch_type, is_64bit)
        print(f"Created: {arch.get_architecture_name()}")
        print(f"  Calling convention: {arch.get_calling_convention().name}")
        print(f"  Register count: {len(arch.get_register_names())}")


if __name__ == "__main__":
    example_x86_usage()
    example_arm_usage()
    example_mips_usage()
    example_architecture_factory()
