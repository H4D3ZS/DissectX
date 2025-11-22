#!/usr/bin/env python3
"""
Unicorn CPU Emulator for DissectX

Provides safe, sandboxed execution of binary code for:
- String decryption
- API hash resolution
- Control flow analysis
- Runtime flag extraction

Author: DissectX Team
"""

import struct
from typing import Optional, List, Dict, Tuple, Callable
from dataclasses import dataclass

try:
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


@dataclass
class EmulationResult:
    """Results from code emulation"""
    success: bool
    instructions_executed: int
    final_registers: Dict[str, int]
    memory_reads: List[Tuple[int, bytes]]
    memory_writes: List[Tuple[int, bytes]]
    output_strings: List[str]
    error: Optional[str] = None


class UnicornEmulator:
    """CPU emulator for safe code execution"""
    
    # Memory layout
    CODE_BASE = 0x400000
    STACK_BASE = 0x7FF000
    STACK_SIZE = 0x10000  # 64KB stack
    HEAP_BASE = 0x800000
    HEAP_SIZE = 0x100000  # 1MB heap
    
    def __init__(self, arch: str = 'x64'):
        """
        Initialize emulator
        
        Args:
            arch: Architecture ('x64' or 'x86')
        """
        if not UNICORN_AVAILABLE:
            raise ImportError("Unicorn engine not installed. Run: pip install unicorn")
        
        self.arch = arch
        
        # Create emulator instance
        if arch == 'x64':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        elif arch == 'x86':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
        
        # Tracking
        self.instruction_count = 0
        self.max_instructions = 10000
        self.memory_reads = []
        self.memory_writes = []
        self.output_strings = []
        
        # Setup memory regions
        self._setup_memory()
        
        # Setup hooks
        self._setup_hooks()
    
    def _setup_memory(self):
        """Setup memory regions (code, stack, heap)"""
        # Map code section (RWX for simplicity)
        self.uc.mem_map(self.CODE_BASE, 2 * 1024 * 1024)  # 2MB code
        
        # Map stack (RW)
        self.uc.mem_map(self.STACK_BASE - self.STACK_SIZE, self.STACK_SIZE)
        
        # Map heap (RW)
        self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)
        
        # Initialize stack pointer
        if self.arch == 'x64':
            self.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE - 0x1000)
            self.uc.reg_write(UC_X86_REG_RBP, self.STACK_BASE - 0x1000)
        else:
            self.uc.reg_write(UC_X86_REG_ESP, self.STACK_BASE - 0x1000)
            self.uc.reg_write(UC_X86_REG_EBP, self.STACK_BASE - 0x1000)
    
    def _setup_hooks(self):
        """Setup emulation hooks for tracking"""
        # Hook code execution
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # Hook memory access
        self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
        
        # Hook invalid memory access
        self.uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            self._hook_mem_invalid
        )
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook for each instruction executed"""
        self.instruction_count += 1
        
        # Stop if max instructions reached
        if self.instruction_count >= self.max_instructions:
            uc.emu_stop()
    
    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        """Hook for memory reads"""
        try:
            data = uc.mem_read(address, size)
            self.memory_reads.append((address, bytes(data)))
        except:
            pass
    
    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        """Hook for memory writes"""
        try:
            data = uc.mem_read(address, size)
            self.memory_writes.append((address, bytes(data)))
        except:
            pass
    
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Hook for invalid memory access"""
        # Try to map the page
        page_size = 0x1000
        page_start = address & ~(page_size - 1)
        
        try:
            uc.mem_map(page_start, page_size)
            return True
        except:
            return False
    
    def load_code(self, code: bytes, base_addr: Optional[int] = None) -> int:
        """
        Load code into memory
        
        Args:
            code: Binary code to load
            base_addr: Base address (default: CODE_BASE)
            
        Returns:
            Address where code was loaded
        """
        if base_addr is None:
            base_addr = self.CODE_BASE
        
        self.uc.mem_write(base_addr, code)
        return base_addr
    
    def set_register(self, reg_name: str, value: int):
        """Set register value"""
        reg_map = {
            'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX,
            'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX,
            'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
            'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP,
            'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9,
            'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX,
            'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
        }
        
        if reg_name.lower() in reg_map:
            self.uc.reg_write(reg_map[reg_name.lower()], value)
    
    def get_register(self, reg_name: str) -> int:
        """Get register value"""
        reg_map = {
            'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX,
            'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX,
            'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
            'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP,
            'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9,
            'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX,
            'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
        }
        
        if reg_name.lower() in reg_map:
            return self.uc.reg_read(reg_map[reg_name.lower()])
        return 0
    
    def read_string(self, address: int, max_len: int = 256) -> Optional[str]:
        """
        Read null-terminated string from memory
        
        Args:
            address: Memory address
            max_len: Maximum string length
            
        Returns:
            String or None
        """
        try:
            data = self.uc.mem_read(address, max_len)
            # Find null terminator
            null_pos = data.find(b'\x00')
            if null_pos != -1:
                return data[:null_pos].decode('utf-8', errors='ignore')
            return data.decode('utf-8', errors='ignore')
        except:
            return None
    
    def write_string(self, address: int, string: str):
        """Write null-terminated string to memory"""
        data = string.encode('utf-8') + b'\x00'
        self.uc.mem_write(address, data)
    

    def load_pe(self, pe_data: bytes):
        """
        Load PE file into emulator memory
        
        Args:
            pe_data: Raw PE file data
        """
        try:
            import pefile
            pe = pefile.PE(data=pe_data)
            
            # Get ImageBase and Size
            image_base = pe.OPTIONAL_HEADER.ImageBase
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            aligned_size = (size_of_image + 0xFFF) & ~0xFFF
            
            self.code_base = image_base
            self.image_size = aligned_size
            
            # Map entire image region
            self.uc.mem_map(image_base, aligned_size)
            print(f"✅ Mapped Image: 0x{image_base:X} - 0x{image_base+aligned_size:X} ({aligned_size} bytes)")
            
            # Write header
            self.uc.mem_write(image_base, pe.header)
            
            # Write sections
            for section in pe.sections:
                vaddr = image_base + section.VirtualAddress
                data = section.get_data()
                self.uc.mem_write(vaddr, data)
                
            # Setup stack
            self.stack_base = 0x00100000 # 1MB
            self.stack_size = 0x00100000 # 1MB
            self.uc.mem_map(self.stack_base, self.stack_size)
            self.uc.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size - 0x100)
            
            # Set Entry Point
            self.entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            print(f"✅ Loaded PE Entry: 0x{self.entry_point:X}")
            
        except ImportError:
            print("❌ pefile not installed")
        except Exception as e:
            print(f"❌ Error loading PE: {e}")

    def dump_memory(self, output_file: str):
        """
        Dump all mapped memory to file
        
        Args:
            output_file: Path to output file
        """
        try:
            # We'll dump the main image region
            # Find the range. Simple approach: Dump from ImageBase to end of last section
            # Or just dump the whole mapped range if we track it.
            
            # For this implementation, we'll dump a fixed large region around the code base
            # This covers the unpacked code.
            
            # Better: Iterate regions (Unicorn 2.0 supports mem_regions())
            # But for compatibility, we'll dump 0x400000 size 0x100000 (1MB) or calculated size
            
            dump_size = getattr(self, 'image_size', 0x200000)
            data = self.uc.mem_read(self.code_base, dump_size)
            
            with open(output_file, 'wb') as f:
                f.write(data)
                
            print(f"💾 Memory dumped to {output_file} (Size: {dump_size} bytes)")
            
        except Exception as e:
            print(f"❌ Error dumping memory: {e}")
            
    def emulate(self, code: bytes = None, count: int = 0):
        """
        Start emulation
        
        Args:
            code: Code to emulate (optional if loaded via load_pe)
            count: Max instructions
        """
        try:
            if code:
                # Legacy mode: map code at fixed address
                self.uc.mem_map(self.code_base, 0x10000)
                self.uc.mem_write(self.code_base, code)
                start = self.code_base
                end = self.code_base + len(code)
            else:
                # PE mode
                start = self.entry_point
                end = self.code_base + 0x100000 # Run until... far?
            
            print(f"🚀 Starting emulation at 0x{start:X}...")
            self.uc.emu_start(start, end, timeout=0, count=count)
            print("✅ Emulation finished")
            
        except Exception as e:
            print(f"⚠️ Emulation stopped: {e}")
            if self.arch == 'x64':
                final_regs = {
                    'rax': self.get_register('rax'),
                    'rbx': self.get_register('rbx'),
                    'rcx': self.get_register('rcx'),
                    'rsi': self.get_register('rsi'),
                    'rdi': self.get_register('rdi'),
                }
            else:
                final_regs = {
                    'eax': self.get_register('eax'),
                    'ebx': self.get_register('ebx'),
                    'ecx': self.get_register('ecx'),
                    'edx': self.get_register('edx'),
                }
            
            return EmulationResult(
                success=True,
                instructions_executed=self.instruction_count,
                final_registers=final_regs,
                memory_reads=self.memory_reads,
                memory_writes=self.memory_writes,
                output_strings=self.output_strings
            )
            
        except UcError as e:
            return EmulationResult(
                success=False,
                instructions_executed=self.instruction_count,
                final_registers={},
                memory_reads=self.memory_reads,
                memory_writes=self.memory_writes,
                output_strings=self.output_strings,
                error=str(e)
            )
    
    def decrypt_xor_string(self, encrypted_data: bytes, key: int) -> str:
        """
        Decrypt XOR-encrypted string via emulation
        
        Args:
            encrypted_data: Encrypted bytes
            key: XOR key
            
        Returns:
            Decrypted string
        """
        # Simple XOR decryption code
        # mov al, [rsi]; xor al, dl; mov [rdi], al; inc rsi; inc rdi; loop
        
        # For now, just do it directly (emulation would be overkill for simple XOR)
        decrypted = bytes([b ^ key for b in encrypted_data])
        return decrypted.decode('utf-8', errors='ignore')


# Standalone test
if __name__ == "__main__":
    if not UNICORN_AVAILABLE:
        print("❌ Unicorn not installed. Run: pip install unicorn")
        exit(1)
    
    print("✅ Unicorn engine available!")
    print("\nTesting basic emulation...")
    
    # Test: Simple addition (mov eax, 5; add eax, 10; ret)
    code = b'\xB8\x05\x00\x00\x00'  # mov eax, 5
    code += b'\x83\xC0\x0A'          # add eax, 10
    code += b'\xC3'                   # ret
    
    emu = UnicornEmulator(arch='x64')
    addr = emu.load_code(code)
    
    result = emu.emulate(addr, max_instructions=100)
    
    if result.success:
        print(f"✓ Emulation successful!")
        print(f"  Instructions executed: {result.instructions_executed}")
        print(f"  Final EAX: {result.final_registers.get('rax', 0)} (expected: 15)")
    else:
        print(f"✗ Emulation failed: {result.error}")
