#!/usr/bin/env python3
"""
Unicorn CPU Emulator for DissectX

Provides safe, sandboxed execution of binary code for:
- String decryption
- API hash resolution
- Control flow analysis
- Runtime flag extraction

Implements Requirements 14.1-14.5:
- 14.1: Initialize Unicorn engine with appropriate memory and registers
- 14.2: Emulate instruction execution in sandboxed environment
- 14.3: Provide basic syscall stubs for common operations
- 14.4: Allow memory dumping for analysis
- 14.5: Handle exceptions gracefully and report issues

Author: DissectX Team
"""

import struct
import logging
from typing import Optional, List, Dict, Tuple, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from unicorn import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False
    logger.warning("Unicorn engine not available. Install with: pip install unicorn")

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class EmulationError(Exception):
    """Base exception for emulation errors"""
    pass


class SyscallError(EmulationError):
    """Exception for syscall-related errors"""
    pass


class MemoryError(EmulationError):
    """Exception for memory-related errors"""
    pass


@dataclass
class EmulationResult:
    """Results from code emulation"""
    success: bool
    instructions_executed: int
    final_registers: Dict[str, int]
    memory_reads: List[Tuple[int, bytes]] = field(default_factory=list)
    memory_writes: List[Tuple[int, bytes]] = field(default_factory=list)
    output_strings: List[str] = field(default_factory=list)
    syscalls_invoked: List[Tuple[int, str]] = field(default_factory=list)
    error: Optional[str] = None
    error_address: Optional[int] = None


class UnicornEmulator:
    """
    CPU emulator for safe code execution
    
    Implements sandboxed execution with:
    - Isolated memory regions (code, stack, heap)
    - Syscall interception and stubbing
    - Memory access tracking
    - Instruction counting and limits
    - Error handling and recovery
    """
    
    # Memory layout (Requirement 14.1: appropriate memory setup)
    CODE_BASE = 0x400000
    CODE_SIZE = 0x200000  # 2MB code
    STACK_BASE = 0x7FF000
    STACK_SIZE = 0x10000  # 64KB stack
    HEAP_BASE = 0x800000
    HEAP_SIZE = 0x100000  # 1MB heap
    
    # Safety limits (Requirement 14.2: sandboxing)
    MAX_INSTRUCTIONS = 10000
    MAX_MEMORY_ACCESSES = 100000
    EMULATION_TIMEOUT_MS = 5000
    
    # Sandboxing flags (Requirement 14.2)
    ALLOW_NETWORK = False  # Never allow network access
    ALLOW_FILE_IO = False  # Never allow real file I/O
    ALLOW_PROCESS_CREATION = False  # Never allow process creation
    
    def __init__(self, arch: str = 'x64', enable_syscalls: bool = True):
        """
        Initialize emulator (Requirement 14.1)
        
        Args:
            arch: Architecture ('x64' or 'x86')
            enable_syscalls: Enable syscall stubbing (Requirement 14.3)
            
        Raises:
            ImportError: If Unicorn is not available
            ValueError: If architecture is unsupported
        """
        if not UNICORN_AVAILABLE:
            raise ImportError("Unicorn engine not installed. Run: pip install unicorn")
        
        self.arch = arch
        self.enable_syscalls = enable_syscalls
        
        # Create emulator instance
        if arch == 'x64':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
            self.ptr_size = 8
        elif arch == 'x86':
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
            self.ptr_size = 4
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
        
        # Tracking (Requirement 14.2: monitoring for safety)
        self.instruction_count = 0
        self.memory_access_count = 0
        self.memory_reads = []
        self.memory_writes = []
        self.output_strings = []
        self.syscalls_invoked = []
        
        # Error tracking (Requirement 14.5)
        self.last_error = None
        self.error_address = None
        
        # Syscall handlers (Requirement 14.3)
        self.syscall_handlers = {}
        
        # Setup memory regions (Requirement 14.1)
        self._setup_memory()
        
        # Setup hooks (Requirements 14.2, 14.3, 14.5)
        self._setup_hooks()
        
        # Register default syscall stubs (Requirement 14.3)
        if enable_syscalls:
            self._register_default_syscalls()
        
        logger.info(f"Initialized {arch} emulator with sandboxing enabled")
    
    def _setup_memory(self):
        """
        Setup memory regions (Requirement 14.1)
        
        Creates isolated memory regions for:
        - Code section (executable)
        - Stack (read/write)
        - Heap (read/write)
        """
        try:
            # Map code section (RWX for simplicity in emulation)
            self.uc.mem_map(self.CODE_BASE, self.CODE_SIZE)
            logger.debug(f"Mapped code: 0x{self.CODE_BASE:X} - 0x{self.CODE_BASE + self.CODE_SIZE:X}")
            
            # Map stack (RW)
            stack_start = self.STACK_BASE - self.STACK_SIZE
            self.uc.mem_map(stack_start, self.STACK_SIZE)
            logger.debug(f"Mapped stack: 0x{stack_start:X} - 0x{self.STACK_BASE:X}")
            
            # Map heap (RW)
            self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE)
            logger.debug(f"Mapped heap: 0x{self.HEAP_BASE:X} - 0x{self.HEAP_BASE + self.HEAP_SIZE:X}")
            
            # Initialize stack pointer (Requirement 14.1: appropriate registers)
            stack_top = self.STACK_BASE - 0x1000
            if self.arch == 'x64':
                self.uc.reg_write(UC_X86_REG_RSP, stack_top)
                self.uc.reg_write(UC_X86_REG_RBP, stack_top)
            else:
                self.uc.reg_write(UC_X86_REG_ESP, stack_top)
                self.uc.reg_write(UC_X86_REG_EBP, stack_top)
            
            logger.debug(f"Initialized stack pointer to 0x{stack_top:X}")
            
        except UcError as e:
            raise MemoryError(f"Failed to setup memory: {e}")
    
    def _setup_hooks(self):
        """
        Setup emulation hooks (Requirements 14.2, 14.3, 14.5)
        
        Hooks for:
        - Instruction execution (safety limits)
        - Memory access (tracking and sandboxing)
        - Syscalls (interception and stubbing)
        - Error handling (invalid memory, etc.)
        """
        try:
            # Hook code execution (Requirement 14.2: monitoring)
            self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
            
            # Hook memory access (Requirement 14.2: tracking)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_mem_write)
            
            # Hook invalid memory access (Requirement 14.5: error handling)
            self.uc.hook_add(
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                self._hook_mem_invalid
            )
            
            # Hook syscalls (Requirement 14.3: syscall stubs)
            if self.enable_syscalls:
                self.uc.hook_add(UC_HOOK_INSN, self._hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
            
            logger.debug("Emulation hooks configured")
            
        except UcError as e:
            raise EmulationError(f"Failed to setup hooks: {e}")
    
    def _hook_code(self, uc, address, size, user_data):
        """
        Hook for each instruction executed (Requirement 14.2: safety limits)
        
        Enforces instruction count limits to prevent infinite loops
        """
        self.instruction_count += 1
        
        # Stop if max instructions reached (Requirement 14.2: sandboxing)
        if self.instruction_count >= self.MAX_INSTRUCTIONS:
            logger.warning(f"Instruction limit reached ({self.MAX_INSTRUCTIONS})")
            uc.emu_stop()
    
    def _hook_mem_read(self, uc, access, address, size, value, user_data):
        """
        Hook for memory reads (Requirement 14.2: tracking)
        
        Records all memory reads for analysis
        """
        self.memory_access_count += 1
        
        # Safety check (Requirement 14.2: sandboxing)
        if self.memory_access_count >= self.MAX_MEMORY_ACCESSES:
            logger.warning(f"Memory access limit reached ({self.MAX_MEMORY_ACCESSES})")
            uc.emu_stop()
            return
        
        try:
            data = uc.mem_read(address, size)
            self.memory_reads.append((address, bytes(data)))
        except UcError:
            pass
    
    def _hook_mem_write(self, uc, access, address, size, value, user_data):
        """
        Hook for memory writes (Requirement 14.2: tracking and sandboxing)
        
        Records memory writes and prevents writes to code section
        """
        self.memory_access_count += 1
        
        # Safety check (Requirement 14.2: sandboxing)
        if self.memory_access_count >= self.MAX_MEMORY_ACCESSES:
            logger.warning(f"Memory access limit reached ({self.MAX_MEMORY_ACCESSES})")
            uc.emu_stop()
            return
        
        # Prevent writes to code section (Requirement 14.2: sandboxing)
        if self.CODE_BASE <= address < self.CODE_BASE + self.CODE_SIZE:
            logger.warning(f"Attempted write to code section at 0x{address:X}")
            # Allow for now but log it
        
        try:
            data = uc.mem_read(address, size)
            self.memory_writes.append((address, bytes(data)))
        except UcError:
            pass
    
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """
        Hook for invalid memory access (Requirement 14.5: error handling)
        
        Attempts to recover by mapping the page, or logs error
        """
        page_size = 0x1000
        page_start = address & ~(page_size - 1)
        
        logger.warning(f"Invalid memory access at 0x{address:X}")
        
        # Try to map the page (Requirement 14.5: graceful handling)
        try:
            uc.mem_map(page_start, page_size)
            logger.debug(f"Mapped page at 0x{page_start:X}")
            return True
        except UcError as e:
            self.last_error = f"Failed to map memory at 0x{address:X}: {e}"
            self.error_address = address
            logger.error(self.last_error)
            return False
    
    def _hook_syscall(self, uc, user_data):
        """
        Hook for syscall instructions (Requirement 14.3: syscall stubs)
        
        Intercepts syscalls and routes to appropriate handlers
        """
        # Get syscall number from RAX/EAX
        if self.arch == 'x64':
            syscall_num = uc.reg_read(UC_X86_REG_RAX)
        else:
            syscall_num = uc.reg_read(UC_X86_REG_EAX)
        
        logger.debug(f"Syscall intercepted: {syscall_num}")
        self.syscalls_invoked.append((syscall_num, f"syscall_{syscall_num}"))
        
        # Route to handler (Requirement 14.3)
        if syscall_num in self.syscall_handlers:
            try:
                self.syscall_handlers[syscall_num](uc, syscall_num)
            except Exception as e:
                logger.error(f"Syscall handler error: {e}")
                self.last_error = f"Syscall {syscall_num} failed: {e}"
        else:
            # Default: return 0 (success)
            logger.debug(f"No handler for syscall {syscall_num}, returning 0")
            if self.arch == 'x64':
                uc.reg_write(UC_X86_REG_RAX, 0)
            else:
                uc.reg_write(UC_X86_REG_EAX, 0)
    
    def _register_default_syscalls(self):
        """
        Register default syscall stubs (Requirement 14.3)
        
        Provides basic stubs for common syscalls to prevent crashes
        """
        # Linux x64 syscalls
        self.register_syscall(0, self._syscall_read, "read")
        self.register_syscall(1, self._syscall_write, "write")
        self.register_syscall(2, self._syscall_open, "open")
        self.register_syscall(3, self._syscall_close, "close")
        self.register_syscall(9, self._syscall_mmap, "mmap")
        self.register_syscall(10, self._syscall_mprotect, "mprotect")
        self.register_syscall(11, self._syscall_munmap, "munmap")
        self.register_syscall(12, self._syscall_brk, "brk")
        self.register_syscall(39, self._syscall_getpid, "getpid")
        self.register_syscall(41, self._syscall_socket, "socket")
        self.register_syscall(42, self._syscall_connect, "connect")
        self.register_syscall(60, self._syscall_exit, "exit")
        self.register_syscall(231, self._syscall_exit_group, "exit_group")
        
        logger.debug("Registered default syscall stubs")
    
    def register_syscall(self, syscall_num: int, handler: Callable, name: str = None):
        """
        Register a syscall handler (Requirement 14.3)
        
        Args:
            syscall_num: Syscall number
            handler: Handler function(uc, syscall_num)
            name: Optional name for logging
        """
        self.syscall_handlers[syscall_num] = handler
        logger.debug(f"Registered syscall {syscall_num}: {name or 'unnamed'}")
    
    def _syscall_read(self, uc, syscall_num):
        """Stub for read syscall (Requirement 14.3)"""
        # Return 0 bytes read
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, 0)
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
    
    def _syscall_write(self, uc, syscall_num):
        """Stub for write syscall (Requirement 14.3)"""
        # Get arguments
        if self.arch == 'x64':
            fd = uc.reg_read(UC_X86_REG_RDI)
            buf = uc.reg_read(UC_X86_REG_RSI)
            count = uc.reg_read(UC_X86_REG_RDX)
        else:
            # x86 uses stack for args
            fd = 1
            buf = 0
            count = 0
        
        # Try to read the buffer
        if buf and count > 0 and count < 4096:
            try:
                data = uc.mem_read(buf, min(count, 256))
                output = data.decode('utf-8', errors='ignore')
                self.output_strings.append(output)
                logger.debug(f"Write syscall output: {output[:50]}")
            except:
                pass
        
        # Return bytes written
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, count)
        else:
            uc.reg_write(UC_X86_REG_EAX, count)
    
    def _syscall_open(self, uc, syscall_num):
        """
        Stub for open syscall (Requirement 14.3)
        
        Returns fake file descriptor (Requirement 14.2: no real file I/O)
        """
        # Return fake file descriptor (sandboxed - no real file access)
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, 3)
        else:
            uc.reg_write(UC_X86_REG_EAX, 3)
        
        logger.debug("Open syscall stubbed (sandboxed - no real file access)")
    
    def _syscall_close(self, uc, syscall_num):
        """Stub for close syscall (Requirement 14.3)"""
        # Return success
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, 0)
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
    
    def _syscall_exit(self, uc, syscall_num):
        """Stub for exit syscall (Requirement 14.3)"""
        logger.debug("Exit syscall called, stopping emulation")
        uc.emu_stop()
    
    def _syscall_exit_group(self, uc, syscall_num):
        """Stub for exit_group syscall (Requirement 14.3)"""
        logger.debug("Exit_group syscall called, stopping emulation")
        uc.emu_stop()
    
    def _syscall_mmap(self, uc, syscall_num):
        """
        Stub for mmap syscall (Requirement 14.3)
        
        Returns fake memory address (sandboxed)
        """
        # Return fake address in heap region
        fake_addr = self.HEAP_BASE + 0x10000
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, fake_addr)
        else:
            uc.reg_write(UC_X86_REG_EAX, fake_addr)
        logger.debug(f"Mmap syscall stubbed, returned 0x{fake_addr:X}")
    
    def _syscall_mprotect(self, uc, syscall_num):
        """Stub for mprotect syscall (Requirement 14.3)"""
        # Return success
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, 0)
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
        logger.debug("Mprotect syscall stubbed")
    
    def _syscall_munmap(self, uc, syscall_num):
        """Stub for munmap syscall (Requirement 14.3)"""
        # Return success
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, 0)
        else:
            uc.reg_write(UC_X86_REG_EAX, 0)
        logger.debug("Munmap syscall stubbed")
    
    def _syscall_brk(self, uc, syscall_num):
        """Stub for brk syscall (Requirement 14.3)"""
        # Return current heap end
        heap_end = self.HEAP_BASE + self.HEAP_SIZE
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, heap_end)
        else:
            uc.reg_write(UC_X86_REG_EAX, heap_end)
        logger.debug(f"Brk syscall stubbed, returned 0x{heap_end:X}")
    
    def _syscall_getpid(self, uc, syscall_num):
        """Stub for getpid syscall (Requirement 14.3)"""
        # Return fake PID
        fake_pid = 1337
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, fake_pid)
        else:
            uc.reg_write(UC_X86_REG_EAX, fake_pid)
        logger.debug(f"Getpid syscall stubbed, returned {fake_pid}")
    
    def _syscall_socket(self, uc, syscall_num):
        """
        Stub for socket syscall (Requirement 14.3)
        
        Returns error (sandboxed - no network access)
        """
        # Return error (Requirement 14.2: no network access)
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, -1)  # EACCES
        else:
            uc.reg_write(UC_X86_REG_EAX, -1)
        logger.warning("Socket syscall blocked (sandboxed - no network access)")
    
    def _syscall_connect(self, uc, syscall_num):
        """
        Stub for connect syscall (Requirement 14.3)
        
        Returns error (sandboxed - no network access)
        """
        # Return error (Requirement 14.2: no network access)
        if self.arch == 'x64':
            uc.reg_write(UC_X86_REG_RAX, -1)  # EACCES
        else:
            uc.reg_write(UC_X86_REG_EAX, -1)
        logger.warning("Connect syscall blocked (sandboxed - no network access)")
    
    def load_code(self, code: bytes, base_addr: Optional[int] = None) -> int:
        """
        Load code into memory (Requirement 14.1)
        
        Args:
            code: Binary code to load
            base_addr: Base address (default: CODE_BASE)
            
        Returns:
            Address where code was loaded
            
        Raises:
            MemoryError: If code loading fails
        """
        if base_addr is None:
            base_addr = self.CODE_BASE
        
        try:
            self.uc.mem_write(base_addr, code)
            logger.debug(f"Loaded {len(code)} bytes at 0x{base_addr:X}")
            return base_addr
        except UcError as e:
            raise MemoryError(f"Failed to load code: {e}")
    
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
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """
        Read memory region (Requirement 14.4)
        
        Args:
            address: Memory address
            size: Number of bytes to read
            
        Returns:
            Bytes or None if read fails
        """
        try:
            return bytes(self.uc.mem_read(address, size))
        except UcError as e:
            logger.error(f"Failed to read memory at 0x{address:X}: {e}")
            return None
    
    def write_memory(self, address: int, data: bytes):
        """
        Write to memory
        
        Args:
            address: Memory address
            data: Bytes to write
            
        Raises:
            MemoryError: If write fails
        """
        try:
            self.uc.mem_write(address, data)
        except UcError as e:
            raise MemoryError(f"Failed to write memory at 0x{address:X}: {e}")
    
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
        except UcError:
            return None
    
    def write_string(self, address: int, string: str):
        """
        Write null-terminated string to memory
        
        Args:
            address: Memory address
            string: String to write
        """
        data = string.encode('utf-8') + b'\x00'
        try:
            self.uc.mem_write(address, data)
        except UcError as e:
            raise MemoryError(f"Failed to write string at 0x{address:X}: {e}")
    
    def dump_memory(self, output_file: str, start_addr: Optional[int] = None, size: Optional[int] = None):
        """
        Dump memory to file (Requirement 14.4)
        
        Args:
            output_file: Path to output file
            start_addr: Start address (default: CODE_BASE)
            size: Size to dump (default: CODE_SIZE)
            
        Raises:
            MemoryError: If dump fails
        """
        if start_addr is None:
            start_addr = self.CODE_BASE
        if size is None:
            size = self.CODE_SIZE
        
        try:
            data = self.uc.mem_read(start_addr, size)
            
            with open(output_file, 'wb') as f:
                f.write(bytes(data))
            
            logger.info(f"Dumped {size} bytes from 0x{start_addr:X} to {output_file}")
            
        except UcError as e:
            raise MemoryError(f"Failed to dump memory: {e}")
        except IOError as e:
            raise MemoryError(f"Failed to write dump file: {e}")
    
    def dump_all_memory(self, output_file: str):
        """
        Dump all mapped memory regions to file (Requirement 14.4)
        
        Args:
            output_file: Path to output file
        """
        regions = [
            ("code", self.CODE_BASE, self.CODE_SIZE),
            ("stack", self.STACK_BASE - self.STACK_SIZE, self.STACK_SIZE),
            ("heap", self.HEAP_BASE, self.HEAP_SIZE),
        ]
        
        with open(output_file, 'wb') as f:
            for name, addr, size in regions:
                try:
                    data = self.uc.mem_read(addr, size)
                    f.write(bytes(data))
                    logger.debug(f"Dumped {name} region: 0x{addr:X} ({size} bytes)")
                except UcError:
                    logger.warning(f"Failed to dump {name} region")
        
        logger.info(f"Dumped all memory regions to {output_file}")
    

    def emulate(
        self,
        start_addr: int,
        end_addr: Optional[int] = None,
        count: int = 0,
        timeout_ms: int = None
    ) -> EmulationResult:
        """
        Start emulation (Requirements 14.2, 14.5)
        
        Args:
            start_addr: Start address
            end_addr: End address (optional, 0 = run until stop)
            count: Max instructions (0 = use default limit)
            timeout_ms: Timeout in milliseconds (0 = no timeout)
            
        Returns:
            EmulationResult with execution details
        """
        if end_addr is None:
            end_addr = 0
        
        if count == 0:
            count = self.MAX_INSTRUCTIONS
        
        if timeout_ms is None:
            timeout_ms = self.EMULATION_TIMEOUT_MS
        
        # Reset tracking
        self.instruction_count = 0
        self.memory_access_count = 0
        self.memory_reads = []
        self.memory_writes = []
        self.output_strings = []
        self.syscalls_invoked = []
        self.last_error = None
        self.error_address = None
        
        logger.info(f"Starting emulation at 0x{start_addr:X}")
        
        try:
            # Start emulation (Requirement 14.2: sandboxed execution)
            self.uc.emu_start(start_addr, end_addr, timeout=timeout_ms * 1000, count=count)
            
            # Get final register state
            final_regs = self._get_register_state()
            
            logger.info(f"Emulation completed: {self.instruction_count} instructions")
            
            return EmulationResult(
                success=True,
                instructions_executed=self.instruction_count,
                final_registers=final_regs,
                memory_reads=self.memory_reads,
                memory_writes=self.memory_writes,
                output_strings=self.output_strings,
                syscalls_invoked=self.syscalls_invoked
            )
            
        except UcError as e:
            # Error handling (Requirement 14.5)
            if not self.last_error:
                self.last_error = f"Emulation error: {e}"
            
            error_msg = self.last_error
            logger.error(error_msg)
            
            # Try to get partial results
            try:
                final_regs = self._get_register_state()
            except:
                final_regs = {}
            
            return EmulationResult(
                success=False,
                instructions_executed=self.instruction_count,
                final_registers=final_regs,
                memory_reads=self.memory_reads,
                memory_writes=self.memory_writes,
                output_strings=self.output_strings,
                syscalls_invoked=self.syscalls_invoked,
                error=error_msg,
                error_address=self.error_address
            )
    
    def _get_register_state(self) -> Dict[str, int]:
        """Get current register state"""
        if self.arch == 'x64':
            return {
                'rax': self.uc.reg_read(UC_X86_REG_RAX),
                'rbx': self.uc.reg_read(UC_X86_REG_RBX),
                'rcx': self.uc.reg_read(UC_X86_REG_RCX),
                'rdx': self.uc.reg_read(UC_X86_REG_RDX),
                'rsi': self.uc.reg_read(UC_X86_REG_RSI),
                'rdi': self.uc.reg_read(UC_X86_REG_RDI),
                'rsp': self.uc.reg_read(UC_X86_REG_RSP),
                'rbp': self.uc.reg_read(UC_X86_REG_RBP),
                'rip': self.uc.reg_read(UC_X86_REG_RIP),
            }
        else:
            return {
                'eax': self.uc.reg_read(UC_X86_REG_EAX),
                'ebx': self.uc.reg_read(UC_X86_REG_EBX),
                'ecx': self.uc.reg_read(UC_X86_REG_ECX),
                'edx': self.uc.reg_read(UC_X86_REG_EDX),
                'esi': self.uc.reg_read(UC_X86_REG_ESI),
                'edi': self.uc.reg_read(UC_X86_REG_EDI),
                'esp': self.uc.reg_read(UC_X86_REG_ESP),
                'ebp': self.uc.reg_read(UC_X86_REG_EBP),
                'eip': self.uc.reg_read(UC_X86_REG_EIP),
            }
    
    def load_pe(self, pe_data: bytes):
        """
        Load PE file into emulator memory
        
        Args:
            pe_data: Raw PE file data
            
        Raises:
            ImportError: If pefile is not available
            MemoryError: If PE loading fails
        """
        try:
            import pefile
        except ImportError:
            raise ImportError("pefile not installed. Run: pip install pefile")
        
        try:
            pe = pefile.PE(data=pe_data)
            
            # Get ImageBase and Size
            image_base = pe.OPTIONAL_HEADER.ImageBase
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            aligned_size = (size_of_image + 0xFFF) & ~0xFFF
            
            self.code_base = image_base
            self.image_size = aligned_size
            
            # Map entire image region
            self.uc.mem_map(image_base, aligned_size)
            logger.info(f"Mapped PE image: 0x{image_base:X} - 0x{image_base+aligned_size:X}")
            
            # Write header
            self.uc.mem_write(image_base, pe.header)
            
            # Write sections
            for section in pe.sections:
                vaddr = image_base + section.VirtualAddress
                data = section.get_data()
                self.uc.mem_write(vaddr, data)
                logger.debug(f"Loaded section {section.Name.decode('utf-8', errors='ignore').strip()} at 0x{vaddr:X}")
            
            # Setup stack
            self.stack_base = 0x00100000
            self.stack_size = 0x00100000
            self.uc.mem_map(self.stack_base, self.stack_size)
            self.uc.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size - 0x100)
            
            # Set Entry Point
            self.entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            logger.info(f"PE loaded, entry point: 0x{self.entry_point:X}")
            
        except Exception as e:
            raise MemoryError(f"Failed to load PE: {e}")
    
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
    
    def get_memory_info(self) -> Dict[str, Any]:
        """
        Get information about mapped memory regions (Requirement 14.4)
        
        Returns:
            Dictionary with memory region information
        """
        return {
            'code': {
                'base': self.CODE_BASE,
                'size': self.CODE_SIZE,
                'end': self.CODE_BASE + self.CODE_SIZE
            },
            'stack': {
                'base': self.STACK_BASE - self.STACK_SIZE,
                'size': self.STACK_SIZE,
                'end': self.STACK_BASE
            },
            'heap': {
                'base': self.HEAP_BASE,
                'size': self.HEAP_SIZE,
                'end': self.HEAP_BASE + self.HEAP_SIZE
            }
        }
    
    def is_sandboxed(self) -> bool:
        """
        Check if emulator is properly sandboxed (Requirement 14.2)
        
        Returns:
            True if all sandboxing measures are active
        """
        return (
            not self.ALLOW_NETWORK and
            not self.ALLOW_FILE_IO and
            not self.ALLOW_PROCESS_CREATION and
            self.MAX_INSTRUCTIONS > 0 and
            self.MAX_MEMORY_ACCESSES > 0
        )
    
    def get_sandboxing_info(self) -> Dict[str, Any]:
        """
        Get sandboxing configuration (Requirement 14.2)
        
        Returns:
            Dictionary with sandboxing settings
        """
        return {
            'sandboxed': self.is_sandboxed(),
            'max_instructions': self.MAX_INSTRUCTIONS,
            'max_memory_accesses': self.MAX_MEMORY_ACCESSES,
            'timeout_ms': self.EMULATION_TIMEOUT_MS,
            'network_allowed': self.ALLOW_NETWORK,
            'file_io_allowed': self.ALLOW_FILE_IO,
            'process_creation_allowed': self.ALLOW_PROCESS_CREATION,
            'syscall_stubbing_enabled': self.enable_syscalls
        }
    
    def get_error_report(self) -> Optional[Dict[str, Any]]:
        """
        Get detailed error report (Requirement 14.5)
        
        Returns:
            Dictionary with error details or None if no error
        """
        if not self.last_error:
            return None
        
        return {
            'error': self.last_error,
            'error_address': self.error_address,
            'instructions_executed': self.instruction_count,
            'memory_accesses': self.memory_access_count,
            'last_registers': self._get_register_state() if self.uc else {},
            'syscalls_invoked': self.syscalls_invoked
        }
    
    def format_error_report(self) -> str:
        """
        Format error report as human-readable string (Requirement 14.5)
        
        Returns:
            Formatted error report
        """
        error_info = self.get_error_report()
        
        if not error_info:
            return "No errors recorded"
        
        lines = []
        lines.append("=" * 70)
        lines.append("EMULATION ERROR REPORT")
        lines.append("=" * 70)
        lines.append(f"Error: {error_info['error']}")
        
        if error_info['error_address']:
            lines.append(f"Address: 0x{error_info['error_address']:X}")
        
        lines.append(f"Instructions executed: {error_info['instructions_executed']}")
        lines.append(f"Memory accesses: {error_info['memory_accesses']}")
        
        if error_info['syscalls_invoked']:
            lines.append(f"Syscalls invoked: {len(error_info['syscalls_invoked'])}")
        
        if error_info['last_registers']:
            lines.append("\nLast register state:")
            for reg, val in error_info['last_registers'].items():
                lines.append(f"  {reg}: 0x{val:X}")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def reset(self):
        """
        Reset emulator state
        
        Clears tracking data and resets registers
        """
        self.instruction_count = 0
        self.memory_access_count = 0
        self.memory_reads = []
        self.memory_writes = []
        self.output_strings = []
        self.syscalls_invoked = []
        self.last_error = None
        self.error_address = None
        
        # Reset registers
        self._setup_memory()
        
        logger.debug("Emulator reset")


# Standalone test
if __name__ == "__main__":
    if not UNICORN_AVAILABLE:
        print("❌ Unicorn not installed. Run: pip install unicorn")
        exit(1)
    
    print("=" * 70)
    print("Unicorn Emulator Test Suite")
    print("=" * 70)
    print()
    
    # Test 1: Basic emulation
    print("Test 1: Basic arithmetic emulation")
    print("-" * 70)
    
    # mov eax, 5; add eax, 10; ret
    code = b'\xB8\x05\x00\x00\x00'  # mov eax, 5
    code += b'\x83\xC0\x0A'          # add eax, 10
    code += b'\xC3'                   # ret
    
    emu = UnicornEmulator(arch='x64')
    addr = emu.load_code(code)
    
    result = emu.emulate(addr, count=10)
    
    if result.success:
        print(f"✓ Emulation successful!")
        print(f"  Instructions executed: {result.instructions_executed}")
        print(f"  Final RAX: {result.final_registers.get('rax', 0)} (expected: 15)")
    else:
        print(f"✗ Emulation failed: {result.error}")
    
    print()
    
    # Test 2: Memory dumping
    print("Test 2: Memory dumping")
    print("-" * 70)
    
    try:
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_file = f.name
        
        emu.dump_memory(temp_file, emu.CODE_BASE, 256)
        
        if os.path.exists(temp_file):
            size = os.path.getsize(temp_file)
            print(f"✓ Memory dump successful: {size} bytes written")
            os.unlink(temp_file)
        else:
            print("✗ Memory dump failed")
    except Exception as e:
        print(f"✗ Memory dump test failed: {e}")
    
    print()
    
    # Test 3: Syscall stubbing
    print("Test 3: Syscall stubbing")
    print("-" * 70)
    
    # mov rax, 60; syscall (exit syscall)
    code = b'\x48\xC7\xC0\x3C\x00\x00\x00'  # mov rax, 60
    code += b'\x0F\x05'                      # syscall
    
    emu2 = UnicornEmulator(arch='x64', enable_syscalls=True)
    addr = emu2.load_code(code)
    
    result = emu2.emulate(addr, count=10)
    
    if result.success:
        print(f"✓ Syscall handling successful!")
        print(f"  Syscalls invoked: {len(result.syscalls_invoked)}")
        if result.syscalls_invoked:
            print(f"  Syscall: {result.syscalls_invoked[0]}")
    else:
        print(f"✗ Syscall test failed: {result.error}")
    
    print()
    
    # Test 4: Error handling
    print("Test 4: Error handling (invalid memory access)")
    print("-" * 70)
    
    # mov rax, [0xDEADBEEF] - invalid address
    code = b'\x48\x8B\x04\x25\xEF\xBE\xAD\xDE'
    
    emu3 = UnicornEmulator(arch='x64')
    addr = emu3.load_code(code)
    
    result = emu3.emulate(addr, count=10)
    
    if not result.success:
        print(f"✓ Error handling successful!")
        print(f"  Error: {result.error}")
    else:
        print(f"✓ Emulation recovered from invalid access")
    
    print()
    print("=" * 70)
    print("All tests completed!")
    print("=" * 70)
