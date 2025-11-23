# DissectX Architecture Guide

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Component Interactions](#component-interactions)
5. [Data Flow](#data-flow)
6. [Extension Points](#extension-points)
7. [Design Decisions](#design-decisions)

---

## Overview

DissectX is a   reverse engineering framework built on a layered architecture that separates concerns and enables extensibility. The system transforms binary analysis from a manual, time-consuming process into an automated, intelligent workflow.

### Design Philosophy

- **Modularity**: Components can be used independently or composed together
- **Extensibility**: Plugin system allows custom analyzers without modifying core code
- **Multi-Architecture**: Unified interface supports x86, ARM, and MIPS through abstraction
- **Safety First**: Dynamic analysis runs in sandboxed environments
- **Progressive Enhancement**: Basic features work immediately, advanced features available when needed

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   CLI    │  │   TUI    │  │   Web    │  │  Plugin  │   │
│  │ Interface│  │ Interface│  │    UI    │  │  System  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                   Analysis Orchestrator                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Coordinates analysis workflow and manages state     │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
┌───────────────────────┐           ┌───────────────────────┐
│  Core Analysis Layer  │           │ Dynamic Analysis Layer│
│  ┌─────────────────┐  │           │  ┌─────────────────┐ │
│  │ Binary Parser   │  │           │  │ Unicorn Engine  │ │
│  │ (PE/ELF/Mach-O) │  │           │  │   Emulator      │ │
│  └─────────────────┘  │           │  └─────────────────┘ │
│  ┌─────────────────┐  │           │  ┌─────────────────┐ │
│  │ Capstone        │  │           │  │ String          │ │
│  │ Disassembler    │  │           │  │ Decryptor       │ │
│  └─────────────────┘  │           │  └─────────────────┘ │
│  ┌─────────────────┐  │           │  ┌─────────────────┐ │
│  │ Architecture    │  │           │  │ Memory Dump     │ │
│  │ Abstraction     │  │           │  │ Analyzer        │ │
│  └─────────────────┘  │           │  └─────────────────┘ │
│  ┌─────────────────┐  │           └───────────────────────┘
│  │ XREF Analyzer   │  │
│  └─────────────────┘  │
│  ┌─────────────────┐  │
│  │ CFG Generator   │  │
│  └─────────────────┘  │
│  ┌─────────────────┐  │
│  │ Call Graph      │  │
│  └─────────────────┘  │
│  ┌─────────────────┐  │
│  │ Decompiler      │  │
│  └─────────────────┘  │
└───────────────────────┘
```

---

## System Architecture

### 1. Presentation Layer

The presentation layer provides multiple interfaces for user interaction:

#### CLI Interface (`main.py`)
- Command-line interface for batch processing
- Supports file input, interactive mode, and stdin piping
- Auto-detection of binary vs assembly input
- Comprehensive flag system for controlling analysis

#### TUI Interface (`src/tui/tui_app.py`)
- Terminal-based interactive interface using Textual framework
- Panel-based layout: code, strings, functions, cross-references
- Keyboard navigation and command system
- Annotation and session management

#### Web UI (`src/web/server.py`)
- Browser-based interface using Flask
- Interactive HTML reports with navigation
- Syntax highlighting and export capabilities
- Team collaboration features

#### Plugin System (`src/plugins/plugin_manager.py`)
- Extensibility layer for custom analyzers
- Hook system for pre/post-analysis
- Custom output format support

### 2. Analysis Orchestrator

The orchestrator coordinates the analysis workflow:

```python
# Typical workflow orchestration
1. Binary Loading → Format Detection → Architecture Detection
2. Static Analysis → Disassembly → XREF Analysis → CFG Generation
3. Dynamic Analysis (optional) → Emulation → String Decryption
4. Report Generation → Output Formatting
```

### 3. Core Analysis Layer

#### Binary Parser
- **Purpose**: Parse binary files and extract metadata
- **Supported Formats**: PE (Windows), ELF (Linux/Unix), Mach-O (macOS)
- **Dependencies**: pefile, pyelftools, macholib
- **Output**: BinaryInfo structure with sections, symbols, imports, exports

#### Capstone Disassembler (`src/capstone_disassembler.py`)
- **Purpose**:   disassembly
- **Architectures**: x86/x64, ARM/ARM64, MIPS/MIPS64
- **Features**: Multiple syntax modes, error handling
- **Integration**: Replaces manual parsing with battle-tested engine

#### Architecture Abstraction (`src/architecture.py`)
- **Purpose**: Unified interface for multiple architectures
- **Pattern**: Strategy pattern for runtime architecture selection
- **Components**:
  - `ArchitectureBase`: Abstract base class
  - `X86Architecture`: x86/x64 implementation
  - `ARMArchitecture`: ARM/ARM64 implementation
  - `MIPSArchitecture`: MIPS/MIPS64 implementation

#### XREF Analyzer (`src/xref_analyzer.py`)
- **Purpose**: Track cross-references between code, data, and strings
- **Data Structure**: Bidirectional maps for O(1) lookup
- **Capabilities**:
  - Function call tracking (caller ↔ callee)
  - String reference mapping
  - Data reference tracking

#### CFG Generator (`src/cfg_generator.py`)
- **Purpose**: Generate control flow graphs
- **Algorithm**: Basic block identification + branch analysis
- **Features**: Loop detection, export to multiple formats
- **Output**: ASCII art, Graphviz DOT, Mermaid

#### Call Graph Generator (`src/call_graph_generator.py`)
- **Purpose**: Build hierarchical function relationships
- **Graph Library**: NetworkX for directed graph operations
- **Features**: Recursion detection, entry point identification, dead code detection

#### Decompiler (`src/decompiler.py`)
- **Purpose**: Generate high-quality pseudo-code
- **Techniques**:
  - Variable name inference from usage patterns
  - Type inference from operations
  - Control flow reconstruction (if/else, loops, switch)
  - SSA form for analysis

### 4. Dynamic Analysis Layer

#### Unicorn Emulator (`src/emulation/unicorn_emulator.py`)
- **Purpose**: Safe CPU emulation for dynamic analysis
- **Safety**: Fully sandboxed, no host system access
- **Features**:
  - Memory and register setup
  - Syscall stubbing
  - Post-emulation memory dumping
  - Error handling and reporting

#### String Decryptor (`src/emulation/string_decryptor.py`)
- **Purpose**: Decrypt obfuscated strings
- **Techniques**:
  - XOR brute-force (256 keys)
  - Stack string detection
  - Emulation-based decryption
  - Confidence scoring

#### Memory Dump Analyzer (`src/pe/memory_dump_analyzer.py`)
- **Purpose**: Analyze memory dumps from emulation
- **Features**: Extract strings, identify code regions, detect patterns

---

## Core Components

### Binary Parser Component

**Interface**:
```python
class BinaryParser:
    def detect_format(self, filepath: str) -> BinaryFormat
    def parse(self, filepath: str) -> BinaryInfo
    def extract_sections(self) -> List[Section]
    def extract_symbols(self) -> List[Symbol]
    def extract_imports(self) -> List[Import]
    def extract_exports(self) -> List[Export]
```

**Workflow**:
1. Read binary file
2. Detect format (PE/ELF/Mach-O) from magic bytes
3. Parse headers and extract metadata
4. Identify code and data sections
5. Extract symbols, imports, exports

### Architecture Abstraction Layer

**Interface**:
```python
class ArchitectureBase:
    def get_register_names(self) -> List[str]
    def get_calling_convention(self) -> CallingConvention
    def translate_instruction(self, instr: Instruction) -> str
    def get_register_size(self, reg: str) -> int
    def is_branch_instruction(self, instr: Instruction) -> bool
```

**Design Pattern**: Strategy Pattern
- Allows runtime architecture selection
- Enables adding new architectures without modifying existing code
- Provides consistent interface across architectures

### XREF Analyzer

**Data Structures**:
```python
@dataclass
class XREFDatabase:
    function_calls: Dict[int, List[int]]  # caller -> [callees]
    function_callers: Dict[int, List[int]]  # callee -> [callers]
    string_refs: Dict[str, List[int]]  # string -> [addresses]
    data_refs: Dict[int, List[int]]  # data_addr -> [code_addresses]
```

**Algorithm**:
1. Scan all instructions
2. Identify call instructions → record caller/callee relationships
3. Identify string references → map strings to functions
4. Identify data references → track memory access patterns
5. Build bidirectional maps for efficient lookup

### CFG Generator

**Basic Block Identification**:
```python
# A basic block is a sequence of instructions with:
# - Single entry point (first instruction)
# - Single exit point (last instruction, which may branch)
# - No internal branches

def identify_basic_blocks(instructions):
    leaders = find_leaders(instructions)  # Entry points
    blocks = []
    for i in range(len(leaders)):
        start = leaders[i]
        end = leaders[i+1] if i+1 < len(leaders) else len(instructions)
        blocks.append(BasicBlock(start, end, instructions[start:end]))
    return blocks
```

**Loop Detection**:
- Identify back edges (jumps to earlier addresses)
- Use dominator analysis for natural loops
- Mark loop headers and bodies

### Decompiler

**Pipeline**:
```
Assembly → SSA Form → Type Inference → Variable Naming → 
Control Flow Reconstruction → Pseudo-Code Generation
```

**Type Inference Rules**:
- `mov [addr], byte` → char/uint8_t
- `mov [addr], dword` → int/uint32_t
- `lea rax, [string]` → char*
- Pointer arithmetic → array access
- Function calls → infer from calling convention

---

## Component Interactions

### Typical Analysis Workflow

```
┌─────────────┐
│ User Input  │
│ (Binary)    │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Format Detector │ ──→ Detect PE/ELF/Mach-O
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│ Architecture Detector│ ──→ Detect x86/ARM/MIPS
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Binary Parser        │ ──→ Extract sections, symbols
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Capstone Disassembler│ ──→ Disassemble code sections
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ XREF Analyzer        │ ──→ Build cross-reference database
└──────────┬───────────┘
           │
           ├──→ ┌──────────────────┐
           │    │ Call Graph Gen   │ ──→ Function relationships
           │    └──────────────────┘
           │
           ├──→ ┌──────────────────┐
           │    │ CFG Generator    │ ──→ Control flow graphs
           │    └──────────────────┘
           │
           └──→ ┌──────────────────┐
                │ Decompiler       │ ──→ Pseudo-code
                └──────────────────┘
```

### Dynamic Analysis Workflow

```
┌─────────────┐
│ Binary      │
└──────┬──────┘
       │
       ▼
┌──────────────────────┐
│ Unicorn Emulator     │
│ - Load binary        │
│ - Setup memory       │
│ - Setup registers    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Execute Instructions │
│ - Hook syscalls      │
│ - Track execution    │
│ - Monitor memory     │
└──────────┬───────────┘
           │
           ├──→ ┌──────────────────┐
           │    │ String Decryptor │ ──→ Reveal hidden strings
           │    └──────────────────┘
           │
           └──→ ┌──────────────────┐
                │ Memory Analyzer  │ ──→ Extract runtime data
                └──────────────────┘
```

### Plugin Integration

```
┌─────────────┐
│ Plugin Dir  │
└──────┬──────┘
       │
       ▼
┌──────────────────────┐
│ Plugin Manager       │
│ - Discover plugins   │
│ - Load plugins       │
│ - Validate plugins   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Hook Registration    │
│ - PRE_ANALYSIS       │
│ - POST_ANALYSIS      │
│ - PRE_DISASSEMBLY    │
│ - POST_DISASSEMBLY   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Execute Hooks        │
│ - Call plugin code   │
│ - Merge results      │
│ - Handle errors      │
└──────────────────────┘
```

---

## Data Flow

### Binary Analysis Data Flow

```
Binary File
    ↓
[Binary Parser]
    ↓
BinaryInfo {format, arch, sections, symbols}
    ↓
[Capstone Disassembler]
    ↓
List[Instruction] {address, mnemonic, operands}
    ↓
[XREF Analyzer]
    ↓
XREFDatabase {calls, refs, strings}
    ↓
[Analysis Components]
    ├→ [Call Graph] → CallGraph
    ├→ [CFG Gen] → ControlFlowGraph
    └→ [Decompiler] → PseudoCode
    ↓
[Report Generator]
    ↓
Formatted Report (Markdown/HTML/PDF)
```

### Emulation Data Flow

```
Binary + Entry Point
    ↓
[Unicorn Emulator Setup]
    ├→ Allocate memory
    ├→ Load binary sections
    └→ Initialize registers
    ↓
[Emulation Loop]
    ├→ Execute instruction
    ├→ Hook syscalls
    ├→ Track memory writes
    └→ Record execution path
    ↓
[Post-Emulation Analysis]
    ├→ Extract decrypted strings
    ├→ Dump modified memory
    └→ Analyze execution trace
    ↓
EmulationResults {strings, memory, trace}
```

---

## Extension Points

### 1. Plugin System

**Creating a Custom Analyzer Plugin**:

```python
from src.plugins.plugin_manager import Plugin

class MyAnalyzerPlugin(Plugin):
    def get_name(self) -> str:
        return "My Custom Analyzer"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict:
        # Custom analysis logic
        results = {}
        # ... perform analysis ...
        return results
    
    def register_hooks(self, manager):
        # Register for post-analysis hook
        manager.register_hook('POST_ANALYSIS', self.post_analysis_hook)
    
    def post_analysis_hook(self, context: Dict):
        # Called after main analysis completes
        pass
```

**Plugin Discovery**:
- Place plugin file in `plugins/` directory
- Plugin manager automatically discovers and loads plugins
- Plugins can register for multiple hooks

### 2. Architecture Support

**Adding a New Architecture**:

```python
from src.architecture import ArchitectureBase

class PowerPCArchitecture(ArchitectureBase):
    def get_register_names(self) -> List[str]:
        return ['r0', 'r1', 'r2', ..., 'r31', 'lr', 'ctr']
    
    def get_calling_convention(self) -> CallingConvention:
        return CallingConvention(
            args_registers=['r3', 'r4', 'r5', 'r6'],
            return_register='r3',
            stack_grows_down=True
        )
    
    def translate_instruction(self, instr: Instruction) -> str:
        # PowerPC-specific translation logic
        pass
```

### 3. Output Formats

**Adding a Custom Output Format**:

```python
class CustomFormatter:
    def format(self, analysis_results: AnalysisResults) -> str:
        # Generate custom format (JSON, XML, etc.)
        output = self.generate_header(analysis_results)
        output += self.generate_body(analysis_results)
        output += self.generate_footer(analysis_results)
        return output
```

### 4. Detection Modules

**Adding a Custom Detector**:

```python
class CustomDetector:
    def detect(self, instructions: List[Instruction]) -> List[Detection]:
        detections = []
        for instr in instructions:
            if self.matches_pattern(instr):
                detections.append(Detection(
                    address=instr.address,
                    type='CUSTOM_PATTERN',
                    description='Custom pattern detected',
                    severity='MEDIUM'
                ))
        return detections
```

---

## Design Decisions

### 1. Why Capstone for Disassembly?

**Decision**: Use Capstone engine instead of manual parsing

**Rationale**:
- Battle-tested: Used by major tools (IDA, Ghidra, radare2)
- Multi-architecture: Single API for x86, ARM, MIPS
- Accurate: Handles complex instruction encodings correctly
- Maintained: Active development and bug fixes

**Trade-offs**:
- External dependency (but widely available)
- Learning curve for API
- Performance overhead (minimal in practice)

### 2. Why Unicorn for Emulation?

**Decision**: Use Unicorn Engine for CPU emulation

**Rationale**:
- Safety: Sandboxed execution, no host system access
- Multi-architecture: Same API for all architectures
- QEMU-based: Proven emulation accuracy
- Hook system: Easy to intercept syscalls and memory access

**Trade-offs**:
- Cannot emulate full OS environment
- Limited syscall support (requires stubs)
- Performance (slower than native execution)

### 3. Why Bidirectional XREF Maps?

**Decision**: Store both forward and reverse cross-references

**Rationale**:
- Performance: O(1) lookup in both directions
- Common queries: "Where is this used?" and "What does this use?"
- Memory trade-off: Acceptable for typical binaries

**Implementation**:
```python
# Forward: caller -> callees
function_calls: Dict[int, List[int]]

# Reverse: callee -> callers  
function_callers: Dict[int, List[int]]
```

### 4. Why Strategy Pattern for Architecture?

**Decision**: Use strategy pattern for architecture abstraction

**Rationale**:
- Runtime selection: Choose architecture based on binary
- Extensibility: Add new architectures without modifying existing code
- Consistency: Uniform interface across architectures
- Testability: Easy to mock architectures for testing

### 5. Why Multiple UI Interfaces?

**Decision**: Provide CLI, TUI, and Web UI

**Rationale**:
- Different use cases:
  - CLI: Batch processing, scripting, CI/CD
  - TUI: Interactive exploration, terminal-only environments
  - Web: Team collaboration, report sharing
- User preference: Some prefer terminal, others prefer browser
- Accessibility: Web UI more accessible for beginners

### 6. Why Plugin System?

**Decision**: Implement extensible plugin architecture

**Rationale**:
- Customization: Users can add domain-specific analyzers
- Maintainability: Core stays focused, extensions separate
- Community: Enable third-party contributions
- Experimentation: Try new techniques without modifying core

### 7. Why Property-Based Testing?

**Decision**: Use property-based testing (Hypothesis) alongside unit tests

**Rationale**:
- Coverage: Tests many inputs automatically
- Edge cases: Discovers cases developers might miss
- Specification: Properties document expected behavior
- Confidence: Higher assurance of correctness

**Example**:
```python
# Instead of testing specific inputs:
def test_xor_specific():
    assert xor_decrypt(b'\x41\x42', 0x01) == b'\x40\x43'

# Test the property across all inputs:
@given(data=st.binary(), key=st.integers(0, 255))
def test_xor_roundtrip(data, key):
    encrypted = xor_encrypt(data, key)
    decrypted = xor_decrypt(encrypted, key)
    assert decrypted == data  # Property: encryption is reversible
```

---

## Performance Considerations

### Optimization Strategies

1. **Lazy Loading**: Load binary sections on-demand
2. **Caching**: Cache disassembly results, XREF lookups
3. **Parallel Processing**: Analyze functions in parallel where possible
4. **Incremental Analysis**: Update only changed parts on re-analysis

### Memory Management

- **Streaming**: Process large binaries in chunks
- **Weak References**: Use weak refs for cached data
- **Resource Limits**: Set limits on emulation memory, instruction count

### Scalability

- **Large Binaries**: Handle multi-MB binaries efficiently
- **Many Functions**: Scale to thousands of functions
- **Deep Call Graphs**: Handle deeply nested call chains

---

## Security Considerations

### Sandboxing

- **Emulation**: Unicorn runs in isolated environment
- **Plugin Execution**: Plugins run with limited permissions
- **File Access**: Validate all file paths, prevent directory traversal

### Input Validation

- **Binary Parsing**: Validate headers, handle malformed binaries
- **Instruction Parsing**: Handle invalid opcodes gracefully
- **User Input**: Sanitize all user-provided data

### Error Handling

- **Graceful Degradation**: Continue analysis on component failure
- **Error Reporting**: Log errors without exposing sensitive data
- **Resource Limits**: Prevent DoS through resource exhaustion

---

## Future Architecture Enhancements

### Planned Improvements

1. **Distributed Analysis**: Split analysis across multiple machines
2. **Database Backend**: Store analysis results in database for large projects
3. **Real-time Collaboration**: Multiple users analyzing same binary
4. **Machine Learning**: ML-based function identification, type inference
5. **Symbolic Execution**: Add symbolic execution engine (angr integration)

### Extensibility Roadmap

1. **More Architectures**: RISC-V, PowerPC, SPARC
2. **More Binary Formats**: COFF, a.out, raw firmware
3. **More Output Formats**: JSON API, GraphQL, Protocol Buffers
4. **More Integrations**: Binary Ninja, Hopper, Cutter

---

## Conclusion

DissectX's architecture is designed for:
- **Modularity**: Components work independently or together
- **Extensibility**: Easy to add new features via plugins
- **Scalability**: Handles small CTF challenges to large malware samples
- **Maintainability**: Clear separation of concerns, well-defined interfaces
- **Usability**: Multiple interfaces for different use cases

The layered architecture ensures that improvements to one component benefit all interfaces, and new features can be added without disrupting existing functionality.

For more information:
- **Plugin Development**: See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md)
- **API Reference**: See [API_REFERENCE.md](API_REFERENCE.md)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)
