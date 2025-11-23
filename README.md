# 🔍 DissectX

**   Binary Analysis & Reverse Engineering Framework**

DissectX is a comprehensive reverse engineering platform designed for CTF competitions, malware analysis, and security research. It combines static analysis, dynamic emulation, and interactive exploration to provide   binary analysis capabilities comparable to IDA Pro, Ghidra, and Binary Ninja.

> **From "Good for picoCTF" → "  Reverse Engineering Framework"**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🎯 Overview

DissectX transforms binary analysis from a manual, time-consuming process into an automated, intelligent workflow. Whether you're solving CTF challenges, analyzing malware, or conducting security research, DissectX provides the tools you need.

**Key Capabilities:**
- 🔍 **Multi-Architecture Support**: x86/x64, ARM/ARM64, MIPS/MIPS64
- 🧠 **Intelligent Analysis**: Automatic flag detection, XOR decryption, string context analysis
- 🦄 **Dynamic Emulation**: Safe CPU emulation with Unicorn Engine
- 🎨 **Multiple Interfaces**: CLI, Terminal UI (TUI), and Web UI
- 🔌 **Extensible**: Plugin system for custom analyzers
- 🛡️ **Security Focus**: Anti-analysis detection, shellcode identification, ROP gadget finding

---

## 🌐 NEW: Web Interface

**DissectX now includes a built-in web server for browser-based analysis!**

Start the web server:
```bash
python3 main.py --web
```

Then open your browser to **http://localhost:8000** and:
- 📁 **Drag & drop** any binary file
- ⚡ Get **instant analysis** results
- 🚩 See **flags**, strings, architecture
- 📄 **Download** full reports

**Custom port:**
```bash
python3 main.py --web --port 9000
```

See [WEB_INTERFACE_GUIDE.md](WEB_INTERFACE_GUIDE.md) for complete documentation.

---

## 🚀 Features

### Core Analysis Engine

#### 1. **Flag Detection & Extraction**
Automatically identifies and extracts CTF flags from binaries:
- Pattern matching for common flag formats (CTF{...}, flag{...}, FLAG{...})
- Base64 and hex-encoded flag detection
- Confidence scoring and ranking
- XOR brute-force decryption (all 256 single-byte keys)

```bash
python main.py challenge.exe
```

#### 2. **String Context Analysis**
Understand how strings are used throughout the binary:
- String-to-function mapping (bidirectional)
- Usage pattern detection (printf, strcmp, memcpy, strcpy)
- Format string vulnerability detection
- Complete cross-reference tracking

#### 3. **Cross-Reference (XREF) Analysis**
Track relationships between code, data, and strings:
- Function call relationship tracking (caller ↔ callee)
- String reference mapping
- Data reference tracking
- Bidirectional lookup ("where is this used" and "what does this use")

#### 4. **Control Flow Analysis**
Visualize and understand program structure:
- **Call Graph Generation**: Hierarchical function relationships
- **Control Flow Graphs (CFG)**: Basic block identification and branching
- **Loop Detection**: Identify loop structures and back edges
- **Dead Code Detection**: Find unreachable code
- **Multiple Export Formats**: ASCII, Graphviz DOT, Mermaid

#### 5. **Decompilation**
Generate high-quality pseudo-code from assembly:
- Variable name inference from usage patterns
- Type inference (char*, int, struct, etc.)
- Control flow reconstruction (if/else, loops, switch)
- C-like syntax with proper indentation

### Multi-Architecture Support

#### Architecture Abstraction Layer
Unified interface for multiple architectures:
- **x86/x64**: Full support with Intel/AT&T syntax
- **ARM/ARM64**: Complete instruction set support
- **MIPS/MIPS64**: Full disassembly and analysis

#### Capstone Integration
  disassembly:
- Battle-tested instruction decoding
- Multiple syntax modes
- Graceful error handling for invalid instructions

#### Auto-Detection
Automatic architecture identification:
- Binary header parsing (ELF, PE, Mach-O)
- Heuristic-based fallback detection
- Manual override via `--arch` flag

```bash
# Auto-detect architecture
python main.py binary.exe

# Manual override
python main.py binary.exe --arch arm64
```

### Dynamic Analysis & Emulation

#### Unicorn Engine Integration
Safe, sandboxed CPU emulation:
- No host system access (fully sandboxed)
- Memory and register inspection
- Syscall stubbing for common operations
- Post-emulation memory dumping

#### String Decryption
Reveal hidden strings through emulation:
- Stack string detection
- XOR brute-force (256 keys)
- Emulation-based decryption
- Confidence scoring for results

```bash
# Decrypt strings using emulation
python main.py packed.exe --decrypt-strings

# Full emulation analysis
python main.py packed.exe --emulate
```

#### Dynamic Unpacking
Automatically unpack obfuscated binaries:
```bash
python main.py --generate-dump packed.exe
```

### Advanced Detection

#### Anti-Analysis Detection
Identify protection mechanisms:
- **Anti-Debugging**: IsDebuggerPresent, PEB checks, NtQueryInformationProcess
- **VM Detection**: CPUID checks, registry queries, VMware artifacts
- **Timing Attacks**: rdtsc and timing-based checks
- **Self-Modifying Code**: Runtime code modification detection
- **Bypass Recommendations**: Suggested techniques for each protection

```bash
python main.py malware.exe --advanced
```

#### Shellcode Detection & Analysis
Identify and analyze embedded shellcode:
- Common pattern detection (GetPC, PEB walking)
- Automatic shellcode extraction
- Safe emulation in sandbox
- Deobfuscation capabilities

#### ROP Gadget Finding
Exploit development assistance:
- Automatic gadget discovery
- Quality scoring based on usefulness
- Chain generation assistance
- Pwntools format export
- Filtering by operation type and registers

```bash
# Find ROP gadgets
python -m src.rop_analyzer binary.exe
```

### Interactive Interfaces

#### Terminal User Interface (TUI)
   terminal-based interface:
- Panel-based layout (code, strings, functions, xrefs)
- Keyboard navigation and shortcuts
- Search and filtering with highlighting
- Syntax highlighting with color themes
- Annotation system with persistence
- Command system (goto, xref, search, comment, export)

```bash
# Launch TUI mode
python demo_tui.py binary.exe
```

#### Web User Interface
Browser-based analysis sharing:
- Interactive HTML reports
- Click-to-navigate functionality
- Syntax highlighting
- PDF and HTML export
- Team collaboration features

```bash
# Start web server
python demo_web_ui.py binary.exe
```

### Tool Integration

#### External Tool Support
Seamless integration with existing workflows:
- **Ghidra**: Import decompilation, export analysis scripts
- **IDA Pro**: Import .idb databases, export Python scripts
- **Radare2**: Bidirectional r2pipe communication
- **Compatible Naming**: Tool-specific naming conventions
- **Annotation Preservation**: Maintain external tool annotations

### Binary Diffing
Compare binaries for patch analysis:
- Function matching by hash and structure
- Change categorization (added, removed, modified)
- Side-by-side comparison view
- Security-relevant change highlighting
- Comprehensive diff statistics

```bash
python -m src.binary_differ old.exe new.exe
```

### Plugin System
Extend DissectX with custom analyzers:
- Plugin discovery from `plugins/` directory
- Pre-analysis and post-analysis hooks
- Custom analyzer integration
- Custom output format support
- Example plugins included

See `plugins/README.md` for plugin development guide.

---

## 📦 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/H4D3ZS/dissectx.git
cd dissectx

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py --help
```

### Requirements

- **Python**: 3.7 or higher
- **Core Dependencies**:
  - `capstone` -    disassembly framework
  - `unicorn-engine` - CPU emulator for dynamic analysis
  - `pefile` - PE file parsing
  - `pyelftools` - ELF file parsing
  - `networkx` - Graph analysis for call graphs
  - `textual` - Modern TUI framework
  - `flask` - Web UI server

### Platform-Specific Notes

**macOS:**
```bash
# Install via Homebrew (recommended)
brew install python3
pip3 install -r requirements.txt
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install python3 python3-pip
pip3 install -r requirements.txt

# Fedora/RHEL
sudo dnf install python3 python3-pip
pip3 install -r requirements.txt
```

**Windows:**
```bash
# Install Python from python.org
# Then install dependencies
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build Docker image
docker build -t dissectx .

# Run DissectX in container
docker run -it -v $(pwd):/workspace dissectx binary.exe
```

---

## 🛠️ Usage Guide

### Basic Usage

#### Quick Analysis
Analyze a binary to find flags and strings:
```bash
python main.py challenge.exe
```

#### Full Analysis
Complete disassembly and translation:
```bash
python main.py challenge.exe --full
```

#### Specific Function Analysis
Focus on a particular function:
```bash
python main.py program.exe --full --function main
```

### Advanced Usage

#### Architecture-Specific Analysis
```bash
# Auto-detect (default)
python main.py binary.exe

# Manual specification
python main.py binary.exe --arch arm64
python main.py binary.exe --arch mips
```

#### Dynamic Analysis
```bash
# String decryption
python main.py packed.exe --decrypt-strings

# Full emulation
python main.py packed.exe --emulate

# Generate memory dump
python main.py --generate-dump packed.exe
```

#### Memory Forensics
```bash
# Analyze memory dump
python main.py --memory-dump process.dmp
```

#### Advanced Detection
```bash
# Enable all advanced detections
python main.py malware.exe --advanced

# Specific detections
python main.py malware.exe --detect-syscalls
python main.py malware.exe --resolve-hashes
python main.py malware.exe --detect-junk
```

### Assembly Input Modes

#### File Input
```bash
python main.py code.asm
```

#### Interactive Mode
```bash
python main.py -i
# Paste assembly, press Ctrl+D when done
```

#### Pipe from Tools
```bash
# From objdump
objdump -d -M intel binary | python main.py

# From clipboard (macOS/Linux)
pbpaste | python main.py

# From clipboard (Windows)
Get-Clipboard | python main.py
```

### Output Options

```bash
# Save to file
python main.py binary.exe --full --output report.md

# Unlimited output (no 1000-line limit)
python main.py binary.exe --full --unlimited

# Strings only (fast mode)
python main.py binary.exe --strings-only
```

---

## 📊 Command Reference

### Core Commands

| Flag | Description |
|------|-------------|
| `file` | Binary or assembly file to analyze |
| `--full` | Complete analysis (disassembly + translation) |
| `--strings-only` | Only show strings (fast mode) |
| `--output FILE`, `-o FILE` | Save output to file |
| `--unlimited` | Remove 1000-line output limit |
| `--function NAME`, `-f NAME` | Analyze specific function |
| `--interactive`, `-i` | Interactive paste mode |

### Architecture Options

| Flag | Description |
|------|-------------|
| `--arch ARCH` | Specify architecture (x86, x86_64, arm, arm64, mips, mips64) |
| `--no-auto-detect` | Disable automatic architecture detection |

### Advanced Analysis

| Flag | Description |
|------|-------------|
| `--advanced` | Enable all advanced detections |
| `--detect-syscalls` | Detect direct syscall stubs |
| `--resolve-hashes` | Resolve API hashes |
| `--detect-junk` | Detect junk code and anti-analysis |

### Dynamic Analysis

| Flag | Description |
|------|-------------|
| `--emulate` | Enable Unicorn emulation |
| `--decrypt-strings` | Attempt string decryption |
| `--generate-dump FILE` | Run binary and generate memory dump |
| `--memory-dump FILE` | Analyze memory dump file |

---

## 📝 Example Workflows

### CTF Challenge Analysis

```bash
# Quick flag extraction
python main.py challenge.exe

# Full analysis with decompilation
python main.py challenge.exe --full

# Focus on main function
python main.py challenge.exe --full --function main
```

### Malware Analysis

```bash
# Initial triage
python main.py malware.exe --advanced

# String decryption
python main.py malware.exe --decrypt-strings

# Dynamic unpacking
python main.py --generate-dump malware.exe

# Analyze unpacked dump
python main.py --memory-dump malware.exe.dmp
```

### Exploit Development

```bash
# Find ROP gadgets
python -m src.rop_analyzer target.exe

# Analyze shellcode
python -m src.detectors.shellcode_detector payload.bin

# Binary diffing for patch analysis
python -m src.binary_differ old_version.exe new_version.exe
```

---

## 📚 Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)**: System design and component interactions
- **[Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md)**: Create custom analyzers
- **[CTF Walkthroughs](docs/CTF_WALKTHROUGHS.md)**: Tutorial examples with real challenges
- **[API Reference](docs/API_REFERENCE.md)**: Complete API documentation

---

## 🧪 Testing

DissectX includes comprehensive test coverage:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/test_flag_detector.py

# Run benchmarks
pytest tests/benchmarks/
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/dissectx.git
cd dissectx

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest
```

---

## 📄 License

MIT License - Open source and free to use for CTFs, learning, and security research.

See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

DissectX builds upon excellent open-source projects:
- **Capstone**: Disassembly framework
- **Unicorn Engine**: CPU emulator
- **Textual**: Modern TUI framework
- **NetworkX**: Graph analysis library

---

## 📞 Support & Community

- **Issues**: [GitHub Issues](https://github.com/yourusername/dissectx/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/dissectx/discussions)
- **Documentation**: [Full Documentation](https://dissectx.readthedocs.io)

---

**Made with ❤️ for the security research community**
