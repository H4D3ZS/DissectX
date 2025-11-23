# Platform Compatibility Guide

This document provides detailed information about DissectX compatibility across different platforms and architectures.

## Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x86_64) | ✅ Fully Supported | Recommended platform |
| Linux (ARM64) | ✅ Fully Supported | Tested on Raspberry Pi 4, AWS Graviton |
| macOS (Intel) | ✅ Fully Supported | macOS 10.15+ |
| macOS (Apple Silicon) | ✅ Fully Supported | Native ARM64 support |
| Windows 10/11 (x86_64) | ⚠️ Mostly Supported | Some limitations (see below) |
| Windows (WSL2) | ✅ Fully Supported | Recommended for Windows users |
| FreeBSD | 🔶 Experimental | Community supported |

## Python Version Support

| Python Version | Status | Notes |
|----------------|--------|-------|
| 3.7 | ✅ Supported | Minimum version |
| 3.8 | ✅ Supported | |
| 3.9 | ✅ Supported | |
| 3.10 | ✅ Supported | |
| 3.11 | ✅ Supported | Recommended |
| 3.12 | ✅ Supported | Latest |
| 3.13+ | 🔶 Experimental | May work but not tested |

## Dependency Compatibility

### Core Dependencies

#### Capstone (Disassembly Engine)

| Platform | Status | Installation Method |
|----------|--------|---------------------|
| Linux | ✅ | `pip install capstone` |
| macOS | ✅ | `pip install capstone` |
| Windows | ✅ | `pip install capstone` |
| ARM64 | ✅ | `pip install capstone` |

**Notes**:
- Capstone 5.0+ required
- Pre-built wheels available for all major platforms
- No compilation required

#### Unicorn Engine (CPU Emulation)

| Platform | Status | Installation Method |
|----------|--------|---------------------|
| Linux (x86_64) | ✅ | `pip install unicorn` |
| Linux (ARM64) | ✅ | `pip install unicorn` |
| macOS (Intel) | ✅ | `pip install unicorn` |
| macOS (Apple Silicon) | ✅ | `pip install unicorn` |
| Windows | ⚠️ | `pip install unicorn` (may need MSVC) |

**Notes**:
- Unicorn 2.0+ required
- Windows may require Visual C++ Build Tools
- Pre-built wheels available for most platforms

#### pefile (PE File Parsing)

| Platform | Status | Notes |
|----------|--------|-------|
| All | ✅ | Pure Python, no platform-specific issues |

#### NetworkX (Graph Analysis)

| Platform | Status | Notes |
|----------|--------|-------|
| All | ✅ | Pure Python, no platform-specific issues |

#### Textual (Terminal UI)

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ | Full support |
| macOS | ✅ | Full support |
| Windows | ⚠️ | Limited color support in cmd.exe, use Windows Terminal |

**Notes**:
- Windows Terminal recommended over cmd.exe
- PowerShell 7+ recommended
- WSL provides best experience on Windows

#### Flask (Web UI)

| Platform | Status | Notes |
|----------|--------|-------|
| All | ✅ | Pure Python, no platform-specific issues |

#### WeasyPrint (PDF Export)

| Platform | Status | Installation Method |
|----------|--------|---------------------|
| Linux | ✅ | `pip install weasyprint` + system deps |
| macOS | ✅ | `pip install weasyprint` + brew deps |
| Windows | ❌ | Not recommended, use HTML export |

**Linux System Dependencies**:
```bash
sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0
```

**macOS System Dependencies**:
```bash
brew install pango gdk-pixbuf libffi
```

**Windows Alternative**:
- Use HTML export instead of PDF
- Or use WSL for full PDF support

#### ROPGadget (ROP Analysis)

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ | Full support |
| macOS | ✅ | Full support |
| Windows | ✅ | Full support |

#### r2pipe (Radare2 Integration)

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ | Requires radare2 installed |
| macOS | ✅ | Requires radare2 installed |
| Windows | ⚠️ | Requires radare2 for Windows |

**Installation**:
- Linux: `sudo apt-get install radare2`
- macOS: `brew install radare2`
- Windows: Download from https://rada.re/n/radare2.html

## Architecture Support

DissectX can analyze binaries for multiple architectures:

| Target Architecture | Analysis Support | Emulation Support |
|---------------------|------------------|-------------------|
| x86 (32-bit) | ✅ | ✅ |
| x86_64 (64-bit) | ✅ | ✅ |
| ARM (32-bit) | ✅ | ✅ |
| ARM64 (AArch64) | ✅ | ✅ |
| MIPS (32-bit) | ✅ | ✅ |
| MIPS64 (64-bit) | ✅ | ✅ |

**Note**: The host platform doesn't need to match the target architecture. You can analyze ARM binaries on x86_64 Linux, for example.

## Binary Format Support

| Format | Linux | macOS | Windows | Notes |
|--------|-------|-------|---------|-------|
| ELF | ✅ | ✅ | ✅ | Linux/Unix binaries |
| PE | ✅ | ✅ | ✅ | Windows binaries |
| Mach-O | ✅ | ✅ | ✅ | macOS binaries |
| Raw Binary | ✅ | ✅ | ✅ | Shellcode, firmware |

## Platform-Specific Features

### Linux

**Advantages**:
- Best overall compatibility
- All features fully supported
- Fastest performance
- Recommended for production use

**Considerations**:
- None - this is the primary development platform

### macOS

**Advantages**:
- Excellent compatibility
- Native Apple Silicon support
- All features work

**Considerations**:
- WeasyPrint requires Homebrew dependencies
- Some system-level analysis features may require SIP disabled

### Windows

**Advantages**:
- Native Windows binary analysis
- Good for analyzing Windows malware

**Considerations**:
- WeasyPrint (PDF export) not recommended - use HTML export
- Terminal UI works best in Windows Terminal, not cmd.exe
- Some dependencies may require Visual C++ Build Tools
- **Recommendation**: Use WSL2 for best experience

### Windows Subsystem for Linux (WSL)

**Advantages**:
- Full Linux compatibility on Windows
- All features work
- Best of both worlds

**Installation**:
```powershell
# PowerShell as Administrator
wsl --install
```

Then follow Linux installation instructions inside WSL.

## Docker Support

Docker provides consistent behavior across all platforms:

| Host Platform | Docker Support | Notes |
|---------------|----------------|-------|
| Linux | ✅ | Native performance |
| macOS | ✅ | Good performance |
| Windows | ✅ | Requires Docker Desktop |

**Advantages**:
- Consistent environment
- No dependency issues
- Easy to deploy
- Isolated from host system

**Usage**:
```bash
docker run -it -v $(pwd):/workspace dissectx:latest binary.exe
```

## Performance Considerations

### Platform Performance

Relative performance for typical analysis tasks:

| Platform | Performance | Notes |
|----------|-------------|-------|
| Linux (x86_64) | 100% (baseline) | Best performance |
| Linux (ARM64) | 85-95% | Depends on CPU |
| macOS (Intel) | 95-100% | Comparable to Linux |
| macOS (Apple Silicon) | 90-100% | Excellent, some deps may use Rosetta |
| Windows (native) | 80-90% | Some overhead |
| Windows (WSL2) | 90-95% | Near-native Linux performance |
| Docker (Linux) | 95-100% | Minimal overhead |
| Docker (macOS/Windows) | 80-90% | VM overhead |

### Memory Requirements

| Task | Minimum RAM | Recommended RAM |
|------|-------------|-----------------|
| Basic analysis | 512 MB | 1 GB |
| Full analysis | 1 GB | 2 GB |
| Large binaries (>10MB) | 2 GB | 4 GB |
| Emulation | 2 GB | 4 GB |
| Web UI | 1 GB | 2 GB |

## Known Issues and Workarounds

### Issue: Unicorn installation fails on Windows

**Workaround**:
1. Install Visual C++ Build Tools
2. Or use pre-built wheels from https://www.lfd.uci.edu/~gohlke/pythonlibs/
3. Or use WSL2 (recommended)

### Issue: WeasyPrint fails on Windows

**Workaround**:
- Use HTML export instead of PDF
- Or use WSL2 for full PDF support

### Issue: Terminal UI colors don't work on Windows

**Workaround**:
- Use Windows Terminal instead of cmd.exe
- Or use PowerShell 7+
- Or use WSL2

### Issue: Permission denied on Linux

**Workaround**:
```bash
pip install --user dissectx
# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install dissectx
```

### Issue: "Command not found" after installation

**Workaround**:
Add Python scripts directory to PATH:

**Linux/macOS**:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

**Windows**:
Add `%APPDATA%\Python\Python3X\Scripts` to PATH

## Testing Platform Compatibility

To test DissectX on your platform:

```bash
# Install DissectX
pip install dissectx

# Run basic test
echo "mov eax, 1" | dissectx -i

# Run test suite (if installed in dev mode)
pytest tests/

# Test specific features
dissectx --help
python -m src.detectors.flag_detector
python -m src.detectors.xor_analyzer
```

## Reporting Platform Issues

If you encounter platform-specific issues:

1. Check this document for known issues
2. Search [GitHub Issues](https://github.com/H4D3ZS/DissectX/issues)
3. Open a new issue with:
   - Operating system and version
   - Python version
   - Architecture (x86_64, ARM64, etc.)
   - Full error message
   - Output of `pip list`

## Contributing Platform Support

To improve platform support:

1. Test on your platform
2. Document any issues or workarounds
3. Submit pull requests with fixes
4. Update this document with findings

---

**Last Updated**: 2025-11-25
**Maintained By**: DissectX Contributors
