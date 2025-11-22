# 🔍 DissectX

**CTF Binary Analysis Tool - Reverse Engineering Made Easy**

DissectX translates x86-64 assembly into plain English and extracts hidden flags from binaries. Perfect for CTF competitions and learning reverse engineering.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze a binary (find flags/passwords)
python main.py challenge.exe

# Full analysis (disassembly + translation)
python main.py challenge.exe --full

# Translate assembly code
python main.py code.asm
```

## Features

- 🚩 **Auto-extract flags** - Finds hidden strings, passwords, and Base64-encoded data
- 📖 **Assembly translation** - Converts x86-64 assembly to human-readable English
- 🛡️ **Security detection** - Identifies packers, anti-debugging, and obfuscation
- 🔍 **Pattern recognition** - Detects loops, conditionals, and function structures
- 🎯 **CTF-optimized** - Built specifically for capture-the-flag challenges

## Usage Examples

### Find the flag in a binary
```bash
python main.py mystery.exe
```
Output shows strings, decoded Base64, and security keywords.

### Understand assembly code
```bash
python main.py code.asm
```
Translates each instruction with context and explanations.

### Full reverse engineering
```bash
python main.py packed.exe --full
```
Disassembles, translates, and detects advanced protections (VMProtect, syscalls, etc.)

### Interactive mode
```bash
python main.py -i
# Paste assembly, press Ctrl+D when done
```

## Installation

```bash
git clone <repo-url>
cd dissectx
pip install -r requirements.txt
```

**Requirements:**
- Python 3.7+
- `objdump` (for binary disassembly)

## Command Reference

```bash
python main.py <file>              # Auto-detect and analyze
python main.py <file> --full       # Complete analysis (auto-saves)
python main.py <file> -o out.txt   # Save to file
python main.py <file> --strings-only  # Only extract strings
python main.py -i                  # Interactive mode
```

## What It Detects

**Strings & Secrets:**
- Plain text flags (flag{...}, CTF{...})
- Base64 encoded data (auto-decoded)
- Passwords and keys
- Security-relevant API calls

**Binary Protections:**
- Packers (UPX, MPRESS, Themida)
- Anti-debugging techniques
- Direct syscalls (Hell's Gate)
- VMProtect virtualization
- API hashing

**Code Patterns:**
- Function prologues/epilogues
- Loops and conditionals
- String operations
- Crypto operations (XOR, etc.)
- Stack canaries

## Helper Tools

**XOR Brute Force:**
```bash
python decode_helper.py "encrypted_hex_string"
```

## Example Output

```
🚩 POSSIBLE FLAG:
   Encoded: ZmxhZ3tyM3YzcnNlX20z...
   Decoded: flag{r3v3rse_m3_engr1ng}

ASSEMBLY TRANSLATION:
cmp eax, 0x1337
  → Compare eax (32-bit accumulator) with 0x1337
je correct_password
  → Jump to correct_password if equal
```

## License

MIT License - Open source and free to use for CTFs, learning, and security research.

## Contributing

Contributions welcome! Run tests with:
```bash
pytest tests/ -v
```

---

**Made for the CTF community** 🚀
