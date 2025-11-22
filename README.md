# 🔍 DissectX

**Advanced Binary Analysis & Reverse Engineering Platform**

DissectX is a professional-grade reverse engineering tool designed for CTF competitions and malware analysis. It bridges the gap between static analysis and dynamic execution, offering powerful features like CPU emulation, memory forensics, and automatic flag extraction.

> **From "Good for picoCTF" → "Dominates Hard Real-World / Malware-Grade Reversing"**

## 🚀 Key Features

### 1. Core Analysis
- **Auto-Translation**: Converts x86-64 assembly into plain English.
- **Decompiled View**: Generates a C-like pseudo-code block for the entire binary.
- **Smart String Extraction**: Finds flags, passwords, and Base64-encoded secrets.
- **Security Highlighting**: Identifies dangerous instructions and API calls.

### 2. Advanced Detection (Static)
- **🛡️ Syscall Detection**: Identifies direct syscall stubs (Hell's Gate, SysWhispers) used to bypass EDR/AV.
- **🔓 API Hash Resolver**: Automatically resolves obfuscated API calls (ROR13, CRC32, FNV-1a).
- **🗑️ Junk Code Detection**: Detects anti-analysis techniques like fake symbols, opaque predicates, and protector signatures (VMProtect, Themida).
- **🚩 Flag Finder**: Automatically extracts flags using regex, Base64 decoding, ROT13, and XOR brute-force.

### 3. Dynamic Analysis (Emulation)
- **🦄 Unicorn Engine**: Safe, sandboxed CPU emulation for x86-64 code.
- **🔐 String Decryption**:
    - **Stack Strings**: Detects strings constructed byte-by-byte on the stack.
    - **XOR Brute Force**: Automatically tries 256 keys to decrypt strings.
    - **Emulation**: Decrypts complex obfuscated strings at runtime.

### 4. Memory Forensics
- **🧠 Memory Dump Analysis**: Analyzes raw memory dumps for injected code and hidden threats.
- **👻 Hidden PE Detection**: Finds PE files hidden inside other files or memory regions.
- **💉 Shellcode Detection**: Identifies common shellcode patterns (GetPC, PEB access).
- **🕳️ Process Hollowing**: Detects manual mapping and process hollowing techniques.

---

## 📦 Installation

```bash
# Clone the repository
git clone <repo-url>
cd dissectx

# Install dependencies (including Unicorn, Capstone, pefile)
pip install -r requirements.txt
```

**Requirements:**
- Python 3.7+
- `unicorn` (for emulation)
- `capstone` (for disassembly)
- `pefile` (for PE analysis)

---

## 🛠️ Usage Guide

### Basic Analysis
Analyze a binary to find flags, strings, and basic info:
```bash
python main.py challenge.exe
```

### Full Disassembly & Translation
Generate a complete analysis report with translated assembly:
```bash
python main.py challenge.exe --full
```

### Advanced Static Analysis
Enable all advanced detection modules (Syscalls, API Hashing, Junk Code):
```bash
python main.py malware.exe --advanced
```

### Dynamic Analysis (Emulation)
Attempt to decrypt strings using emulation and stack string detection:
```bash
python main.py packed.exe --decrypt-strings
```
Run full emulation for deeper analysis:
```bash
python main.py packed.exe --emulate
```

### Dynamic Unpacking (Generate Dump)
Automatically unpack a binary by running it in the emulator and dumping memory:
```bash
python main.py --generate-dump packed.exe
```
This is useful for packed malware that hides its code until runtime.

### Memory Forensics
Analyze a memory dump file for hidden malware:
```bash
python main.py --memory-dump process_dump.dmp
```

---

## 📊 Command Reference

| Flag | Description |
|------|-------------|
| `--full` | Complete analysis (disassembly + translation) |
| `--advanced` | Enable all advanced static detections |
| `--detect-syscalls` | Detect direct syscall stubs |
| `--resolve-hashes` | Resolve API hashes |
| `--detect-junk` | Detect junk code & anti-analysis |
| `--decrypt-strings` | Attempt to decrypt strings (XOR/Stack) |
| `--emulate` | Enable Unicorn emulation |
| `--generate-dump <file>` | Run binary in emulator and dump memory |
| `--memory-dump <file>` | Analyze a memory dump file |
| `--strings-only` | Only show strings (fast mode) |
| `-i`, `--interactive` | Interactive mode |

---

## 📝 Example Output

```text
🚩 FLAG DETECTION RESULTS
======================================================================
✅ Found 2 potential flag(s)!

🎯 Flag #1 [HIGH CONFIDENCE]
  Value: flag{reverse_m3_engr1ng}
  Method: String Analysis

⚠️ Flag #2 [MEDIUM CONFIDENCE]
  Value: flag{n0_sn1ff1ng}
  Method: XOR Decode (key: 0x55)
======================================================================

🔓 DECRYPTED STRINGS
======================================================================
Found 1 decrypted string(s)!

🎯 String #1 [HIGH CONFIDENCE]
  Value: http://malicious-c2.com/payload.exe
  Method: Stack String Analysis
  Encryption: Stack Construction
======================================================================

MEMORY DUMP ANALYSIS
======================================================================
🔍 Hidden PE Files (1):
  • Offset: 0x14000, Size: 0x2000 [MANUALLY MAPPED]

💉 Shellcode Patterns (2):
  • 0x401000: JMP/POP pattern (GetPC)
  • 0x401050: PEB access (x64)
======================================================================
```

## 📄 License

MIT License - Open source and free to use for CTFs, learning, and security research.

---

**Made for the CTF community** 🚀
