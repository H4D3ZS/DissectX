# Directory Traversal Module

## Overview

The Directory Traversal module provides automated testing for path traversal vulnerabilities with multiple encoding variations. It tests for the ability to access files outside the intended directory structure through various bypass techniques.

## Features

### Traversal Techniques

1. **Basic Traversal**
   - Standard `../` and `..\` sequences
   - Multiple depth levels (1-8)
   - Tests both Unix and Windows path separators

2. **URL Encoded Traversal**
   - Single URL encoding of traversal sequences
   - Encodes dots, slashes, and backslashes
   - Example: `%2e%2e%2f` for `../`

3. **Double URL Encoded Traversal**
   - Double URL encoding to bypass filters
   - Example: `%252e%252e%252f` for `../`

4. **Null Byte Injection**
   - Appends null bytes to bypass extension checks
   - Variants: `%00`, `\x00`
   - Example: `../../etc/passwd%00.jpg`

5. **Unicode Encoding**
   - UTF-8 overlong encoding
   - UTF-16 encoding
   - Example: `%c0%ae%c0%ae/` for `../`

6. **Mixed Encoding**
   - Combination of multiple encoding techniques
   - Mix of encoded and non-encoded characters
   - Absolute paths with traversal sequences

### Target Files

The module tests against common sensitive files:

**Unix/Linux:**
- `/etc/passwd` - User account information
- `/etc/shadow` - Password hashes
- `/etc/hosts` - Host name mappings
- `/proc/self/environ` - Process environment variables
- `/root/.ssh/id_rsa` - SSH private keys
- `/var/log/apache2/access.log` - Web server logs
- `/var/www/html/config.php` - Application configuration

**Windows:**
- `C:\Windows\win.ini` - Windows configuration
- `C:\Windows\System32\drivers\etc\hosts` - Host mappings
- `C:\boot.ini` - Boot configuration
- `C:\Windows\System32\config\SAM` - Security Account Manager
- `C:\inetpub\wwwroot\web.config` - IIS configuration

## Usage

### Basic Usage

```python
from app.modules.directory_traversal import DirectoryTraversalTester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = DirectoryTraversalTester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="file",
    location="query",
    original_value="index.php",
    url="https://example.com/view.php?file=index.php",
    method="GET",
)

# Test for directory traversal
results = await tester.test_injection_point(injection_point)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable! Technique: {result.technique.value}")
        print(f"Payload: {result.payload}")
        print(f"File content: {result.file_content[:200]}")
```

### Testing Specific Techniques

```python
from app.modules.directory_traversal import TraversalTechnique

# Test only URL encoding
results = await tester.test_injection_point(
    injection_point,
    techniques=[TraversalTechnique.URL_ENCODED]
)
```

### Custom Target Files

```python
# Test specific files
custom_files = [
    "/etc/passwd",
    "/var/www/html/config.php",
    "C:\\Windows\\win.ini",
]

results = await tester.test_injection_point(
    injection_point,
    target_files=custom_files
)
```

## Detection Methods

The module uses multiple methods to detect successful traversal:

1. **Pattern Matching**
   - Looks for known file content patterns
   - Example: `root:x:0:0` for `/etc/passwd`

2. **Response Length Analysis**
   - Compares response length to baseline
   - Significant differences indicate file content

3. **Content Indicators**
   - Checks for file-specific markers
   - Example: `[fonts]` for Windows INI files

## Integration

### With Request Handler

The module integrates with the core Request Handler for HTTP communication:

```python
from app.core.request_handler import RequestHandler
from app.core.config import Config

config = Config()
request_handler = RequestHandler(config)
tester = DirectoryTraversalTester(request_handler)
```

### With Payload Engine

Custom payloads can be added through the Payload Engine:

```python
from app.core.payload_engine import PayloadEngine

payload_engine = PayloadEngine()
payload_engine.add_custom_payload("../../../../etc/passwd", "traversal_custom")

tester = DirectoryTraversalTester(request_handler, payload_engine)
```

## Result Structure

```python
@dataclass
class TraversalResult:
    injection_point: InjectionPoint
    is_vulnerable: bool
    technique: Optional[TraversalTechnique]
    payload: Optional[str]
    confidence: float  # 0.0 to 1.0
    file_content: Optional[str]
    target_file: Optional[str]
    evidence: List[str]
    metadata: Dict
```

## Requirements Validation

This module implements the following requirements:

- **Requirement 10.1**: Inject path traversal sequences with encodings
- **Requirement 10.2**: Apply URL encoding, double encoding, null bytes
- **Requirement 10.3**: Display file contents in UI
- **Requirement 10.4**: Target common sensitive files
- **Requirement 10.5**: Allow custom file path specification

## Security Considerations

This module is designed for:
- Authorized security testing
- CTF competitions
- Educational purposes
- Bug bounty programs

**Never use this module against systems without explicit authorization.**

## Examples

See `backend/examples/directory_traversal_demo.py` for complete usage examples.
