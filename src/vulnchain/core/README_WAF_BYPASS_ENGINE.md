# WAF Bypass Engine

## Overview

The WAF Bypass Engine provides intelligent detection and evasion capabilities for web application firewalls (WAFs). It can automatically detect WAF presence, fingerprint the vendor, and apply various bypass techniques to evade detection.

## Features

### WAF Detection

The engine can detect the following WAFs:
- **Cloudflare** - Detects via CF-Ray headers and blocking pages
- **Akamai** - Detects via Akamai-specific headers
- **AWS WAF** - Detects via AWS request IDs and error patterns
- **ModSecurity** - Detects via 406 responses and error messages
- **Imperva/Incapsula** - Detects via Incapsula cookies and headers
- **F5 BIG-IP** - Detects via F5-specific headers and error pages
- **FortiWeb** - Detects via Fortinet patterns
- **Barracuda** - Detects via Barracuda-specific patterns
- **Sucuri** - Detects via Sucuri headers and blocking pages
- **Wordfence** - Detects via WordPress-specific WAF patterns

### Bypass Techniques

The engine supports multiple bypass technique categories:

#### Encoding Techniques
- **URL Encoding** - Standard URL encoding of special characters
- **Double URL Encoding** - Apply URL encoding twice
- **Unicode Encoding** - Use Unicode escape sequences
- **Hex Encoding** - Encode characters as hex values

#### Obfuscation Techniques
- **Case Variation** - Mix uppercase and lowercase
- **Comment Injection** - Insert SQL/code comments to break patterns
- **Whitespace Manipulation** - Add extra whitespace and tabs

#### Protocol Techniques
- **HTTP Parameter Pollution (HPP)** - Duplicate parameters
- **Multipart Boundary Abuse** - Manipulate multipart form boundaries
- **Charset Confusion** - Use alternative character sets
- **Path Normalization** - Use path traversal sequences

#### Header Techniques
- **Header Manipulation** - Add bypass headers
- **Content-Type Confusion** - Use unexpected Content-Type values

## Usage

### Basic WAF Detection

```python
from app.core.waf_bypass_engine import WAFBypassEngine
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
waf_engine = WAFBypassEngine(request_handler)

# Detect WAF
waf_info = await waf_engine.detect_waf(
    url="https://target.com",
    test_payload="' OR '1'='1"
)

if waf_info:
    print(f"WAF Detected: {waf_info.vendor}")
    print(f"Confidence: {waf_info.confidence}")
    print(f"Detected from: {waf_info.detected_from}")
else:
    print("No WAF detected")
```

### Get Bypass Techniques

```python
# Get all techniques
techniques = waf_engine.get_bypass_techniques()

# Get techniques prioritized for specific WAF
techniques = waf_engine.get_bypass_techniques(waf_vendor="Cloudflare")

for tech in techniques:
    print(f"{tech.name} ({tech.category}): {tech.description}")
```

### Apply Bypass Technique

```python
from app.core.waf_bypass_engine import BypassTechnique

# Get a technique
technique = BypassTechnique(
    name="Double URL Encoding",
    description="Apply URL encoding twice",
    category="encoding",
    apply_function="apply_double_url_encoding",
)

# Apply to payload
original = "' OR '1'='1"
bypassed = waf_engine.apply_bypass(original, technique)
print(f"Original: {original}")
print(f"Bypassed: {bypassed}")
```

### Test Bypass Technique

```python
# Test if a technique works
result = await waf_engine.test_bypass(
    url="https://target.com",
    payload="' OR '1'='1",
    technique=technique
)

if result.success:
    print(f"Bypass successful with {result.technique.name}!")
    print(f"Original blocked: {result.original_blocked}")
    print(f"Bypassed blocked: {result.bypassed_blocked}")
else:
    print(f"Bypass failed: {result.error}")
```

### Find Working Bypass

```python
# Automatically find a working bypass
result = await waf_engine.find_working_bypass(
    url="https://target.com",
    payload="' OR '1'='1",
    waf_vendor="Cloudflare",  # Optional: prioritize techniques
    max_attempts=5
)

if result and result.success:
    print(f"Found working bypass: {result.technique.name}")
    print(f"Response status: {result.response.status_code}")
else:
    print("No working bypass found")
```

## Integration with Attack Modules

The WAF bypass engine can be integrated with attack modules to automatically apply bypass techniques:

```python
from app.core.waf_bypass_engine import WAFBypassEngine

class SQLInjectionModule:
    def __init__(self):
        self.waf_engine = WAFBypassEngine()
        self.detected_waf = None
    
    async def test_injection(self, url: str, payload: str):
        # Detect WAF if not already detected
        if not self.detected_waf:
            self.detected_waf = await self.waf_engine.detect_waf(url, payload)
        
        # If WAF detected, try to find bypass
        if self.detected_waf:
            bypass_result = await self.waf_engine.find_working_bypass(
                url=url,
                payload=payload,
                waf_vendor=self.detected_waf.vendor
            )
            
            if bypass_result and bypass_result.success:
                # Use bypassed payload
                payload = self.waf_engine.apply_bypass(
                    payload,
                    bypass_result.technique
                )
        
        # Continue with injection testing using bypassed payload
        # ...
```

## Bypass Persistence

The engine supports saving successful bypass patterns for reuse:

```python
# After finding a working bypass
if result and result.success:
    # Save the technique for this WAF vendor
    waf_engine._bypass_cache[waf_info.vendor] = [result.technique]
    
    # Later, retrieve cached bypasses
    cached_techniques = waf_engine._bypass_cache.get(waf_info.vendor, [])
```

## Architecture

### WAFInfo
Contains information about detected WAF:
- `vendor`: WAF vendor name
- `confidence`: Detection confidence (0.0 to 1.0)
- `detected_from`: List of indicators that led to detection
- `blocking_patterns`: Patterns that trigger blocks

### BypassTechnique
Represents a bypass technique:
- `name`: Technique name
- `description`: What the technique does
- `category`: encoding, obfuscation, protocol, or header
- `apply_function`: Method name to apply the technique
- `effectiveness`: low, medium, or high

### BypassResult
Result of a bypass attempt:
- `success`: Whether bypass was successful
- `technique`: The technique that was tested
- `original_blocked`: Whether original payload was blocked
- `bypassed_blocked`: Whether bypassed payload was blocked
- `response`: Response from bypassed request
- `error`: Error message if any

## Detection Algorithm

The WAF detection algorithm:

1. **Send benign request** - Establish baseline behavior
2. **Send malicious request** - Trigger WAF with known attack payload
3. **Analyze responses** - Check for WAF signatures:
   - Response headers (CF-Ray, Akamai-GRN, etc.)
   - Body patterns (vendor-specific error messages)
   - Status codes (403, 406, 503)
4. **Calculate confidence** - Score based on number of indicators
5. **Return detection** - If confidence > 0.5, WAF is detected

## Bypass Testing Algorithm

The bypass testing algorithm:

1. **Test original payload** - Send payload without bypass
2. **Check if blocked** - Determine if WAF blocked the request
3. **Apply bypass technique** - Transform payload using technique
4. **Test bypassed payload** - Send transformed payload
5. **Compare results** - Success if original blocked but bypass not blocked

## Best Practices

1. **Always detect WAF first** - Know what you're dealing with
2. **Use vendor-specific techniques** - Prioritize techniques known to work
3. **Cache successful bypasses** - Reuse working techniques
4. **Combine techniques** - Some bypasses work better together
5. **Monitor responses** - WAFs may adapt to bypass attempts
6. **Respect rate limits** - Avoid triggering additional protections

## Limitations

- Some WAFs use ML-based detection that adapts to bypass attempts
- Certain bypasses only work for specific vulnerability types
- Header-based bypasses require proper request construction
- Some techniques may break payload functionality

## Future Enhancements

- Machine learning to predict effective bypasses
- Automatic technique combination
- Real-time bypass adaptation
- Integration with payload mutation engine
- Support for more WAF vendors
- Advanced obfuscation techniques
