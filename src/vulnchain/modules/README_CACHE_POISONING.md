# Cache Poisoning Module

## Overview

The Cache Poisoning module provides automated testing for web cache vulnerabilities including cache poisoning via unkeyed headers, web cache deception, CDN cache key normalization issues, and origin server bypass attacks.

## Features

### 1. Cache Key Analysis
- Automatically identifies keyed and unkeyed components
- Detects cache status (HIT/MISS)
- Identifies CDN providers (Cloudflare, Fastly, Akamai, etc.)
- Analyzes cache control headers

### 2. Unkeyed Header Poisoning
- Tests common unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.)
- Injects XSS payloads to poison cache
- Verifies persistence of poisoned content
- Provides XSS amplification guidance

### 3. Web Cache Deception
- Tests path confusion attacks
- Identifies cacheable sensitive content
- Tests various path manipulation techniques:
  - Path parameters (`;.css`)
  - Encoded paths (`%2f`)
  - Null bytes (`%00`)
  - Query strings and fragments

### 4. CDN Normalization Testing
- Tests port normalization (`:80`, `:443`)
- Tests case normalization
- Tests scheme normalization
- Tests path normalization (double slashes, dot segments)

### 5. Origin Server Bypass
- Tests header-based routing overrides
- Tests IP spoofing headers
- Tests method override headers
- Identifies access control bypasses

## Usage

### Basic Usage

```python
from app.core.request_handler import RequestHandler
from app.modules.cache_poisoning import CachePoisoningTester, CacheTestPoint

# Initialize
request_handler = RequestHandler()
tester = CachePoisoningTester(request_handler)

# Create test point
test_point = CacheTestPoint(
    url="https://target.com/api/endpoint",
    method="GET",
    headers={"User-Agent": "VulnChain/1.0"},
)

# Analyze cache keys
cache_analysis = await tester.analyze_cache_keys(test_point)
print(f"Unkeyed headers: {cache_analysis.unkeyed_headers}")
print(f"CDN detected: {cache_analysis.cdn_detected}")

# Test for unkeyed header poisoning
results = await tester.test_unkeyed_header_poisoning(test_point, cache_analysis)
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable to cache poisoning via {result.unkeyed_header}")
        print(result.exploitation_guidance)

# Test for web cache deception
deception_results = await tester.test_web_cache_deception(test_point)
for result in deception_results:
    if result.is_vulnerable:
        print(f"Web cache deception vulnerability found")
        print(result.exploitation_guidance)
```

### Comprehensive Testing

```python
from app.modules.cache_poisoning import test_cache_poisoning

# Run all cache poisoning tests
all_results = await test_cache_poisoning(
    target_url="https://target.com/",
    request_handler=request_handler,
)

# Process results
for vuln_type, results in all_results.items():
    print(f"\n{vuln_type.upper()} Results:")
    for result in results:
        if result.is_vulnerable:
            print(f"  - Vulnerable: {result.evidence}")
```

## Vulnerability Types

### Unkeyed Header Poisoning

**Description**: Cache accepts certain headers as input but doesn't include them in the cache key, allowing attackers to poison the cache.

**Common Unkeyed Headers**:
- `X-Forwarded-Host`
- `X-Forwarded-Scheme`
- `X-Original-URL`
- `X-Rewrite-URL`
- `X-Host`

**Impact**: XSS amplification, credential theft, session hijacking

### Web Cache Deception

**Description**: Application serves sensitive content at paths that appear to be static resources, causing caches to store private data.

**Attack Pattern**:
1. Attacker sends victim: `https://target.com/account/settings/style.css`
2. Victim visits while authenticated
3. Cache stores response (including sensitive data)
4. Attacker retrieves cached sensitive data

**Impact**: Information disclosure, account takeover

### CDN Normalization Issues

**Description**: CDN and origin server normalize requests differently, creating cache key collisions.

**Examples**:
- Port normalization: `:80` vs no port
- Case normalization: `HOST` vs `host`
- Path normalization: `//path` vs `/path`

**Impact**: Cache poisoning, access control bypass

### Origin Server Bypass

**Description**: CDN forwards certain headers to origin, allowing bypass of origin-level protections.

**Bypass Headers**:
- `X-Original-URL`: Override request path
- `X-Forwarded-Host`: Override host header
- `X-Forwarded-For`: Spoof source IP
- `X-HTTP-Method-Override`: Change HTTP method

**Impact**: Access to admin panels, authentication bypass

## Data Structures

### CacheTestPoint
```python
@dataclass
class CacheTestPoint:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, str] = field(default_factory=dict)
```

### CachePoisoningResult
```python
@dataclass
class CachePoisoningResult:
    test_point: CacheTestPoint
    is_vulnerable: bool
    poisoning_type: Optional[CachePoisoningType] = None
    unkeyed_header: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    cache_keys: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    exploitation_guidance: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
```

### CacheKeyAnalysis
```python
@dataclass
class CacheKeyAnalysis:
    url: str
    keyed_components: List[str] = field(default_factory=list)
    unkeyed_headers: List[str] = field(default_factory=list)
    cache_status: CacheStatus = CacheStatus.UNKNOWN
    cache_control_headers: Dict[str, str] = field(default_factory=dict)
    cdn_detected: Optional[str] = None
```

## Requirements Validation

This module implements the following requirements from the specification:

- **Requirement 43.1**: Tests for cache poisoning through unkeyed header injection
- **Requirement 43.2**: Identifies cache keys and tests for web cache deception attacks
- **Requirement 43.3**: Verifies cache poisoning persistence through subsequent requests
- **Requirement 43.4**: Tests for CDN cache key normalization issues and origin server bypass
- **Requirement 43.5**: Provides exploitation guidance for XSS amplification and credential theft

## Testing

The module includes comprehensive testing capabilities:

1. **Cache Key Identification**: Automatically determines which components are included in cache keys
2. **Unkeyed Header Detection**: Tests all common unkeyed headers
3. **Persistence Verification**: Confirms that poisoned content persists in cache
4. **CDN Detection**: Identifies CDN providers for targeted testing
5. **Exploitation Guidance**: Provides detailed exploitation steps for each vulnerability

## Security Considerations

**WARNING**: This module is designed for authorized security testing only. Use only on:
- Applications you own
- Systems you have explicit permission to test
- Authorized CTF competitions
- Legal bug bounty programs

Unauthorized cache poisoning can:
- Affect other users
- Cause service disruption
- Violate computer fraud laws
- Result in legal consequences

## References

- [Web Cache Poisoning - PortSwigger](https://portswigger.net/research/practical-web-cache-poisoning)
- [Web Cache Deception Attack](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
- [CDN Cache Poisoning](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf)
