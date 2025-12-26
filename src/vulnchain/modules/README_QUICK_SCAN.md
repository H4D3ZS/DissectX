# Quick-Scan Module

## Overview

The Quick-Scan module provides rapid vulnerability triage and CTF pattern detection capabilities. It executes lightweight tests across all major vulnerability categories to quickly identify the most likely attack vectors, allowing CTF competitors to rapidly assess challenges and focus their efforts on the most promising exploitation paths.

## Features

### 1. Lightweight Vulnerability Testing
- **SQL Injection**: Tests for error-based and time-based blind SQLi indicators
- **XSS**: Checks for reflected input and filter bypass opportunities
- **Command Injection**: Tests for command execution indicators
- **SSRF**: Checks for internal service access
- **Directory Traversal**: Tests for path traversal vulnerabilities
- **SSTI**: Checks for template injection indicators
- **Authentication Issues**: Tests for accessible admin panels
- **Information Disclosure**: Analyzes headers and error messages

### 2. Vulnerability Likelihood Ranking
- Assigns confidence scores (0.0 to 1.0) to each detected indicator
- Ranks vulnerabilities by exploitation probability
- Considers response patterns, error messages, and timing differences
- Prioritizes high-confidence findings

### 3. CTF-Specific Pattern Detection
- **Flag Formats**: Detects common CTF flag patterns (CTF{...}, FLAG{...}, etc.)
- **Hint Comments**: Finds hints in HTML comments
- **Debug Endpoints**: Identifies debug/test endpoints
- **Custom Headers**: Detects headers with potential hints

### 4. Attack Module Recommendations
- Maps detected vulnerabilities to specific attack modules
- Provides prioritized list of recommended next steps
- Weights recommendations by confidence scores

### 5. Preset Configurations
- **Default**: Balanced scan across all categories
- **HackTheBox**: Optimized for HTB challenges
- **CTFd**: Optimized for CTFd-based competitions
- **PicoCTF**: Optimized for PicoCTF challenges
- **Web Only**: Focus on common web vulnerabilities
- **Injection Focus**: Deep focus on injection vulnerabilities
- **Custom**: Create your own preset configurations

## Usage

### Basic Quick-Scan

```python
from app.modules.quick_scan import QuickScanModule, VulnerabilityCategory
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

# Initialize
request_handler = RequestHandler()
quick_scan = QuickScanModule(request_handler)

# Configure target
target = TargetConfig(
    url="https://challenge.ctf.com",
    custom_headers={"User-Agent": "VulnChain/1.0"}
)

# Perform quick-scan
result = await quick_scan.quick_scan(target)

# Review results
print(f"Scan completed in {result.scan_duration:.2f}s")
print(f"Found {len(result.indicators)} vulnerability indicators")
print(f"Found {len(result.ctf_patterns)} CTF patterns")

# Top recommendations
print("\nRecommended attack modules:")
for module in result.recommended_modules[:5]:
    print(f"  - {module}")

# High-confidence indicators
print("\nHigh-confidence vulnerabilities:")
for indicator in result.indicators:
    if indicator.confidence >= 0.7:
        print(f"  [{indicator.category.value}] {indicator.description}")
        print(f"    Confidence: {indicator.confidence:.1%}")
        print(f"    Evidence: {indicator.evidence}")
```

### Using Presets

```python
from app.modules.quick_scan import QuickScanModule, QuickScanPreset

# List available presets
presets = QuickScanPreset.list_presets()
for preset in presets:
    print(f"{preset['name']}: {preset['description']}")

# Use a specific preset
htb_preset = QuickScanPreset.get_preset('hackthebox')
result = await quick_scan.quick_scan(
    target,
    categories=htb_preset['categories']
)
```

### Custom Preset

```python
from app.modules.quick_scan import QuickScanPreset, VulnerabilityCategory

# Create custom preset
custom_preset = QuickScanPreset.create_custom_preset(
    name="My Custom Scan",
    description="Focus on injection and auth",
    categories=[
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.COMMAND_INJECTION,
        VulnerabilityCategory.AUTHENTICATION,
    ],
    timeout=25
)

# Use custom preset
result = await quick_scan.quick_scan(
    target,
    categories=custom_preset['categories']
)
```

### Analyzing Results

```python
# Group indicators by category
from collections import defaultdict

by_category = defaultdict(list)
for indicator in result.indicators:
    by_category[indicator.category].append(indicator)

for category, indicators in by_category.items():
    print(f"\n{category.value}:")
    for ind in indicators:
        print(f"  - {ind.description} (confidence: {ind.confidence:.1%})")

# Check for CTF patterns
if result.ctf_patterns:
    print("\nCTF Patterns Detected:")
    for pattern in result.ctf_patterns:
        print(f"  [{pattern.pattern_type}] {pattern.description}")
        print(f"    Value: {pattern.value}")
        print(f"    Location: {pattern.location}")
```

## Data Structures

### VulnerabilityIndicator

```python
@dataclass
class VulnerabilityIndicator:
    category: VulnerabilityCategory  # Type of vulnerability
    confidence: float  # 0.0 to 1.0
    evidence: str  # What was detected
    description: str  # Human-readable description
    recommended_modules: List[str]  # Suggested next steps
```

### CTFPattern

```python
@dataclass
class CTFPattern:
    pattern_type: str  # flag_format, hint_comment, debug_endpoint, etc.
    value: str  # The actual pattern found
    location: str  # Where it was found
    description: str  # What it means
```

### QuickScanResult

```python
@dataclass
class QuickScanResult:
    target_url: str
    indicators: List[VulnerabilityIndicator]  # Sorted by confidence
    ctf_patterns: List[CTFPattern]
    recommended_modules: List[str]  # Prioritized list
    scan_duration: float  # Seconds
    error: Optional[str]
```

## Vulnerability Categories

The module tests for the following vulnerability categories:

1. **SQL_INJECTION**: Database injection vulnerabilities
2. **XSS**: Cross-site scripting
3. **COMMAND_INJECTION**: OS command injection
4. **SSRF**: Server-side request forgery
5. **XXE**: XML external entity injection
6. **DIRECTORY_TRAVERSAL**: Path traversal
7. **SSTI**: Server-side template injection
8. **DESERIALIZATION**: Insecure deserialization
9. **AUTHENTICATION**: Authentication bypass/issues
10. **AUTHORIZATION**: Authorization bypass/issues
11. **INFORMATION_DISCLOSURE**: Information leakage
12. **MISCONFIGURATION**: Security misconfigurations

## Detection Methods

### Error Pattern Matching
The module looks for specific error messages that indicate vulnerabilities:
- SQL errors (MySQL, PostgreSQL, Oracle, SQL Server)
- Command execution errors (bash, sh)
- Template engine errors (Jinja2, Twig)
- Deserialization errors

### Response Analysis
- **Timing Differences**: Detects time-based blind injections
- **Length Changes**: Identifies significant response size variations
- **Status Codes**: Analyzes HTTP status code patterns

### Header Analysis
- Missing security headers
- Information disclosure headers (Server, X-Powered-By)
- Custom headers with hints

### Content Analysis
- Flag patterns in response body
- HTML comments with hints
- Debug endpoint references
- Error messages and stack traces

## Best Practices

### 1. Start with Quick-Scan
Always begin with a quick-scan to identify the most promising attack vectors before diving into specific modules.

### 2. Use Appropriate Presets
Choose presets that match your target platform for better accuracy and faster results.

### 3. Review All Indicators
Don't ignore low-confidence indicators - they might still be valid, especially in CTF environments.

### 4. Follow Recommendations
The recommended modules list is prioritized based on detected indicators - follow it for efficient exploitation.

### 5. Check CTF Patterns
CTF-specific patterns often contain direct hints or flags - always review them first.

## Integration with Other Modules

The Quick-Scan module is designed to work seamlessly with other VulnChain modules:

```python
# After quick-scan, use recommended modules
result = await quick_scan.quick_scan(target)

if "SQL Injection" in result.recommended_modules:
    from app.modules.sql_injection import SQLInjectionModule
    sqli = SQLInjectionModule(request_handler)
    # Proceed with SQL injection testing

if "XSS Testing" in result.recommended_modules:
    from app.modules.xss import XSSModule
    xss = XSSModule(request_handler)
    # Proceed with XSS testing
```

## Performance Considerations

- **Lightweight**: Uses minimal payloads (1-2 per category)
- **Fast**: Typical scan completes in 10-30 seconds
- **Concurrent**: Tests multiple categories in parallel
- **Timeout**: Configurable timeout per preset (default: 30s)

## Limitations

1. **False Positives**: Quick-scan prioritizes speed over accuracy
2. **Surface-Level**: Only performs lightweight tests
3. **No Exploitation**: Detects indicators but doesn't exploit
4. **Limited Coverage**: Tests only common patterns

## Requirements

- Python 3.11+
- aiohttp or httpx for async HTTP requests
- Access to target URL

## Validation: Requirements Coverage

This implementation satisfies:

- **Requirement 24.1**: Executes lightweight tests across all major vulnerability categories
- **Requirement 24.2**: Ranks vulnerability likelihood based on response patterns and error messages
- **Requirement 24.3**: Provides prioritized list of recommended attack modules
- **Requirement 24.4**: Identifies CTF-specific patterns (flag formats, hint comments, debug endpoints)
- **Requirement 24.5**: Allows customization through presets and custom configurations
