# Header Analyzer Module

## Overview

The Header Analyzer module provides comprehensive security analysis of HTTP response headers. It identifies missing security headers, detects misconfigurations, flags information disclosure issues, and generates an overall security score.

**Validates Requirements:** 20.1, 20.2, 20.3, 20.4, 20.5

## Features

### 1. Security Header Analysis (Requirement 20.1, 20.2)
- Extracts and analyzes all security-relevant headers
- Identifies missing critical security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-XSS-Protection

### 2. Misconfiguration Detection (Requirement 20.3)
- Detects weak CSP configurations (unsafe-inline, unsafe-eval, wildcards)
- Identifies insufficient HSTS max-age values
- Flags deprecated X-Frame-Options configurations
- Highlights insecure Referrer-Policy settings
- Provides specific remediation recommendations for each issue

### 3. Information Disclosure Detection (Requirement 20.4)
- Flags headers that reveal technology stack:
  - Server
  - X-Powered-By
  - X-AspNet-Version
  - X-AspNetMvc-Version
  - X-Generator
- Recommends removal or obfuscation

### 4. Security Score Dashboard (Requirement 20.5)
- Calculates overall security score (0-100)
- Assigns letter grade (A+ to F)
- Breaks down findings by severity (Critical, High, Medium, Low, Info)
- Tracks security header coverage
- Provides actionable metrics

## Usage

### Basic Analysis

```python
from app.core.header_analyzer import HeaderAnalyzer

# Initialize analyzer
analyzer = HeaderAnalyzer()

# Analyze response headers
headers = {
    "Content-Type": "text/html",
    "Server": "Apache/2.4.41",
    "X-Powered-By": "PHP/7.4.3"
}

findings = analyzer.analyze_headers(headers)

# Print findings
for finding in findings:
    print(f"{finding.severity.value.upper()}: {finding.description}")
```

### Generate Security Score

```python
# Calculate security score
score = analyzer.calculate_security_score(headers)

print(f"Security Score: {score.total_score}/100 (Grade: {score.grade})")
print(f"Total Findings: {score.total_findings}")
print(f"Security Headers Present: {score.security_headers_present}")
print(f"Security Headers Missing: {score.security_headers_missing}")
```

### Generate Reports

```python
# Generate text report
text_report = analyzer.generate_report(headers, format="text")
print(text_report)

# Generate markdown report
markdown_report = analyzer.generate_report(headers, format="markdown")

# Generate JSON report
json_report = analyzer.generate_report(headers, format="json")
```

### Filter Findings

```python
from app.core.header_analyzer import Severity

# Get high severity findings
high_severity = analyzer.get_findings_by_severity(Severity.HIGH)

# Get missing headers
missing_headers = analyzer.get_findings_by_type("missing")

# Get information disclosure issues
info_disclosure = analyzer.get_findings_by_type("information_disclosure")
```

## Data Models

### HeaderFinding

Represents a single security finding:

```python
@dataclass
class HeaderFinding:
    header_name: str                    # Name of the header
    severity: Severity                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    issue_type: str                     # "missing", "misconfigured", "information_disclosure"
    description: str                    # Human-readable description
    current_value: Optional[str]        # Current header value (if present)
    recommended_value: Optional[str]    # Recommended value
    remediation: str                    # How to fix the issue
    cve_references: List[str]           # Related CVEs (if applicable)
```

### SecurityScore

Overall security assessment:

```python
@dataclass
class SecurityScore:
    total_score: int                           # 0-100
    grade: str                                 # A+, A, B, C, D, F
    findings_by_severity: Dict[Severity, int]  # Count by severity
    total_findings: int                        # Total number of findings
    headers_analyzed: int                      # Total headers in response
    security_headers_present: int              # Count of security headers present
    security_headers_missing: int              # Count of security headers missing
```

## Scoring System

The security score starts at 100 and deducts points based on findings:

- **Critical findings:** -25 points each
- **High findings:** -15 points each
- **Medium findings:** -10 points each
- **Low findings:** -5 points each
- **Info findings:** -2 points each

### Grade Scale

- **A+ (95-100):** Excellent security posture
- **A (90-94):** Very good security
- **B (80-89):** Good security with minor issues
- **C (70-79):** Adequate security with notable gaps
- **D (60-69):** Poor security with significant issues
- **F (0-59):** Failing security posture

## Security Headers Reference

### Critical Headers

1. **Content-Security-Policy (CSP)**
   - Prevents XSS and data injection attacks
   - Recommended: `default-src 'self'; script-src 'self'; object-src 'none'`

2. **Strict-Transport-Security (HSTS)**
   - Enforces HTTPS connections
   - Recommended: `max-age=31536000; includeSubDomains; preload`

### Important Headers

3. **X-Frame-Options**
   - Prevents clickjacking
   - Recommended: `DENY` or `SAMEORIGIN`

4. **X-Content-Type-Options**
   - Prevents MIME sniffing
   - Recommended: `nosniff`

### Additional Headers

5. **Referrer-Policy**
   - Controls referrer information
   - Recommended: `no-referrer` or `strict-origin-when-cross-origin`

6. **Permissions-Policy**
   - Controls browser features
   - Recommended: `geolocation=(), microphone=(), camera=()`

## Integration with Other Modules

### With Request Handler

```python
from app.core.request_handler import RequestHandler
from app.core.header_analyzer import HeaderAnalyzer

# Send request
handler = RequestHandler()
response = await handler.send_request("GET", "https://example.com")

# Analyze headers
analyzer = HeaderAnalyzer()
findings = analyzer.analyze_headers(response.headers)
score = analyzer.calculate_security_score(response.headers)
```

### With Workspace Manager

```python
from app.core.workspace_manager import WorkspaceManager
from app.core.header_analyzer import HeaderAnalyzer

# Analyze and save findings
analyzer = HeaderAnalyzer()
findings = analyzer.analyze_headers(response.headers)

workspace = workspace_manager.get_workspace(workspace_id)
for finding in findings:
    # Convert to Finding object and save
    workspace_manager.save_finding(workspace_id, finding)
```

## Best Practices

1. **Run Early:** Analyze headers during initial reconnaissance
2. **Track Changes:** Re-analyze after configuration changes
3. **Prioritize Fixes:** Address high and critical findings first
4. **Document Exceptions:** Some findings may be acceptable in specific contexts
5. **Combine with Other Tests:** Use alongside vulnerability scanning

## Common Weak Configurations

### CSP Issues
- `unsafe-inline` - Allows inline scripts (defeats XSS protection)
- `unsafe-eval` - Allows eval() (enables code injection)
- `*` wildcard - Too permissive

### HSTS Issues
- `max-age=0` - Disables protection
- Short max-age - Should be at least 1 year (31536000 seconds)
- Missing `includeSubDomains` - Subdomains not protected

### Information Disclosure
- `Server: Apache/2.4.41` - Reveals exact version
- `X-Powered-By: PHP/7.4.3` - Reveals framework version
- `X-AspNet-Version` - Reveals .NET version

## Example Output

### Text Report

```
============================================================
HTTP SECURITY HEADER ANALYSIS REPORT
============================================================

Overall Security Score: 45/100 (Grade: F)
Total Findings: 9
Security Headers Present: 0/7
Security Headers Missing: 7

Findings by Severity:
  HIGH: 2
  MEDIUM: 2
  LOW: 5

============================================================
DETAILED FINDINGS
============================================================

[1] Content-Security-Policy
    Severity: HIGH
    Type: missing
    Description: Missing security header: Content Security Policy helps prevent XSS and data injection attacks
    Recommended: default-src 'self'; script-src 'self'; object-src 'none'
    Remediation: Implement a strict Content Security Policy to control resource loading

[2] Server
    Severity: LOW
    Type: information_disclosure
    Description: Server header reveals web server software and version
    Current Value: Apache/2.4.41
    Recommended: <removed>
    Remediation: Remove or obfuscate the Server header to hide technology stack
```

## Testing

The module includes comprehensive unit tests covering:
- Missing header detection
- Misconfiguration detection
- Information disclosure detection
- Security score calculation
- Report generation
- Edge cases and error handling

Run tests with:
```bash
pytest backend/tests/test_header_analyzer.py -v
```
