# CSRF Module

## Overview

The CSRF (Cross-Site Request Forgery) module provides automated testing for CSRF vulnerabilities in web applications. It implements multiple testing techniques and generates proof-of-concept code for demonstrating vulnerabilities.

## Features

### Testing Techniques

1. **Token Omission Testing**
   - Tests if requests succeed without CSRF tokens
   - Validates: Requirements 14.1

2. **Token Reuse Testing**
   - Tests if CSRF tokens can be reused multiple times
   - Validates: Requirements 14.2

3. **Token Expiration Testing**
   - Tests if expired or invalid tokens are accepted
   - Validates: Requirements 14.2

4. **Method Switching**
   - Tests if POST requests can be converted to GET
   - Bypasses CSRF protection that only checks POST requests
   - Validates: Requirements 14.3

5. **Referer Header Bypass**
   - Tests if malicious referer headers are accepted
   - Validates: Requirements 14.3

6. **Origin Header Bypass**
   - Tests if malicious origin headers are accepted
   - Validates: Requirements 14.3

### PoC Generation

1. **HTML PoC**
   - Generates complete HTML pages for demonstrating CSRF
   - Includes both manual and automatic triggers
   - Provides safe demonstration instructions
   - Validates: Requirements 14.4, 14.5

2. **JavaScript PoC**
   - Generates JavaScript exploit code
   - Multiple attack methods (Form, Fetch, XMLHttpRequest)
   - Includes safety warnings and instructions
   - Validates: Requirements 14.4, 14.5

## Usage

### Basic Usage

```python
from app.modules.csrf import CSRFTester, CSRFTestPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
csrf_tester = CSRFTester(request_handler)

# Define test point
test_point = CSRFTestPoint(
    url="https://example.com/transfer",
    method="POST",
    parameters={
        "amount": "1000",
        "to_account": "attacker",
        "csrf_token": "abc123xyz"
    },
    csrf_token_name="csrf_token",
    csrf_token_value="abc123xyz",
    csrf_token_location="parameter"
)

# Test for CSRF
results = await csrf_tester.test_endpoint(test_point)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"CSRF vulnerability found: {result.technique.value}")
        print(f"Confidence: {result.confidence}")
        print(f"PoC HTML: {result.poc_html}")
```

### Testing Specific Techniques

```python
from app.modules.csrf import CSRFTechnique

# Test only token omission
results = await csrf_tester.test_endpoint(
    test_point,
    techniques=[CSRFTechnique.TOKEN_OMISSION]
)

# Test multiple specific techniques
results = await csrf_tester.test_endpoint(
    test_point,
    techniques=[
        CSRFTechnique.TOKEN_OMISSION,
        CSRFTechnique.METHOD_SWITCHING
    ]
)
```

### Generating PoC

```python
from app.modules.csrf import CSRFPoCGenerator, CSRFTechnique

poc_generator = CSRFPoCGenerator()

# Generate HTML PoC
html_poc = poc_generator.generate_html_poc(
    test_point,
    CSRFTechnique.TOKEN_OMISSION
)

# Generate JavaScript PoC
js_poc = poc_generator.generate_javascript_poc(
    test_point,
    CSRFTechnique.METHOD_SWITCHING
)

# Save to files
with open("csrf_poc.html", "w") as f:
    f.write(html_poc)

with open("csrf_exploit.js", "w") as f:
    f.write(js_poc)
```

## Data Models

### CSRFTestPoint

Represents an endpoint to test for CSRF vulnerabilities.

```python
@dataclass
class CSRFTestPoint:
    url: str                              # Target URL
    method: str = "POST"                  # HTTP method
    parameters: Dict[str, str]            # Request parameters
    headers: Dict[str, str]               # Request headers
    cookies: Dict[str, str]               # Request cookies
    csrf_token_name: Optional[str]        # CSRF token parameter name
    csrf_token_value: Optional[str]       # CSRF token value
    csrf_token_location: Optional[str]    # Token location (parameter/header/cookie)
```

### CSRFResult

Contains the results of CSRF testing.

```python
@dataclass
class CSRFResult:
    test_point: CSRFTestPoint             # The tested endpoint
    is_vulnerable: bool                   # Whether vulnerability was found
    technique: Optional[CSRFTechnique]    # Technique that worked
    confidence: float                     # Confidence score (0.0-1.0)
    evidence: List[str]                   # Evidence of vulnerability
    baseline_response: Optional[Response] # Legitimate response
    attack_response: Optional[Response]   # Attack response
    poc_html: Optional[str]               # HTML PoC
    poc_javascript: Optional[str]         # JavaScript PoC
    metadata: Dict                        # Additional metadata
```

## Testing Workflow

1. **Token Detection**
   - Automatically detects CSRF tokens in parameters, headers, or cookies
   - Identifies common token names (csrf_token, _token, authenticity_token, etc.)

2. **Baseline Request**
   - Sends legitimate request with all tokens
   - Captures baseline response for comparison

3. **Attack Testing**
   - Tests each technique sequentially
   - Stops after first successful vulnerability
   - Compares attack responses with baseline

4. **PoC Generation**
   - Generates HTML and JavaScript PoCs for successful attacks
   - Includes safe demonstration instructions
   - Provides multiple attack methods

## Security Considerations

### Safe Testing

- Only test applications you own or have permission to test
- CSRF attacks can perform real actions on behalf of users
- Always use test accounts and test data
- Never test on production systems without authorization

### PoC Safety

- Generated PoCs include safety warnings
- Automatic triggers have delays to allow cancellation
- Instructions emphasize authorized testing only
- Code includes comments about responsible disclosure

## Common CSRF Token Names

The module automatically detects these common token names:

- csrf_token
- csrf
- _csrf
- csrftoken
- token
- _token
- authenticity_token
- anti_csrf_token
- xsrf_token
- xsrf
- _xsrf
- csrf-token
- x-csrf-token
- x-xsrf-token

## Integration

### With Session Manager

```python
from app.core.session_manager import SessionManager

session_manager = SessionManager()
csrf_tester = CSRFTester(request_handler, session_manager)

# Session manager handles cookies automatically
```

### With Workspace Manager

```python
from app.core.workspace_manager import WorkspaceManager

workspace_manager = WorkspaceManager()

# Save CSRF findings
for result in results:
    if result.is_vulnerable:
        finding = {
            "type": "CSRF",
            "technique": result.technique.value,
            "url": result.test_point.url,
            "confidence": result.confidence,
            "poc_html": result.poc_html,
            "poc_js": result.poc_javascript
        }
        workspace_manager.save_finding(workspace_id, finding)
```

## Examples

See `examples/csrf_demo.py` for complete usage examples including:
- Basic CSRF testing
- Token omission testing
- Method switching attacks
- PoC generation
- Safe demonstration practices
