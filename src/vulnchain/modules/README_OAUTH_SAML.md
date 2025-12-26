# OAuth and SAML Exploitation Module

## Overview

This module provides automated testing and exploitation capabilities for OAuth 2.0 and SAML authentication vulnerabilities. It implements comprehensive testing for common misconfigurations and security flaws in federated identity systems.

## Features

### OAuth 2.0 Testing

1. **redirect_uri Bypass Testing**
   - Open redirect vulnerabilities
   - Path traversal attacks
   - Subdomain bypass techniques
   - Domain append attacks
   - Null byte injection
   - @ symbol bypass
   - Backslash bypass
   - Fragment bypass

2. **State Parameter Testing**
   - Missing state parameter detection
   - State validation bypass
   - CSRF attack vectors

3. **Token Leakage Detection**
   - Implicit flow vulnerabilities
   - Token exposure in URL fragments
   - Referer header leakage

4. **PKCE Bypass Testing**
   - Code challenge omission
   - Code verifier bypass
   - Downgrade attacks

5. **Authorization Code Interception**
   - HTTP redirect URI detection
   - Man-in-the-middle risks
   - Code theft scenarios

### SAML Testing

1. **XML Signature Wrapping**
   - Signature validation bypass
   - Assertion wrapping attacks
   - Identity spoofing

2. **Assertion Replay**
   - Nonce validation testing
   - Timestamp validation
   - Replay protection bypass

3. **Recipient Validation Bypass**
   - Recipient attribute manipulation
   - Cross-service assertion reuse

4. **Attribute Injection**
   - Privilege escalation via attributes
   - Role injection (admin, superuser)
   - Custom attribute manipulation

### Account Takeover Demonstration

- Step-by-step exploitation guides
- Impact assessment
- Remediation recommendations
- Prioritized vulnerability reporting

## Usage

### OAuth Testing

```python
from app.core.request_handler import RequestHandler
from app.modules.oauth_saml import test_oauth_vulnerabilities

# Initialize request handler
request_handler = RequestHandler()

# Test OAuth flow
results, takeover_steps = await test_oauth_vulnerabilities(
    authorization_endpoint="https://oauth.example.com/authorize",
    token_endpoint="https://oauth.example.com/token",
    client_id="your_client_id",
    redirect_uri="https://app.example.com/callback",
    request_handler=request_handler,
    use_pkce=True,
)

# Review results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerability: {result.vulnerability_type.value}")
        print(f"Confidence: {result.confidence * 100}%")
        print(f"Evidence: {result.evidence}")
        print(f"Exploitation steps: {result.exploitation_steps}")

# View account takeover demonstration
for step in takeover_steps:
    print(step)
```

### SAML Testing

```python
from app.core.request_handler import RequestHandler
from app.modules.oauth_saml import test_saml_vulnerabilities

# Initialize request handler
request_handler = RequestHandler()

# SAML assertion XML (captured from legitimate flow)
assertion_xml = """<saml:Assertion ...>...</saml:Assertion>"""

# Test SAML assertion
results, takeover_steps = await test_saml_vulnerabilities(
    assertion_xml=assertion_xml,
    acs_url="https://app.example.com/saml/acs",
    request_handler=request_handler,
)

# Review results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerability: {result.vulnerability_type.value}")
        print(f"Confidence: {result.confidence * 100}%")
        print(f"Evidence: {result.evidence}")
        print(f"Exploitation steps: {result.exploitation_steps}")

# View account takeover demonstration
for step in takeover_steps:
    print(step)
```

### Advanced Usage

```python
from app.modules.oauth_saml import (
    OAuthTester,
    SAMLTester,
    OAuthConfig,
    AccountTakeoverDemo,
)

# Custom OAuth testing
config = OAuthConfig(
    authorization_endpoint="https://oauth.example.com/authorize",
    token_endpoint="https://oauth.example.com/token",
    client_id="client_id",
    client_secret="client_secret",
    redirect_uri="https://app.example.com/callback",
    scope="openid profile email",
    response_type="code",
    use_pkce=True,
)

tester = OAuthTester(request_handler)
results = await tester.test_oauth_flow(config)

# Custom SAML testing
saml_tester = SAMLTester(request_handler)
results = await saml_tester.test_saml_assertion(assertion_xml, acs_url)

# Generate custom takeover demonstration
oauth_steps = AccountTakeoverDemo.generate_oauth_takeover_steps(oauth_results)
saml_steps = AccountTakeoverDemo.generate_saml_takeover_steps(saml_results)
```

## Vulnerability Types

### OAuth Vulnerabilities

- `REDIRECT_URI_BYPASS`: redirect_uri validation can be bypassed
- `STATE_MISSING`: State parameter not required
- `STATE_NOT_VALIDATED`: State parameter not properly validated
- `TOKEN_LEAKAGE`: Tokens exposed via URL fragments or Referer
- `CODE_INTERCEPTION`: Authorization code can be intercepted
- `PKCE_BYPASS`: PKCE protection can be bypassed
- `IMPLICIT_FLOW`: Insecure implicit flow in use
- `OPEN_REDIRECT`: Open redirect vulnerability present

### SAML Vulnerabilities

- `SIGNATURE_WRAPPING`: XML signature wrapping attack possible
- `ASSERTION_REPLAY`: Assertion can be replayed
- `RECIPIENT_BYPASS`: Recipient validation can be bypassed
- `ATTRIBUTE_INJECTION`: Attributes can be injected
- `PRIVILEGE_ESCALATION`: Privilege escalation via attribute injection
- `UNSIGNED_ASSERTION`: Unsigned assertions accepted
- `WEAK_SIGNATURE`: Weak signature algorithm in use

## Security Considerations

### Testing Authorization

- Only test OAuth/SAML implementations you own or have explicit permission to test
- Obtain written authorization before testing production systems
- Be aware of rate limiting and account lockout mechanisms
- Use test accounts when possible

### Responsible Disclosure

- Report vulnerabilities through proper channels
- Allow reasonable time for remediation
- Do not exploit vulnerabilities for malicious purposes
- Follow coordinated disclosure practices

### Legal Compliance

- Ensure testing complies with local laws and regulations
- Respect terms of service and acceptable use policies
- Obtain proper authorization before testing
- Document all testing activities

## Remediation Guidance

### OAuth Security Best Practices

1. **redirect_uri Validation**
   - Use exact string matching for redirect_uri
   - Never use regex or substring matching
   - Whitelist specific redirect URIs
   - Reject any redirect_uri not in whitelist

2. **State Parameter**
   - Always require state parameter
   - Generate cryptographically random state values
   - Validate state on callback
   - Bind state to user session

3. **PKCE**
   - Enforce PKCE for all public clients
   - Use S256 code challenge method
   - Validate code_verifier on token exchange
   - Reject requests without PKCE

4. **Token Security**
   - Use authorization code flow instead of implicit flow
   - Never expose tokens in URL fragments
   - Implement proper token binding
   - Use short-lived access tokens

### SAML Security Best Practices

1. **Signature Validation**
   - Validate XML structure before signature verification
   - Use proper XML canonicalization
   - Reject assertions with multiple signatures
   - Validate signature covers entire assertion

2. **Replay Protection**
   - Implement nonce validation
   - Enforce timestamp validation (NotBefore, NotOnOrAfter)
   - Track used assertion IDs
   - Reject replayed assertions

3. **Recipient Validation**
   - Validate Recipient attribute matches ACS URL
   - Use exact string matching
   - Reject assertions with mismatched recipients

4. **Attribute Security**
   - Validate all assertion attributes
   - Sanitize attribute values
   - Use attribute whitelisting
   - Never trust attributes without validation

## References

- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [SAML Security Considerations](https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf)
- [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
- [SAML 2.0 Profile for OAuth 2.0 Client Authentication](https://tools.ietf.org/html/rfc7522)

## Requirements Validation

This module implements the following requirements:

- **Requirement 45.1**: OAuth redirect_uri bypass, state issues, token leakage testing
- **Requirement 45.2**: SAML XML signature wrapping, assertion replay testing
- **Requirement 45.3**: OAuth authorization code interception and PKCE bypass
- **Requirement 45.4**: SAML attribute injection and privilege escalation
- **Requirement 45.5**: Account takeover demonstration with step-by-step exploitation
