# Target Configuration System

## Overview

The Target Configuration system provides a comprehensive way to configure and manage attack targets in VulnChain. It includes URL validation according to RFC 3986, configuration persistence, and integration with the WAF Bypass Profile system.

## Features

### URL Validation (RFC 3986)

- Validates URLs according to RFC 3986 standards
- Supports HTTP and HTTPS schemes only
- Validates IPv4, IPv6, and domain names
- Validates port numbers (1-65535)
- Validates URL structure (scheme, authority, path, query, fragment)

### Target Configuration

The `TargetConfig` class stores all configuration needed to interact with a target:

- **URL**: Target URL (validated)
- **Custom Headers**: Dictionary of custom HTTP headers
- **Proxy**: Optional proxy URL (also validated)
- **WAF Bypass Profile**: Name of WAF bypass profile to apply
- **Rate Limiting**: Optional rate limiting configuration
- **Session ID**: Optional session identifier
- **Metadata**: Name and description for organization

### Persistence

Target configurations can be saved to and loaded from JSON files:

```python
# Save configuration
target = TargetConfig(url="https://example.com")
target.save(Path("target.json"))

# Load configuration
loaded = TargetConfig.load(Path("target.json"))
```

### Session Management

The `Session` class manages authenticated session state:

- Session ID and domain
- Cookies and headers
- Creation and expiration timestamps
- Expiration checking

## Usage Examples

### Basic Target Configuration

```python
from app.models.target import TargetConfig

# Create a simple target
target = TargetConfig(
    url="https://example.com",
    name="Example Target",
    description="A test target"
)
```

### Target with Custom Headers

```python
target = TargetConfig(
    url="https://api.example.com",
    custom_headers={
        "Authorization": "Bearer token123",
        "X-API-Key": "my-api-key",
    }
)
```

### Target with Proxy

```python
target = TargetConfig(
    url="https://example.com",
    proxy="http://proxy.example.com:8080"
)
```

### Target with WAF Bypass Profile

```python
target = TargetConfig(
    url="https://protected.example.com",
    waf_bypass_profile="cloudflare"
)
```

### Target with Rate Limiting

```python
from app.models.target import RateLimit

rate_limit = RateLimit(
    requests_per_second=5.0,
    burst_size=10
)

target = TargetConfig(
    url="https://api.example.com",
    rate_limit=rate_limit
)
```

### URL Validation

```python
from app.models.target import validate_url, URLValidationError

try:
    validate_url("https://example.com")
    print("Valid URL")
except URLValidationError as e:
    print(f"Invalid URL: {e}")
```

### Updating Configuration

```python
target = TargetConfig(url="https://example.com")

# Update fields
target.update(
    custom_headers={"X-New": "header"},
    waf_bypass_profile="akamai"
)

# Updated timestamp is automatically set
print(target.updated_at)
```

### Session Management

```python
from app.models.target import Session
from datetime import datetime, timedelta, timezone

# Create session
session = Session(
    session_id="sess123",
    domain="example.com",
    cookies={"session": "abc123"},
    expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
)

# Check expiration
if session.is_expired():
    print("Session expired")
else:
    print("Session valid")
```

## API Reference

### TargetConfig

**Constructor Parameters:**
- `url` (str): Target URL (required)
- `custom_headers` (Dict[str, str]): Custom HTTP headers
- `proxy` (Optional[str]): Proxy URL
- `waf_bypass_profile` (Optional[str]): WAF bypass profile name
- `rate_limit` (Optional[RateLimit]): Rate limiting configuration
- `session_id` (Optional[str]): Session identifier
- `name` (Optional[str]): Target name
- `description` (Optional[str]): Target description

**Methods:**
- `to_dict()`: Convert to dictionary
- `from_dict(data)`: Create from dictionary (class method)
- `save(filepath)`: Save to JSON file
- `load(filepath)`: Load from JSON file (class method)
- `update(**kwargs)`: Update configuration fields

### Session

**Constructor Parameters:**
- `session_id` (str): Session identifier (required)
- `domain` (str): Domain for session (required)
- `cookies` (Dict[str, str]): Session cookies
- `headers` (Dict[str, str]): Session headers
- `expires_at` (Optional[datetime]): Expiration timestamp

**Methods:**
- `to_dict()`: Convert to dictionary
- `from_dict(data)`: Create from dictionary (class method)
- `is_expired()`: Check if session is expired

### RateLimit

**Constructor Parameters:**
- `requests_per_second` (float): Maximum requests per second (default: 10.0)
- `burst_size` (int): Maximum burst size (default: 20)

### Functions

**validate_url(url: str) -> bool**

Validates a URL according to RFC 3986.

- Raises `URLValidationError` if invalid
- Returns `True` if valid

## Integration with Request Handler

The Target Configuration system integrates seamlessly with the Request Handler:

```python
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

# Create target with WAF profile
target = TargetConfig(
    url="https://example.com",
    waf_bypass_profile="cloudflare",
    custom_headers={"User-Agent": "VulnChain/1.0"}
)

# Create request handler
handler = RequestHandler()

# Apply WAF profile
handler.apply_waf_bypass_profile(target.waf_bypass_profile)

# Make request with custom headers
response = await handler.send_request(
    method="GET",
    url=target.url,
    headers=target.custom_headers,
    proxy=target.proxy
)
```

## Testing

Comprehensive tests are available in `tests/test_target_config.py`:

- URL validation tests (valid and invalid URLs)
- Target configuration creation and manipulation
- Serialization and deserialization
- File persistence
- Session management
- Rate limiting

Run tests:
```bash
pytest tests/test_target_config.py -v
```

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 1.1**: URL validation according to RFC 3986
- **Requirement 1.2**: Custom HTTP headers support
- **Requirement 1.3**: Proxy configuration support
- **Requirement 1.4**: WAF Bypass Profile integration
- **Requirement 1.5**: Configuration persistence

## See Also

- [WAF Bypass Profiles](../core/README_WAF_PROFILES.md)
- [Request Handler](../core/request_handler.py)
- [Session Manager](../core/session_manager.py)
