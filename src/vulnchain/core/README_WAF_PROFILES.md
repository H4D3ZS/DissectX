# WAF Bypass Profile System

## Overview

The WAF Bypass Profile system provides pre-configured header sets designed to evade common Web Application Firewalls (WAFs). It includes profiles for major WAF vendors and allows custom profile creation.

## Features

### Built-in Profiles

The system includes 10 pre-configured profiles:

1. **Cloudflare** - Bypass profile for Cloudflare WAF
2. **Akamai** - Bypass profile for Akamai WAF
3. **AWS WAF** - Bypass profile for AWS WAF
4. **ModSecurity** - Bypass profile for ModSecurity WAF
5. **Imperva** - Bypass profile for Imperva (Incapsula) WAF
6. **F5 BIG-IP** - Bypass profile for F5 BIG-IP ASM
7. **FortiWeb** - Bypass profile for FortiWeb WAF
8. **Barracuda** - Bypass profile for Barracuda WAF
9. **Generic** - Generic bypass profile for unknown WAFs
10. **Aggressive** - Aggressive bypass with multiple header variations

### Profile Properties

Each profile includes:

- **Name**: Unique identifier
- **Description**: Human-readable description
- **Vendor**: WAF vendor name
- **Effectiveness**: Estimated effectiveness (high, medium, low)
- **Headers**: Dictionary of bypass headers

### Custom Profiles

Users can create and register custom WAF bypass profiles for specific targets.

## Usage Examples

### List Available Profiles

```python
from app.core.waf_profiles import list_waf_profiles

profiles = list_waf_profiles()
print(f"Available profiles: {profiles}")
```

### Get Profile Information

```python
from app.core.waf_profiles import get_waf_profile

profile = get_waf_profile("cloudflare")
print(f"Name: {profile.name}")
print(f"Vendor: {profile.vendor}")
print(f"Headers: {profile.headers}")
```

### Apply Profile to Headers

```python
from app.core.waf_profiles import apply_waf_profile

# Original headers
headers = {
    "User-Agent": "VulnChain/1.0",
    "Accept": "application/json"
}

# Apply Cloudflare bypass profile
updated_headers = apply_waf_profile("cloudflare", headers)

# Updated headers now include bypass headers
print(updated_headers)
```

### Use with Request Handler

```python
from app.core.request_handler import RequestHandler

handler = RequestHandler()

# Apply WAF bypass profile
handler.apply_waf_bypass_profile("cloudflare")

# All subsequent requests will include bypass headers
response = await handler.send_request(
    method="GET",
    url="https://protected.example.com"
)
```

### Create Custom Profile

```python
from app.core.waf_profiles import WAFBypassProfile, WAFProfileManager

# Create custom profile
custom_profile = WAFBypassProfile(
    name="my_custom_waf",
    description="Custom WAF bypass for specific target",
    vendor="CustomVendor",
    effectiveness="high",
    headers={
        "X-Custom-Header": "bypass-value",
        "X-Forwarded-For": "10.0.0.1",
        "X-Real-IP": "10.0.0.1",
    }
)

# Register profile
manager = WAFProfileManager()
manager.add_custom_profile(custom_profile)

# Use custom profile
headers = apply_waf_profile("my_custom_waf", {})
```

### Get Profile Details

```python
from app.core.waf_profiles import WAFProfileManager

manager = WAFProfileManager()
info = manager.get_profile_info("cloudflare")

print(f"Name: {info['name']}")
print(f"Vendor: {info['vendor']}")
print(f"Effectiveness: {info['effectiveness']}")
print(f"Header count: {info['header_count']}")
```

## Profile Details

### Cloudflare Profile

Headers:
- `CF-Connecting-IP: 127.0.0.1`
- `X-Forwarded-For: 127.0.0.1`
- `X-Forwarded-Host: 127.0.0.1`
- `X-Original-URL: /`
- `X-Rewrite-URL: /`

### Akamai Profile

Headers:
- `X-Forwarded-For: 127.0.0.1`
- `True-Client-IP: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `X-Original-URL: /`

### AWS WAF Profile

Headers:
- `X-Forwarded-For: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Remote-IP: 127.0.0.1`

### Generic Profile

Headers (10 total):
- `X-Forwarded-For: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Remote-IP: 127.0.0.1`
- `X-Client-IP: 127.0.0.1`
- `X-Remote-Addr: 127.0.0.1`
- `X-Original-URL: /`
- `X-Rewrite-URL: /`
- `True-Client-IP: 127.0.0.1`
- `Client-IP: 127.0.0.1`

### Aggressive Profile

Headers (20 total):
- All IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
- URL rewriting headers (X-Original-URL, X-Rewrite-URL, etc.)
- Host manipulation headers (X-Forwarded-Host, X-Host)
- Protocol manipulation headers (X-Forwarded-Proto, etc.)
- Additional bypass headers

## API Reference

### WAFBypassProfile

**Constructor Parameters:**
- `name` (str): Profile name (required)
- `description` (str): Profile description (required)
- `headers` (Dict[str, str]): Bypass headers
- `vendor` (Optional[str]): WAF vendor name
- `effectiveness` (Optional[str]): Effectiveness rating

**Methods:**
- `apply_to_headers(existing_headers)`: Apply bypass headers to existing headers

### WAFProfileManager

**Methods:**
- `get_profile(name)`: Get profile by name
- `list_profiles()`: List all profile names
- `list_builtin_profiles()`: List built-in profile names
- `list_custom_profiles()`: List custom profile names
- `add_custom_profile(profile)`: Add custom profile
- `remove_custom_profile(name)`: Remove custom profile
- `get_profile_info(name)`: Get profile information
- `apply_profile_to_headers(profile_name, existing_headers)`: Apply profile to headers

### Convenience Functions

**get_waf_profile(name: str) -> Optional[WAFBypassProfile]**

Get a WAF bypass profile by name.

**list_waf_profiles() -> List[str]**

List all available WAF bypass profiles.

**apply_waf_profile(profile_name: str, headers: Dict[str, str]) -> Dict[str, str]**

Apply a WAF bypass profile to headers.

## How WAF Bypass Works

WAF bypass profiles work by manipulating HTTP headers that WAFs use for:

1. **IP Detection**: Headers like `X-Forwarded-For`, `X-Real-IP` can be used to spoof the client IP address
2. **URL Rewriting**: Headers like `X-Original-URL`, `X-Rewrite-URL` can bypass path-based rules
3. **Host Manipulation**: Headers like `X-Forwarded-Host` can bypass host-based rules
4. **Protocol Manipulation**: Headers like `X-Forwarded-Proto` can bypass protocol-based rules

### Common Bypass Techniques

1. **IP Spoofing**: Set IP headers to trusted addresses (127.0.0.1, 10.0.0.1)
2. **Header Injection**: Add multiple IP-related headers to confuse WAF
3. **URL Rewriting**: Use alternative URL headers to bypass path filters
4. **Header Stacking**: Include multiple variations of the same header

## Integration with Target Configuration

WAF profiles integrate seamlessly with Target Configuration:

```python
from app.models.target import TargetConfig

# Create target with WAF profile
target = TargetConfig(
    url="https://protected.example.com",
    waf_bypass_profile="cloudflare"
)

# Profile will be automatically applied to all requests
```

## Testing

Comprehensive tests are available in `tests/test_waf_profiles.py`:

- Profile creation and management
- Header application
- Custom profile support
- Profile information retrieval
- Integration tests

Run tests:
```bash
pytest tests/test_waf_profiles.py -v
```

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 1.4**: WAF Bypass Profile system with pre-configured header sets
- **Requirement 21.1**: WAF detection capability (profiles support detection)
- **Requirement 21.2**: WAF vendor identification (profiles include vendor info)
- **Requirement 21.3**: Bypass technique application (profiles apply evasion methods)
- **Requirement 21.5**: Bypass pattern persistence (profiles can be saved and reused)

## Security Considerations

**Important**: This system is designed for:
- Authorized security testing
- CTF competitions
- Bug bounty programs
- Educational purposes

**Never use** WAF bypass techniques against systems without explicit authorization.

## See Also

- [Target Configuration](../models/README_TARGET_CONFIG.md)
- [Request Handler](request_handler.py)
- [Example Usage](../../examples/target_config_demo.py)
