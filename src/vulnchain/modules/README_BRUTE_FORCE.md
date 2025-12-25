# Brute-Force Login Module

## Overview

The brute-force login module provides automated credential testing capabilities for login forms. It implements intelligent timing delays, multiple success detection methods, username enumeration, and automatic session capture.

## Features

### 1. Credential Testing
- Test username-password combinations from wordlists
- Support for both GET and POST login methods
- Concurrent request handling with configurable limits
- Rate limiting to avoid detection

### 2. Intelligent Timing
- Adaptive delay adjustment based on response patterns
- Configurable delay between attempts
- Automatic slowdown on detection of rate limiting
- Maximum delay cap to prevent excessive waiting

### 3. Success Detection Methods
- **Regex matching**: Match success/failure patterns in response
- **Content length**: Compare response sizes
- **Status code**: Check for specific HTTP status codes
- **Redirect detection**: Detect successful login redirects
- **Cookie presence**: Check if authentication cookies are set

### 4. Username Enumeration
- Identify valid usernames from response differences
- Compare response profiles (timing, length, status, cookies)
- Confidence scoring for enumeration results
- Baseline comparison with known invalid username

### 5. Session Capture
- Automatically capture authenticated sessions on successful login
- Extract and store cookies for subsequent requests
- Integration with Session Manager

## Usage

### Basic Brute-Force Attack

```python
from app.core.request_handler import RequestHandler
from app.core.session_manager import SessionManager
from app.modules.brute_force import BruteForceAttack, LoginConfig, LoginMethod, SuccessDetectionMethod

# Initialize components
request_handler = RequestHandler()
session_manager = SessionManager()
attack = BruteForceAttack(request_handler, session_manager)

# Configure login
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
    success_detection=SuccessDetectionMethod.REGEX,
    success_regex=r"Welcome|Dashboard|Logout",
    failure_regex=r"Invalid|Incorrect|Failed",
    delay_between_attempts=0.5,
    adaptive_delay=True,
    max_concurrent=5,
)

# Prepare credentials
usernames = ["admin", "user", "test"]
passwords = ["password", "123456", "admin"]

# Execute attack
results = await attack.attack(config, usernames, passwords, enumerate_first=True)

# Check results
print(f"Successful logins: {results['successful_attempts']}")
for login in results['successful_logins']:
    print(f"  {login['username']}:{login['password']}")
    print(f"  Session: {login['session_id']}")
```

### Username Enumeration Only

```python
from app.modules.brute_force import BruteForceTester, LoginConfig

tester = BruteForceTester(request_handler, session_manager)

config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
)

usernames = ["admin", "user", "test", "guest"]
results = await tester.enumerate_usernames(config, usernames)

for result in results:
    if result.exists:
        print(f"[+] Valid username: {result.username} (confidence: {result.confidence:.2%})")
```

### Custom Success Detection

```python
# Using status code detection
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="user",
    password_param="pass",
    success_detection=SuccessDetectionMethod.STATUS_CODE,
    success_status_codes=[200, 302],
)

# Using redirect detection
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="email",
    password_param="password",
    success_detection=SuccessDetectionMethod.REDIRECT,
)

# Using cookie detection
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
    success_detection=SuccessDetectionMethod.COOKIE,
)
```

### Rate Limiting

```python
# Limit to 2 requests per second
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
    requests_per_second=2.0,
    max_concurrent=1,  # Sequential requests
)

# Or use fixed delay
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
    delay_between_attempts=1.0,
    adaptive_delay=False,
)
```

### Additional Form Data

```python
# Include CSRF tokens or other form fields
config = LoginConfig(
    url="https://example.com/login",
    method=LoginMethod.POST,
    username_param="username",
    password_param="password",
    additional_data={
        "csrf_token": "abc123",
        "remember_me": "1",
        "redirect": "/dashboard",
    },
)
```

## Configuration Options

### LoginConfig

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | str | Required | Login form URL |
| `method` | LoginMethod | POST | HTTP method (GET or POST) |
| `username_param` | str | "username" | Username parameter name |
| `password_param` | str | "password" | Password parameter name |
| `headers` | Dict | {} | Custom HTTP headers |
| `additional_data` | Dict | {} | Additional form fields |
| `success_detection` | SuccessDetectionMethod | REGEX | Method for detecting success |
| `success_regex` | str | None | Regex pattern for successful login |
| `failure_regex` | str | None | Regex pattern for failed login |
| `success_status_codes` | List[int] | [200, 302] | Status codes indicating success |
| `delay_between_attempts` | float | 0.5 | Delay between attempts (seconds) |
| `adaptive_delay` | bool | True | Enable adaptive timing |
| `max_delay` | float | 5.0 | Maximum delay (seconds) |
| `max_concurrent` | int | 5 | Maximum concurrent requests |
| `requests_per_second` | float | None | Rate limit (requests/second) |

## Success Detection Methods

### 1. Regex (Recommended)
Best for most scenarios. Define patterns that appear on successful/failed login.

```python
success_regex=r"Welcome|Dashboard|Logout"
failure_regex=r"Invalid|Incorrect|Failed"
```

### 2. Status Code
Useful when successful login returns specific status code.

```python
success_detection=SuccessDetectionMethod.STATUS_CODE
success_status_codes=[200, 302]
```

### 3. Redirect
Detects if login causes a redirect (common pattern).

```python
success_detection=SuccessDetectionMethod.REDIRECT
```

### 4. Cookie
Checks if authentication cookies are set.

```python
success_detection=SuccessDetectionMethod.COOKIE
```

## Username Enumeration

The module can identify valid usernames by analyzing response differences:

- **Response time**: Valid usernames may take longer to process
- **Content length**: Different error messages for valid/invalid users
- **Status codes**: Different codes for valid/invalid users
- **Redirects**: Different redirect behavior
- **Cookies**: Different cookie-setting behavior
- **Content hash**: Different response content

Confidence scoring helps identify the most likely valid usernames.

## Adaptive Timing

The module implements intelligent timing to avoid detection:

1. **Response time monitoring**: Tracks average response times
2. **Slowdown detection**: Increases delay if responses slow down
3. **Failure tracking**: Increases delay after consecutive failures
4. **Maximum cap**: Prevents excessive delays

## Best Practices

1. **Start with username enumeration** to reduce total attempts
2. **Use regex detection** for most reliable success detection
3. **Enable adaptive delay** to avoid account lockout
4. **Set appropriate rate limits** based on target
5. **Test with known credentials** first to verify configuration
6. **Monitor for CAPTCHA** or other anti-automation measures

## CTF-Specific Tips

1. **Common CTF usernames**: admin, user, guest, ctf, flag
2. **Common CTF passwords**: password, admin, 123456, ctf, flag
3. **Check for default credentials**: admin:admin, user:user
4. **Look for hints** in page source or comments
5. **Try username as password**: admin:admin, user:user

## Integration with Other Modules

### Session Manager
Automatically captures authenticated sessions for use in other attacks.

```python
# After successful login
session = results['successful_logins'][0]['session_id']
session_obj = session_manager.get_session(session)

# Use session in other requests
response = await request_handler.send_request(
    method="GET",
    url="https://example.com/admin",
    cookies=session_obj.get_cookies_for_request("https://example.com/admin"),
)
```

### Payload Engine
Load credentials from wordlists.

```python
from app.core.payload_engine import PayloadEngine

payload_engine = PayloadEngine()
payload_engine.load_wordlist("wordlists/usernames.txt", "usernames")
payload_engine.load_wordlist("wordlists/passwords.txt", "passwords")

usernames = [p.encoded for p in payload_engine.get_payloads("usernames")]
passwords = [p.encoded for p in payload_engine.get_payloads("passwords")]
```

## Requirements Validation

This module implements the following requirements:

- **Requirement 4.1**: Test username-password combinations from wordlists
- **Requirement 4.2**: Implement intelligent timing delays to avoid account lockout
- **Requirement 4.3**: Determine success via regex or content length comparison
- **Requirement 4.4**: Identify valid usernames from response differences
- **Requirement 4.5**: Capture authenticated session automatically

## Error Handling

The module handles various error conditions:

- Network timeouts
- Connection errors
- Invalid URLs
- Missing parameters
- Rate limiting responses
- CAPTCHA challenges (detection only)

## Performance

- Concurrent request handling for speed
- Adaptive timing to avoid detection
- Efficient response comparison
- Memory-efficient result storage

## Security Considerations

This module is designed for:
- Authorized penetration testing
- CTF competitions
- Security research
- Educational purposes

**Never use against systems without explicit authorization.**
