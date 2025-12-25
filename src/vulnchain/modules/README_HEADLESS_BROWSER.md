# Headless Browser Module

## Overview

The Headless Browser module provides browser automation capabilities for testing JavaScript-heavy applications and client-side vulnerabilities. It integrates Playwright for rendering dynamic content, executing JavaScript, intercepting API calls, and extracting client-side storage.

## Features

### 1. Browser Automation
- Render JavaScript-heavy applications
- Execute JavaScript in controlled environment
- Capture screenshots and console logs
- Monitor network requests

### 2. SPA Testing
- Intercept and modify API calls
- Test Single Page Applications
- Capture request/response data
- Modify requests on-the-fly

### 3. Clickjacking Testing
- Verify frame-busting bypass
- Check X-Frame-Options and CSP headers
- Generate visual proof-of-concept
- Test iframe loading

### 4. Client-Side Storage Extraction
- Extract localStorage data
- Extract sessionStorage data
- Extract IndexedDB data
- Extract cookies with metadata

## Installation

Install Playwright:

```bash
pip install playwright
playwright install
```

## Usage Examples

### Basic Page Rendering

```python
from app.modules.headless_browser import HeadlessBrowser
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

# Initialize
request_handler = RequestHandler()
browser = HeadlessBrowser(request_handler)

# Configure target
target = TargetConfig(url="https://example.com")

# Render page
result = await browser.render_page(
    target=target,
    wait_time=2.0,
    capture_screenshot=True,
    capture_network=True
)

if result.success:
    print(f"Rendered HTML length: {len(result.rendered_html)}")
    print(f"Console logs: {result.console_logs}")
    print(f"Network requests: {len(result.network_requests)}")
    print(f"Storage items: {len(result.storage_data)}")

# Cleanup
await browser.close()
```

### Execute JavaScript

```python
# Execute custom JavaScript
javascript_code = """
() => {
    // Check for sensitive data
    const sensitiveData = {
        cookies: document.cookie,
        localStorage: Object.keys(localStorage),
        sessionStorage: Object.keys(sessionStorage)
    };
    return sensitiveData;
}
"""

result = await browser.execute_javascript(
    target=target,
    javascript_code=javascript_code,
    wait_time=1.0
)

if result.success:
    print(f"JavaScript result: {result.metadata['javascript_result']}")
```

### Test SPA with API Interception

```python
# Define request modifier
def modify_api_request(api_call):
    # Modify headers
    api_call.headers['X-Custom-Header'] = 'injected'
    
    # Modify request body
    if api_call.request_body:
        # Parse and modify JSON
        import json
        try:
            data = json.loads(api_call.request_body)
            data['injected'] = True
            api_call.request_body = json.dumps(data)
        except:
            pass
    
    return api_call

# Test SPA
result = await browser.test_spa_with_interception(
    target=target,
    interaction_script="document.querySelector('#login-button').click();",
    modify_requests=modify_api_request
)

if result.success:
    print(f"Intercepted {len(result.api_calls)} API calls")
    for api_call in result.api_calls:
        print(f"  {api_call.method} {api_call.url}")
        print(f"    Status: {api_call.response_status}")
```

### Test for Clickjacking

```python
# Test clickjacking vulnerability
result = await browser.test_clickjacking(
    target=target,
    generate_poc=True
)

print(f"Vulnerable to clickjacking: {result.is_vulnerable}")
print(f"X-Frame-Options: {result.x_frame_options}")
print(f"CSP frame-ancestors: {result.csp_frame_ancestors}")
print(f"Frame-busting present: {result.frame_busting_present}")
print(f"Frame-busting bypassed: {result.frame_busting_bypassed}")

if result.is_vulnerable and result.poc_html:
    # Save PoC
    with open('clickjacking_poc.html', 'w') as f:
        f.write(result.poc_html)
    print("PoC saved to clickjacking_poc.html")

for evidence in result.evidence:
    print(f"  - {evidence}")
```

### Extract Client-Side Storage

```python
from app.modules.headless_browser import StorageType

# Extract all storage types
storage_data = await browser.extract_client_storage(
    target=target,
    storage_types=[
        StorageType.LOCAL_STORAGE,
        StorageType.SESSION_STORAGE,
        StorageType.INDEXED_DB,
        StorageType.COOKIES
    ]
)

print(f"Extracted {len(storage_data)} storage items")

for item in storage_data:
    print(f"\n{item.storage_type.value}:")
    print(f"  Key: {item.key}")
    print(f"  Value: {item.value}")
    print(f"  Domain: {item.domain}")
    
    if item.metadata:
        print(f"  Metadata: {item.metadata}")
```

### Complete Workflow

```python
async def test_javascript_app(target_url: str):
    """Complete workflow for testing JavaScript-heavy application"""
    
    request_handler = RequestHandler()
    browser = HeadlessBrowser(request_handler)
    
    target = TargetConfig(url=target_url)
    
    try:
        # 1. Render page and capture initial state
        print("[*] Rendering page...")
        render_result = await browser.render_page(
            target=target,
            capture_screenshot=True,
            capture_network=True
        )
        
        if not render_result.success:
            print(f"[!] Failed to render page: {render_result.error}")
            return
        
        print(f"[+] Page rendered successfully")
        print(f"    Console logs: {len(render_result.console_logs)}")
        print(f"    Network requests: {len(render_result.network_requests)}")
        
        # 2. Extract client-side storage
        print("\n[*] Extracting client-side storage...")
        storage_data = await browser.extract_client_storage(target)
        
        print(f"[+] Extracted {len(storage_data)} storage items")
        for item in storage_data:
            print(f"    {item.storage_type.value}: {item.key}")
        
        # 3. Test for clickjacking
        print("\n[*] Testing for clickjacking...")
        clickjacking_result = await browser.test_clickjacking(
            target=target,
            generate_poc=True
        )
        
        if clickjacking_result.is_vulnerable:
            print("[!] VULNERABLE to clickjacking!")
            for evidence in clickjacking_result.evidence:
                print(f"    - {evidence}")
        else:
            print("[+] Not vulnerable to clickjacking")
        
        # 4. Test SPA with API interception
        print("\n[*] Testing SPA with API interception...")
        spa_result = await browser.test_spa_with_interception(target)
        
        if spa_result.success:
            print(f"[+] Intercepted {len(spa_result.api_calls)} API calls")
            for api_call in spa_result.api_calls:
                print(f"    {api_call.method} {api_call.url}")
        
        print("\n[+] Testing complete!")
    
    finally:
        await browser.close()

# Run the test
import asyncio
asyncio.run(test_javascript_app("https://example.com"))
```

## Data Structures

### BrowserResult

Contains results from browser operations:
- `url`: Target URL
- `success`: Whether operation succeeded
- `rendered_html`: Rendered HTML after JavaScript execution
- `screenshot`: Screenshot bytes (if captured)
- `console_logs`: List of console log messages
- `network_requests`: List of network requests
- `storage_data`: List of extracted storage data
- `api_calls`: List of intercepted API calls
- `error`: Error message (if failed)
- `metadata`: Additional metadata

### StorageData

Represents client-side storage data:
- `storage_type`: Type of storage (localStorage, sessionStorage, indexedDB, cookies)
- `key`: Storage key
- `value`: Storage value
- `domain`: Domain the storage belongs to
- `metadata`: Additional metadata (e.g., cookie attributes)

### APICall

Represents an intercepted API call:
- `url`: API endpoint URL
- `method`: HTTP method
- `headers`: Request headers
- `request_body`: Request body (if any)
- `response_status`: Response status code
- `response_headers`: Response headers
- `response_body`: Response body
- `timestamp`: Timestamp of the call

### ClickjackingResult

Contains clickjacking test results:
- `is_vulnerable`: Whether site is vulnerable
- `frame_busting_present`: Whether frame-busting code is present
- `frame_busting_bypassed`: Whether frame-busting was bypassed
- `x_frame_options`: X-Frame-Options header value
- `csp_frame_ancestors`: CSP frame-ancestors directive
- `poc_html`: Proof-of-concept HTML
- `evidence`: List of evidence strings

## Requirements Validation

This module validates the following requirements:

- **Requirement 47.1**: Headless browser automation for JavaScript-heavy applications
- **Requirement 47.2**: JavaScript execution in controlled environment
- **Requirement 47.3**: SPA testing with API call interception
- **Requirement 47.4**: Clickjacking testing with frame-busting bypass verification
- **Requirement 47.5**: Client-side storage extraction (localStorage, sessionStorage, IndexedDB)

## Security Considerations

1. **Sandboxing**: Browser runs in headless mode with restricted permissions
2. **Resource Limits**: Set timeouts to prevent hanging
3. **Network Isolation**: Can be configured to use proxy for isolation
4. **Screenshot Privacy**: Screenshots may contain sensitive data
5. **Storage Extraction**: Extracted data may contain credentials or tokens

## Performance Notes

- Browser initialization has overhead (~1-2 seconds)
- Reuse browser instance for multiple operations
- Close browser when done to free resources
- Screenshots increase memory usage
- Network capture adds minimal overhead

## Troubleshooting

### Playwright Not Installed

```
ImportError: Playwright not installed
```

**Solution**: Install Playwright and browser binaries:
```bash
pip install playwright
playwright install
```

### Browser Launch Failed

```
Error: Failed to launch browser
```

**Solution**: Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install -y \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2
```

### Timeout Errors

```
Error: Timeout waiting for page to load
```

**Solution**: Increase timeout or check network connectivity:
```python
result = await browser.render_page(
    target=target,
    wait_time=5.0  # Increase wait time
)
```

## Advanced Usage

### Custom Browser Configuration

```python
# Use Firefox instead of Chromium
browser._browser_type = "firefox"

# Or WebKit
browser._browser_type = "webkit"
```

### Capture Specific Network Requests

```python
# Filter network requests
result = await browser.render_page(target, capture_network=True)

api_requests = [
    req for req in result.network_requests
    if '/api/' in req['url']
]

print(f"API requests: {len(api_requests)}")
```

### Execute Complex JavaScript

```python
# Multi-step JavaScript execution
javascript_code = """
async () => {
    // Click button
    document.querySelector('#submit').click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Extract result
    return document.querySelector('#result').textContent;
}
"""

result = await browser.execute_javascript(
    target=target,
    javascript_code=javascript_code,
    wait_time=2.0
)
```

## Integration with Other Modules

### With XSS Module

```python
from app.modules.xss import XSSTester

# Test DOM-based XSS
xss_tester = XSSTester(request_handler)
browser = HeadlessBrowser(request_handler)

# Render page with XSS payload
target.url = f"https://example.com/?q=<script>alert(1)</script>"
result = await browser.render_page(target)

# Check console logs for XSS execution
for log in result.console_logs:
    if 'alert' in log.lower():
        print("[!] XSS executed!")
```

### With Reconnaissance Module

```python
from app.modules.reconnaissance import ReconnaissanceModule

# Discover JavaScript endpoints
recon = ReconnaissanceModule(request_handler)
browser = HeadlessBrowser(request_handler)

# Render page to execute JavaScript
result = await browser.render_page(target)

# Extract API endpoints from network requests
api_endpoints = [
    req['url'] for req in result.network_requests
    if req['resource_type'] == 'fetch' or req['resource_type'] == 'xhr'
]

print(f"Discovered {len(api_endpoints)} API endpoints")
```
