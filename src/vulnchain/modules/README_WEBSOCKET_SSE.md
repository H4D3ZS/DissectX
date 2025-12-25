# WebSocket and Server-Sent Events (SSE) Testing Module

## Overview

This module provides comprehensive testing capabilities for WebSocket and Server-Sent Events (SSE) endpoints, including:

- **WebSocket Testing**: Intercept, modify, and replay WebSocket messages
- **Authentication Bypass**: Test for authentication bypass vulnerabilities
- **Message Injection**: Test for XSS, SQL injection, and command injection in WebSocket messages
- **Cross-Site WebSocket Hijacking (CSWSH)**: Test for origin validation issues
- **SSE Testing**: Test for injection vulnerabilities in Server-Sent Events streams
- **Message Format Analysis**: Analyze and fuzz message parameters
- **WebSocket Client Interface**: Manual exploitation interface for interactive testing

## Requirements

This module requires the `websockets` library:

```bash
pip install websockets
```

## Components

### 1. WebSocketTester

Main class for automated WebSocket vulnerability testing.

**Features:**
- Authentication bypass detection
- Message injection testing (XSS, SQLi, Command Injection)
- Cross-Site WebSocket Hijacking (CSWSH) detection
- Message interception and modification
- Message replay capabilities

**Example Usage:**

```python
from app.modules.websocket_sse import WebSocketTester
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = WebSocketTester(request_handler)

# Test WebSocket endpoint
results = await tester.test_websocket(
    ws_url="wss://example.com/ws",
    headers={"Authorization": "Bearer token"},
    cookies={"session": "abc123"}
)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerability: {result.vulnerability_type.value}")
        print(f"Confidence: {result.confidence}")
        print(f"Evidence: {result.evidence}")
```

### 2. SSETester

Class for testing Server-Sent Events endpoints.

**Features:**
- Injection testing in SSE streams
- SSE message parsing
- XSS detection in event data

**Example Usage:**

```python
from app.modules.websocket_sse import SSETester

# Initialize
sse_tester = SSETester(request_handler)

# Test SSE endpoint
results = await sse_tester.test_sse_endpoint(
    sse_url="https://example.com/events",
    headers={"Authorization": "Bearer token"}
)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"SSE Injection detected: {result.payload}")
```

### 3. MessageAnalyzer

Analyzes message formats and generates fuzz payloads.

**Features:**
- Message format detection (JSON, XML, text, binary)
- Parameter extraction from JSON messages
- Automatic fuzz payload generation

**Example Usage:**

```python
from app.modules.websocket_sse import MessageAnalyzer

analyzer = MessageAnalyzer()

# Analyze captured messages
analysis = analyzer.analyze_message_format(captured_messages)
print(f"Message types: {analysis['message_types']}")
print(f"JSON fields: {analysis['json_fields']}")

# Generate fuzz payloads
base_message = '{"action": "test", "data": "hello"}'
payloads = analyzer.generate_fuzz_payloads(base_message, MessageType.JSON)
```

### 4. WebSocketClient

Interactive WebSocket client for manual exploitation.

**Features:**
- Connect to WebSocket endpoints
- Send and receive messages
- Message history tracking
- Manual message crafting

**Example Usage:**

```python
from app.modules.websocket_sse import WebSocketClient

# Initialize client
client = WebSocketClient()

# Connect
connected = await client.connect(
    ws_url="wss://example.com/ws",
    headers={"Authorization": "Bearer token"}
)

if connected:
    # Send message
    await client.send_message('{"action": "test"}')
    
    # Receive response
    response = await client.receive_message(timeout=5.0)
    print(f"Response: {response}")
    
    # Get message history
    history = client.get_message_history()
    
    # Close connection
    await client.close()
```

## Vulnerability Types

The module detects the following vulnerability types:

### 1. Authentication Bypass (AUTH_BYPASS)
- WebSocket connections accepted without proper authentication
- Missing or weak authentication checks

### 2. Message Injection (MESSAGE_INJECTION)
- XSS in WebSocket messages
- SQL injection in WebSocket messages
- Command injection in WebSocket messages

### 3. Cross-Site WebSocket Hijacking (CSWSH)
- Missing or weak Origin header validation
- Allows connections from malicious origins

### 4. SSE Injection (SSE_INJECTION)
- Injection vulnerabilities in Server-Sent Events streams
- Reflected XSS in event data

## Data Models

### WebSocketMessage

Represents a WebSocket message:

```python
@dataclass
class WebSocketMessage:
    message_id: str
    direction: str  # "sent" or "received"
    message_type: MessageType
    content: Any
    timestamp: float
    metadata: Dict
```

### SSEMessage

Represents a Server-Sent Event:

```python
@dataclass
class SSEMessage:
    event_type: Optional[str]
    data: str
    event_id: Optional[str]
    retry: Optional[int]
    timestamp: float
    metadata: Dict
```

### WebSocketTestResult

Result of WebSocket testing:

```python
@dataclass
class WebSocketTestResult:
    url: str
    is_vulnerable: bool
    vulnerability_type: Optional[VulnerabilityType]
    confidence: float
    evidence: List[str]
    messages: List[WebSocketMessage]
    payload: Optional[str]
    metadata: Dict
```

## Testing Techniques

### 1. Authentication Bypass Testing

Tests if WebSocket connections can be established without proper authentication:

- Connects without authentication headers/cookies
- Sends test messages
- Checks if server responds to unauthenticated requests

### 2. Message Injection Testing

Tests for injection vulnerabilities in WebSocket messages:

- **XSS Testing**: Injects XSS payloads and checks if reflected
- **SQL Injection**: Injects SQL payloads and checks for error messages
- **Command Injection**: Injects command payloads and checks for execution indicators

### 3. CSWSH Testing

Tests for Cross-Site WebSocket Hijacking:

- Connects with malicious Origin header
- Checks if connection is accepted
- Verifies if server validates Origin header

### 4. SSE Injection Testing

Tests for injection in Server-Sent Events:

- Injects payloads via query parameters
- Checks if payloads are reflected in event stream
- Parses SSE events to verify injection

## Integration with VulnChain

This module integrates with the VulnChain framework:

1. **Request Handler**: Uses the core request handler for HTTP requests
2. **Logging**: All findings are logged through the logging system
3. **Workspace**: Results are saved to the active workspace
4. **UI**: Results are displayed in the web UI

## Security Considerations

**Important**: This module is designed for:
- Authorized security testing
- CTF competitions
- Educational purposes
- Bug bounty programs with proper authorization

**Never use this module against systems you don't own or have explicit permission to test.**

## Limitations

1. **WebSocket Library Required**: The `websockets` library must be installed
2. **Timeout Constraints**: Tests use timeouts to avoid hanging
3. **Limited Payload Coverage**: Uses a subset of payloads for efficiency
4. **Binary Message Support**: Limited support for binary WebSocket messages

## Future Enhancements

Potential improvements for future versions:

1. Support for WebSocket compression
2. Support for WebSocket subprotocols
3. More comprehensive payload libraries
4. Binary message fuzzing
5. WebSocket proxy support
6. Message replay with timing control
7. Automated exploit generation
8. Integration with browser automation for client-side testing

## References

- **WebSocket Protocol**: RFC 6455
- **Server-Sent Events**: W3C Specification
- **CSWSH**: Cross-Site WebSocket Hijacking research
- **OWASP WebSocket Security**: Testing guidelines
