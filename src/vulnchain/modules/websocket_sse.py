"""WebSocket and Server-Sent Events (SSE) module for automated testing

This module implements:
- WebSocket connection interception, modification, and replay
- Authentication bypass testing for WebSocket
- Message injection testing
- Server-Sent Events (SSE) testing
- Message format analysis and fuzzing
- WebSocket client interface for manual exploitation
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse, parse_qs

try:
    import websockets
    from websockets.client import WebSocketClientProtocol
    from websockets.exceptions import WebSocketException
except ImportError:
    websockets = None
    WebSocketClientProtocol = None
    WebSocketException = Exception

from src.vulnchain.core.request_handler import RequestHandler, Response


class MessageType(Enum):
    """Types of WebSocket/SSE messages"""
    
    TEXT = "text"
    BINARY = "binary"
    JSON = "json"
    XML = "xml"
    UNKNOWN = "unknown"


class VulnerabilityType(Enum):
    """Types of WebSocket/SSE vulnerabilities"""
    
    AUTH_BYPASS = "auth_bypass"
    MESSAGE_INJECTION = "message_injection"
    XSS = "xss"
    SQLI = "sqli"
    COMMAND_INJECTION = "command_injection"
    CSWSH = "cswsh"  # Cross-Site WebSocket Hijacking
    SSE_INJECTION = "sse_injection"


@dataclass
class WebSocketMessage:
    """Represents a WebSocket message"""
    
    message_id: str
    direction: str  # sent, received
    message_type: MessageType
    content: Any
    timestamp: float
    metadata: Dict = field(default_factory=dict)


@dataclass
class SSEMessage:
    """Represents a Server-Sent Event message"""
    
    event_type: Optional[str]
    data: str
    event_id: Optional[str]
    retry: Optional[int]
    timestamp: float
    metadata: Dict = field(default_factory=dict)


@dataclass
class WebSocketTestResult:
    """Result of WebSocket testing"""
    
    url: str
    is_vulnerable: bool
    vulnerability_type: Optional[VulnerabilityType] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    messages: List[WebSocketMessage] = field(default_factory=list)
    payload: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class SSETestResult:
    """Result of SSE testing"""
    
    url: str
    is_vulnerable: bool
    vulnerability_type: Optional[VulnerabilityType] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    events: List[SSEMessage] = field(default_factory=list)
    payload: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class WebSocketTester:
    """WebSocket testing with interception, modification, and replay"""
    
    # XSS payloads for WebSocket
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ]
    
    # SQL injection payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "admin'--",
        "' UNION SELECT NULL--",
    ]
    
    # Command injection payloads
    CMD_PAYLOADS = [
        "; ls",
        "| whoami",
        "& dir",
        "`id`",
    ]

    def __init__(self, request_handler: RequestHandler):
        """Initialize WebSocket tester
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        if websockets is None:
            raise ImportError(
                "websockets library is required for WebSocket testing. "
                "Install it with: pip install websockets"
            )
        
        self.request_handler = request_handler
        self.message_history: List[WebSocketMessage] = []
        self.message_counter = 0
    
    async def test_websocket(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[WebSocketTestResult]:
        """Test WebSocket endpoint for vulnerabilities
        
        Args:
            ws_url: WebSocket URL to test
            headers: Optional headers to include
            cookies: Optional cookies to include
        
        Returns:
            List of test results
        """
        results = []
        
        # Test authentication bypass
        auth_result = await self._test_auth_bypass(ws_url, headers, cookies)
        if auth_result:
            results.append(auth_result)
        
        # Test message injection
        injection_result = await self._test_message_injection(ws_url, headers, cookies)
        if injection_result:
            results.append(injection_result)
        
        # Test Cross-Site WebSocket Hijacking
        cswsh_result = await self._test_cswsh(ws_url, headers, cookies)
        if cswsh_result:
            results.append(cswsh_result)
        
        return results
    
    async def _test_auth_bypass(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> Optional[WebSocketTestResult]:
        """Test for authentication bypass
        
        Args:
            ws_url: WebSocket URL
            headers: Headers
            cookies: Cookies
        
        Returns:
            Test result if vulnerability found
        """
        # Try connecting without authentication
        try:
            # Connect without cookies/auth headers
            async with websockets.connect(ws_url) as websocket:
                # Send a test message
                test_message = json.dumps({"action": "test", "data": "hello"})
                await websocket.send(test_message)
                
                # Wait for response
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    
                    # If we got a response, authentication might be bypassed
                    return WebSocketTestResult(
                        url=ws_url,
                        is_vulnerable=True,
                        vulnerability_type=VulnerabilityType.AUTH_BYPASS,
                        confidence=0.85,
                        evidence=[
                            "WebSocket connection established without authentication",
                            "Server responded to unauthenticated message",
                            f"Response: {response[:200]}",
                        ],
                        messages=[
                            WebSocketMessage(
                                message_id=self._get_message_id(),
                                direction="sent",
                                message_type=MessageType.JSON,
                                content=test_message,
                                timestamp=time.time(),
                            ),
                            WebSocketMessage(
                                message_id=self._get_message_id(),
                                direction="received",
                                message_type=self._detect_message_type(response),
                                content=response,
                                timestamp=time.time(),
                            ),
                        ],
                    )
                except asyncio.TimeoutError:
                    # No response - might still be vulnerable but can't confirm
                    pass
        
        except WebSocketException as e:
            # Connection failed - authentication might be enforced
            pass
        except Exception as e:
            # Other error
            pass
        
        return None

    async def _test_message_injection(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> Optional[WebSocketTestResult]:
        """Test for message injection vulnerabilities
        
        Args:
            ws_url: WebSocket URL
            headers: Headers
            cookies: Cookies
        
        Returns:
            Test result if vulnerability found
        """
        # Prepare connection headers
        extra_headers = {}
        if headers:
            extra_headers.update(headers)
        
        # Add cookies to headers if provided
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            extra_headers["Cookie"] = cookie_str
        
        try:
            async with websockets.connect(ws_url, extra_headers=extra_headers) as websocket:
                # Test XSS injection
                for xss_payload in self.XSS_PAYLOADS[:3]:  # Test first 3
                    message = json.dumps({"message": xss_payload})
                    await websocket.send(message)
                    
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                        
                        # Check if payload is reflected without sanitization
                        if xss_payload in response:
                            return WebSocketTestResult(
                                url=ws_url,
                                is_vulnerable=True,
                                vulnerability_type=VulnerabilityType.XSS,
                                confidence=0.90,
                                evidence=[
                                    "XSS payload reflected in WebSocket response",
                                    f"Payload: {xss_payload}",
                                    f"Response contains: {xss_payload}",
                                ],
                                payload=xss_payload,
                                messages=[
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="sent",
                                        message_type=MessageType.JSON,
                                        content=message,
                                        timestamp=time.time(),
                                    ),
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="received",
                                        message_type=self._detect_message_type(response),
                                        content=response,
                                        timestamp=time.time(),
                                    ),
                                ],
                            )
                    except asyncio.TimeoutError:
                        pass
                
                # Test SQL injection
                for sqli_payload in self.SQLI_PAYLOADS[:2]:  # Test first 2
                    message = json.dumps({"query": sqli_payload})
                    await websocket.send(message)
                    
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                        
                        # Check for SQL error messages
                        sql_errors = [
                            "sql syntax",
                            "mysql",
                            "postgresql",
                            "sqlite",
                            "ora-",
                            "syntax error",
                        ]
                        
                        response_lower = response.lower()
                        if any(error in response_lower for error in sql_errors):
                            return WebSocketTestResult(
                                url=ws_url,
                                is_vulnerable=True,
                                vulnerability_type=VulnerabilityType.SQLI,
                                confidence=0.85,
                                evidence=[
                                    "SQL injection detected in WebSocket message",
                                    f"Payload: {sqli_payload}",
                                    "SQL error message in response",
                                ],
                                payload=sqli_payload,
                                messages=[
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="sent",
                                        message_type=MessageType.JSON,
                                        content=message,
                                        timestamp=time.time(),
                                    ),
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="received",
                                        message_type=self._detect_message_type(response),
                                        content=response,
                                        timestamp=time.time(),
                                    ),
                                ],
                            )
                    except asyncio.TimeoutError:
                        pass
                
                # Test command injection
                for cmd_payload in self.CMD_PAYLOADS[:2]:  # Test first 2
                    message = json.dumps({"command": cmd_payload})
                    await websocket.send(message)
                    
                    try:
                        response = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                        
                        # Check for command execution indicators
                        cmd_indicators = [
                            "root:",
                            "uid=",
                            "gid=",
                            "volume",
                            "directory of",
                        ]
                        
                        response_lower = response.lower()
                        if any(indicator in response_lower for indicator in cmd_indicators):
                            return WebSocketTestResult(
                                url=ws_url,
                                is_vulnerable=True,
                                vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                                confidence=0.90,
                                evidence=[
                                    "Command injection detected in WebSocket message",
                                    f"Payload: {cmd_payload}",
                                    "Command execution output in response",
                                ],
                                payload=cmd_payload,
                                messages=[
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="sent",
                                        message_type=MessageType.JSON,
                                        content=message,
                                        timestamp=time.time(),
                                    ),
                                    WebSocketMessage(
                                        message_id=self._get_message_id(),
                                        direction="received",
                                        message_type=self._detect_message_type(response),
                                        content=response,
                                        timestamp=time.time(),
                                    ),
                                ],
                            )
                    except asyncio.TimeoutError:
                        pass
        
        except Exception as e:
            pass
        
        return None
    
    async def _test_cswsh(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> Optional[WebSocketTestResult]:
        """Test for Cross-Site WebSocket Hijacking
        
        Args:
            ws_url: WebSocket URL
            headers: Headers
            cookies: Cookies
        
        Returns:
            Test result if vulnerability found
        """
        # Test with malicious origin
        malicious_headers = {"Origin": "https://attacker.com"}
        if headers:
            malicious_headers.update(headers)
        
        # Add cookies
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            malicious_headers["Cookie"] = cookie_str
        
        try:
            async with websockets.connect(ws_url, extra_headers=malicious_headers) as websocket:
                # If connection succeeds with malicious origin, CSWSH is possible
                test_message = json.dumps({"action": "test"})
                await websocket.send(test_message)
                
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    
                    return WebSocketTestResult(
                        url=ws_url,
                        is_vulnerable=True,
                        vulnerability_type=VulnerabilityType.CSWSH,
                        confidence=0.85,
                        evidence=[
                            "Cross-Site WebSocket Hijacking detected",
                            "Connection accepted with malicious Origin header",
                            "Server does not validate Origin header",
                        ],
                        metadata={"malicious_origin": "https://attacker.com"},
                    )
                except asyncio.TimeoutError:
                    pass
        
        except WebSocketException:
            # Connection rejected - origin validation might be in place
            pass
        except Exception:
            pass
        
        return None
    
    def _detect_message_type(self, message: Any) -> MessageType:
        """Detect the type of a message
        
        Args:
            message: The message to analyze
        
        Returns:
            MessageType
        """
        if isinstance(message, bytes):
            return MessageType.BINARY
        
        if isinstance(message, str):
            # Try to parse as JSON
            try:
                json.loads(message)
                return MessageType.JSON
            except:
                pass
            
            # Check if it's XML
            if message.strip().startswith("<"):
                return MessageType.XML
            
            return MessageType.TEXT
        
        return MessageType.UNKNOWN
    
    def _get_message_id(self) -> str:
        """Generate a unique message ID
        
        Returns:
            Message ID string
        """
        self.message_counter += 1
        return f"msg_{self.message_counter}_{int(time.time() * 1000)}"
    
    async def intercept_and_modify(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        modifier: Optional[Callable[[str], str]] = None,
    ) -> List[WebSocketMessage]:
        """Intercept and modify WebSocket messages
        
        Args:
            ws_url: WebSocket URL
            headers: Optional headers
            cookies: Optional cookies
            modifier: Optional function to modify messages
        
        Returns:
            List of intercepted messages
        """
        messages = []
        
        # Prepare headers
        extra_headers = {}
        if headers:
            extra_headers.update(headers)
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            extra_headers["Cookie"] = cookie_str
        
        try:
            async with websockets.connect(ws_url, extra_headers=extra_headers) as websocket:
                # Listen for messages for a short time
                try:
                    while True:
                        message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                        
                        # Record original message
                        msg_obj = WebSocketMessage(
                            message_id=self._get_message_id(),
                            direction="received",
                            message_type=self._detect_message_type(message),
                            content=message,
                            timestamp=time.time(),
                        )
                        messages.append(msg_obj)
                        
                        # Modify and replay if modifier provided
                        if modifier:
                            modified = modifier(message)
                            await websocket.send(modified)
                            
                            modified_msg = WebSocketMessage(
                                message_id=self._get_message_id(),
                                direction="sent",
                                message_type=self._detect_message_type(modified),
                                content=modified,
                                timestamp=time.time(),
                                metadata={"modified": True},
                            )
                            messages.append(modified_msg)
                
                except asyncio.TimeoutError:
                    pass
        
        except Exception as e:
            pass
        
        return messages
    
    async def replay_message(
        self,
        ws_url: str,
        message: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Replay a captured WebSocket message
        
        Args:
            ws_url: WebSocket URL
            message: Message to replay
            headers: Optional headers
            cookies: Optional cookies
        
        Returns:
            Response message if any
        """
        # Prepare headers
        extra_headers = {}
        if headers:
            extra_headers.update(headers)
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            extra_headers["Cookie"] = cookie_str
        
        try:
            async with websockets.connect(ws_url, extra_headers=extra_headers) as websocket:
                await websocket.send(message)
                
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                    return response
                except asyncio.TimeoutError:
                    return None
        
        except Exception:
            return None


class SSETester:
    """Server-Sent Events testing"""
    
    # Injection payloads for SSE
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "data: <svg onload=alert(1)>",
    ]

    def __init__(self, request_handler: RequestHandler):
        """Initialize SSE tester
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
    
    async def test_sse_endpoint(
        self,
        sse_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[SSETestResult]:
        """Test SSE endpoint for injection vulnerabilities
        
        Args:
            sse_url: SSE endpoint URL
            headers: Optional headers
            cookies: Optional cookies
        
        Returns:
            List of test results
        """
        results = []
        
        # Test XSS injection in SSE stream
        for payload in self.XSS_PAYLOADS:
            # Inject payload via query parameter
            test_url = f"{sse_url}?message={payload}"
            
            result = await self._test_sse_injection(test_url, payload, headers, cookies)
            if result:
                results.append(result)
                break
        
        return results
    
    async def _test_sse_injection(
        self,
        sse_url: str,
        payload: str,
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> Optional[SSETestResult]:
        """Test for injection in SSE stream
        
        Args:
            sse_url: SSE URL with payload
            payload: Injection payload
            headers: Headers
            cookies: Cookies
        
        Returns:
            Test result if vulnerability found
        """
        try:
            # Send request to SSE endpoint
            response = await self.request_handler.send_request(
                method="GET",
                url=sse_url,
                headers=headers or {},
                cookies=cookies or {},
            )
            
            # Check if payload is reflected in SSE stream
            if payload in response.text:
                # Parse SSE events
                events = self._parse_sse_stream(response.text)
                
                return SSETestResult(
                    url=sse_url,
                    is_vulnerable=True,
                    vulnerability_type=VulnerabilityType.SSE_INJECTION,
                    confidence=0.90,
                    evidence=[
                        "Injection detected in SSE stream",
                        f"Payload: {payload}",
                        "Payload reflected without sanitization",
                    ],
                    events=events,
                    payload=payload,
                )
        
        except Exception:
            pass
        
        return None
    
    def _parse_sse_stream(self, stream_data: str) -> List[SSEMessage]:
        """Parse SSE stream data
        
        Args:
            stream_data: Raw SSE stream data
        
        Returns:
            List of SSE messages
        """
        events = []
        lines = stream_data.split("\n")
        
        current_event = {
            "event": None,
            "data": [],
            "id": None,
            "retry": None,
        }
        
        for line in lines:
            line = line.strip()
            
            if not line:
                # Empty line indicates end of event
                if current_event["data"]:
                    events.append(SSEMessage(
                        event_type=current_event["event"],
                        data="\n".join(current_event["data"]),
                        event_id=current_event["id"],
                        retry=current_event["retry"],
                        timestamp=time.time(),
                    ))
                    current_event = {
                        "event": None,
                        "data": [],
                        "id": None,
                        "retry": None,
                    }
                continue
            
            if line.startswith(":"):
                # Comment line
                continue
            
            if ":" in line:
                field, value = line.split(":", 1)
                value = value.lstrip()
                
                if field == "event":
                    current_event["event"] = value
                elif field == "data":
                    current_event["data"].append(value)
                elif field == "id":
                    current_event["id"] = value
                elif field == "retry":
                    try:
                        current_event["retry"] = int(value)
                    except ValueError:
                        pass
        
        return events


class MessageAnalyzer:
    """Analyze and fuzz WebSocket/SSE message formats"""
    
    def __init__(self):
        """Initialize message analyzer"""
        pass
    
    def analyze_message_format(self, messages: List[WebSocketMessage]) -> Dict[str, Any]:
        """Analyze message format to identify parameters
        
        Args:
            messages: List of messages to analyze
        
        Returns:
            Dictionary with format analysis
        """
        analysis = {
            "message_types": {},
            "json_fields": set(),
            "patterns": [],
        }
        
        for msg in messages:
            # Count message types
            msg_type = msg.message_type.value
            analysis["message_types"][msg_type] = analysis["message_types"].get(msg_type, 0) + 1
            
            # Extract JSON fields
            if msg.message_type == MessageType.JSON:
                try:
                    data = json.loads(msg.content)
                    if isinstance(data, dict):
                        analysis["json_fields"].update(data.keys())
                except:
                    pass
        
        # Convert set to list for JSON serialization
        analysis["json_fields"] = list(analysis["json_fields"])
        
        return analysis
    
    def generate_fuzz_payloads(
        self,
        base_message: str,
        message_type: MessageType,
    ) -> List[str]:
        """Generate fuzz payloads based on message format
        
        Args:
            base_message: Base message to fuzz
            message_type: Type of message
        
        Returns:
            List of fuzz payloads
        """
        payloads = []
        
        if message_type == MessageType.JSON:
            try:
                data = json.loads(base_message)
                
                if isinstance(data, dict):
                    # Fuzz each field
                    for key in data.keys():
                        # XSS payloads
                        fuzzed = data.copy()
                        fuzzed[key] = "<script>alert(1)</script>"
                        payloads.append(json.dumps(fuzzed))
                        
                        # SQL injection payloads
                        fuzzed = data.copy()
                        fuzzed[key] = "' OR '1'='1"
                        payloads.append(json.dumps(fuzzed))
                        
                        # Command injection payloads
                        fuzzed = data.copy()
                        fuzzed[key] = "; ls"
                        payloads.append(json.dumps(fuzzed))
            except:
                pass
        
        else:
            # For non-JSON, just append payloads
            payloads.extend([
                base_message + "<script>alert(1)</script>",
                base_message + "' OR '1'='1",
                base_message + "; ls",
            ])
        
        return payloads


class WebSocketClient:
    """WebSocket client interface for manual exploitation"""
    
    def __init__(self):
        """Initialize WebSocket client"""
        if websockets is None:
            raise ImportError(
                "websockets library is required. "
                "Install it with: pip install websockets"
            )
        
        self.connection: Optional[WebSocketClientProtocol] = None
        self.message_history: List[WebSocketMessage] = []
        self.message_counter = 0
    
    async def connect(
        self,
        ws_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Connect to WebSocket endpoint
        
        Args:
            ws_url: WebSocket URL
            headers: Optional headers
            cookies: Optional cookies
        
        Returns:
            True if connected successfully
        """
        extra_headers = {}
        if headers:
            extra_headers.update(headers)
        if cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
            extra_headers["Cookie"] = cookie_str
        
        try:
            self.connection = await websockets.connect(ws_url, extra_headers=extra_headers)
            return True
        except Exception:
            return False
    
    async def send_message(self, message: str) -> bool:
        """Send a message
        
        Args:
            message: Message to send
        
        Returns:
            True if sent successfully
        """
        if not self.connection:
            return False
        
        try:
            await self.connection.send(message)
            
            # Record message
            self.message_history.append(WebSocketMessage(
                message_id=self._get_message_id(),
                direction="sent",
                message_type=self._detect_message_type(message),
                content=message,
                timestamp=time.time(),
            ))
            
            return True
        except Exception:
            return False
    
    async def receive_message(self, timeout: float = 5.0) -> Optional[str]:
        """Receive a message
        
        Args:
            timeout: Timeout in seconds
        
        Returns:
            Received message or None
        """
        if not self.connection:
            return None
        
        try:
            message = await asyncio.wait_for(self.connection.recv(), timeout=timeout)
            
            # Record message
            self.message_history.append(WebSocketMessage(
                message_id=self._get_message_id(),
                direction="received",
                message_type=self._detect_message_type(message),
                content=message,
                timestamp=time.time(),
            ))
            
            return message
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
    
    async def close(self):
        """Close the connection"""
        if self.connection:
            await self.connection.close()
            self.connection = None
    
    def get_message_history(self) -> List[WebSocketMessage]:
        """Get message history
        
        Returns:
            List of messages
        """
        return self.message_history
    
    def _detect_message_type(self, message: Any) -> MessageType:
        """Detect message type"""
        if isinstance(message, bytes):
            return MessageType.BINARY
        
        if isinstance(message, str):
            try:
                json.loads(message)
                return MessageType.JSON
            except:
                pass
            
            if message.strip().startswith("<"):
                return MessageType.XML
            
            return MessageType.TEXT
        
        return MessageType.UNKNOWN
    
    def _get_message_id(self) -> str:
        """Generate message ID"""
        self.message_counter += 1
        return f"msg_{self.message_counter}_{int(time.time() * 1000)}"
