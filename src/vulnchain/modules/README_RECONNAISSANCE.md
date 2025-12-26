# Reconnaissance Module

The Reconnaissance Module provides automated target discovery and fingerprinting capabilities for the VulnChain CTF framework.

## Features

### 1. Technology Fingerprinting

#### WhatWeb Integration
- Executes WhatWeb for comprehensive technology detection
- Identifies web technologies, frameworks, and server software
- Extracts version information and confidence levels
- Supports custom headers and proxy configuration

```python
from app.modules.reconnaissance import ReconnaissanceModule
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig

request_handler = RequestHandler()
recon = ReconnaissanceModule(request_handler)

target = TargetConfig(url="https://example.com")
result = await recon.fingerprint_whatweb(target)

for tech in result.technologies:
    print(f"{tech.name} {tech.version}")
```

#### Wappalyzer-style Detection
- Analyzes HTML content for technology signatures
- Detects client-side frameworks (React, Vue.js, Angular)
- Identifies CMS platforms (WordPress, Drupal, Joomla)
- Extracts information from HTTP headers and meta tags

```python
result = await recon.fingerprint_wappalyzer(target)

for tech in result.technologies:
    print(f"{tech.name} [{tech.category}]")
```

### 2. Attack Module Suggestions

Automatically maps detected technologies to relevant attack modules and known vulnerabilities:

```python
technologies = result.technologies
suggestions = recon.suggest_attack_modules(technologies)

for tech_name, modules in suggestions.items():
    print(f"{tech_name}: {', '.join(modules)}")
```

**Supported Technology Mappings:**
- WordPress → CMS Scanner (WPScan), SQL Injection, File Upload
- Drupal → CMS Scanner (Droopescan), SQL Injection, RCE
- Node.js → Prototype Pollution, Command Injection, SSRF
- PHP → File Inclusion, Deserialization, Command Injection
- And many more...

### 3. Directory and File Fuzzing

Concurrent directory and file discovery with intelligent filtering:

```python
results = await recon.fuzz_directories(
    target,
    wordlist_path="/path/to/wordlist.txt",
    status_codes=[200, 301, 302, 403],
    max_concurrent=50
)

for entry in results:
    if entry.is_sensitive:
        print(f"[SENSITIVE] {entry.path} [{entry.status_code}]")
```

**Features:**
- Concurrent requests with configurable limits
- Status code filtering
- Automatic sensitive file detection (.git, .env, etc.)
- Redirect tracking
- Response time and content length analysis

### 4. Subdomain Enumeration

Multi-technique subdomain discovery:

```python
subdomains = await recon.enumerate_subdomains(
    domain="example.com",
    wordlist_path="/path/to/subdomains.txt",
    use_crt_sh=True,
    use_dns_brute=True,
    max_concurrent=50
)

for subdomain in subdomains:
    if subdomain.is_alive:
        print(f"✓ {subdomain.subdomain} [{subdomain.discovery_method}]")
```

**Techniques:**
- Certificate Transparency Logs (crt.sh)
- DNS Brute-force
- Automatic liveness probing
- Quick technology fingerprinting

### 5. Parameter Discovery

Extract parameters from multiple sources:

```python
parameters = await recon.discover_parameters(
    target,
    common_params=["id", "user", "page", "debug"]
)

for param in parameters:
    print(f"{param.name} [{param.location}]")
```

**Sources:**
- URL query parameters
- HTML form fields (input, select, textarea)
- JavaScript code analysis
- Common parameter name fuzzing

### 6. JavaScript Analysis

Comprehensive JavaScript file analysis:

```python
result = await recon.analyze_javascript(target)

print(f"JS Files: {len(result['js_files'])}")
print(f"Endpoints: {len(result['endpoints'])}")
print(f"API Keys: {len(result['api_keys'])}")
print(f"Tokens: {len(result['tokens'])}")
print(f"Sensitive Comments: {len(result['comments'])}")
```

**Extracts:**
- JavaScript file URLs
- API endpoints and internal URLs
- Authentication tokens and API keys
- Sensitive comments (TODO, FIXME, passwords, etc.)
- Hidden parameters

## Data Models

### Technology
```python
@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    confidence: Optional[str] = None
    category: Optional[str] = None
    website: Optional[str] = None
    cpe: Optional[str] = None
```

### FingerprintResult
```python
@dataclass
class FingerprintResult:
    url: str
    technologies: List[Technology] = field(default_factory=list)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
```

### DirectoryEntry
```python
@dataclass
class DirectoryEntry:
    path: str
    status_code: int
    content_length: int
    response_time: float
    is_sensitive: bool = False
    redirect_location: Optional[str] = None
```

### Subdomain
```python
@dataclass
class Subdomain:
    subdomain: str
    ip_address: Optional[str] = None
    is_alive: bool = False
    technologies: List[Technology] = field(default_factory=list)
    discovery_method: Optional[str] = None
```

### Parameter
```python
@dataclass
class Parameter:
    name: str
    location: str  # url, form, javascript, header
    example_value: Optional[str] = None
    source_url: Optional[str] = None
```

### JavaScriptEndpoint
```python
@dataclass
class JavaScriptEndpoint:
    url: str
    source_file: str
    method: Optional[str] = None
    line_number: Optional[int] = None
```

## Requirements

### External Tools
- **WhatWeb**: Required for `fingerprint_whatweb()`
  ```bash
  # Ubuntu/Debian
  apt-get install whatweb
  
  # macOS
  brew install whatweb
  ```

- **nslookup**: Required for DNS brute-force (usually pre-installed)

### Python Dependencies
All dependencies are included in the main requirements.txt:
- aiohttp
- httpx
- Standard library modules (re, json, asyncio, etc.)

## Usage Examples

### Complete Reconnaissance Workflow

```python
import asyncio
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig
from app.modules.reconnaissance import ReconnaissanceModule

async def full_recon(target_url: str):
    """Perform complete reconnaissance on a target"""
    
    # Setup
    target = TargetConfig(url=target_url)
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    # 1. Technology Fingerprinting
    print("Phase 1: Technology Fingerprinting")
    whatweb_result = await recon.fingerprint_whatweb(target)
    wappalyzer_result = await recon.fingerprint_wappalyzer(target)
    
    all_technologies = whatweb_result.technologies + wappalyzer_result.technologies
    
    # 2. Attack Module Suggestions
    print("Phase 2: Attack Module Suggestions")
    suggestions = recon.suggest_attack_modules(all_technologies)
    
    # 3. Directory Fuzzing
    print("Phase 3: Directory Fuzzing")
    directories = await recon.fuzz_directories(
        target,
        "/usr/share/wordlists/dirb/common.txt",
        max_concurrent=50
    )
    
    # 4. Parameter Discovery
    print("Phase 4: Parameter Discovery")
    parameters = await recon.discover_parameters(target)
    
    # 5. JavaScript Analysis
    print("Phase 5: JavaScript Analysis")
    js_analysis = await recon.analyze_javascript(target)
    
    # Cleanup
    await request_handler.close()
    
    return {
        'technologies': all_technologies,
        'suggestions': suggestions,
        'directories': directories,
        'parameters': parameters,
        'javascript': js_analysis
    }

# Run
results = asyncio.run(full_recon("https://example.com"))
```

### Targeted Subdomain Enumeration

```python
async def enumerate_all_subdomains(domain: str):
    """Comprehensive subdomain enumeration"""
    
    request_handler = RequestHandler()
    recon = ReconnaissanceModule(request_handler)
    
    # Enumerate with multiple techniques
    subdomains = await recon.enumerate_subdomains(
        domain,
        wordlist_path="/usr/share/wordlists/subdomains.txt",
        use_crt_sh=True,
        use_dns_brute=True,
        max_concurrent=100
    )
    
    # Filter for live subdomains
    live_subdomains = [s for s in subdomains if s.is_alive]
    
    print(f"Found {len(subdomains)} subdomains, {len(live_subdomains)} alive")
    
    await request_handler.close()
    return live_subdomains
```

## Performance Considerations

### Concurrency
- Directory fuzzing: Default 50 concurrent requests
- Subdomain enumeration: Default 50 concurrent DNS queries
- Adjust `max_concurrent` based on target and network capacity

### Rate Limiting
- Use `TargetConfig.rate_limit` to control request rate
- Implement delays between requests if needed
- Respect target's robots.txt and rate limits

### Timeouts
- Default request timeout: 30 seconds
- DNS query timeout: 5 seconds
- Adjust based on target responsiveness

## Error Handling

All methods handle errors gracefully:

```python
result = await recon.fingerprint_whatweb(target)

if result.error:
    print(f"Error: {result.error}")
    # Handle error (e.g., WhatWeb not installed)
else:
    # Process results
    for tech in result.technologies:
        print(tech.name)
```

## Testing

Run the test suite:

```bash
cd backend
python -m pytest tests/test_reconnaissance.py -v
```

Run the demo:

```bash
cd backend
python examples/reconnaissance_demo.py
```

## Integration with Other Modules

The reconnaissance module integrates seamlessly with other VulnChain components:

```python
# Use with Session Manager
from app.core.session_manager import SessionManager

session_manager = SessionManager()
# Capture session from login
# Then use in reconnaissance
target.session_id = session.session_id

# Use with Payload Engine
from app.core.payload_engine import PayloadEngine

payload_engine = PayloadEngine()
payload_engine.load_wordlist("/path/to/payloads.txt", "sqli")

# Use discovered parameters for injection testing
for param in parameters:
    for payload in payload_engine.get_payloads("sqli"):
        # Test parameter with payload
        pass
```

## Best Practices

1. **Start with fingerprinting**: Always begin with technology detection to guide subsequent attacks
2. **Use attack suggestions**: Leverage the automatic attack module suggestions
3. **Combine techniques**: Use multiple reconnaissance methods for comprehensive coverage
4. **Respect targets**: Only scan authorized targets and respect rate limits
5. **Save results**: Store reconnaissance results for later analysis and reporting
6. **Iterate**: Use discovered information to guide deeper reconnaissance

## Troubleshooting

### WhatWeb Not Found
```
Error: WhatWeb not found. Please install WhatWeb: apt-get install whatweb
```
**Solution**: Install WhatWeb using your package manager

### DNS Resolution Failures
```
Error: nslookup command failed
```
**Solution**: Ensure nslookup is installed and DNS is properly configured

### Connection Timeouts
```
Error: Request timeout
```
**Solution**: Increase timeout values or check network connectivity

### Empty Results
If reconnaissance returns no results:
1. Verify target is accessible
2. Check proxy configuration
3. Verify wordlist paths are correct
4. Check for rate limiting or WAF blocking

## Future Enhancements

Planned features:
- Integration with additional fingerprinting tools
- Machine learning-based technology detection
- Automated vulnerability correlation
- Enhanced JavaScript deobfuscation
- API schema discovery (OpenAPI/Swagger)
- GraphQL introspection
- Cloud service detection (AWS, Azure, GCP)
