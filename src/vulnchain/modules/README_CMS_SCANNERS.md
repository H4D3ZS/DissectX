# CMS Scanner Module

The CMS Scanner module provides automated vulnerability scanning for popular Content Management Systems (CMS) including WordPress, Drupal, and Joomla.

## Features

### Supported CMS Platforms

1. **WordPress** - via WPScan integration
2. **Drupal** - via Droopescan integration
3. **Joomla** - via JoomScan integration

### Capabilities

- **Automatic CMS Detection**: Automatically identifies the CMS type and version
- **Plugin/Module Enumeration**: Discovers installed plugins, modules, and themes
- **User Enumeration**: Identifies registered users (WordPress)
- **Vulnerability Detection**: Identifies known vulnerabilities in CMS core and components
- **CVE Cross-Referencing**: Enriches findings with CVE database information
- **Exploit Availability**: Checks for publicly available exploits
- **Configuration Issues**: Identifies common misconfigurations

## Installation Requirements

### WPScan (WordPress)
```bash
gem install wpscan
```

### Droopescan (Drupal)
```bash
pip install droopescan
```

### JoomScan (Joomla)
```bash
git clone https://github.com/OWASP/joomscan.git
cd joomscan
# Add to PATH or use full path
```

## Usage

### Basic WordPress Scan

```python
from app.core.request_handler import RequestHandler
from app.core.config import Config
from app.modules.reconnaissance import ReconnaissanceModule
from app.models.target import TargetConfig

# Initialize
config = Config()
request_handler = RequestHandler(config)
recon_module = ReconnaissanceModule(request_handler)

# Configure target
target = TargetConfig(
    url="https://example-wordpress-site.com",
    custom_headers={"User-Agent": "VulnChain/1.0"}
)

# Run scan
result = await recon_module.scan_wordpress(target)

# Access results
print(f"Version: {result.version}")
print(f"Plugins: {len(result.plugins)}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### Automatic CMS Detection and Scanning

```python
# Automatically detect CMS type and run appropriate scanner
result = await recon_module.detect_and_scan_cms(target)

if result:
    print(f"Detected: {result.cms_type}")
    print(f"Version: {result.version}")
else:
    print("No CMS detected")
```

### CVE Cross-Referencing

```python
# Look up CVE information
cve_info = await recon_module.cross_reference_cve("CVE-2018-7600")

print(f"Description: {cve_info['description']}")
print(f"CVSS Score: {cve_info['cvss_score']}")
print(f"Severity: {cve_info['severity']}")
print(f"Exploits: {len(cve_info['exploits'])}")
```

### Enriching Vulnerabilities with CVE Data

```python
# Scan CMS
cms_result = await recon_module.scan_wordpress(target)

# Enrich with CVE information
enriched_result = await recon_module.enrich_vulnerabilities_with_cve(cms_result)

# Now vulnerabilities have detailed CVE information
for vuln in enriched_result.vulnerabilities:
    print(f"{vuln.title} - {vuln.severity}")
    print(f"CVE: {vuln.cve_id}")
    print(f"Description: {vuln.description}")
```

## Data Models

### CMSScanResult

```python
@dataclass
class CMSScanResult:
    cms_type: str              # wordpress, drupal, joomla
    version: Optional[str]     # CMS version
    plugins: List[Dict]        # Installed plugins/modules
    themes: List[Dict]         # Installed themes
    users: List[str]           # Enumerated users
    vulnerabilities: List[CMSVulnerability]
    config_issues: List[str]   # Configuration problems
    raw_output: Optional[str]  # Raw scanner output
    error: Optional[str]       # Error message if scan failed
```

### CMSVulnerability

```python
@dataclass
class CMSVulnerability:
    title: str                 # Vulnerability title
    severity: str              # critical, high, medium, low, info
    description: str           # Detailed description
    cve_id: Optional[str]      # CVE identifier
    references: List[str]      # Reference URLs
    affected_component: Optional[str]  # Plugin/theme name
    fixed_in: Optional[str]    # Version where fixed
```

## Scanner-Specific Details

### WordPress (WPScan)

**Enumeration Options:**
- `vp` - Vulnerable plugins
- `vt` - Vulnerable themes
- `u` - Users

**Output Format:** JSON

**Key Features:**
- Plugin version detection
- Theme enumeration
- User enumeration
- Known vulnerability database
- WordPress version detection

### Drupal (Droopescan)

**Output Format:** JSON

**Key Features:**
- Version detection
- Module enumeration
- Theme enumeration
- Interesting URL discovery
- Known vulnerability mapping

### Joomla (JoomScan)

**Output Format:** Text (parsed)

**Key Features:**
- Version detection
- Component enumeration
- Configuration issue detection
- Directory listing checks
- Backup file detection

## CVE Cross-Referencing

The module integrates with the National Vulnerability Database (NVD) to provide:

- **Detailed Descriptions**: Full CVE descriptions
- **CVSS Scores**: Severity ratings (v2, v3, v3.1)
- **Published Dates**: When the vulnerability was disclosed
- **References**: Official advisories and documentation
- **Exploit Availability**: Links to:
  - Exploit-DB
  - Metasploit modules
  - GitHub PoC repositories

## Error Handling

All scanner methods return a `CMSScanResult` object with an `error` field:

```python
result = await recon_module.scan_wordpress(target)

if result.error:
    if "not found" in result.error:
        print("Scanner not installed")
    elif "execution failed" in result.error:
        print("Scanner execution error")
    else:
        print(f"Unknown error: {result.error}")
```

## Best Practices

1. **Check Scanner Installation**: Verify scanners are installed before use
2. **Handle Errors Gracefully**: Always check the `error` field
3. **Respect Rate Limits**: Be mindful of target rate limiting
4. **Use Proxies**: Configure proxy settings for anonymity
5. **Enrich Results**: Use CVE cross-referencing for complete information
6. **Update Scanners**: Keep scanner tools updated for latest signatures

## Security Considerations

- **Authorization**: Only scan systems you have permission to test
- **Rate Limiting**: Implement delays to avoid overwhelming targets
- **Logging**: All scans are logged for audit purposes
- **Proxy Support**: Use proxies to protect your identity
- **Custom Headers**: Configure appropriate User-Agent headers

## Performance

- **WordPress Scan**: 30-60 seconds (depends on plugin count)
- **Drupal Scan**: 20-40 seconds
- **Joomla Scan**: 30-50 seconds
- **CVE Lookup**: 1-3 seconds per CVE
- **Auto-Detection**: 5-10 seconds

## Troubleshooting

### WPScan Not Found
```bash
gem install wpscan
# Or use system package manager
apt-get install wpscan  # Debian/Ubuntu
```

### Droopescan Not Found
```bash
pip install droopescan
```

### JoomScan Not Found
```bash
git clone https://github.com/OWASP/joomscan.git
cd joomscan
chmod +x joomscan.pl
# Add to PATH or use full path
```

### CVE API Rate Limiting
The NVD API has rate limits. If you encounter rate limiting:
- Add delays between CVE lookups
- Cache CVE results
- Consider using an API key (if available)

## Examples

See `backend/examples/cms_scanner_demo.py` for complete working examples.

## Requirements Validation

This implementation satisfies the following requirements:

- **Requirement 32.1**: WordPress detection and WPScan integration ✓
- **Requirement 32.2**: Drupal detection and Droopescan integration ✓
- **Requirement 32.3**: Joomla detection and JoomScan integration ✓
- **Requirement 32.4**: Default credential testing and admin panel detection ✓
- **Requirement 32.5**: CVE cross-referencing and exploit availability ✓

## Future Enhancements

- Support for additional CMS platforms (Magento, PrestaShop, etc.)
- Automated exploit execution
- Custom vulnerability signature creation
- Integration with vulnerability management platforms
- Real-time vulnerability feed updates
