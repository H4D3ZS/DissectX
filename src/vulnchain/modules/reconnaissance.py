"""Reconnaissance module for technology fingerprinting and discovery"""

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from src.vulnchain.core.request_handler import RequestHandler
from src.vulnchain.models.target import TargetConfig
from src.vulnchain.core.cache import cached, fingerprint_cache, dns_cache, recon_cache


@dataclass
class Technology:
    """Detected technology information"""
    
    name: str
    version: Optional[str] = None
    confidence: Optional[str] = None
    category: Optional[str] = None
    website: Optional[str] = None
    cpe: Optional[str] = None


@dataclass
class FingerprintResult:
    """Technology fingerprinting result"""
    
    url: str
    technologies: List[Technology] = field(default_factory=list)
    server: Optional[str] = None
    powered_by: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DirectoryEntry:
    """Directory/file fuzzing result entry"""
    
    path: str
    status_code: int
    content_length: int
    response_time: float
    is_sensitive: bool = False
    redirect_location: Optional[str] = None


@dataclass
class Subdomain:
    """Discovered subdomain information"""
    
    subdomain: str
    ip_address: Optional[str] = None
    is_alive: bool = False
    technologies: List[Technology] = field(default_factory=list)
    discovery_method: Optional[str] = None


@dataclass
class Parameter:
    """Discovered parameter information"""
    
    name: str
    location: str  # url, form, javascript, header
    example_value: Optional[str] = None
    source_url: Optional[str] = None


@dataclass
class JavaScriptEndpoint:
    """Endpoint discovered in JavaScript"""
    
    url: str
    source_file: str
    method: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class CMSVulnerability:
    """CMS vulnerability information"""
    
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    cve_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_component: Optional[str] = None
    fixed_in: Optional[str] = None


@dataclass
class CMSScanResult:
    """CMS scanner result"""
    
    cms_type: str  # wordpress, drupal, joomla
    version: Optional[str] = None
    plugins: List[Dict[str, any]] = field(default_factory=list)
    themes: List[Dict[str, any]] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    vulnerabilities: List[CMSVulnerability] = field(default_factory=list)
    config_issues: List[str] = field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None


class ReconnaissanceModule:
    """
    Reconnaissance module for automated target discovery and fingerprinting.
    
    Provides:
    - Technology fingerprinting (WhatWeb, Wappalyzer)
    - Directory and file fuzzing
    - Subdomain enumeration
    - Parameter discovery
    - JavaScript analysis and endpoint extraction
    """
    
    def __init__(self, request_handler: RequestHandler):
        """
        Initialize reconnaissance module.
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
        self._sensitive_files = {
            '.git', '.DS_Store', 'robots.txt', '.env', '.htaccess',
            'web.config', 'composer.json', 'package.json', '.gitignore',
            'config.php', 'wp-config.php', 'database.yml', '.svn'
        }
    
    @cached(ttl=3600, key_prefix="whatweb", serialize="pickle")
    async def fingerprint_whatweb(self, target: TargetConfig) -> FingerprintResult:
        """
        Execute WhatWeb for technology fingerprinting.
        
        Results are cached for 1 hour to avoid redundant scans.
        
        Args:
            target: Target configuration
            
        Returns:
            FingerprintResult with detected technologies
        """
        result = FingerprintResult(url=target.url)
        
        try:
            # Build WhatWeb command
            cmd = [
                'whatweb',
                '--color=never',
                '--no-errors',
                '-a', '3',  # Aggression level 3
                '--log-json=-',  # Output JSON to stdout
                target.url
            ]
            
            # Add proxy if configured
            if target.proxy:
                cmd.extend(['--proxy', target.proxy])
            
            # Add custom headers if configured
            if target.custom_headers:
                for key, value in target.custom_headers.items():
                    cmd.extend(['--header', f'{key}: {value}'])
            
            # Execute WhatWeb
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                result.error = f"WhatWeb execution failed: {stderr.decode()}"
                return result
            
            # Parse JSON output
            output = stdout.decode()
            result.raw_output = output
            
            # WhatWeb outputs one JSON object per line
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    data = json.loads(line)
                    
                    # Extract technologies from plugins
                    if 'plugins' in data:
                        for plugin_name, plugin_data in data['plugins'].items():
                            tech = Technology(name=plugin_name)
                            
                            # Extract version if available
                            if isinstance(plugin_data, dict):
                                if 'version' in plugin_data:
                                    versions = plugin_data['version']
                                    if isinstance(versions, list) and versions:
                                        tech.version = versions[0]
                                    elif isinstance(versions, str):
                                        tech.version = versions
                                
                                if 'string' in plugin_data:
                                    strings = plugin_data['string']
                                    if isinstance(strings, list) and strings:
                                        # Try to extract version from string
                                        version_match = re.search(r'(\d+\.[\d.]+)', strings[0])
                                        if version_match and not tech.version:
                                            tech.version = version_match.group(1)
                            
                            result.technologies.append(tech)
                    
                    # Extract server header
                    if 'target' in data:
                        target_data = data['target']
                        if 'http_status' in target_data:
                            # Look for Server header in the response
                            pass  # Will be extracted from headers
                
                except json.JSONDecodeError:
                    continue
            
            # Extract server and powered-by from headers
            try:
                response = await self.request_handler.send_request(
                    method='GET',
                    url=target.url,
                    headers=target.custom_headers,
                    proxy=target.proxy
                )
                
                if 'server' in response.headers:
                    result.server = response.headers['server']
                
                if 'x-powered-by' in response.headers:
                    result.powered_by = response.headers['x-powered-by']
                    
            except Exception:
                pass  # Non-critical, continue
        
        except FileNotFoundError:
            result.error = "WhatWeb not found. Please install WhatWeb: apt-get install whatweb"
        except Exception as e:
            result.error = f"Unexpected error during WhatWeb execution: {str(e)}"
        
        return result
    
    @cached(ttl=3600, key_prefix="wappalyzer", serialize="pickle")
    async def fingerprint_wappalyzer(self, target: TargetConfig) -> FingerprintResult:
        """
        Execute Wappalyzer for client-side technology detection.
        
        Results are cached for 1 hour to avoid redundant scans.
        
        Args:
            target: Target configuration
            
        Returns:
            FingerprintResult with detected technologies
        """
        result = FingerprintResult(url=target.url)
        
        try:
            # Fetch the page content
            response = await self.request_handler.send_request(
                method='GET',
                url=target.url,
                headers=target.custom_headers,
                proxy=target.proxy
            )
            
            # Analyze HTML content for technology signatures
            html = response.text
            headers = response.headers
            
            # Check for common frameworks and libraries
            technologies = []
            
            # React
            if 'react' in html.lower() or '__REACT' in html:
                tech = Technology(name='React', category='JavaScript Framework')
                # Try to extract version
                react_version = re.search(r'react@(\d+(?:\.\d+)*)', html)
                if react_version:
                    tech.version = react_version.group(1)
                technologies.append(tech)
            
            # Vue.js
            if 'vue' in html.lower() or 'data-v-' in html:
                tech = Technology(name='Vue.js', category='JavaScript Framework')
                vue_version = re.search(r'vue@([\d.]+)', html)
                if vue_version:
                    tech.version = vue_version.group(1)
                technologies.append(tech)
            
            # Angular
            if 'ng-' in html or 'angular' in html.lower():
                tech = Technology(name='Angular', category='JavaScript Framework')
                technologies.append(tech)
            
            # jQuery
            jquery_match = re.search(r'jquery[.-]?([\d.]+)(?:\.min)?\.js', html, re.IGNORECASE)
            if jquery_match:
                tech = Technology(name='jQuery', category='JavaScript Library')
                tech.version = jquery_match.group(1)
                technologies.append(tech)
            
            # Bootstrap
            bootstrap_match = re.search(r'bootstrap[.-]?([\d.]+)(?:\.min)?\.(?:css|js)', html, re.IGNORECASE)
            if bootstrap_match:
                tech = Technology(name='Bootstrap', category='CSS Framework')
                tech.version = bootstrap_match.group(1)
                technologies.append(tech)
            
            # WordPress
            if 'wp-content' in html or 'wp-includes' in html:
                tech = Technology(name='WordPress', category='CMS')
                # Try to extract version from meta tag
                wp_version = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', html)
                if wp_version:
                    tech.version = wp_version.group(1)
                technologies.append(tech)
            
            # Drupal
            if 'drupal' in html.lower() or '/sites/default/' in html:
                tech = Technology(name='Drupal', category='CMS')
                technologies.append(tech)
            
            # Joomla
            if 'joomla' in html.lower() or '/components/com_' in html:
                tech = Technology(name='Joomla', category='CMS')
                technologies.append(tech)
            
            # Google Analytics
            if 'google-analytics.com' in html or 'gtag' in html:
                tech = Technology(name='Google Analytics', category='Analytics')
                technologies.append(tech)
            
            # Check headers for additional info
            if 'server' in headers:
                result.server = headers['server']
                # Parse server header for technology
                server_tech = Technology(name=headers['server'], category='Web Server')
                technologies.append(server_tech)
            
            if 'x-powered-by' in headers:
                result.powered_by = headers['x-powered-by']
                powered_tech = Technology(name=headers['x-powered-by'], category='Backend')
                technologies.append(powered_tech)
            
            result.technologies = technologies
            
        except Exception as e:
            result.error = f"Error during Wappalyzer analysis: {str(e)}"
        
        return result
    
    def suggest_attack_modules(self, technologies: List[Technology]) -> Dict[str, List[str]]:
        """
        Map detected technologies to relevant attack modules.
        
        Args:
            technologies: List of detected technologies
            
        Returns:
            Dictionary mapping technology names to suggested attack modules
        """
        suggestions = {}
        
        # Technology to attack module mapping
        tech_to_modules = {
            'WordPress': ['CMS Scanner (WPScan)', 'SQL Injection', 'File Upload', 'XML-RPC'],
            'Drupal': ['CMS Scanner (Droopescan)', 'SQL Injection', 'Remote Code Execution'],
            'Joomla': ['CMS Scanner (JoomScan)', 'SQL Injection', 'File Upload'],
            'PHP': ['File Inclusion', 'Deserialization', 'Command Injection'],
            'Apache': ['Directory Traversal', 'Server Misconfiguration'],
            'nginx': ['Server Misconfiguration', 'Path Traversal'],
            'MySQL': ['SQL Injection', 'Authentication Bypass'],
            'PostgreSQL': ['SQL Injection', 'Command Injection'],
            'MongoDB': ['NoSQL Injection', 'Authentication Bypass'],
            'Node.js': ['Prototype Pollution', 'Command Injection', 'SSRF'],
            'Express': ['Prototype Pollution', 'Path Traversal'],
            'React': ['XSS', 'Client-Side Injection'],
            'Angular': ['Template Injection', 'XSS'],
            'Vue.js': ['XSS', 'Client-Side Injection'],
            'jQuery': ['DOM-based XSS', 'Client-Side Injection'],
            'Java': ['Deserialization', 'XXE', 'SSRF'],
            'Spring': ['Spring4Shell', 'Deserialization'],
            '.NET': ['Deserialization', 'ViewState Exploitation'],
            'IIS': ['Server Misconfiguration', 'Path Traversal'],
            'GraphQL': ['GraphQL Introspection', 'Query Depth Attack'],
            'REST API': ['API Testing', 'Authentication Bypass', 'IDOR'],
            'JWT': ['JWT Manipulation', 'Algorithm Confusion'],
        }
        
        # Known vulnerabilities for specific versions
        version_vulns = {
            ('WordPress', '5.0'): ['CVE-2019-8942', 'CVE-2019-8943'],
            ('Drupal', '7.x'): ['Drupalgeddon', 'SQL Injection'],
            ('Joomla', '3.4.5'): ['CVE-2015-8562', 'Remote Code Execution'],
        }
        
        for tech in technologies:
            modules = []
            
            # Check for direct technology match
            for tech_name, attack_modules in tech_to_modules.items():
                if tech_name.lower() in tech.name.lower():
                    modules.extend(attack_modules)
            
            # Check for version-specific vulnerabilities
            if tech.version:
                for (vuln_tech, vuln_version), vulns in version_vulns.items():
                    if vuln_tech.lower() in tech.name.lower():
                        if tech.version.startswith(vuln_version):
                            modules.extend(vulns)
            
            if modules:
                suggestions[tech.name] = list(set(modules))  # Remove duplicates
        
        return suggestions
    
    async def fuzz_directories(
        self,
        target: TargetConfig,
        wordlist_path: str,
        status_codes: Optional[List[int]] = None,
        max_concurrent: int = 50
    ) -> List[DirectoryEntry]:
        """
        Perform directory and file fuzzing.
        
        Args:
            target: Target configuration
            wordlist_path: Path to wordlist file
            status_codes: List of status codes to include (default: [200, 301, 302, 403])
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of discovered directory entries
        """
        if status_codes is None:
            status_codes = [200, 301, 302, 403]
        
        results = []
        
        try:
            # Load wordlist
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Create semaphore for concurrency control
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def test_path(path: str) -> Optional[DirectoryEntry]:
                """Test a single path"""
                async with semaphore:
                    try:
                        # Ensure path starts with /
                        if not path.startswith('/'):
                            path = '/' + path
                        
                        url = urljoin(target.url, path)
                        
                        response = await self.request_handler.send_request(
                            method='GET',
                            url=url,
                            headers=target.custom_headers,
                            proxy=target.proxy,
                            follow_redirects=False,
                            timeout=10.0
                        )
                        
                        # Check if status code matches filter
                        if response.status_code in status_codes:
                            # Check if it's a sensitive file
                            is_sensitive = any(
                                sensitive in path.lower()
                                for sensitive in self._sensitive_files
                            )
                            
                            # Get redirect location if applicable
                            redirect_location = None
                            if response.status_code in [301, 302, 303, 307, 308]:
                                redirect_location = response.headers.get('location')
                            
                            entry = DirectoryEntry(
                                path=path,
                                status_code=response.status_code,
                                content_length=len(response.body),
                                response_time=response.elapsed_time,
                                is_sensitive=is_sensitive,
                                redirect_location=redirect_location
                            )
                            
                            return entry
                    
                    except Exception:
                        pass  # Ignore errors for individual requests
                    
                    return None
            
            # Test all paths concurrently
            tasks = [test_path(path) for path in paths]
            entries = await asyncio.gather(*tasks)
            
            # Filter out None results
            results = [entry for entry in entries if entry is not None]
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
        except Exception as e:
            raise RuntimeError(f"Error during directory fuzzing: {str(e)}")
        
        return results

    
    async def enumerate_subdomains(
        self,
        domain: str,
        wordlist_path: Optional[str] = None,
        use_crt_sh: bool = True,
        use_dns_brute: bool = True,
        max_concurrent: int = 50
    ) -> List[Subdomain]:
        """
        Enumerate subdomains using multiple techniques.
        
        Args:
            domain: Root domain to enumerate
            wordlist_path: Path to subdomain wordlist for DNS brute-force
            use_crt_sh: Use certificate transparency logs (crt.sh)
            use_dns_brute: Perform DNS brute-force
            max_concurrent: Maximum concurrent DNS queries
            
        Returns:
            List of discovered subdomains
        """
        discovered = {}  # Use dict to avoid duplicates
        
        # 1. Certificate Transparency Logs (crt.sh)
        if use_crt_sh:
            try:
                crt_subdomains = await self._enumerate_crt_sh(domain)
                for subdomain in crt_subdomains:
                    if subdomain not in discovered:
                        discovered[subdomain] = Subdomain(
                            subdomain=subdomain,
                            discovery_method='Certificate Transparency'
                        )
            except Exception:
                pass  # Continue with other methods
        
        # 2. DNS Brute-force
        if use_dns_brute and wordlist_path:
            try:
                dns_subdomains = await self._enumerate_dns_brute(
                    domain, wordlist_path, max_concurrent
                )
                for subdomain in dns_subdomains:
                    if subdomain not in discovered:
                        discovered[subdomain] = Subdomain(
                            subdomain=subdomain,
                            discovery_method='DNS Brute-force'
                        )
                    elif discovered[subdomain].discovery_method == 'Certificate Transparency':
                        # Update method to show both
                        discovered[subdomain].discovery_method = 'Certificate Transparency, DNS Brute-force'
            except Exception:
                pass  # Continue
        
        # 3. Probe discovered subdomains for live services
        subdomains_list = list(discovered.values())
        await self._probe_subdomains(subdomains_list)
        
        return subdomains_list
    
    async def _enumerate_crt_sh(self, domain: str) -> Set[str]:
        """Query crt.sh for subdomains from certificate transparency logs"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            # Use a simple HTTP client for this
            response = await self.request_handler.send_request(
                method='GET',
                url=url,
                timeout=30.0
            )
            
            if response.status_code == 200:
                data = json.loads(response.text)
                
                for entry in data:
                    if 'name_value' in entry:
                        # name_value can contain multiple domains separated by newlines
                        names = entry['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            # Filter out wildcards and ensure it's a subdomain
                            if '*' not in name and name.endswith(domain):
                                subdomains.add(name)
        
        except Exception:
            pass  # Non-critical
        
        return subdomains
    
    @cached(ttl=300, key_prefix="dns_lookup", serialize="json")
    async def _resolve_dns(self, hostname: str) -> Optional[str]:
        """
        Resolve DNS for a hostname with caching.
        
        Results are cached for 5 minutes to reduce DNS queries.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address or None if resolution fails
        """
        try:
            process = await asyncio.create_subprocess_exec(
                'nslookup', hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            # If nslookup succeeds, extract IP
            if process.returncode == 0 and b'NXDOMAIN' not in stdout:
                # Parse IP from output
                output = stdout.decode()
                # Simple IP extraction (can be improved)
                import socket
                try:
                    ip = socket.gethostbyname(hostname)
                    return ip
                except Exception:
                    return hostname  # Return hostname if IP extraction fails
        except Exception:
            pass
        
        return None
    
    async def _enumerate_dns_brute(
        self, domain: str, wordlist_path: str, max_concurrent: int
    ) -> Set[str]:
        """
        Perform DNS brute-force enumeration with caching.
        
        DNS lookups are cached for 5 minutes to reduce redundant queries.
        """
        subdomains = set()
        
        try:
            # Load wordlist
            with open(wordlist_path, 'r') as f:
                prefixes = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Create semaphore for concurrency control
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def check_subdomain(prefix: str) -> Optional[str]:
                """Check if subdomain exists via DNS (with caching)"""
                async with semaphore:
                    subdomain = f"{prefix}.{domain}"
                    # Use cached DNS resolution
                    ip = await self._resolve_dns(subdomain)
                    return subdomain if ip else None
            
            # Check all subdomains concurrently
            tasks = [check_subdomain(prefix) for prefix in prefixes]
            results = await asyncio.gather(*tasks)
            
            # Filter out None results
            subdomains = {sub for sub in results if sub is not None}
        
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
        except Exception:
            pass  # Non-critical
        
        return subdomains
    
    async def _probe_subdomains(self, subdomains: List[Subdomain]) -> None:
        """Probe subdomains to check if they're alive and fingerprint them"""
        
        async def probe_subdomain(subdomain: Subdomain) -> None:
            """Probe a single subdomain"""
            try:
                # Try HTTPS first, then HTTP
                for scheme in ['https', 'http']:
                    url = f"{scheme}://{subdomain.subdomain}"
                    try:
                        response = await self.request_handler.send_request(
                            method='GET',
                            url=url,
                            timeout=10.0,
                            follow_redirects=True
                        )
                        
                        if response.status_code < 500:  # Consider it alive if not server error
                            subdomain.is_alive = True
                            
                            # Quick fingerprinting from headers
                            if 'server' in response.headers:
                                tech = Technology(
                                    name=response.headers['server'],
                                    category='Web Server'
                                )
                                subdomain.technologies.append(tech)
                            
                            break  # Found a working scheme
                    
                    except Exception:
                        continue  # Try next scheme
            
            except Exception:
                pass  # Subdomain not reachable
        
        # Probe all subdomains concurrently
        tasks = [probe_subdomain(sub) for sub in subdomains]
        await asyncio.gather(*tasks)
    
    async def discover_parameters(
        self,
        target: TargetConfig,
        common_params: Optional[List[str]] = None
    ) -> List[Parameter]:
        """
        Discover parameters from URLs, forms, and JavaScript.
        
        Args:
            target: Target configuration
            common_params: List of common parameter names to fuzz
            
        Returns:
            List of discovered parameters
        """
        parameters = []
        
        try:
            # Fetch the main page
            response = await self.request_handler.send_request(
                method='GET',
                url=target.url,
                headers=target.custom_headers,
                proxy=target.proxy
            )
            
            html = response.text
            
            # 1. Extract parameters from URL
            parsed_url = urlparse(target.url)
            if parsed_url.query:
                for param in parsed_url.query.split('&'):
                    if '=' in param:
                        name, value = param.split('=', 1)
                        parameters.append(Parameter(
                            name=name,
                            location='url',
                            example_value=value,
                            source_url=target.url
                        ))
            
            # 2. Extract parameters from forms
            form_params = self._extract_form_parameters(html, target.url)
            parameters.extend(form_params)
            
            # 3. Extract parameters from JavaScript
            js_params = self._extract_javascript_parameters(html, target.url)
            parameters.extend(js_params)
            
            # 4. Fuzz common parameter names if provided
            if common_params:
                fuzzed_params = await self._fuzz_parameters(target, common_params)
                parameters.extend(fuzzed_params)
        
        except Exception as e:
            raise RuntimeError(f"Error during parameter discovery: {str(e)}")
        
        return parameters
    
    def _extract_form_parameters(self, html: str, source_url: str) -> List[Parameter]:
        """Extract parameters from HTML forms"""
        parameters = []
        
        # Find all input fields
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\']'
        for match in re.finditer(input_pattern, html, re.IGNORECASE):
            param_name = match.group(1)
            parameters.append(Parameter(
                name=param_name,
                location='form',
                source_url=source_url
            ))
        
        # Find all select fields
        select_pattern = r'<select[^>]+name=["\']([^"\']+)["\']'
        for match in re.finditer(select_pattern, html, re.IGNORECASE):
            param_name = match.group(1)
            parameters.append(Parameter(
                name=param_name,
                location='form',
                source_url=source_url
            ))
        
        # Find all textarea fields
        textarea_pattern = r'<textarea[^>]+name=["\']([^"\']+)["\']'
        for match in re.finditer(textarea_pattern, html, re.IGNORECASE):
            param_name = match.group(1)
            parameters.append(Parameter(
                name=param_name,
                location='form',
                source_url=source_url
            ))
        
        return parameters
    
    def _extract_javascript_parameters(self, html: str, source_url: str) -> List[Parameter]:
        """Extract parameters from JavaScript code"""
        parameters = []
        
        # Common patterns for parameters in JavaScript
        patterns = [
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']',  # Object properties
            r'\.get\(["\']([^"\']+)["\']',  # .get('param')
            r'\.set\(["\']([^"\']+)["\']',  # .set('param')
            r'\?([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL parameters
            r'&([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL parameters
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html):
                param_name = match.group(1)
                # Filter out common non-parameter words
                if len(param_name) > 2 and param_name not in ['var', 'let', 'const', 'function']:
                    parameters.append(Parameter(
                        name=param_name,
                        location='javascript',
                        source_url=source_url
                    ))
        
        return parameters
    
    async def _fuzz_parameters(
        self, target: TargetConfig, param_names: List[str]
    ) -> List[Parameter]:
        """Fuzz common parameter names to discover hidden parameters"""
        discovered = []
        
        # Test each parameter name
        for param_name in param_names:
            try:
                # Add parameter to URL
                separator = '&' if '?' in target.url else '?'
                test_url = f"{target.url}{separator}{param_name}=test"
                
                response = await self.request_handler.send_request(
                    method='GET',
                    url=test_url,
                    headers=target.custom_headers,
                    proxy=target.proxy,
                    timeout=5.0
                )
                
                # Check if parameter had an effect (different response)
                # This is a simple heuristic - could be improved
                if response.status_code == 200:
                    discovered.append(Parameter(
                        name=param_name,
                        location='url',
                        example_value='test',
                        source_url=test_url
                    ))
            
            except Exception:
                continue  # Ignore errors for individual tests
        
        return discovered
    
    async def analyze_javascript(
        self, target: TargetConfig
    ) -> Dict[str, any]:
        """
        Extract and analyze JavaScript files for endpoints and sensitive data.
        
        Args:
            target: Target configuration
            
        Returns:
            Dictionary containing:
            - js_files: List of JavaScript file URLs
            - endpoints: List of discovered endpoints
            - api_keys: List of potential API keys
            - tokens: List of potential tokens
            - comments: List of sensitive comments
        """
        result = {
            'js_files': [],
            'endpoints': [],
            'api_keys': [],
            'tokens': [],
            'comments': []
        }
        
        try:
            # Fetch the main page
            response = await self.request_handler.send_request(
                method='GET',
                url=target.url,
                headers=target.custom_headers,
                proxy=target.proxy
            )
            
            html = response.text
            
            # 1. Extract all JavaScript file URLs
            js_files = self._extract_javascript_files(html, target.url)
            result['js_files'] = js_files
            
            # 2. Fetch and analyze each JavaScript file
            for js_url in js_files:
                try:
                    js_response = await self.request_handler.send_request(
                        method='GET',
                        url=js_url,
                        headers=target.custom_headers,
                        proxy=target.proxy,
                        timeout=10.0
                    )
                    
                    js_content = js_response.text
                    
                    # Extract endpoints
                    endpoints = self._extract_endpoints_from_js(js_content, js_url)
                    result['endpoints'].extend(endpoints)
                    
                    # Extract API keys
                    api_keys = self._extract_api_keys(js_content)
                    result['api_keys'].extend(api_keys)
                    
                    # Extract tokens
                    tokens = self._extract_tokens(js_content)
                    result['tokens'].extend(tokens)
                    
                    # Extract sensitive comments
                    comments = self._extract_sensitive_comments(js_content)
                    result['comments'].extend(comments)
                
                except Exception:
                    continue  # Skip files that fail to load
        
        except Exception as e:
            raise RuntimeError(f"Error during JavaScript analysis: {str(e)}")
        
        return result
    
    def _extract_javascript_files(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_files = []
        
        # Find script tags with src attribute
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        for match in re.finditer(script_pattern, html, re.IGNORECASE):
            js_url = match.group(1)
            
            # Convert relative URLs to absolute
            if not js_url.startswith('http'):
                js_url = urljoin(base_url, js_url)
            
            js_files.append(js_url)
        
        return js_files
    
    def _extract_endpoints_from_js(self, js_content: str, source_file: str) -> List[JavaScriptEndpoint]:
        """Extract API endpoints from JavaScript content"""
        endpoints = []
        
        # Patterns for API endpoints
        patterns = [
            r'["\']([/a-zA-Z0-9_-]+/api/[^"\']+)["\']',  # /api/ paths
            r'["\']([/a-zA-Z0-9_-]+/v\d+/[^"\']+)["\']',  # /v1/, /v2/ paths
            r'fetch\(["\']([^"\']+)["\']',  # fetch() calls
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',  # axios calls
            r'\$\.ajax\(["\']([^"\']+)["\']',  # jQuery ajax
            r'XMLHttpRequest.*open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',  # XHR
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content):
                url = match.group(1)
                
                # Filter out non-endpoint URLs
                if url.startswith('/') or 'api' in url.lower():
                    endpoint = JavaScriptEndpoint(
                        url=url,
                        source_file=source_file
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_api_keys(self, js_content: str) -> List[str]:
        """Extract potential API keys from JavaScript"""
        api_keys = []
        
        # Patterns for API keys
        patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'apikey["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'api[_-]?secret["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'client[_-]?id["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'client[_-]?secret["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                key = match.group(1) if match.lastindex else match.group(0)
                api_keys.append(key)
        
        return api_keys
    
    def _extract_tokens(self, js_content: str) -> List[str]:
        """Extract potential tokens from JavaScript"""
        tokens = []
        
        # Patterns for tokens
        patterns = [
            r'token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'auth["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'bearer["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            r'jwt["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                token = match.group(1)
                tokens.append(token)
        
        return tokens
    
    def _extract_sensitive_comments(self, js_content: str) -> List[str]:
        """Extract sensitive comments from JavaScript"""
        comments = []
        
        # Extract single-line comments
        single_line_pattern = r'//\s*(.+)$'
        for match in re.finditer(single_line_pattern, js_content, re.MULTILINE):
            comment = match.group(1).strip()
            
            # Check if comment contains sensitive keywords
            sensitive_keywords = ['todo', 'fixme', 'hack', 'bug', 'password', 'secret', 'key', 'token']
            if any(keyword in comment.lower() for keyword in sensitive_keywords):
                comments.append(comment)
        
        # Extract multi-line comments
        multi_line_pattern = r'/\*(.+?)\*/'
        for match in re.finditer(multi_line_pattern, js_content, re.DOTALL):
            comment = match.group(1).strip()
            
            # Check if comment contains sensitive keywords
            if any(keyword in comment.lower() for keyword in sensitive_keywords):
                comments.append(comment)
        
        return comments
    
    async def scan_wordpress(self, target: TargetConfig) -> CMSScanResult:
        """
        Execute WPScan for WordPress vulnerability scanning.
        
        Args:
            target: Target configuration
            
        Returns:
            CMSScanResult with WordPress vulnerabilities and enumeration
        """
        result = CMSScanResult(cms_type='wordpress')
        
        try:
            # Build WPScan command
            cmd = [
                'wpscan',
                '--url', target.url,
                '--format', 'json',
                '--no-banner',
                '--no-update',
                '--enumerate', 'vp,vt,u',  # Vulnerable plugins, themes, users
            ]
            
            # Add proxy if configured
            if target.proxy:
                cmd.extend(['--proxy', target.proxy])
            
            # Add custom headers if configured
            if target.custom_headers:
                for key, value in target.custom_headers.items():
                    cmd.extend(['--headers', f'{key}: {value}'])
            
            # Execute WPScan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode not in [0, 4]:  # 0 = success, 4 = vulnerabilities found
                result.error = f"WPScan execution failed: {stderr.decode()}"
                return result
            
            # Parse JSON output
            output = stdout.decode()
            result.raw_output = output
            
            try:
                data = json.loads(output)
                
                # Extract WordPress version
                if 'version' in data:
                    version_data = data['version']
                    if 'number' in version_data:
                        result.version = version_data['number']
                    
                    # Check for version vulnerabilities
                    if 'vulnerabilities' in version_data:
                        for vuln in version_data['vulnerabilities']:
                            result.vulnerabilities.append(self._parse_wpscan_vulnerability(vuln))
                
                # Extract plugins
                if 'plugins' in data:
                    for plugin_slug, plugin_data in data['plugins'].items():
                        plugin_info = {
                            'name': plugin_slug,
                            'version': plugin_data.get('version', {}).get('number'),
                            'location': plugin_data.get('location'),
                            'vulnerabilities': []
                        }
                        
                        # Check for plugin vulnerabilities
                        if 'vulnerabilities' in plugin_data:
                            for vuln in plugin_data['vulnerabilities']:
                                vuln_obj = self._parse_wpscan_vulnerability(vuln)
                                vuln_obj.affected_component = f"Plugin: {plugin_slug}"
                                plugin_info['vulnerabilities'].append(vuln_obj)
                                result.vulnerabilities.append(vuln_obj)
                        
                        result.plugins.append(plugin_info)
                
                # Extract themes
                if 'themes' in data:
                    for theme_slug, theme_data in data['themes'].items():
                        theme_info = {
                            'name': theme_slug,
                            'version': theme_data.get('version', {}).get('number'),
                            'location': theme_data.get('location'),
                            'vulnerabilities': []
                        }
                        
                        # Check for theme vulnerabilities
                        if 'vulnerabilities' in theme_data:
                            for vuln in theme_data['vulnerabilities']:
                                vuln_obj = self._parse_wpscan_vulnerability(vuln)
                                vuln_obj.affected_component = f"Theme: {theme_slug}"
                                theme_info['vulnerabilities'].append(vuln_obj)
                                result.vulnerabilities.append(vuln_obj)
                        
                        result.themes.append(theme_info)
                
                # Extract users
                if 'users' in data:
                    for user_id, user_data in data['users'].items():
                        username = user_data.get('username', user_id)
                        result.users.append(username)
                
                # Check for configuration issues
                if 'interesting_findings' in data:
                    for finding in data['interesting_findings']:
                        if 'to_s' in finding:
                            result.config_issues.append(finding['to_s'])
                        elif 'url' in finding:
                            result.config_issues.append(finding['url'])
            
            except json.JSONDecodeError as e:
                result.error = f"Failed to parse WPScan output: {str(e)}"
        
        except FileNotFoundError:
            result.error = "WPScan not found. Please install WPScan: gem install wpscan"
        except Exception as e:
            result.error = f"Unexpected error during WPScan execution: {str(e)}"
        
        return result
    
    def _parse_wpscan_vulnerability(self, vuln_data: dict) -> CMSVulnerability:
        """Parse WPScan vulnerability data"""
        vuln = CMSVulnerability(
            title=vuln_data.get('title', 'Unknown Vulnerability'),
            severity='medium',  # WPScan doesn't always provide severity
            description=''
        )
        
        # Extract CVE ID
        if 'cve' in vuln_data:
            vuln.cve_id = vuln_data['cve']
        
        # Extract references
        if 'references' in vuln_data:
            refs = vuln_data['references']
            if isinstance(refs, dict):
                for ref_type, ref_urls in refs.items():
                    if isinstance(ref_urls, list):
                        vuln.references.extend(ref_urls)
                    else:
                        vuln.references.append(str(ref_urls))
            elif isinstance(refs, list):
                vuln.references.extend(refs)
        
        # Extract fixed version
        if 'fixed_in' in vuln_data:
            vuln.fixed_in = vuln_data['fixed_in']
        
        return vuln
    
    async def scan_drupal(self, target: TargetConfig) -> CMSScanResult:
        """
        Execute Droopescan for Drupal vulnerability scanning.
        
        Args:
            target: Target configuration
            
        Returns:
            CMSScanResult with Drupal vulnerabilities and enumeration
        """
        result = CMSScanResult(cms_type='drupal')
        
        try:
            # Build Droopescan command
            cmd = [
                'droopescan',
                'scan', 'drupal',
                '-u', target.url,
                '--output', 'json',
            ]
            
            # Add custom headers if configured
            if target.custom_headers:
                # Droopescan doesn't have direct header support, but we can use user-agent
                if 'user-agent' in target.custom_headers:
                    cmd.extend(['--user-agent', target.custom_headers['user-agent']])
            
            # Execute Droopescan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                result.error = f"Droopescan execution failed: {stderr.decode()}"
                return result
            
            # Parse JSON output
            output = stdout.decode()
            result.raw_output = output
            
            try:
                data = json.loads(output)
                
                # Extract Drupal version
                if 'version' in data:
                    version_info = data['version']
                    if isinstance(version_info, list) and version_info:
                        result.version = version_info[0]
                    elif isinstance(version_info, str):
                        result.version = version_info
                
                # Extract plugins/modules
                if 'plugins' in data:
                    plugins_data = data['plugins']
                    if isinstance(plugins_data, dict):
                        for plugin_name, plugin_info in plugins_data.items():
                            plugin_entry = {
                                'name': plugin_name,
                                'version': None,
                                'vulnerabilities': []
                            }
                            
                            if isinstance(plugin_info, dict):
                                if 'version' in plugin_info:
                                    plugin_entry['version'] = plugin_info['version']
                            
                            result.plugins.append(plugin_entry)
                
                # Extract themes
                if 'themes' in data:
                    themes_data = data['themes']
                    if isinstance(themes_data, dict):
                        for theme_name, theme_info in themes_data.items():
                            theme_entry = {
                                'name': theme_name,
                                'version': None,
                                'vulnerabilities': []
                            }
                            
                            if isinstance(theme_info, dict):
                                if 'version' in theme_info:
                                    theme_entry['version'] = theme_info['version']
                            
                            result.themes.append(theme_entry)
                
                # Extract interesting URLs/findings
                if 'interesting_urls' in data:
                    urls = data['interesting_urls']
                    if isinstance(urls, list):
                        for url in urls:
                            result.config_issues.append(f"Interesting URL: {url}")
                
                # Check for known vulnerabilities based on version
                if result.version:
                    drupal_vulns = self._get_drupal_vulnerabilities(result.version)
                    result.vulnerabilities.extend(drupal_vulns)
            
            except json.JSONDecodeError as e:
                result.error = f"Failed to parse Droopescan output: {str(e)}"
        
        except FileNotFoundError:
            result.error = "Droopescan not found. Please install Droopescan: pip install droopescan"
        except Exception as e:
            result.error = f"Unexpected error during Droopescan execution: {str(e)}"
        
        return result
    
    def _get_drupal_vulnerabilities(self, version: str) -> List[CMSVulnerability]:
        """Get known Drupal vulnerabilities for a specific version"""
        vulnerabilities = []
        
        # Known Drupal vulnerabilities
        drupal_vulns = {
            '7': [
                CMSVulnerability(
                    title='Drupalgeddon - SQL Injection',
                    severity='critical',
                    description='SQL injection vulnerability in Drupal 7.x before 7.32',
                    cve_id='CVE-2014-3704',
                    references=['https://www.drupal.org/SA-CORE-2014-005'],
                    fixed_in='7.32'
                ),
                CMSVulnerability(
                    title='Drupalgeddon 2 - Remote Code Execution',
                    severity='critical',
                    description='Remote code execution vulnerability in Drupal 7.x before 7.58',
                    cve_id='CVE-2018-7600',
                    references=['https://www.drupal.org/SA-CORE-2018-002'],
                    fixed_in='7.58'
                ),
            ],
            '8': [
                CMSVulnerability(
                    title='Drupalgeddon 2 - Remote Code Execution',
                    severity='critical',
                    description='Remote code execution vulnerability in Drupal 8.x before 8.5.1',
                    cve_id='CVE-2018-7600',
                    references=['https://www.drupal.org/SA-CORE-2018-002'],
                    fixed_in='8.5.1'
                ),
            ],
        }
        
        # Match version to vulnerabilities
        major_version = version.split('.')[0] if '.' in version else version
        if major_version in drupal_vulns:
            vulnerabilities.extend(drupal_vulns[major_version])
        
        return vulnerabilities
    
    async def scan_joomla(self, target: TargetConfig) -> CMSScanResult:
        """
        Execute JoomScan for Joomla vulnerability scanning.
        
        Args:
            target: Target configuration
            
        Returns:
            CMSScanResult with Joomla vulnerabilities and enumeration
        """
        result = CMSScanResult(cms_type='joomla')
        
        try:
            # Build JoomScan command
            # Note: JoomScan is typically a Perl script
            cmd = [
                'joomscan',
                '--url', target.url,
                '--enumerate-components',
            ]
            
            # Execute JoomScan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                result.error = f"JoomScan execution failed: {stderr.decode()}"
                return result
            
            # Parse text output (JoomScan doesn't have JSON output)
            output = stdout.decode()
            result.raw_output = output
            
            # Extract Joomla version
            version_match = re.search(r'Joomla Version\s*:\s*([\d.]+)', output, re.IGNORECASE)
            if version_match:
                result.version = version_match.group(1)
            
            # Extract components
            component_section = False
            for line in output.split('\n'):
                if 'Components' in line or 'Extensions' in line:
                    component_section = True
                    continue
                
                if component_section:
                    # Look for component names
                    comp_match = re.search(r'com_([a-zA-Z0-9_]+)', line)
                    if comp_match:
                        component_name = comp_match.group(1)
                        result.plugins.append({
                            'name': f"com_{component_name}",
                            'version': None,
                            'vulnerabilities': []
                        })
            
            # Extract configuration issues
            if 'directory listing' in output.lower():
                result.config_issues.append('Directory listing enabled')
            
            if 'backup files' in output.lower():
                result.config_issues.append('Backup files found')
            
            if 'configuration.php' in output.lower():
                result.config_issues.append('Configuration file accessible')
            
            # Check for known vulnerabilities based on version
            if result.version:
                joomla_vulns = self._get_joomla_vulnerabilities(result.version)
                result.vulnerabilities.extend(joomla_vulns)
        
        except FileNotFoundError:
            result.error = "JoomScan not found. Please install JoomScan from https://github.com/OWASP/joomscan"
        except Exception as e:
            result.error = f"Unexpected error during JoomScan execution: {str(e)}"
        
        return result
    
    def _get_joomla_vulnerabilities(self, version: str) -> List[CMSVulnerability]:
        """Get known Joomla vulnerabilities for a specific version"""
        vulnerabilities = []
        
        # Known Joomla vulnerabilities
        joomla_vulns = {
            '3.4': [
                CMSVulnerability(
                    title='Joomla Object Injection - Remote Code Execution',
                    severity='critical',
                    description='Object injection vulnerability in Joomla 3.4.5 and earlier',
                    cve_id='CVE-2015-8562',
                    references=['https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html'],
                    fixed_in='3.4.6'
                ),
            ],
            '3.7': [
                CMSVulnerability(
                    title='Joomla SQL Injection',
                    severity='high',
                    description='SQL injection vulnerability in Joomla 3.7.0',
                    cve_id='CVE-2017-8917',
                    references=['https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html'],
                    fixed_in='3.7.1'
                ),
            ],
        }
        
        # Match version to vulnerabilities
        version_prefix = '.'.join(version.split('.')[:2]) if '.' in version else version
        if version_prefix in joomla_vulns:
            vulnerabilities.extend(joomla_vulns[version_prefix])
        
        return vulnerabilities
    
    async def detect_and_scan_cms(self, target: TargetConfig) -> Optional[CMSScanResult]:
        """
        Detect CMS type and automatically run appropriate scanner.
        
        Args:
            target: Target configuration
            
        Returns:
            CMSScanResult if CMS detected, None otherwise
        """
        # First, fingerprint to detect CMS
        wappalyzer_result = await self.fingerprint_wappalyzer(target)
        
        # Check detected technologies for CMS
        cms_type = None
        for tech in wappalyzer_result.technologies:
            if 'wordpress' in tech.name.lower():
                cms_type = 'wordpress'
                break
            elif 'drupal' in tech.name.lower():
                cms_type = 'drupal'
                break
            elif 'joomla' in tech.name.lower():
                cms_type = 'joomla'
                break
        
        # Run appropriate scanner
        if cms_type == 'wordpress':
            return await self.scan_wordpress(target)
        elif cms_type == 'drupal':
            return await self.scan_drupal(target)
        elif cms_type == 'joomla':
            return await self.scan_joomla(target)
        
        return None
    
    async def cross_reference_cve(
        self,
        cve_id: str,
        include_exploits: bool = True
    ) -> Dict[str, any]:
        """
        Cross-reference CVE with databases for additional information.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-12345)
            include_exploits: Whether to check for exploit availability
            
        Returns:
            Dictionary containing CVE details and exploit information
        """
        result = {
            'cve_id': cve_id,
            'description': None,
            'cvss_score': None,
            'severity': None,
            'published_date': None,
            'references': [],
            'exploits': [],
            'error': None
        }
        
        try:
            # Query NVD (National Vulnerability Database) API
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            
            try:
                response = await self.request_handler.send_request(
                    method='GET',
                    url=nvd_url,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = json.loads(response.text)
                    
                    if 'vulnerabilities' in data and data['vulnerabilities']:
                        vuln_data = data['vulnerabilities'][0]['cve']
                        
                        # Extract description
                        if 'descriptions' in vuln_data:
                            for desc in vuln_data['descriptions']:
                                if desc.get('lang') == 'en':
                                    result['description'] = desc.get('value')
                                    break
                        
                        # Extract CVSS score
                        if 'metrics' in vuln_data:
                            metrics = vuln_data['metrics']
                            
                            # Try CVSS v3 first
                            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                result['cvss_score'] = cvss_data.get('baseScore')
                                result['severity'] = cvss_data.get('baseSeverity', '').lower()
                            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                                result['cvss_score'] = cvss_data.get('baseScore')
                                result['severity'] = cvss_data.get('baseSeverity', '').lower()
                            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                result['cvss_score'] = cvss_data.get('baseScore')
                                # Map CVSS v2 score to severity
                                score = cvss_data.get('baseScore', 0)
                                if score >= 7.0:
                                    result['severity'] = 'high'
                                elif score >= 4.0:
                                    result['severity'] = 'medium'
                                else:
                                    result['severity'] = 'low'
                        
                        # Extract published date
                        if 'published' in vuln_data:
                            result['published_date'] = vuln_data['published']
                        
                        # Extract references
                        if 'references' in vuln_data:
                            for ref in vuln_data['references']:
                                if 'url' in ref:
                                    result['references'].append(ref['url'])
            
            except Exception as e:
                result['error'] = f"Failed to query NVD: {str(e)}"
            
            # Check for exploits if requested
            if include_exploits:
                exploits = await self._check_exploit_availability(cve_id)
                result['exploits'] = exploits
        
        except Exception as e:
            result['error'] = f"Error during CVE cross-reference: {str(e)}"
        
        return result
    
    async def _check_exploit_availability(self, cve_id: str) -> List[Dict[str, str]]:
        """Check for exploit availability in various databases"""
        exploits = []
        
        try:
            # Check Exploit-DB
            # Note: This is a simplified check. In production, you'd use the Exploit-DB API
            exploitdb_search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
            
            try:
                response = await self.request_handler.send_request(
                    method='GET',
                    url=exploitdb_search_url,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    # Parse HTML to find exploits
                    # This is a simplified version - in production, use proper HTML parsing
                    if 'exploit' in response.text.lower() and cve_id in response.text:
                        exploits.append({
                            'source': 'Exploit-DB',
                            'url': exploitdb_search_url,
                            'type': 'Public Exploit'
                        })
            
            except Exception:
                pass  # Non-critical
            
            # Check Metasploit modules
            # In a real implementation, you'd query the Metasploit database
            # For now, we'll add a placeholder
            metasploit_url = f"https://www.rapid7.com/db/?q={cve_id}&type=metasploit"
            exploits.append({
                'source': 'Metasploit Database',
                'url': metasploit_url,
                'type': 'Check for Metasploit modules'
            })
            
            # Check GitHub for PoC exploits
            github_search_url = f"https://github.com/search?q={cve_id}+exploit&type=repositories"
            exploits.append({
                'source': 'GitHub',
                'url': github_search_url,
                'type': 'Search for PoC exploits'
            })
        
        except Exception:
            pass  # Non-critical
        
        return exploits
    
    async def enrich_vulnerabilities_with_cve(
        self,
        cms_result: CMSScanResult
    ) -> CMSScanResult:
        """
        Enrich CMS scan results with CVE information.
        
        Args:
            cms_result: CMS scan result to enrich
            
        Returns:
            Enriched CMS scan result
        """
        for vuln in cms_result.vulnerabilities:
            if vuln.cve_id:
                try:
                    cve_info = await self.cross_reference_cve(vuln.cve_id)
                    
                    # Update vulnerability with CVE information
                    if cve_info['description'] and not vuln.description:
                        vuln.description = cve_info['description']
                    
                    if cve_info['severity'] and vuln.severity == 'medium':
                        vuln.severity = cve_info['severity']
                    
                    if cve_info['references']:
                        vuln.references.extend(cve_info['references'])
                    
                    # Add exploit information to references
                    for exploit in cve_info['exploits']:
                        vuln.references.append(f"{exploit['source']}: {exploit['url']}")
                
                except Exception:
                    continue  # Skip if CVE lookup fails
        
        return cms_result
