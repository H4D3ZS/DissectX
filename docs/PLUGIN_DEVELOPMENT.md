# DissectX Plugin Development Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Plugin System Overview](#plugin-system-overview)
3. [Getting Started](#getting-started)
4. [Plugin Types](#plugin-types)
5. [Creating Your First Plugin](#creating-your-first-plugin)
6. [Advanced Plugin Features](#advanced-plugin-features)
7. [Plugin API Reference](#plugin-api-reference)
8. [Best Practices](#best-practices)
9. [Testing Plugins](#testing-plugins)
10. [Troubleshooting](#troubleshooting)
11. [Examples](#examples)

---

## Introduction

The DissectX plugin system allows you to extend the framework with custom analyzers, output formats, and hooks without modifying the core codebase. This guide will walk you through creating, testing, and deploying plugins.

### What Can Plugins Do?

- **Custom Analysis**: Perform specialized analysis on binary data
- **Output Formats**: Define new ways to present analysis results
- **Workflow Hooks**: Execute code at specific points in the analysis pipeline
- **Integration**: Connect DissectX with external tools and services

### Why Use Plugins?

- **Extensibility**: Add features without modifying core code
- **Modularity**: Keep custom logic separate and maintainable
- **Reusability**: Share plugins across projects and teams
- **Experimentation**: Try new analysis techniques safely

---

## Plugin System Overview

### Architecture

```
┌─────────────────────────────────────────┐
│         DissectX Core                    │
│  ┌───────────────────────────────────┐  │
│  │    Plugin Manager                 │  │
│  │  - Discovery                      │  │
│  │  - Loading                        │  │
│  │  - Hook Management                │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐    ┌───▼───┐    ┌───▼───┐
│Plugin │    │Plugin │    │Plugin │
│   1   │    │   2   │    │   3   │
└───────┘    └───────┘    └───────┘
```

### Plugin Lifecycle

1. **Discovery**: PluginManager scans `plugins/` directory
2. **Loading**: Python modules are imported dynamically
3. **Instantiation**: Plugin classes are instantiated
4. **Registration**: Plugins register hooks and capabilities
5. **Execution**: Plugins are invoked during analysis
6. **Cleanup**: Resources are released when done

### Hook Points

Plugins can hook into these analysis stages:

- `PRE_ANALYSIS`: Before analysis begins
- `POST_ANALYSIS`: After analysis completes
- `PRE_DISASSEMBLY`: Before disassembly
- `POST_DISASSEMBLY`: After disassembly

---

## Getting Started

### Prerequisites

- Python 3.7 or higher
- DissectX installed and working
- Basic understanding of Python classes and inheritance

### Plugin Directory Structure

```
dissectx/
├── plugins/
│   ├── __init__.py
│   ├── my_plugin.py          # Your plugin
│   ├── example_analyzer_plugin.py
│   └── example_format_plugin.py
├── src/
│   └── plugins/
│       ├── __init__.py
│       └── plugin_manager.py  # Plugin system core
└── main.py
```

### Minimal Plugin Template

```python
from src.plugins import Plugin
from typing import Dict, Any

class MyPlugin(Plugin):
    def get_name(self) -> str:
        return "MyPlugin"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Your analysis logic here
        return {"status": "success"}
```

---

## Plugin Types

### 1. Analyzer Plugins

Analyzer plugins perform custom analysis on binary data.

**Use Cases**:
- String pattern detection
- Cryptographic constant identification
- Custom signature matching
- Statistical analysis

**Example**:
```python
class CustomAnalyzer(Plugin):
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Perform analysis
        results = self.find_patterns(binary_data)
        return {"patterns": results}
```

### 2. Format Plugins

Format plugins define custom output formats for analysis results.

**Use Cases**:
- JSON/XML export
- Custom report templates
- Integration with external tools
- Database export

**Example**:
```python
class JSONFormatter(Plugin):
    def format(self, analysis_results: Dict[str, Any]) -> str:
        import json
        return json.dumps(analysis_results, indent=2)
```

### 3. Hook Plugins

Hook plugins execute code at specific points in the analysis workflow.

**Use Cases**:
- Logging and monitoring
- Pre-processing binary data
- Post-processing results
- Integration with CI/CD pipelines

**Example**:
```python
def pre_analysis_hook(context: dict) -> dict:
    print(f"Starting analysis: {context['binary_path']}")
    context['start_time'] = time.time()
    return context
```

---

## Creating Your First Plugin

### Step 1: Create Plugin File

Create a new file in the `plugins/` directory:

```bash
touch plugins/my_first_plugin.py
```

### Step 2: Import Required Modules

```python
from src.plugins import Plugin
from typing import Dict, Any
import re
```

### Step 3: Define Plugin Class

```python
class EmailExtractor(Plugin):
    """Extract email addresses from binary data."""
    
    def get_name(self) -> str:
        return "EmailExtractor"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "Extracts email addresses from binary data"
    
    def get_author(self) -> str:
        return "Your Name"
```

### Step 4: Implement Analysis Logic

```python
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """Extract email addresses from binary data."""
        # Convert binary to string (ignore errors)
        text = binary_data.decode('utf-8', errors='ignore')
        
        # Email regex pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        
        # Find all emails
        emails = re.findall(email_pattern, text)
        
        # Remove duplicates
        unique_emails = list(set(emails))
        
        return {
            "analyzer": self.get_name(),
            "total_emails": len(unique_emails),
            "emails": unique_emails
        }
```

### Step 5: Test Your Plugin

```python
# test_plugin.py
from plugins.my_first_plugin import EmailExtractor

# Test data
test_data = b"Contact us at support@example.com or admin@test.org"

# Create plugin instance
plugin = EmailExtractor()

# Run analysis
results = plugin.analyze(test_data)

# Print results
print(f"Found {results['total_emails']} emails:")
for email in results['emails']:
    print(f"  - {email}")
```

### Step 6: Use Plugin with DissectX

```python
from src.plugins import PluginManager

# Initialize plugin manager
pm = PluginManager()

# Load all plugins
pm.load_all_plugins()

# Get your plugin
email_plugin = pm.get_plugin_by_name("EmailExtractor")

# Analyze binary
with open("binary.exe", "rb") as f:
    binary_data = f.read()

results = email_plugin.analyze(binary_data)
print(results)
```

---

## Advanced Plugin Features

### Using Hooks

Hooks allow you to execute code at specific points in the analysis workflow.

#### Registering a Hook

```python
from src.plugins import PluginManager, HookType

def my_pre_analysis_hook(context: dict) -> dict:
    """Hook that runs before analysis."""
    print(f"[PRE] Analyzing: {context.get('binary_path')}")
    
    # Add custom data to context
    context['custom_flag'] = True
    context['start_time'] = time.time()
    
    return context

def my_post_analysis_hook(context: dict) -> dict:
    """Hook that runs after analysis."""
    elapsed = time.time() - context.get('start_time', 0)
    print(f"[POST] Analysis completed in {elapsed:.2f}s")
    
    return context

# Register hooks
pm = PluginManager()
pm.register_hook(HookType.PRE_ANALYSIS, my_pre_analysis_hook)
pm.register_hook(HookType.POST_ANALYSIS, my_post_analysis_hook)
```

#### Hook Context

The context dictionary contains:

```python
context = {
    'binary_path': str,      # Path to binary being analyzed
    'binary_data': bytes,    # Binary data
    'options': dict,         # Analysis options
    'results': dict,         # Analysis results (POST hooks only)
}
```

### Custom Output Formats

Create custom formatters for analysis results:

```python
class XMLFormatter(Plugin):
    """Format analysis results as XML."""
    
    def get_name(self) -> str:
        return "XMLFormatter"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Not used for formatters
        return {}
    
    def format(self, analysis_results: Dict[str, Any]) -> str:
        """Format results as XML."""
        xml = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml.append('<analysis>')
        
        # Format binary info
        if 'binary_info' in analysis_results:
            xml.append('  <binary_info>')
            for key, value in analysis_results['binary_info'].items():
                xml.append(f'    <{key}>{value}</{key}>')
            xml.append('  </binary_info>')
        
        # Format functions
        if 'functions' in analysis_results:
            xml.append('  <functions>')
            for addr, func in analysis_results['functions'].items():
                xml.append(f'    <function address="{addr}">')
                for key, value in func.items():
                    xml.append(f'      <{key}>{value}</{key}>')
                xml.append('    </function>')
            xml.append('  </functions>')
        
        xml.append('</analysis>')
        return '\n'.join(xml)

# Register the formatter
pm = PluginManager()
formatter = XMLFormatter()
pm.register_format('xml', formatter.format)

# Use the formatter
results = {...}  # Analysis results
xml_output = pm.get_custom_formats()['xml'](results)
```

### Accessing DissectX Components

Plugins can access DissectX components:

```python
class AdvancedAnalyzer(Plugin):
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Import DissectX components
        from src.capstone_disassembler import CapstoneDisassembler
        from src.xref_analyzer import XREFAnalyzer
        
        # Use Capstone for disassembly
        disasm = CapstoneDisassembler(arch='x86', mode='64')
        instructions = disasm.disassemble(binary_data, 0x1000)
        
        # Use XREF analyzer
        xref = XREFAnalyzer()
        xref_db = xref.analyze(instructions)
        
        return {
            "instruction_count": len(instructions),
            "xrefs": len(xref_db.function_calls)
        }
```

### Configuration Files

Plugins can use configuration files:

```python
import json
from pathlib import Path

class ConfigurablePlugin(Plugin):
    def __init__(self):
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load plugin configuration."""
        config_path = Path(__file__).parent / 'my_plugin_config.json'
        
        if config_path.exists():
            with open(config_path) as f:
                return json.load(f)
        
        # Default configuration
        return {
            "enabled": True,
            "threshold": 0.8,
            "patterns": []
        }
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        if not self.config['enabled']:
            return {"status": "disabled"}
        
        # Use configuration
        threshold = self.config['threshold']
        patterns = self.config['patterns']
        
        # Perform analysis...
        return {"status": "success"}
```

---

## Plugin API Reference

### Plugin Base Class

```python
class Plugin(ABC):
    """Abstract base class for all plugins."""
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the plugin name."""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return the plugin version (semantic versioning)."""
        pass
    
    @abstractmethod
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Perform analysis on binary data.
        
        Args:
            binary_data: Raw binary data to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    def get_description(self) -> str:
        """Return plugin description (optional)."""
        return ""
    
    def get_author(self) -> str:
        """Return plugin author (optional)."""
        return ""
```

### PluginManager Class

```python
class PluginManager:
    """Manages plugin discovery, loading, and execution."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        """Initialize with plugin directory."""
        pass
    
    def discover_plugins(self, plugin_dir: Optional[str] = None) -> List[str]:
        """Discover plugin files in directory."""
        pass
    
    def load_plugin(self, plugin_path: str) -> Optional[Plugin]:
        """Load a single plugin from file path."""
        pass
    
    def load_all_plugins(self, plugin_dir: Optional[str] = None) -> int:
        """Load all plugins from directory."""
        pass
    
    def register_hook(self, hook_type: HookType, handler: Callable) -> None:
        """Register a hook handler."""
        pass
    
    def execute_hooks(self, hook_type: HookType, context: Dict) -> Dict:
        """Execute all hooks of a specific type."""
        pass
    
    def register_analyzer(self, plugin: Plugin) -> None:
        """Register plugin as custom analyzer."""
        pass
    
    def register_format(self, format_name: str, formatter: Callable) -> None:
        """Register custom output format."""
        pass
    
    def get_plugins(self) -> List[Plugin]:
        """Get all loaded plugins."""
        pass
    
    def get_plugin_by_name(self, name: str) -> Optional[Plugin]:
        """Get plugin by name."""
        pass
```

### HookType Enum

```python
class HookType(Enum):
    """Available hook types."""
    PRE_ANALYSIS = "pre_analysis"
    POST_ANALYSIS = "post_analysis"
    PRE_DISASSEMBLY = "pre_disassembly"
    POST_DISASSEMBLY = "post_disassembly"
```

---

## Best Practices

### 1. Plugin Design

**Keep Plugins Focused**
```python
# Good: Single responsibility
class FlagDetector(Plugin):
    """Detects CTF flags in binary data."""
    pass

# Bad: Multiple responsibilities
class EverythingAnalyzer(Plugin):
    """Detects flags, extracts strings, finds vulnerabilities..."""
    pass
```

**Use Descriptive Names**
```python
# Good
class Base64StringDecoder(Plugin):
    pass

# Bad
class Plugin1(Plugin):
    pass
```

### 2. Error Handling

**Always Handle Errors Gracefully**
```python
def analyze(self, binary_data: bytes) -> Dict[str, Any]:
    try:
        # Analysis logic
        results = self.perform_analysis(binary_data)
        return {"status": "success", "results": results}
    
    except ValueError as e:
        return {"status": "error", "message": f"Invalid data: {e}"}
    
    except Exception as e:
        return {"status": "error", "message": f"Analysis failed: {e}"}
```

### 3. Performance

**Optimize for Large Binaries**
```python
def analyze(self, binary_data: bytes) -> Dict[str, Any]:
    # Process in chunks for large files
    chunk_size = 1024 * 1024  # 1MB chunks
    
    results = []
    for i in range(0, len(binary_data), chunk_size):
        chunk = binary_data[i:i+chunk_size]
        results.extend(self.analyze_chunk(chunk))
    
    return {"results": results}
```

**Use Caching**
```python
from functools import lru_cache

class CachedAnalyzer(Plugin):
    @lru_cache(maxsize=128)
    def expensive_operation(self, data_hash: str):
        # Expensive computation
        pass
```

### 4. Documentation

**Document Your Plugin**
```python
class WellDocumentedPlugin(Plugin):
    """
    Extracts and analyzes cryptographic constants.
    
    This plugin identifies common cryptographic constants such as:
    - AES S-boxes
    - SHA round constants
    - RSA public exponents
    
    Usage:
        plugin = WellDocumentedPlugin()
        results = plugin.analyze(binary_data)
    
    Returns:
        Dictionary with keys:
        - 'constants': List of detected constants
        - 'algorithms': List of detected algorithms
        - 'confidence': Confidence score (0.0-1.0)
    """
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Analyze binary data for cryptographic constants.
        
        Args:
            binary_data: Raw binary data to analyze
            
        Returns:
            Dictionary containing:
            - constants: List of detected constants
            - algorithms: List of detected algorithms
            - confidence: Confidence score
            
        Raises:
            ValueError: If binary_data is empty
        """
        pass
```

### 5. Testing

**Write Unit Tests**
```python
# test_my_plugin.py
import pytest
from plugins.my_plugin import MyPlugin

def test_plugin_basic():
    plugin = MyPlugin()
    assert plugin.get_name() == "MyPlugin"
    assert plugin.get_version() == "1.0.0"

def test_plugin_analysis():
    plugin = MyPlugin()
    test_data = b"test data"
    results = plugin.analyze(test_data)
    
    assert "status" in results
    assert results["status"] == "success"

def test_plugin_error_handling():
    plugin = MyPlugin()
    results = plugin.analyze(b"")  # Empty data
    
    assert results["status"] == "error"
```

### 6. Versioning

**Use Semantic Versioning**
```python
def get_version(self) -> str:
    # MAJOR.MINOR.PATCH
    # MAJOR: Breaking changes
    # MINOR: New features (backward compatible)
    # PATCH: Bug fixes
    return "2.1.3"
```

---

## Testing Plugins

### Unit Testing

```python
# test_email_extractor.py
import pytest
from plugins.my_first_plugin import EmailExtractor

class TestEmailExtractor:
    def setup_method(self):
        self.plugin = EmailExtractor()
    
    def test_single_email(self):
        data = b"Contact: test@example.com"
        results = self.plugin.analyze(data)
        
        assert results['total_emails'] == 1
        assert 'test@example.com' in results['emails']
    
    def test_multiple_emails(self):
        data = b"Emails: a@test.com, b@test.com, c@test.com"
        results = self.plugin.analyze(data)
        
        assert results['total_emails'] == 3
    
    def test_no_emails(self):
        data = b"No emails here"
        results = self.plugin.analyze(data)
        
        assert results['total_emails'] == 0
    
    def test_duplicate_emails(self):
        data = b"test@example.com and test@example.com"
        results = self.plugin.analyze(data)
        
        # Should deduplicate
        assert results['total_emails'] == 1
```

### Integration Testing

```python
def test_plugin_integration():
    """Test plugin with PluginManager."""
    from src.plugins import PluginManager
    
    pm = PluginManager()
    pm.load_all_plugins()
    
    # Verify plugin loaded
    plugin = pm.get_plugin_by_name("EmailExtractor")
    assert plugin is not None
    
    # Test analysis
    test_data = b"test@example.com"
    results = plugin.analyze(test_data)
    assert results['total_emails'] == 1
```

### Manual Testing

```bash
# Test plugin directly
python -c "
from plugins.my_first_plugin import EmailExtractor
plugin = EmailExtractor()
results = plugin.analyze(open('binary.exe', 'rb').read())
print(results)
"
```

---

## Troubleshooting

### Plugin Not Loading

**Problem**: Plugin doesn't appear in loaded plugins list

**Solutions**:
1. Check file is in `plugins/` directory
2. Verify class inherits from `Plugin`
3. Ensure all required methods are implemented
4. Check for syntax errors in plugin file

```python
# Debug plugin loading
from src.plugins import PluginManager
import logging

logging.basicConfig(level=logging.DEBUG)
pm = PluginManager()
pm.load_all_plugins()
```

### Import Errors

**Problem**: `ModuleNotFoundError` or `ImportError`

**Solutions**:
1. Add parent directory to Python path:
```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
```

2. Use relative imports:
```python
from ..src.plugins import Plugin
```

### Hook Not Executing

**Problem**: Hook handler not being called

**Solutions**:
1. Verify hook is registered:
```python
pm = PluginManager()
pm.register_hook(HookType.PRE_ANALYSIS, my_hook)
print(pm.hooks[HookType.PRE_ANALYSIS])  # Should show your hook
```

2. Check hook signature:
```python
# Correct signature
def my_hook(context: dict) -> dict:
    return context

# Wrong signature (missing return)
def my_hook(context: dict):
    pass
```

### Performance Issues

**Problem**: Plugin is slow

**Solutions**:
1. Profile your code:
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your plugin code
plugin.analyze(binary_data)

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(10)
```

2. Use generators for large datasets:
```python
def analyze_large_file(self, binary_data: bytes):
    # Instead of loading everything
    results = []
    for chunk in self.chunks(binary_data):
        results.extend(self.analyze_chunk(chunk))
    
    # Use generator
    for chunk in self.chunks(binary_data):
        yield from self.analyze_chunk(chunk)
```

---

## Examples

### Example 1: URL Extractor

```python
from src.plugins import Plugin
from typing import Dict, Any
import re

class URLExtractor(Plugin):
    """Extract URLs from binary data."""
    
    def get_name(self) -> str:
        return "URLExtractor"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        text = binary_data.decode('utf-8', errors='ignore')
        
        # URL regex
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        # Categorize URLs
        categorized = {
            'http': [u for u in urls if u.startswith('http://')],
            'https': [u for u in urls if u.startswith('https://')],
        }
        
        return {
            "total_urls": len(urls),
            "urls": list(set(urls)),
            "categorized": categorized
        }
```

### Example 2: Entropy Calculator

```python
from src.plugins import Plugin
from typing import Dict, Any
import math
from collections import Counter

class EntropyCalculator(Plugin):
    """Calculate Shannon entropy of binary data."""
    
    def get_name(self) -> str:
        return "EntropyCalculator"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        if not binary_data:
            return {"entropy": 0.0}
        
        # Calculate byte frequency
        byte_counts = Counter(binary_data)
        total_bytes = len(binary_data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        
        # Classify entropy
        classification = self.classify_entropy(entropy)
        
        return {
            "entropy": round(entropy, 4),
            "classification": classification,
            "max_entropy": 8.0,
            "percentage": round((entropy / 8.0) * 100, 2)
        }
    
    def classify_entropy(self, entropy: float) -> str:
        """Classify entropy level."""
        if entropy < 3.0:
            return "Low (likely plain text)"
        elif entropy < 5.0:
            return "Medium (mixed content)"
        elif entropy < 7.0:
            return "High (compressed or encrypted)"
        else:
            return "Very High (likely encrypted or random)"
```

### Example 3: Logging Hook

```python
from src.plugins import HookType
import logging
import time

class AnalysisLogger:
    """Log analysis workflow."""
    
    def __init__(self):
        self.logger = logging.getLogger('DissectX.Analysis')
        self.start_times = {}
    
    def pre_analysis_hook(self, context: dict) -> dict:
        """Log start of analysis."""
        binary_path = context.get('binary_path', 'unknown')
        self.logger.info(f"Starting analysis: {binary_path}")
        self.start_times[binary_path] = time.time()
        return context
    
    def post_analysis_hook(self, context: dict) -> dict:
        """Log end of analysis."""
        binary_path = context.get('binary_path', 'unknown')
        start_time = self.start_times.get(binary_path, time.time())
        elapsed = time.time() - start_time
        
        results = context.get('results', {})
        func_count = len(results.get('functions', []))
        string_count = len(results.get('strings', []))
        
        self.logger.info(
            f"Completed analysis: {binary_path} "
            f"({elapsed:.2f}s, {func_count} functions, {string_count} strings)"
        )
        
        return context

# Register hooks
logger = AnalysisLogger()
pm.register_hook(HookType.PRE_ANALYSIS, logger.pre_analysis_hook)
pm.register_hook(HookType.POST_ANALYSIS, logger.post_analysis_hook)
```

---

## Conclusion

The DissectX plugin system provides a powerful way to extend the framework with custom functionality. By following this guide and the best practices outlined, you can create robust, maintainable plugins that enhance DissectX's capabilities.

### Next Steps

1. Review the example plugins in `plugins/`
2. Create your first plugin following the templates
3. Test your plugin thoroughly
4. Share your plugin with the community

### Resources

- **Example Plugins**: `plugins/example_*.py`
- **Plugin Manager Source**: `src/plugins/plugin_manager.py`
- **Architecture Guide**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **API Reference**: [API_REFERENCE.md](API_REFERENCE.md)

### Contributing

We welcome plugin contributions! To contribute:

1. Create your plugin following this guide
2. Write tests for your plugin
3. Document your plugin's functionality
4. Submit a pull request

For questions or support, open an issue on GitHub.
