# DissectX Plugin API Documentation

This directory contains example plugins demonstrating the DissectX plugin system.

## Overview

The DissectX plugin system allows you to extend the framework with:
- **Custom Analyzers**: Perform additional analysis on binary data
- **Custom Output Formats**: Define new ways to present analysis results
- **Hooks**: Execute code at specific points in the analysis workflow

## Plugin Structure

All plugins must inherit from the `Plugin` base class and implement the required methods:

```python
from src.plugins import Plugin
from typing import Dict, Any

class MyPlugin(Plugin):
    def get_name(self) -> str:
        """Return the plugin name."""
        return "MyPlugin"
    
    def get_version(self) -> str:
        """Return the plugin version."""
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Perform custom analysis on binary data.
        
        Args:
            binary_data: The binary data to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        # Your analysis logic here
        return {"result": "analysis complete"}
```

## Optional Methods

Plugins can also implement these optional methods:

```python
def get_description(self) -> str:
    """Return a description of the plugin."""
    return "My plugin description"

def get_author(self) -> str:
    """Return the plugin author."""
    return "Your Name"
```

## Creating an Analyzer Plugin

Analyzer plugins perform custom analysis on binary data. See `example_analyzer_plugin.py` for a complete example.

### Example: String Statistics Analyzer

```python
from src.plugins import Plugin
from typing import Dict, Any

class StringStatisticsAnalyzer(Plugin):
    def get_name(self) -> str:
        return "StringStatisticsAnalyzer"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Extract strings
        strings = self._extract_strings(binary_data)
        
        # Compute statistics
        stats = {
            "total_strings": len(strings),
            "average_length": sum(len(s) for s in strings) / len(strings) if strings else 0
        }
        
        return {
            "analyzer": self.get_name(),
            "statistics": stats
        }
    
    def _extract_strings(self, binary_data: bytes, min_length: int = 4) -> list:
        # String extraction logic
        pass
```

## Creating a Format Plugin

Format plugins define custom output formats for analysis results. See `example_format_plugin.py` for complete examples.

### Example: JSON Formatter

```python
from src.plugins import Plugin
from typing import Dict, Any
import json

class JSONCompactFormatter(Plugin):
    def get_name(self) -> str:
        return "JSONCompactFormatter"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        # Not used for format plugins
        return {}
    
    def format(self, analysis_results: Dict[str, Any]) -> str:
        """Format analysis results as compact JSON."""
        return json.dumps(analysis_results, separators=(',', ':'))
```

## Using Hooks

Hooks allow you to execute code at specific points in the analysis workflow.

### Available Hook Types

- `PRE_ANALYSIS`: Before analysis begins
- `POST_ANALYSIS`: After analysis completes
- `PRE_DISASSEMBLY`: Before disassembly
- `POST_DISASSEMBLY`: After disassembly

### Example: Registering a Hook

```python
from src.plugins import PluginManager, HookType

def my_pre_analysis_hook(context: dict) -> dict:
    """Hook that runs before analysis."""
    print(f"Starting analysis of: {context.get('binary_path')}")
    # Modify context if needed
    context['custom_flag'] = True
    return context

# Register the hook
plugin_manager = PluginManager()
plugin_manager.register_hook(HookType.PRE_ANALYSIS, my_pre_analysis_hook)
```

## Using the Plugin Manager

### Loading Plugins

```python
from src.plugins import PluginManager

# Initialize plugin manager
pm = PluginManager(plugin_dir="plugins")

# Discover and load all plugins
pm.load_all_plugins()

# Get loaded plugins
plugins = pm.get_plugins()
for plugin in plugins:
    print(f"Loaded: {plugin.get_name()} v{plugin.get_version()}")
```

### Running Custom Analyzers

```python
# Register a plugin as a custom analyzer
pm.register_analyzer(plugin)

# Get all custom analyzers
analyzers = pm.get_custom_analyzers()

# Run analysis
binary_data = open("binary.exe", "rb").read()
for analyzer in analyzers:
    results = analyzer.analyze(binary_data)
    print(results)
```

### Using Custom Formats

```python
# Register a custom format
pm.register_format("markdown", markdown_formatter.format)

# Get available formats
formats = pm.get_custom_formats()

# Use a format
analysis_results = {"functions": [...], "strings": [...]}
formatted_output = formats["markdown"](analysis_results)
print(formatted_output)
```

### Executing Hooks

```python
from src.plugins import HookType

# Execute pre-analysis hooks
context = {
    "binary_path": "sample.exe",
    "options": {"verbose": True}
}

context = pm.execute_hooks(HookType.PRE_ANALYSIS, context)

# Perform analysis...

# Execute post-analysis hooks
context["results"] = analysis_results
context = pm.execute_hooks(HookType.POST_ANALYSIS, context)
```

## Plugin Discovery

The PluginManager automatically discovers plugins in the specified directory:

1. Searches for `.py` files (excluding `__init__.py`)
2. Loads each file as a Python module
3. Finds classes that inherit from `Plugin`
4. Instantiates the plugin class
5. Adds the plugin to the loaded plugins list

## Error Handling

The plugin system handles errors gracefully:

- If a plugin fails to load, it logs an error and continues with other plugins
- If a hook handler fails, it logs an error and continues with other hooks
- Failed plugins are skipped, allowing the core system to continue functioning

## Best Practices

1. **Keep plugins focused**: Each plugin should do one thing well
2. **Handle errors gracefully**: Use try-except blocks in your analysis code
3. **Document your plugin**: Provide clear descriptions and usage examples
4. **Version your plugins**: Use semantic versioning (MAJOR.MINOR.PATCH)
5. **Test your plugins**: Write unit tests for your plugin logic
6. **Minimize dependencies**: Keep external dependencies to a minimum
7. **Return structured data**: Use dictionaries with clear keys for analysis results

## Example Plugins

This directory includes three example plugins:

1. **example_analyzer_plugin.py**: Demonstrates custom analysis (string statistics)
2. **example_format_plugin.py**: Demonstrates custom formats (JSON, Markdown, CSV)

## Troubleshooting

### Plugin Not Loading

- Check that your plugin file is in the `plugins/` directory
- Ensure your plugin class inherits from `Plugin`
- Verify all required methods are implemented
- Check the logs for error messages

### Hook Not Executing

- Verify the hook is registered with the correct `HookType`
- Ensure the hook handler accepts a `context` dictionary parameter
- Check that hooks are being executed at the right point in the workflow

### Import Errors

- Make sure the `src` directory is in your Python path
- Use relative imports or add the parent directory to `sys.path`

## Contributing

To contribute a plugin:

1. Create your plugin file in the `plugins/` directory
2. Follow the plugin structure and best practices
3. Test your plugin thoroughly
4. Document your plugin's functionality
5. Submit a pull request with your plugin and documentation

## Support

For questions or issues with the plugin system:
- Check the main DissectX documentation
- Review the example plugins
- Open an issue on the GitHub repository
