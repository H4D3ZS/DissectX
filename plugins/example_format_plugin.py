"""
Example Format Plugin for DissectX.

This plugin demonstrates how to create a custom output format
for analysis results.
"""

from typing import Dict, Any
import json
import sys
import os

# Add parent directory to path to import Plugin
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.plugins import Plugin


class JSONCompactFormatter(Plugin):
    """
    Example format plugin that outputs analysis results in compact JSON format.
    
    This plugin demonstrates:
    - Implementing the Plugin interface
    - Creating custom output formats
    - Processing analysis results
    """
    
    def get_name(self) -> str:
        """Return the plugin name."""
        return "JSONCompactFormatter"
    
    def get_version(self) -> str:
        """Return the plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return a description of the plugin."""
        return "Formats analysis results as compact JSON (single line, no indentation)"
    
    def get_author(self) -> str:
        """Return the plugin author."""
        return "DissectX Team"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        This method is not used for format plugins.
        Format plugins use the format() method instead.
        """
        return {}
    
    def format(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format analysis results as compact JSON.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            Formatted string (compact JSON)
        """
        # Convert to compact JSON (no indentation, no newlines)
        return json.dumps(analysis_results, separators=(',', ':'))


class MarkdownFormatter(Plugin):
    """
    Example format plugin that outputs analysis results in Markdown format.
    
    This plugin demonstrates creating a human-readable format.
    """
    
    def get_name(self) -> str:
        """Return the plugin name."""
        return "MarkdownFormatter"
    
    def get_version(self) -> str:
        """Return the plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return a description of the plugin."""
        return "Formats analysis results as Markdown for documentation"
    
    def get_author(self) -> str:
        """Return the plugin author."""
        return "DissectX Team"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        This method is not used for format plugins.
        Format plugins use the format() method instead.
        """
        return {}
    
    def format(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format analysis results as Markdown.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            Formatted string (Markdown)
        """
        lines = []
        lines.append("# DissectX Analysis Report")
        lines.append("")
        
        # Format binary info
        if "binary_info" in analysis_results:
            lines.append("## Binary Information")
            lines.append("")
            binary_info = analysis_results["binary_info"]
            for key, value in binary_info.items():
                lines.append(f"- **{key}**: {value}")
            lines.append("")
        
        # Format functions
        if "functions" in analysis_results:
            lines.append("## Functions")
            lines.append("")
            functions = analysis_results["functions"]
            lines.append(f"Total functions: {len(functions)}")
            lines.append("")
            for func_addr, func_info in list(functions.items())[:10]:  # Show first 10
                lines.append(f"### Function at {func_addr}")
                for key, value in func_info.items():
                    lines.append(f"- **{key}**: {value}")
                lines.append("")
        
        # Format strings
        if "strings" in analysis_results:
            lines.append("## Strings")
            lines.append("")
            strings = analysis_results["strings"]
            lines.append(f"Total strings: {len(strings)}")
            lines.append("")
            for string_info in strings[:20]:  # Show first 20
                lines.append(f"- `{string_info}`")
            lines.append("")
        
        # Format flags
        if "flags" in analysis_results:
            lines.append("## Detected Flags")
            lines.append("")
            flags = analysis_results["flags"]
            for flag in flags:
                lines.append(f"- **{flag.get('value', 'N/A')}** (confidence: {flag.get('confidence', 'N/A')})")
            lines.append("")
        
        return "\n".join(lines)


class CSVFormatter(Plugin):
    """
    Example format plugin that outputs analysis results in CSV format.
    
    This plugin demonstrates creating a machine-readable tabular format.
    """
    
    def get_name(self) -> str:
        """Return the plugin name."""
        return "CSVFormatter"
    
    def get_version(self) -> str:
        """Return the plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return a description of the plugin."""
        return "Formats analysis results as CSV for spreadsheet import"
    
    def get_author(self) -> str:
        """Return the plugin author."""
        return "DissectX Team"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        This method is not used for format plugins.
        Format plugins use the format() method instead.
        """
        return {}
    
    def format(self, analysis_results: Dict[str, Any]) -> str:
        """
        Format analysis results as CSV.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            Formatted string (CSV)
        """
        lines = []
        
        # Format functions as CSV
        if "functions" in analysis_results:
            lines.append("# Functions")
            lines.append("Address,Name,Size,Calls")
            functions = analysis_results["functions"]
            for func_addr, func_info in functions.items():
                name = func_info.get("name", "unknown")
                size = func_info.get("size", 0)
                calls = func_info.get("calls", 0)
                lines.append(f"{func_addr},{name},{size},{calls}")
            lines.append("")
        
        # Format strings as CSV
        if "strings" in analysis_results:
            lines.append("# Strings")
            lines.append("Offset,Length,Value")
            strings = analysis_results["strings"]
            for string_info in strings:
                if isinstance(string_info, dict):
                    offset = string_info.get("offset", 0)
                    value = string_info.get("value", "")
                    length = len(value)
                    # Escape quotes in CSV
                    value = value.replace('"', '""')
                    lines.append(f'{offset},{length},"{value}"')
            lines.append("")
        
        return "\n".join(lines)
