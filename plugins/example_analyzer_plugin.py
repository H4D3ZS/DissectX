"""
Example Analyzer Plugin for DissectX.

This plugin demonstrates how to create a custom analyzer that
performs additional analysis on binary data.
"""

from typing import Dict, Any
import sys
import os

# Add parent directory to path to import Plugin
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.plugins import Plugin


class StringStatisticsAnalyzer(Plugin):
    """
    Example analyzer plugin that computes statistics about strings in binary data.
    
    This plugin demonstrates:
    - Implementing the Plugin interface
    - Performing custom analysis
    - Returning structured results
    """
    
    def get_name(self) -> str:
        """Return the plugin name."""
        return "StringStatisticsAnalyzer"
    
    def get_version(self) -> str:
        """Return the plugin version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return a description of the plugin."""
        return "Analyzes string statistics in binary data including length distribution and character frequency"
    
    def get_author(self) -> str:
        """Return the plugin author."""
        return "DissectX Team"
    
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Analyze string statistics in binary data.
        
        Args:
            binary_data: The binary data to analyze
            
        Returns:
            Dictionary containing string statistics
        """
        # Extract printable strings (simple implementation)
        strings = self._extract_strings(binary_data)
        
        # Compute statistics
        stats = {
            "total_strings": len(strings),
            "total_length": sum(len(s) for s in strings),
            "average_length": sum(len(s) for s in strings) / len(strings) if strings else 0,
            "min_length": min(len(s) for s in strings) if strings else 0,
            "max_length": max(len(s) for s in strings) if strings else 0,
            "character_frequency": self._compute_char_frequency(strings),
            "strings_by_length": self._group_by_length(strings)
        }
        
        return {
            "analyzer": self.get_name(),
            "version": self.get_version(),
            "statistics": stats
        }
    
    def _extract_strings(self, binary_data: bytes, min_length: int = 4) -> list:
        """
        Extract printable ASCII strings from binary data.
        
        Args:
            binary_data: Binary data to search
            min_length: Minimum string length to extract
            
        Returns:
            List of extracted strings
        """
        strings = []
        current_string = []
        
        for byte in binary_data:
            # Check if byte is printable ASCII
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        
        # Don't forget the last string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))
        
        return strings
    
    def _compute_char_frequency(self, strings: list) -> Dict[str, int]:
        """
        Compute character frequency across all strings.
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            Dictionary mapping characters to their frequency
        """
        frequency = {}
        for string in strings:
            for char in string:
                frequency[char] = frequency.get(char, 0) + 1
        
        # Sort by frequency (descending) and return top 10
        sorted_freq = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_freq[:10])
    
    def _group_by_length(self, strings: list) -> Dict[str, int]:
        """
        Group strings by length ranges.
        
        Args:
            strings: List of strings to group
            
        Returns:
            Dictionary mapping length ranges to counts
        """
        ranges = {
            "4-10": 0,
            "11-20": 0,
            "21-50": 0,
            "51-100": 0,
            "100+": 0
        }
        
        for string in strings:
            length = len(string)
            if length <= 10:
                ranges["4-10"] += 1
            elif length <= 20:
                ranges["11-20"] += 1
            elif length <= 50:
                ranges["21-50"] += 1
            elif length <= 100:
                ranges["51-100"] += 1
            else:
                ranges["100+"] += 1
        
        return ranges
