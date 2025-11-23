#!/usr/bin/env python3
"""
FlagDetector for DissectX    Framework

Implements basic flag pattern detection with confidence scoring.
This is the foundational component for CTF flag detection.

Requirements: 1.1, 1.2, 1.4
"""

import re
import base64
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class ConfidenceLevel(Enum):
    """Confidence levels for flag detection"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DetectedFlag:
    """Represents a detected flag with metadata"""
    value: str
    confidence: ConfidenceLevel
    pattern_type: str
    location: Optional[int] = None
    
    def __str__(self) -> str:
        return f"Flag: {self.value} (Confidence: {self.confidence.value}, Type: {self.pattern_type})"


class FlagDetector:
    """
    Detects CTF flags in binary data using pattern matching.
    
    Supports common flag formats:
    - CTF{...}
    - flag{...}
    - FLAG{...}
    
    Assigns confidence scores based on pattern specificity and content validation.
    """
    
    # High-confidence patterns: Well-known CTF platforms
    HIGH_CONFIDENCE_PATTERNS = [
        (rb'picoCTF\{[^}]+\}', 'picoCTF'),
        (rb'HTB\{[^}]+\}', 'HackTheBox'),
        (rb'CHTB\{[^}]+\}', 'CyberApocalypse'),
    ]
    
    # Medium-confidence patterns: Standard flag formats
    MEDIUM_CONFIDENCE_PATTERNS = [
        (rb'CTF\{[^}]+\}', 'CTF'),
        (rb'FLAG\{[^}]+\}', 'FLAG'),
        (rb'flag\{[^}]+\}', 'flag'),
    ]
    
    # Low-confidence patterns: Generic brace patterns
    LOW_CONFIDENCE_PATTERNS = [
        (rb'[a-zA-Z0-9_]{3,20}\{[a-zA-Z0-9_@!?-]{3,100}\}', 'generic'),
    ]
    
    def __init__(self):
        """Initialize the FlagDetector"""
        self.detected_flags: List[DetectedFlag] = []
    
    def find_flags(self, data: bytes, strings: List[str]) -> List[DetectedFlag]:
        """
        Find all flags in binary data using pattern matching.
        
        Args:
            data: Binary data to search
            strings: List of extracted strings (for future use)
            
        Returns:
            List of DetectedFlag objects, sorted by confidence (high to low)
        """
        flags = []
        
        # Search for high-confidence patterns
        for pattern, pattern_type in self.HIGH_CONFIDENCE_PATTERNS:
            flags.extend(self._search_pattern(data, pattern, pattern_type, ConfidenceLevel.HIGH))
        
        # Search for medium-confidence patterns
        for pattern, pattern_type in self.MEDIUM_CONFIDENCE_PATTERNS:
            flags.extend(self._search_pattern(data, pattern, pattern_type, ConfidenceLevel.MEDIUM))
        
        # Search for low-confidence patterns
        for pattern, pattern_type in self.LOW_CONFIDENCE_PATTERNS:
            flags.extend(self._search_pattern(data, pattern, pattern_type, ConfidenceLevel.LOW))
        
        # Search for Base64-encoded flags
        flags.extend(self._search_base64_flags(data))
        
        # Search for hex-encoded flags
        flags.extend(self._search_hex_flags(data))
        
        # Deduplicate and sort by confidence
        flags = self._deduplicate_flags(flags)
        flags = self._sort_by_confidence(flags)
        
        self.detected_flags = flags
        return flags
    
    def _search_base64_flags(self, data: bytes) -> List[DetectedFlag]:
        """
        Search for Base64-encoded flags in binary data.
        
        This method identifies potential Base64 strings and decodes them
        to check for flag patterns. Handles various encoding edge cases.
        
        Args:
            data: Binary data to search
            
        Returns:
            List of DetectedFlag objects found in Base64-encoded data
        """
        flags = []
        
        # Pattern to match potential Base64 strings
        # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        # Look for strings of reasonable length (at least 8 chars for a minimal flag)
        base64_pattern = rb'[A-Za-z0-9+/]{8,}={0,2}'
        
        for match in re.finditer(base64_pattern, data):
            try:
                encoded_str = match.group(0)
                
                # Try to decode the Base64 string
                decoded_data = self._safe_base64_decode(encoded_str)
                
                if decoded_data is None:
                    continue
                
                # Search for flag patterns in the decoded data
                decoded_flags = self._search_decoded_data(decoded_data, match.start())
                flags.extend(decoded_flags)
                
            except Exception:
                # Skip any problematic matches
                continue
        
        return flags
    
    def _safe_base64_decode(self, encoded: bytes) -> Optional[bytes]:
        """
        Safely decode Base64 data, handling edge cases.
        
        Args:
            encoded: Base64-encoded bytes
            
        Returns:
            Decoded bytes if successful, None otherwise
        """
        try:
            # Try standard Base64 decoding
            decoded = base64.b64decode(encoded, validate=True)
            
            # Verify the decoded data is reasonable
            # Should be mostly printable or contain valid binary data
            if len(decoded) == 0:
                return None
            
            return decoded
            
        except Exception:
            # Handle padding issues by trying to add padding
            try:
                # Add padding if missing
                padding_needed = (4 - len(encoded) % 4) % 4
                padded = encoded + b'=' * padding_needed
                decoded = base64.b64decode(padded, validate=True)
                
                if len(decoded) == 0:
                    return None
                
                return decoded
                
            except Exception:
                # If all decoding attempts fail, return None
                return None
    
    def _search_decoded_data(self, decoded_data: bytes, original_location: int) -> List[DetectedFlag]:
        """
        Search for flag patterns in decoded Base64 data.
        
        Args:
            decoded_data: Decoded binary data
            original_location: Location of the Base64 string in original data
            
        Returns:
            List of DetectedFlag objects
        """
        flags = []
        
        # Try to decode as UTF-8 string
        try:
            decoded_str = decoded_data.decode('utf-8', errors='ignore')
        except Exception:
            return flags
        
        # Search for all flag patterns in the decoded string
        all_patterns = (
            [(p, t, ConfidenceLevel.HIGH) for p, t in self.HIGH_CONFIDENCE_PATTERNS] +
            [(p, t, ConfidenceLevel.MEDIUM) for p, t in self.MEDIUM_CONFIDENCE_PATTERNS] +
            [(p, t, ConfidenceLevel.LOW) for p, t in self.LOW_CONFIDENCE_PATTERNS]
        )
        
        for pattern, pattern_type, confidence in all_patterns:
            # Convert pattern to string pattern for searching decoded text
            try:
                str_pattern = pattern.decode('utf-8', errors='ignore')
            except Exception:
                continue
            
            for match in re.finditer(str_pattern, decoded_str, re.IGNORECASE):
                flag_value = match.group(0)
                
                # Validate the flag content
                if self._is_valid_flag_content(flag_value):
                    # Adjust confidence based on content validation
                    adjusted_confidence = self._adjust_confidence(flag_value, confidence)
                    
                    flag = DetectedFlag(
                        value=flag_value,
                        confidence=adjusted_confidence,
                        pattern_type=f"{pattern_type} (Base64)",
                        location=original_location
                    )
                    flags.append(flag)
        
        return flags
    
    def _search_hex_flags(self, data: bytes) -> List[DetectedFlag]:
        """
        Search for hex-encoded flags in binary data.
        
        This method identifies potential hex-encoded strings and decodes them
        to check for flag patterns. Handles various encoding edge cases.
        
        Args:
            data: Binary data to search
            
        Returns:
            List of DetectedFlag objects found in hex-encoded data
        """
        flags = []
        
        # Pattern to match potential hex strings
        # Hex uses 0-9, a-f, A-F
        # Look for strings of reasonable length (at least 10 chars for a minimal flag)
        # Must be even length (2 hex chars = 1 byte)
        hex_pattern = rb'[0-9a-fA-F]{10,}'
        
        for match in re.finditer(hex_pattern, data):
            try:
                hex_str = match.group(0)
                
                # Only process even-length hex strings
                if len(hex_str) % 2 != 0:
                    continue
                
                # Try to decode the hex string
                decoded_data = self._safe_hex_decode(hex_str)
                
                if decoded_data is None:
                    continue
                
                # Search for flag patterns in the decoded data
                decoded_flags = self._search_decoded_data_hex(decoded_data, match.start())
                flags.extend(decoded_flags)
                
            except Exception:
                # Skip any problematic matches
                continue
        
        return flags
    
    def _safe_hex_decode(self, hex_encoded: bytes) -> Optional[bytes]:
        """
        Safely decode hex data, handling edge cases.
        
        Args:
            hex_encoded: Hex-encoded bytes
            
        Returns:
            Decoded bytes if successful, None otherwise
        """
        try:
            # Convert bytes to string for hex decoding
            hex_str = hex_encoded.decode('ascii')
            
            # Try standard hex decoding
            decoded = bytes.fromhex(hex_str)
            
            # Verify the decoded data is reasonable
            # Should be mostly printable or contain valid binary data
            if len(decoded) == 0:
                return None
            
            return decoded
            
        except Exception:
            # If decoding fails, return None
            return None
    
    def _search_decoded_data_hex(self, decoded_data: bytes, original_location: int) -> List[DetectedFlag]:
        """
        Search for flag patterns in decoded hex data.
        
        Args:
            decoded_data: Decoded binary data
            original_location: Location of the hex string in original data
            
        Returns:
            List of DetectedFlag objects
        """
        flags = []
        
        # Try to decode as UTF-8 string
        try:
            decoded_str = decoded_data.decode('utf-8', errors='ignore')
        except Exception:
            return flags
        
        # Search for all flag patterns in the decoded string
        all_patterns = (
            [(p, t, ConfidenceLevel.HIGH) for p, t in self.HIGH_CONFIDENCE_PATTERNS] +
            [(p, t, ConfidenceLevel.MEDIUM) for p, t in self.MEDIUM_CONFIDENCE_PATTERNS] +
            [(p, t, ConfidenceLevel.LOW) for p, t in self.LOW_CONFIDENCE_PATTERNS]
        )
        
        for pattern, pattern_type, confidence in all_patterns:
            # Convert pattern to string pattern for searching decoded text
            try:
                str_pattern = pattern.decode('utf-8', errors='ignore')
            except Exception:
                continue
            
            for match in re.finditer(str_pattern, decoded_str, re.IGNORECASE):
                flag_value = match.group(0)
                
                # Validate the flag content
                if self._is_valid_flag_content(flag_value):
                    # Adjust confidence based on content validation
                    adjusted_confidence = self._adjust_confidence(flag_value, confidence)
                    
                    flag = DetectedFlag(
                        value=flag_value,
                        confidence=adjusted_confidence,
                        pattern_type=f"{pattern_type} (Hex)",
                        location=original_location
                    )
                    flags.append(flag)
        
        return flags
    
    def _search_pattern(
        self, 
        data: bytes, 
        pattern: bytes, 
        pattern_type: str, 
        confidence: ConfidenceLevel
    ) -> List[DetectedFlag]:
        """
        Search for a specific pattern in binary data.
        
        Args:
            data: Binary data to search
            pattern: Regex pattern to match
            pattern_type: Human-readable pattern type
            confidence: Confidence level for matches
            
        Returns:
            List of DetectedFlag objects
        """
        flags = []
        
        for match in re.finditer(pattern, data, re.IGNORECASE):
            try:
                flag_value = match.group(0).decode('utf-8', errors='ignore')
                
                # Validate the flag content
                if self._is_valid_flag_content(flag_value):
                    # Adjust confidence based on content validation
                    adjusted_confidence = self._adjust_confidence(flag_value, confidence)
                    
                    flag = DetectedFlag(
                        value=flag_value,
                        confidence=adjusted_confidence,
                        pattern_type=pattern_type,
                        location=match.start()
                    )
                    flags.append(flag)
            except (UnicodeDecodeError, AttributeError):
                # Skip invalid matches
                continue
        
        return flags
    
    def _is_valid_flag_content(self, flag: str) -> bool:
        """
        Validate that flag content is reasonable.
        
        Args:
            flag: Flag string to validate
            
        Returns:
            True if flag content is valid, False otherwise
        """
        if not flag or len(flag) < 5:
            return False
        
        # Must contain opening and closing braces
        if '{' not in flag or '}' not in flag:
            return False
        
        # Extract content between braces
        match = re.search(r'\{([^}]+)\}', flag)
        if not match:
            return False
        
        content = match.group(1)
        
        # Content should be reasonable length
        if len(content) < 3 or len(content) > 200:
            return False
        
        # Content should be mostly printable ASCII
        printable_count = sum(1 for c in content if c.isprintable())
        if printable_count < len(content) * 0.8:
            return False
        
        return True
    
    def _adjust_confidence(self, flag: str, base_confidence: ConfidenceLevel) -> ConfidenceLevel:
        """
        Adjust confidence level based on flag content characteristics.
        
        Args:
            flag: Flag string
            base_confidence: Initial confidence level
            
        Returns:
            Adjusted confidence level
        """
        # Extract content between braces
        match = re.search(r'\{([^}]+)\}', flag)
        if not match:
            return base_confidence
        
        content = match.group(1)
        
        # Only downgrade for MEDIUM and LOW confidence patterns
        # HIGH confidence patterns (picoCTF, HTB, etc.) are trusted
        if base_confidence == ConfidenceLevel.HIGH:
            return base_confidence
        
        # Downgrade if content looks suspicious
        suspicious_indicators = [
            len(content) < 3,  # Very short content (less than 3 chars)
            len(content) > 150,  # Very long content
            content.count('_') > len(content) * 0.6,  # Too many underscores
            not any(c.isalnum() for c in content),  # No alphanumeric characters
        ]
        
        if any(suspicious_indicators):
            # Downgrade confidence by one level
            if base_confidence == ConfidenceLevel.MEDIUM:
                return ConfidenceLevel.LOW
        
        return base_confidence
    
    def _deduplicate_flags(self, flags: List[DetectedFlag]) -> List[DetectedFlag]:
        """
        Remove duplicate flags, keeping the highest confidence version.
        
        Args:
            flags: List of detected flags
            
        Returns:
            Deduplicated list of flags
        """
        seen = {}
        
        for flag in flags:
            if flag.value not in seen:
                seen[flag.value] = flag
            else:
                # Keep higher confidence version
                existing = seen[flag.value]
                if self._confidence_rank(flag.confidence) > self._confidence_rank(existing.confidence):
                    seen[flag.value] = flag
        
        return list(seen.values())
    
    def _sort_by_confidence(self, flags: List[DetectedFlag]) -> List[DetectedFlag]:
        """
        Sort flags by confidence level (high to low).
        
        Args:
            flags: List of detected flags
            
        Returns:
            Sorted list of flags
        """
        return sorted(flags, key=lambda f: self._confidence_rank(f.confidence), reverse=True)
    
    def _confidence_rank(self, confidence: ConfidenceLevel) -> int:
        """
        Get numeric rank for confidence level.
        
        Args:
            confidence: Confidence level
            
        Returns:
            Numeric rank (higher is better)
        """
        ranks = {
            ConfidenceLevel.HIGH: 3,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.LOW: 1,
        }
        return ranks.get(confidence, 0)
    
    def format_report(self) -> str:
        """
        Format detected flags as a human-readable report.
        
        Returns:
            Formatted report string
        """
        if not self.detected_flags:
            return "No flags detected."
        
        lines = []
        lines.append(f"Detected {len(self.detected_flags)} flag(s):")
        lines.append("")
        
        for i, flag in enumerate(self.detected_flags, 1):
            lines.append(f"{i}. {flag.value}")
            lines.append(f"   Confidence: {flag.confidence.value}")
            lines.append(f"   Pattern: {flag.pattern_type}")
            if flag.location is not None:
                lines.append(f"   Location: 0x{flag.location:X}")
            lines.append("")
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    # Test with sample data
    test_data = b"This is a test CTF{test_flag_123} and flag{another_one} picoCTF{real_flag}"
    
    # Add Base64-encoded flag for testing
    # "CTF{base64_test}" encoded in Base64 is "Q1RGe2Jhc2U2NF90ZXN0fQ=="
    test_data += b" Q1RGe2Jhc2U2NF90ZXN0fQ=="
    
    # Add hex-encoded flag for testing
    # "CTF{hex_test}" encoded in hex is "4354467b6865785f746573747d"
    test_data += b" 4354467b6865785f746573747d"
    
    detector = FlagDetector()
    flags = detector.find_flags(test_data, [])
    
    print(detector.format_report())
    
    for flag in flags:
        print(flag)
