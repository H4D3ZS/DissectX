#!/usr/bin/env python3
"""
XORAnalyzer for DissectX    Framework

Implements XOR decryption and analysis capabilities for obfuscated strings.
Supports single-byte and multi-byte XOR key detection with quality scoring.

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
"""

import math
from typing import List, Optional
from dataclasses import dataclass
from collections import Counter


@dataclass
class XORResult:
    """Represents a single XOR decryption result with quality metrics"""
    key: int
    decrypted_data: bytes
    entropy: float
    printable_ratio: float
    quality_score: float
    
    def __str__(self) -> str:
        preview = self.decrypted_data[:50].decode('utf-8', errors='replace')
        return (f"Key: 0x{self.key:02X} | Quality: {self.quality_score:.2f} | "
                f"Entropy: {self.entropy:.2f} | Printable: {self.printable_ratio:.2%} | "
                f"Preview: {preview}")


@dataclass
class MultiByteXORResult:
    """Represents a multi-byte XOR decryption result"""
    key: bytes
    key_length: int
    decrypted_data: bytes
    confidence: float
    
    def __str__(self) -> str:
        key_hex = ''.join(f'{b:02X}' for b in self.key)
        preview = self.decrypted_data[:50].decode('utf-8', errors='replace')
        return (f"Key: {key_hex} (length: {self.key_length}) | "
                f"Confidence: {self.confidence:.2f} | Preview: {preview}")


class XORAnalyzer:
    """
    Analyzes binary data for XOR encryption and performs brute-force decryption.
    
    Features:
    - Single-byte XOR brute force (all keys 0x00-0xFF)
    - Entropy calculation for quality scoring
    - Multi-byte XOR key detection
    - Printable ASCII prioritization
    """
    
    def __init__(self):
        """Initialize the XORAnalyzer"""
        self.results: List[XORResult] = []
    
    def brute_force_xor(self, data: bytes) -> List[XORResult]:
        """
        Perform single-byte XOR brute force on binary data.
        
        Tries all possible single-byte keys (0x00-0xFF) and calculates
        quality scores based on entropy and printable character ratio.
        
        Args:
            data: Binary data to decrypt
            
        Returns:
            List of XORResult objects for all 256 keys, sorted by quality score
        """
        if not data:
            return []
        
        results = []
        
        # Try all 256 possible single-byte keys
        for key in range(256):
            # Decrypt data with this key
            decrypted = self._xor_single_byte(data, key)
            
            # Calculate quality metrics
            entropy = self._calculate_entropy(decrypted)
            printable_ratio = self._calculate_printable_ratio(decrypted)
            quality_score = self._calculate_quality_score(entropy, printable_ratio)
            
            result = XORResult(
                key=key,
                decrypted_data=decrypted,
                entropy=entropy,
                printable_ratio=printable_ratio,
                quality_score=quality_score
            )
            results.append(result)
        
        # Sort by quality score (highest first)
        results.sort(key=lambda r: r.quality_score, reverse=True)
        
        self.results = results
        return results
    
    def _xor_single_byte(self, data: bytes, key: int) -> bytes:
        """
        XOR data with a single-byte key.
        
        Args:
            data: Binary data to XOR
            key: Single-byte key (0-255)
            
        Returns:
            XORed data
        """
        return bytes(b ^ key for b in data)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Entropy measures randomness/information density:
        - Low entropy (~0-3): Highly structured/repetitive data
        - Medium entropy (~3-6): Natural language text
        - High entropy (~6-8): Random/encrypted data
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_printable_ratio(self, data: bytes) -> float:
        """
        Calculate the ratio of printable ASCII characters in data.
        
        Printable ASCII includes:
        - Space (0x20)
        - Printable characters (0x21-0x7E)
        - Common whitespace (tab, newline, carriage return)
        
        Args:
            data: Binary data to analyze
            
        Returns:
            Ratio of printable characters (0.0 to 1.0)
        """
        if not data:
            return 0.0
        
        printable_count = 0
        for byte in data:
            # Check if byte is printable ASCII or common whitespace
            if (0x20 <= byte <= 0x7E) or byte in (0x09, 0x0A, 0x0D):
                printable_count += 1
        
        return printable_count / len(data)
    
    def _calculate_quality_score(self, entropy: float, printable_ratio: float) -> float:
        """
        Calculate overall quality score for decrypted data.
        
        Quality scoring strategy:
        - High printable ratio is good (indicates readable text)
        - Medium entropy is good (indicates natural language)
        - Very low or very high entropy is bad (too repetitive or too random)
        
        Args:
            entropy: Shannon entropy (0.0 to 8.0)
            printable_ratio: Ratio of printable characters (0.0 to 1.0)
            
        Returns:
            Quality score (0.0 to 100.0)
        """
        # Printable ratio component (0-50 points)
        # Heavily weight printable content
        printable_score = printable_ratio * 50.0
        
        # Entropy component (0-50 points)
        # Prefer medium entropy (natural language is around 4-5)
        # Use a bell curve centered at 4.5
        ideal_entropy = 4.5
        entropy_deviation = abs(entropy - ideal_entropy)
        
        # Maximum deviation is 4.5 (from 0 or 9 to 4.5)
        # Normalize to 0-1 range, then invert (lower deviation = higher score)
        normalized_deviation = min(entropy_deviation / 4.5, 1.0)
        entropy_score = (1.0 - normalized_deviation) * 50.0
        
        # Combine scores
        quality_score = printable_score + entropy_score
        
        return quality_score
    
    def get_top_results(self, n: int = 10) -> List[XORResult]:
        """
        Get the top N results by quality score.
        
        Args:
            n: Number of results to return
            
        Returns:
            List of top N XORResult objects
        """
        return self.results[:n]
    
    def get_printable_results(self, min_ratio: float = 0.8) -> List[XORResult]:
        """
        Get results with high printable character ratio.
        
        Args:
            min_ratio: Minimum printable ratio (0.0 to 1.0)
            
        Returns:
            List of XORResult objects with printable_ratio >= min_ratio
        """
        return [r for r in self.results if r.printable_ratio >= min_ratio]
    
    def detect_multibyte_xor(self, data: bytes, max_key_length: int = 16) -> List[MultiByteXORResult]:
        """
        Detect multi-byte XOR keys using repeating pattern analysis.
        
        This method uses the Index of Coincidence (IC) technique to detect
        the key length, then performs frequency analysis to recover the key.
        
        Args:
            data: Binary data to analyze
            max_key_length: Maximum key length to test (default: 16)
            
        Returns:
            List of MultiByteXORResult objects, sorted by confidence
        """
        if not data or len(data) < 4:
            return []
        
        # Step 1: Detect likely key lengths using Index of Coincidence
        key_length_candidates = self._detect_key_length(data, max_key_length)
        
        # Step 2: For each candidate key length, try to recover the key
        results = []
        for key_length, ic_score in key_length_candidates[:5]:  # Try top 5 candidates
            key = self._recover_multibyte_key(data, key_length)
            if key:
                # Decrypt with the recovered key
                decrypted = self._xor_multibyte(data, key)
                
                # Calculate confidence based on IC score and decrypted quality
                printable_ratio = self._calculate_printable_ratio(decrypted)
                entropy = self._calculate_entropy(decrypted)
                
                # Confidence combines IC score and quality metrics
                confidence = (ic_score * 0.4 + printable_ratio * 0.4 + 
                            (1.0 - abs(entropy - 4.5) / 4.5) * 0.2)
                
                result = MultiByteXORResult(
                    key=key,
                    key_length=key_length,
                    decrypted_data=decrypted,
                    confidence=confidence
                )
                results.append(result)
        
        # Sort by confidence (highest first)
        results.sort(key=lambda r: r.confidence, reverse=True)
        
        return results
    
    def _detect_key_length(self, data: bytes, max_length: int) -> List[tuple]:
        """
        Detect likely key lengths using Index of Coincidence.
        
        The Index of Coincidence measures how similar a text is to random data.
        For the correct key length, each column (bytes at positions 0, k, 2k, ...)
        should have a higher IC (more like natural language).
        
        Args:
            data: Binary data to analyze
            max_length: Maximum key length to test
            
        Returns:
            List of (key_length, ic_score) tuples, sorted by IC score
        """
        ic_scores = []
        
        for key_length in range(1, min(max_length + 1, len(data) // 2)):
            # Split data into columns based on key length
            columns = [[] for _ in range(key_length)]
            for i, byte in enumerate(data):
                columns[i % key_length].append(byte)
            
            # Calculate average IC across all columns
            total_ic = 0.0
            for column in columns:
                if len(column) > 1:
                    total_ic += self._calculate_ic(column)
            
            avg_ic = total_ic / key_length if key_length > 0 else 0.0
            ic_scores.append((key_length, avg_ic))
        
        # Sort by IC score (higher is better)
        ic_scores.sort(key=lambda x: x[1], reverse=True)
        
        return ic_scores
    
    def _calculate_ic(self, data: List[int]) -> float:
        """
        Calculate Index of Coincidence for a sequence of bytes.
        
        IC = sum(n_i * (n_i - 1)) / (N * (N - 1))
        where n_i is the frequency of byte i, and N is the total length.
        
        For random data, IC ≈ 1/256 ≈ 0.0039
        For English text, IC ≈ 0.065
        
        Args:
            data: List of byte values
            
        Returns:
            Index of Coincidence value
        """
        if len(data) < 2:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        
        # Calculate IC
        n = len(data)
        ic = sum(count * (count - 1) for count in byte_counts.values())
        ic = ic / (n * (n - 1))
        
        return ic
    
    def _recover_multibyte_key(self, data: bytes, key_length: int) -> Optional[bytes]:
        """
        Recover a multi-byte XOR key using frequency analysis.
        
        For each position in the key, we analyze the bytes at that position
        and try all 256 possible key bytes, selecting the one that produces
        the most "English-like" result.
        
        Args:
            data: Binary data
            key_length: Length of the key to recover
            
        Returns:
            Recovered key as bytes, or None if recovery fails
        """
        key = []
        
        # Expected frequency of space character in English text
        SPACE_CHAR = ord(' ')
        
        for key_pos in range(key_length):
            # Extract bytes at this key position
            column = bytes(data[i] for i in range(key_pos, len(data), key_length))
            
            # Try all 256 possible key bytes
            best_key_byte = 0
            best_score = -1.0
            
            for key_byte in range(256):
                decrypted = bytes(b ^ key_byte for b in column)
                
                # Score based on multiple factors
                printable_ratio = self._calculate_printable_ratio(decrypted)
                
                # Count common English characters
                common_chars = sum(1 for b in decrypted if chr(b) in 'etaoinshrdlu ETAOINSHRDLU')
                common_ratio = common_chars / len(decrypted) if decrypted else 0
                
                # Check for space character frequency (should be ~13-20% in English)
                space_count = decrypted.count(SPACE_CHAR)
                space_ratio = space_count / len(decrypted) if decrypted else 0
                space_score = 1.0 - abs(space_ratio - 0.15) / 0.15  # Ideal ~15%
                space_score = max(0, space_score)
                
                # Combined score
                score = (printable_ratio * 0.5 + 
                        common_ratio * 0.3 + 
                        space_score * 0.2)
                
                if score > best_score:
                    best_score = score
                    best_key_byte = key_byte
            
            key.append(best_key_byte)
        
        return bytes(key) if key else None
    
    def _xor_multibyte(self, data: bytes, key: bytes) -> bytes:
        """
        XOR data with a multi-byte repeating key.
        
        Args:
            data: Binary data to XOR
            key: Multi-byte key
            
        Returns:
            XORed data
        """
        if not key:
            return data
        
        key_length = len(key)
        return bytes(data[i] ^ key[i % key_length] for i in range(len(data)))
    
    def get_prioritized_results(self) -> List[XORResult]:
        """
        Get results prioritized by quality score.
        
        Results are automatically sorted by quality score during brute_force_xor,
        which prioritizes:
        1. High printable ASCII ratio
        2. Medium entropy (natural language characteristics)
        
        Returns:
            List of XORResult objects sorted by quality (best first)
        """
        return self.results
    
    def get_results_by_printable_priority(self) -> List[XORResult]:
        """
        Get results prioritized specifically by printable ASCII content.
        
        This method re-sorts results to prioritize printable content over
        other quality metrics, useful when looking for readable strings.
        
        Returns:
            List of XORResult objects sorted by printable ratio (highest first)
        """
        return sorted(self.results, key=lambda r: r.printable_ratio, reverse=True)
    
    def format_report(self, top_n: int = 10) -> str:
        """
        Format analysis results as a human-readable report.
        
        Args:
            top_n: Number of top results to include
            
        Returns:
            Formatted report string
        """
        if not self.results:
            return "No XOR analysis results available."
        
        lines = []
        lines.append(f"XOR Analysis Results (showing top {top_n} of {len(self.results)}):")
        lines.append("=" * 80)
        lines.append("")
        
        for i, result in enumerate(self.results[:top_n], 1):
            lines.append(f"{i}. {result}")
            lines.append("")
        
        return "\n".join(lines)
    
    def format_printable_report(self, min_ratio: float = 0.8, max_results: int = 10) -> str:
        """
        Format a report showing only highly printable results.
        
        This report focuses on results that are likely to be readable text,
        filtering by printable character ratio.
        
        Args:
            min_ratio: Minimum printable ratio to include (0.0 to 1.0)
            max_results: Maximum number of results to show
            
        Returns:
            Formatted report string
        """
        printable_results = self.get_printable_results(min_ratio)
        
        if not printable_results:
            return f"No results with printable ratio >= {min_ratio:.0%}"
        
        lines = []
        lines.append(f"Highly Printable XOR Results (>= {min_ratio:.0%} printable):")
        lines.append("=" * 80)
        lines.append("")
        
        for i, result in enumerate(printable_results[:max_results], 1):
            lines.append(f"{i}. {result}")
            lines.append("")
        
        return "\n".join(lines)


# Example usage
if __name__ == "__main__":
    print("=" * 80)
    print("Test 1: Single-byte XOR")
    print("=" * 80)
    
    # Test with sample encrypted data
    # "Hello, World!" XORed with key 0x42
    plaintext = b"Hello, World!"
    key = 0x42
    encrypted = bytes(b ^ key for b in plaintext)
    
    print(f"Original: {plaintext}")
    print(f"Encrypted with key 0x{key:02X}: {encrypted.hex()}")
    print()
    
    # Analyze
    analyzer = XORAnalyzer()
    results = analyzer.brute_force_xor(encrypted)
    
    print(analyzer.format_report(top_n=5))
    
    # Check if we found the correct key
    correct_result = next((r for r in results if r.key == key), None)
    if correct_result:
        print(f"\nCorrect key found at position: {results.index(correct_result) + 1}")
        print(f"Decrypted: {correct_result.decrypted_data}")
    
    print("\n" + "=" * 80)
    print("Test 2: Multi-byte XOR")
    print("=" * 80)
    
    # Test multi-byte XOR
    plaintext2 = b"This is a longer test message for multi-byte XOR encryption. " * 3
    multibyte_key = b"KEY"
    encrypted2 = bytes(plaintext2[i] ^ multibyte_key[i % len(multibyte_key)] 
                      for i in range(len(plaintext2)))
    
    print(f"Original length: {len(plaintext2)} bytes")
    print(f"Multi-byte key: {multibyte_key}")
    print(f"Encrypted (first 50 bytes): {encrypted2[:50].hex()}")
    print()
    
    # Detect multi-byte XOR
    multibyte_results = analyzer.detect_multibyte_xor(encrypted2, max_key_length=10)
    
    print(f"Multi-byte XOR Detection Results (top 3):")
    print("-" * 80)
    for i, result in enumerate(multibyte_results[:3], 1):
        print(f"{i}. {result}")
        if result.key == multibyte_key:
            print("   ✓ CORRECT KEY FOUND!")
    
    if multibyte_results and multibyte_results[0].key == multibyte_key:
        print(f"\n✓ Successfully recovered the correct key: {multibyte_key}")
    
    print("\n" + "=" * 80)
    print("Test 3: Result Prioritization")
    print("=" * 80)
    
    # Create test data with mixed quality results
    test_data = b"Some random binary data with \x00\x01\x02 non-printable chars"
    
    # Encrypt with a key
    test_key = 0x55
    encrypted_test = bytes(b ^ test_key for b in test_data)
    
    # Analyze
    analyzer2 = XORAnalyzer()
    analyzer2.brute_force_xor(encrypted_test)
    
    print("\nTop 5 by overall quality score:")
    print("-" * 80)
    for i, result in enumerate(analyzer2.get_prioritized_results()[:5], 1):
        print(f"{i}. Key: 0x{result.key:02X} | Quality: {result.quality_score:.2f} | "
              f"Printable: {result.printable_ratio:.2%}")
    
    print("\nTop 5 by printable ratio:")
    print("-" * 80)
    for i, result in enumerate(analyzer2.get_results_by_printable_priority()[:5], 1):
        print(f"{i}. Key: 0x{result.key:02X} | Quality: {result.quality_score:.2f} | "
              f"Printable: {result.printable_ratio:.2%}")
    
    print("\n" + analyzer2.format_printable_report(min_ratio=0.9, max_results=5))
