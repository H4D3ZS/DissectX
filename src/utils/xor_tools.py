"""
XOR Analysis and Bruteforce Tools

Provides utilities for:
- Single-byte XOR bruteforce
- Multi-byte XOR key detection
- XOR encryption/decryption
- Repeating key XOR analysis
"""

import string
from typing import List, Tuple, Optional
from collections import Counter


class XORTools:
    """XOR cryptanalysis and bruteforce utilities"""
    
    # Common English letter frequencies (%)
    ENGLISH_FREQ = {
        'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 13.0, 'f': 2.2,
        'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
        'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0,
        's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
        'y': 2.0, 'z': 0.074, ' ': 13.0
    }
    
    @staticmethod
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        """XOR data with key (repeating if necessary)"""
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    
    @staticmethod
    def score_english(text: bytes) -> float:
        """
        Score text based on English letter frequency
        Higher score = more likely to be English
        """
        try:
            text_str = text.decode('utf-8', errors='ignore').lower()
        except:
            return 0.0
        
        # Count printable characters
        printable_count = sum(1 for c in text_str if c in string.printable)
        if printable_count < len(text_str) * 0.8:
            return 0.0
        
        # Calculate frequency score
        counter = Counter(text_str)
        score = 0.0
        
        for char, freq in XORTools.ENGLISH_FREQ.items():
            observed = (counter.get(char, 0) / len(text_str)) * 100
            score += abs(freq - observed)
        
        # Lower score is better, invert it
        return 1000.0 / (score + 1)
    
    @staticmethod
    def single_byte_xor_bruteforce(ciphertext: bytes, top_n: int = 5) -> List[Tuple[int, bytes, float]]:
        """
        Bruteforce single-byte XOR
        
        Returns list of (key, plaintext, score) tuples
        """
        results = []
        
        for key in range(256):
            plaintext = bytes(b ^ key for b in ciphertext)
            score = XORTools.score_english(plaintext)
            results.append((key, plaintext, score))
        
        # Sort by score (descending)
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:top_n]
    
    @staticmethod
    def detect_xor_key_length(ciphertext: bytes, max_keylen: int = 40) -> List[Tuple[int, float]]:
        """
        Detect likely XOR key length using Hamming distance
        
        Returns list of (keylen, score) tuples sorted by likelihood
        """
        def hamming_distance(b1: bytes, b2: bytes) -> int:
            """Calculate Hamming distance between two byte strings"""
            return sum(bin(x ^ y).count('1') for x, y in zip(b1, b2))
        
        scores = []
        
        for keylen in range(2, min(max_keylen + 1, len(ciphertext) // 2)):
            # Take multiple chunks and average the distances
            distances = []
            chunks = [ciphertext[i:i+keylen] for i in range(0, len(ciphertext), keylen)]
            
            for i in range(len(chunks) - 1):
                if len(chunks[i]) == keylen and len(chunks[i+1]) == keylen:
                    dist = hamming_distance(chunks[i], chunks[i+1])
                    normalized = dist / keylen
                    distances.append(normalized)
            
            if distances:
                avg_distance = sum(distances) / len(distances)
                scores.append((keylen, avg_distance))
        
        # Sort by score (ascending - lower is better)
        scores.sort(key=lambda x: x[1])
        return scores[:10]
    
    @staticmethod
    def break_repeating_key_xor(ciphertext: bytes, keylen: Optional[int] = None) -> Tuple[bytes, bytes]:
        """
        Break repeating-key XOR cipher
        
        Returns (key, plaintext) tuple
        """
        # Detect key length if not provided
        if keylen is None:
            likely_keylens = XORTools.detect_xor_key_length(ciphertext)
            if not likely_keylens:
                raise ValueError("Could not detect key length")
            keylen = likely_keylens[0][0]
        
        # Transpose ciphertext into blocks
        blocks = [ciphertext[i::keylen] for i in range(keylen)]
        
        # Bruteforce each block (single-byte XOR)
        key = bytearray()
        for block in blocks:
            results = XORTools.single_byte_xor_bruteforce(block, top_n=1)
            if results:
                key.append(results[0][0])
            else:
                key.append(0)
        
        # Decrypt with found key
        plaintext = XORTools.xor_bytes(ciphertext, bytes(key))
        
        return bytes(key), plaintext
    
    @staticmethod
    def xor_hex_strings(hex1: str, hex2: str) -> str:
        """XOR two hex strings"""
        b1 = bytes.fromhex(hex1)
        b2 = bytes.fromhex(hex2)
        
        # Pad shorter string
        max_len = max(len(b1), len(b2))
        b1 = b1.ljust(max_len, b'\x00')
        b2 = b2.ljust(max_len, b'\x00')
        
        result = XORTools.xor_bytes(b1, b2)
        return result.hex()
    
    @staticmethod
    def find_xor_key(plaintext: bytes, ciphertext: bytes) -> bytes:
        """
        Find XOR key given plaintext and ciphertext
        Useful for known-plaintext attacks
        """
        if len(plaintext) != len(ciphertext):
            raise ValueError("Plaintext and ciphertext must be same length")
        
        return bytes(p ^ c for p, c in zip(plaintext, ciphertext))
