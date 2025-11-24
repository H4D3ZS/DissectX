"""
Common Cipher Tools for CTF
"""

import string
from typing import List, Tuple


class CipherTools:
    """
    Common cipher encoding/decoding utilities
    """
    
    @staticmethod
    def rot13(text: str) -> str:
        """ROT13 cipher"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + 13) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def caesar_shift(text: str, shift: int) -> str:
        """Caesar cipher with custom shift"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def caesar_bruteforce(ciphertext: str) -> List[Tuple[int, str]]:
        """
        Try all 26 possible Caesar shifts
        
        Returns:
            List of (shift, plaintext) tuples
        """
        results = []
        for shift in range(26):
            plaintext = CipherTools.caesar_shift(ciphertext, shift)
            results.append((shift, plaintext))
        return results
    
    @staticmethod
    def atbash(text: str) -> str:
        """Atbash cipher (A=Z, B=Y, etc.)"""
        result = []
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result.append(chr(ord('Z') - (ord(char) - ord('A'))))
                else:
                    result.append(chr(ord('z') - (ord(char) - ord('a'))))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def vigenere_decrypt(ciphertext: str, key: str) -> str:
        """
        Vigenere cipher decryption
        
        Args:
            ciphertext: Encrypted text
            key: Decryption key
            
        Returns:
            Decrypted plaintext
        """
        result = []
        key = key.upper()
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                shift = ord(key[key_index % len(key)]) - ord('A')
                result.append(chr((ord(char) - base - shift) % 26 + base))
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """Base64 decode"""
        import base64
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except:
            return "Invalid Base64"
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """Base64 encode"""
        import base64
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def hex_decode(hex_string: str) -> str:
        """Hex to ASCII"""
        try:
            return bytes.fromhex(hex_string.replace(' ', '')).decode('utf-8', errors='ignore')
        except:
            return "Invalid Hex"
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """ASCII to Hex"""
        return text.encode().hex()
