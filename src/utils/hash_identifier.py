"""
Hash Identification and Analysis Tools
"""

import re
from typing import List, Dict, Optional


class HashIdentifier:
    """
    Identify hash types based on length and patterns
    """
    
    HASH_PATTERNS = {
        'MD5': {
            'length': 32,
            'pattern': r'^[a-f0-9]{32}$',
            'example': '5d41402abc4b2a76b9719d911017c592'
        },
        'SHA1': {
            'length': 40,
            'pattern': r'^[a-f0-9]{40}$',
            'example': 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
        },
        'SHA256': {
            'length': 64,
            'pattern': r'^[a-f0-9]{64}$',
            'example': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
        },
        'SHA512': {
            'length': 128,
            'pattern': r'^[a-f0-9]{128}$',
            'example': '...'
        },
        'NTLM': {
            'length': 32,
            'pattern': r'^[a-f0-9]{32}$',
            'example': 'b4b9b02e6f09a9bd760f388b67351e2b'
        },
        'MySQL5': {
            'length': 40,
            'pattern': r'^\*[a-f0-9]{40}$',
            'example': '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
        },
        'bcrypt': {
            'length': 60,
            'pattern': r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$',
            'example': '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
        },
    }
    
    @staticmethod
    def identify(hash_string: str) -> List[Dict[str, str]]:
        """
        Identify possible hash types
        
        Args:
            hash_string: Hash to identify
            
        Returns:
            List of possible hash types with confidence
        """
        hash_string = hash_string.strip()
        matches = []
        
        for hash_type, info in HashIdentifier.HASH_PATTERNS.items():
            if re.match(info['pattern'], hash_string, re.IGNORECASE):
                matches.append({
                    'type': hash_type,
                    'confidence': 'high' if len(matches) == 0 else 'medium',
                    'length': len(hash_string)
                })
        
        return matches if matches else [{'type': 'Unknown', 'confidence': 'none', 'length': len(hash_string)}]
    
    @staticmethod
    def get_hashcat_mode(hash_type: str) -> Optional[int]:
        """
        Get hashcat mode number for hash type
        
        Args:
            hash_type: Hash type name
            
        Returns:
            Hashcat mode number or None
        """
        modes = {
            'MD5': 0,
            'SHA1': 100,
            'SHA256': 1400,
            'SHA512': 1700,
            'NTLM': 1000,
            'bcrypt': 3200,
            'MySQL5': 300,
        }
        return modes.get(hash_type)
