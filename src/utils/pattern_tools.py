import struct

class PatternGenerator:
    """
    Generates cyclic patterns (De Bruijn sequences) to find buffer overflow offsets.
    """

    def __init__(self):
        pass

    def create(self, length: int) -> str:
        """
        Generate a cyclic pattern of a given length.
        Uses a modified De Bruijn sequence generator (Aa0Aa1Aa2...).
        
        Args:
            length: Length of the pattern to generate
            
        Returns:
            Generated pattern string
        """
        pattern = ""
        parts = []
        
        # Standard pattern: uppercase, lowercase, digit
        # A, a, 0, A, a, 1, ...
        # Cycle: 26 * 26 * 10 = 6760 unique 3-char sequences, but we need 4-byte uniqueness usually.
        # Common tools use 4-byte cycles.
        # Let's use a simple robust generator compatible with Metasploit/pwntools style
        
        for x in range(26): # A-Z
            for y in range(26): # a-z
                for z in range(10): # 0-9
                    if len(pattern) < length:
                        chunk = chr(65+x) + chr(97+y) + str(z)
                        pattern += chunk
                    else:
                        return pattern[:length]
        
        # If we need more, we can extend the logic, but 26*26*10*3 = 20280 chars is usually enough for stack overflows.
        # For larger patterns, we'd need a full De Bruijn generator.
        return pattern[:length]

    def offset(self, value: str) -> int:
        """
        Find the offset of a value in the pattern.
        
        Args:
            value: The value to find (can be hex string '0x41414141' or raw string 'AAAA')
            
        Returns:
            Offset integer or -1 if not found
        """
        # Generate a large enough pattern to search in (e.g., 20000 chars)
        search_pattern = self.create(20000)
        
        # Handle hex input (e.g., 0x41414141)
        if value.startswith('0x'):
            try:
                # Convert hex to bytes, then to string (little endian usually for x86)
                hex_val = value[2:]
                if len(hex_val) % 2 != 0:
                    hex_val = '0' + hex_val
                byte_val = bytes.fromhex(hex_val)
                # Try little endian (standard for x86)
                search_val = byte_val[::-1].decode('latin-1')
                
                # Check if found
                idx = search_pattern.find(search_val)
                if idx != -1:
                    return idx
                
                # Try big endian
                search_val = byte_val.decode('latin-1')
                idx = search_pattern.find(search_val)
                if idx != -1:
                    return idx
                    
            except Exception:
                pass
        
        # Handle raw string input
        idx = search_pattern.find(value)
        return idx
