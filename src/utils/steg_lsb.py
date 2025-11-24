"""
LSB (Least Significant Bit) Steganography Extractor

Extract hidden data from images using LSB techniques.
Supports PNG, BMP, and other lossless formats.
"""

from PIL import Image
import numpy as np
from typing import Optional, Tuple, List, Dict, Any


class LSBExtractor:
    """Extract hidden data using LSB steganography"""
    
    @staticmethod
    def extract_lsb(image_path: str, num_bits: int = 1, channel: str = 'all') -> bytes:
        """
        Extract LSB data from image
        
        Args:
            image_path: Path to image file
            num_bits: Number of LSB bits to extract (1-4)
            channel: Which channel to extract from ('R', 'G', 'B', 'A', 'all')
        
        Returns:
            Extracted bytes
        """
        img = Image.open(image_path)
        img_array = np.array(img)
        
        # Handle different image modes
        if img.mode == 'L':  # Grayscale
            channels = [img_array]
        elif img.mode == 'RGB':
            channels = [img_array[:, :, i] for i in range(3)]
        elif img.mode == 'RGBA':
            channels = [img_array[:, :, i] for i in range(4)]
        else:
            raise ValueError(f"Unsupported image mode: {img.mode}")
        
        # Select channel
        if channel == 'all':
            selected_channels = channels
        elif channel == 'R':
            selected_channels = [channels[0]]
        elif channel == 'G':
            selected_channels = [channels[1]]
        elif channel == 'B':
            selected_channels = [channels[2]]
        elif channel == 'A' and len(channels) > 3:
            selected_channels = [channels[3]]
        else:
            raise ValueError(f"Invalid channel: {channel}")
        
        # Extract bits
        bits = []
        for ch in selected_channels:
            flat = ch.flatten()
            for pixel in flat:
                for bit_pos in range(num_bits):
                    bits.append((pixel >> bit_pos) & 1)
        
        # Convert bits to bytes
        result = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte |= (bits[i + j] << j)
                result.append(byte)
        
        return bytes(result)
    
    @staticmethod
    def extract_all_channels(image_path: str, num_bits: int = 1) -> Dict[str, bytes]:
        """Extract LSB from all channels separately"""
        img = Image.open(image_path)
        results = {}
        
        if img.mode == 'RGB':
            channels = ['R', 'G', 'B']
        elif img.mode == 'RGBA':
            channels = ['R', 'G', 'B', 'A']
        elif img.mode == 'L':
            channels = ['L']
        else:
            channels = ['all']
        
        for channel in channels:
            try:
                results[channel] = LSBExtractor.extract_lsb(image_path, num_bits, channel)
            except:
                pass
        
        return results
    
    @staticmethod
    def auto_detect_hidden_data(image_path: str) -> Optional[Dict[str, Any]]:
        """
        Automatically detect hidden data in image
        Tries different bit depths and channels
        """
        results = []
        
        for num_bits in [1, 2, 3, 4]:
            for channel in ['R', 'G', 'B', 'A', 'all']:
                try:
                    data = LSBExtractor.extract_lsb(image_path, num_bits, channel)
                    
                    # Check if data looks meaningful
                    score = LSBExtractor._score_data(data)
                    
                    if score > 0.5:  # Threshold for "meaningful" data
                        results.append({
                            'channel': channel,
                            'bits': num_bits,
                            'data': data,
                            'score': score,
                            'preview': data[:100].decode('utf-8', errors='ignore')
                        })
                except:
                    continue
        
        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)
        
        return results[:5] if results else None
    
    @staticmethod
    def _score_data(data: bytes) -> float:
        """
        Score extracted data for likelihood of being meaningful
        Returns 0.0 to 1.0
        """
        if len(data) < 10:
            return 0.0
        
        score = 0.0
        
        # Check for printable ASCII
        printable_count = sum(1 for b in data[:1000] if 32 <= b <= 126 or b in [9, 10, 13])
        printable_ratio = printable_count / min(len(data), 1000)
        score += printable_ratio * 0.4
        
        # Check for common file signatures
        signatures = {
            b'PNG': 0.3,
            b'GIF': 0.3,
            b'JFIF': 0.3,
            b'PDF': 0.3,
            b'PK\x03\x04': 0.3,  # ZIP
            b'\x7fELF': 0.3,
            b'flag{': 0.5,
            b'CTF{': 0.5,
            b'picoCTF{': 0.5
        }
        
        for sig, sig_score in signatures.items():
            if sig in data[:100]:
                score += sig_score
                break
        
        # Check entropy (not too random, not too uniform)
        byte_counts = [0] * 256
        for b in data[:1000]:
            byte_counts[b] += 1
        
        non_zero = sum(1 for c in byte_counts if c > 0)
        if 10 < non_zero < 200:  # Sweet spot
            score += 0.3
        
        return min(score, 1.0)
    
    @staticmethod
    def extract_with_length_prefix(image_path: str, channel: str = 'all') -> Optional[bytes]:
        """
        Extract data that has a length prefix (common in CTFs)
        First 32 bits = length of hidden data
        """
        try:
            data = LSBExtractor.extract_lsb(image_path, 1, channel)
            
            # Read length (first 4 bytes)
            if len(data) < 4:
                return None
            
            length = int.from_bytes(data[:4], byteorder='big')
            
            # Sanity check
            if length > len(data) - 4 or length <= 0:
                return None
            
            return data[4:4+length]
        except:
            return None
