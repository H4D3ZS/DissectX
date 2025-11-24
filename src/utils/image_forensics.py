"""
Image Forensics Analyzer

Provides various image analysis techniques for CTF challenges:
- Color plane separation
- Bit plane analysis
- Metadata extraction
- Image transformations
"""

from PIL import Image, ImageOps
from PIL.ExifTags import TAGS
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
import io
import base64


class ImageForensics:
    """Image forensics and analysis tools"""
    
    @staticmethod
    def extract_metadata(image_path: str) -> Dict[str, Any]:
        """Extract EXIF and other metadata from image"""
        img = Image.open(image_path)
        metadata = {
            'format': img.format,
            'mode': img.mode,
            'size': img.size,
            'info': dict(img.info)
        }
        
        # Extract EXIF data
        exif_data = {}
        try:
            exif = img._getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = str(value)
        except:
            pass
        
        metadata['exif'] = exif_data
        
        return metadata
    
    @staticmethod
    def separate_color_planes(image_path: str) -> Dict[str, bytes]:
        """
        Separate image into individual color planes
        Returns base64-encoded PNG images for each plane
        """
        img = Image.open(image_path)
        
        if img.mode not in ['RGB', 'RGBA']:
            img = img.convert('RGB')
        
        planes = {}
        
        # Split into R, G, B (and A if present)
        if img.mode == 'RGBA':
            r, g, b, a = img.split()
            planes['alpha'] = ImageForensics._image_to_base64(a)
        else:
            r, g, b = img.split()
        
        planes['red'] = ImageForensics._image_to_base64(r)
        planes['green'] = ImageForensics._image_to_base64(g)
        planes['blue'] = ImageForensics._image_to_base64(b)
        
        return planes
    
    @staticmethod
    def extract_bit_planes(image_path: str, channel: str = 'red') -> Dict[int, bytes]:
        """
        Extract individual bit planes (0-7) from a channel
        Returns base64-encoded images
        """
        img = Image.open(image_path)
        
        if img.mode not in ['RGB', 'RGBA']:
            img = img.convert('RGB')
        
        # Get the specified channel
        if channel == 'red':
            ch = img.split()[0]
        elif channel == 'green':
            ch = img.split()[1]
        elif channel == 'blue':
            ch = img.split()[2]
        elif channel == 'alpha' and img.mode == 'RGBA':
            ch = img.split()[3]
        else:
            ch = img.split()[0]
        
        ch_array = np.array(ch)
        bit_planes = {}
        
        # Extract each bit plane
        for bit in range(8):
            bit_plane = ((ch_array >> bit) & 1) * 255
            bit_img = Image.fromarray(bit_plane.astype(np.uint8))
            bit_planes[bit] = ImageForensics._image_to_base64(bit_img)
        
        return bit_planes
    
    @staticmethod
    def apply_transformations(image_path: str) -> Dict[str, bytes]:
        """
        Apply various transformations that might reveal hidden data
        Returns base64-encoded images
        """
        img = Image.open(image_path)
        transformations = {}
        
        # Invert colors
        inverted = ImageOps.invert(img.convert('RGB'))
        transformations['inverted'] = ImageForensics._image_to_base64(inverted)
        
        # Grayscale
        gray = img.convert('L')
        transformations['grayscale'] = ImageForensics._image_to_base64(gray)
        
        # Flip horizontal
        flipped_h = ImageOps.mirror(img)
        transformations['flipped_horizontal'] = ImageForensics._image_to_base64(flipped_h)
        
        # Flip vertical
        flipped_v = ImageOps.flip(img)
        transformations['flipped_vertical'] = ImageForensics._image_to_base64(flipped_v)
        
        # Rotate 180
        rotated = img.rotate(180)
        transformations['rotated_180'] = ImageForensics._image_to_base64(rotated)
        
        return transformations
    
    @staticmethod
    def analyze_histogram(image_path: str) -> Dict[str, List[int]]:
        """Analyze color histogram for anomalies"""
        img = Image.open(image_path)
        
        if img.mode not in ['RGB', 'RGBA']:
            img = img.convert('RGB')
        
        histograms = {}
        
        r, g, b = img.split()[:3]
        
        histograms['red'] = r.histogram()
        histograms['green'] = g.histogram()
        histograms['blue'] = b.histogram()
        
        return histograms
    
    @staticmethod
    def detect_anomalies(image_path: str) -> List[Dict[str, Any]]:
        """
        Detect potential anomalies in the image
        Returns list of findings
        """
        findings = []
        
        # Check metadata
        metadata = ImageForensics.extract_metadata(image_path)
        
        # Check for suspicious comments
        if 'comment' in metadata['info']:
            findings.append({
                'type': 'metadata',
                'description': 'Comment found in image metadata',
                'data': metadata['info']['comment']
            })
        
        # Check for unusual EXIF data
        if metadata['exif']:
            for key, value in metadata['exif'].items():
                if any(keyword in str(value).lower() for keyword in ['flag', 'password', 'secret', 'key']):
                    findings.append({
                        'type': 'exif',
                        'description': f'Suspicious EXIF tag: {key}',
                        'data': value
                    })
        
        # Check image dimensions
        width, height = metadata['size']
        if width != height and abs(width - height) == 1:
            findings.append({
                'type': 'dimensions',
                'description': 'Unusual dimensions (off by 1)',
                'data': f'{width}x{height}'
            })
        
        return findings
    
    @staticmethod
    def _image_to_base64(img: Image.Image) -> str:
        """Convert PIL Image to base64 string"""
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_bytes = buffer.getvalue()
        return base64.b64encode(img_bytes).decode('utf-8')
    
    @staticmethod
    def _base64_to_image(b64_string: str) -> Image.Image:
        """Convert base64 string to PIL Image"""
        img_bytes = base64.b64decode(b64_string)
        return Image.open(io.BytesIO(img_bytes))
