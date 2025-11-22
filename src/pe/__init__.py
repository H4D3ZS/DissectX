"""PE analysis package"""

try:
    from .memory_parser import MemoryPEParser, MemoryPEAnalysis, PEFILE_AVAILABLE
    __all__ = ['MemoryPEParser', 'MemoryPEAnalysis', 'PEFILE_AVAILABLE']
except ImportError:
    PEFILE_AVAILABLE = False
    __all__ = []
