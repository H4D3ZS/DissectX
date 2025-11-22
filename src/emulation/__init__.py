"""Emulation package for dynamic analysis"""

try:
    from .unicorn_emulator import UnicornEmulator, EmulationResult, UNICORN_AVAILABLE
    __all__ = ['UnicornEmulator', 'EmulationResult', 'UNICORN_AVAILABLE']
except ImportError:
    UNICORN_AVAILABLE = False
    __all__ = []
