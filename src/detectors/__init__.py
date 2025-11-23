"""Detectors package for advanced binary analysis"""

from .syscall_detector import SyscallDetector
from .api_hash_resolver import APIHashResolver
from .junk_detector import JunkDetector
from .flag_finder import FlagFinder
from .flag_detector import FlagDetector, DetectedFlag, ConfidenceLevel
from .xor_analyzer import XORAnalyzer, XORResult, MultiByteXORResult
from .anti_analysis_detector import (
    AntiAnalysisDetector, 
    DetectedTechnique, 
    AntiAnalysisReport,
    TechniqueType
)
from .shellcode_detector import (
    ShellcodeDetector,
    ShellcodePattern,
    ExtractedShellcode,
    DeobfuscatedShellcode,
    ShellcodeAnalysisReport,
    ShellcodeType
)

__all__ = [
    'SyscallDetector', 
    'APIHashResolver', 
    'JunkDetector', 
    'FlagFinder',
    'FlagDetector',
    'DetectedFlag',
    'ConfidenceLevel',
    'XORAnalyzer',
    'XORResult',
    'MultiByteXORResult',
    'AntiAnalysisDetector',
    'DetectedTechnique',
    'AntiAnalysisReport',
    'TechniqueType',
    'ShellcodeDetector',
    'ShellcodePattern',
    'ExtractedShellcode',
    'DeobfuscatedShellcode',
    'ShellcodeAnalysisReport',
    'ShellcodeType'
]
