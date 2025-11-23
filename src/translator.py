"""
Backward compatibility module for translator.py

This module maintains backward compatibility by re-exporting the InstructionTranslator
from the new decompiler module. All new code should use src.decompiler.Decompiler instead.

DEPRECATED: Use src.decompiler.Decompiler for new code.
"""

# Import the backward-compatible InstructionTranslator from decompiler
from src.decompiler import InstructionTranslator, Decompiler

# Re-export for backward compatibility
__all__ = ['InstructionTranslator', 'Decompiler']

# Note: The original InstructionTranslator implementation has been moved to decompiler.py
# and enhanced with variable name inference, type inference, and control flow reconstruction.
