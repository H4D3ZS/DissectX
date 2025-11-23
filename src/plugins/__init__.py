"""
Plugin system for DissectX.

This module provides the plugin infrastructure for extending DissectX
with custom analyzers, output formats, and hooks.
"""

from .plugin_manager import PluginManager, Plugin, HookType

__all__ = ['PluginManager', 'Plugin', 'HookType']
