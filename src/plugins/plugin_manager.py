"""
Plugin Manager for DissectX.

Provides plugin discovery, loading, and hook management capabilities.
"""

import os
import sys
import importlib.util
import inspect
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Callable, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class HookType(Enum):
    """Types of hooks that plugins can register for."""
    PRE_ANALYSIS = "pre_analysis"
    POST_ANALYSIS = "post_analysis"
    PRE_DISASSEMBLY = "pre_disassembly"
    POST_DISASSEMBLY = "post_disassembly"


class Plugin(ABC):
    """
    Abstract base class for DissectX plugins.
    
    All plugins must inherit from this class and implement the required methods.
    """
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the plugin name."""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return the plugin version."""
        pass
    
    @abstractmethod
    def analyze(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Perform custom analysis on binary data.
        
        Args:
            binary_data: The binary data to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        pass
    
    def get_description(self) -> str:
        """Return a description of the plugin (optional)."""
        return ""
    
    def get_author(self) -> str:
        """Return the plugin author (optional)."""
        return ""


class PluginManager:
    """
    Manages plugin discovery, loading, and hook execution.
    
    The PluginManager discovers plugins in the plugins/ directory,
    loads them dynamically, and manages hook registration and execution.
    """
    
    def __init__(self, plugin_dir: str = "plugins"):
        """
        Initialize the PluginManager.
        
        Args:
            plugin_dir: Directory to search for plugins (default: "plugins")
        """
        self.plugin_dir = plugin_dir
        self.plugins: List[Plugin] = []
        self.hooks: Dict[HookType, List[Callable]] = {
            hook_type: [] for hook_type in HookType
        }
        self.custom_analyzers: List[Plugin] = []
        self.custom_formats: Dict[str, Callable] = {}
        
        logger.info(f"PluginManager initialized with plugin directory: {plugin_dir}")
    
    def discover_plugins(self, plugin_dir: Optional[str] = None) -> List[str]:
        """
        Discover plugin files in the plugin directory.
        
        Args:
            plugin_dir: Optional override for the plugin directory
            
        Returns:
            List of plugin file paths
        """
        search_dir = plugin_dir or self.plugin_dir
        plugin_files = []
        
        if not os.path.exists(search_dir):
            logger.warning(f"Plugin directory does not exist: {search_dir}")
            return plugin_files
        
        logger.info(f"Discovering plugins in: {search_dir}")
        
        # Search for Python files in the plugin directory
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    plugin_path = os.path.join(root, file)
                    plugin_files.append(plugin_path)
                    logger.debug(f"Discovered plugin file: {plugin_path}")
        
        logger.info(f"Discovered {len(plugin_files)} plugin file(s)")
        return plugin_files
    
    def load_plugin(self, plugin_path: str) -> Optional[Plugin]:
        """
        Load a plugin from a file path.
        
        Args:
            plugin_path: Path to the plugin file
            
        Returns:
            Loaded Plugin instance or None if loading failed
        """
        try:
            logger.info(f"Loading plugin from: {plugin_path}")
            
            # Create module name from file path
            module_name = Path(plugin_path).stem
            
            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            if spec is None or spec.loader is None:
                logger.error(f"Failed to create module spec for: {plugin_path}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find Plugin subclasses in the module
            plugin_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, Plugin) and obj is not Plugin:
                    plugin_class = obj
                    break
            
            if plugin_class is None:
                logger.warning(f"No Plugin subclass found in: {plugin_path}")
                return None
            
            # Instantiate the plugin
            plugin = plugin_class()
            self.plugins.append(plugin)
            
            logger.info(f"Successfully loaded plugin: {plugin.get_name()} v{plugin.get_version()}")
            return plugin
            
        except Exception as e:
            logger.error(f"Failed to load plugin from {plugin_path}: {e}")
            return None
    
    def load_all_plugins(self, plugin_dir: Optional[str] = None) -> int:
        """
        Discover and load all plugins from the plugin directory.
        
        Args:
            plugin_dir: Optional override for the plugin directory
            
        Returns:
            Number of successfully loaded plugins
        """
        plugin_files = self.discover_plugins(plugin_dir)
        loaded_count = 0
        
        for plugin_file in plugin_files:
            plugin = self.load_plugin(plugin_file)
            if plugin is not None:
                loaded_count += 1
        
        logger.info(f"Loaded {loaded_count} plugin(s) successfully")
        return loaded_count
    
    def register_hook(self, hook_type: HookType, handler: Callable) -> None:
        """
        Register a hook handler for a specific hook type.
        
        Args:
            hook_type: The type of hook to register
            handler: The callable to execute when the hook is triggered
        """
        if hook_type not in self.hooks:
            logger.error(f"Invalid hook type: {hook_type}")
            return
        
        self.hooks[hook_type].append(handler)
        logger.info(f"Registered hook handler for {hook_type.value}")
    
    def execute_hooks(self, hook_type: HookType, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute all registered hooks for a specific hook type.
        
        Args:
            hook_type: The type of hook to execute
            context: Context dictionary passed to hook handlers
            
        Returns:
            Modified context dictionary after all hooks have executed
        """
        if hook_type not in self.hooks:
            logger.error(f"Invalid hook type: {hook_type}")
            return context
        
        handlers = self.hooks[hook_type]
        logger.debug(f"Executing {len(handlers)} hook(s) for {hook_type.value}")
        
        for handler in handlers:
            try:
                result = handler(context)
                if result is not None:
                    context = result
            except Exception as e:
                logger.error(f"Hook handler failed: {e}")
                # Continue with other hooks even if one fails
        
        return context
    
    def register_analyzer(self, plugin: Plugin) -> None:
        """
        Register a plugin as a custom analyzer.
        
        Args:
            plugin: The plugin to register as an analyzer
        """
        if plugin not in self.custom_analyzers:
            self.custom_analyzers.append(plugin)
            logger.info(f"Registered custom analyzer: {plugin.get_name()}")
    
    def register_format(self, format_name: str, formatter: Callable) -> None:
        """
        Register a custom output format.
        
        Args:
            format_name: Name of the format (e.g., "json", "xml")
            formatter: Callable that formats analysis results
        """
        self.custom_formats[format_name] = formatter
        logger.info(f"Registered custom format: {format_name}")
    
    def get_plugins(self) -> List[Plugin]:
        """
        Get all loaded plugins.
        
        Returns:
            List of loaded Plugin instances
        """
        return self.plugins
    
    def get_plugin_by_name(self, name: str) -> Optional[Plugin]:
        """
        Get a plugin by name.
        
        Args:
            name: The plugin name to search for
            
        Returns:
            Plugin instance or None if not found
        """
        for plugin in self.plugins:
            if plugin.get_name() == name:
                return plugin
        return None
    
    def get_custom_analyzers(self) -> List[Plugin]:
        """
        Get all registered custom analyzers.
        
        Returns:
            List of custom analyzer plugins
        """
        return self.custom_analyzers
    
    def get_custom_formats(self) -> Dict[str, Callable]:
        """
        Get all registered custom formats.
        
        Returns:
            Dictionary mapping format names to formatter callables
        """
        return self.custom_formats
    
    def unload_plugin(self, plugin: Plugin) -> bool:
        """
        Unload a plugin.
        
        Args:
            plugin: The plugin to unload
            
        Returns:
            True if successfully unloaded, False otherwise
        """
        try:
            if plugin in self.plugins:
                self.plugins.remove(plugin)
            if plugin in self.custom_analyzers:
                self.custom_analyzers.remove(plugin)
            
            logger.info(f"Unloaded plugin: {plugin.get_name()}")
            return True
        except Exception as e:
            logger.error(f"Failed to unload plugin: {e}")
            return False
