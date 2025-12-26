"""Plugin system for extensibility and custom attack modules

This module provides a plugin architecture that allows:
- Loading custom attack modules from external files
- Registering custom payloads
- Plugin configuration management
- Access to core framework APIs
"""

import importlib.util
import inspect
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Type
import sys


@dataclass
class PluginMetadata:
    """Plugin metadata information"""
    name: str
    version: str
    author: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """Result from module execution"""
    success: bool
    vulnerability_found: bool
    findings: List[Any] = field(default_factory=list)
    execution_time: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class Plugin(ABC):
    """
    Base class for all plugins.
    
    Plugins must inherit from this class and implement the required methods.
    """
    
    def __init__(self):
        """Initialize plugin"""
        self.core_engine = None
        self.config: Dict[str, Any] = {}
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.
        
        Returns:
            PluginMetadata object with plugin information
        """
        pass
    
    @abstractmethod
    def initialize(self, core_engine: Any):
        """
        Initialize plugin with core engine access.
        
        Args:
            core_engine: CoreEngine instance providing access to framework APIs
        """
        pass
    
    def get_config_schema(self) -> Dict[str, Any]:
        """
        Get configuration schema for the plugin.
        
        Returns:
            JSON schema describing configuration options
        """
        metadata = self.get_metadata()
        return metadata.config_schema
    
    def set_config(self, config: Dict[str, Any]):
        """
        Set plugin configuration.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get current plugin configuration.
        
        Returns:
            Configuration dictionary
        """
        return self.config
    
    def get_modules(self) -> List[Type]:
        """
        Get list of attack modules provided by this plugin.
        
        Returns:
            List of module classes
        """
        return []
    
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        Get custom payloads provided by this plugin.
        
        Returns:
            Dictionary mapping payload categories to payload lists
        """
        return {}


class AttackModule(ABC):
    """
    Base class for attack modules.
    
    Attack modules implement specific vulnerability testing logic.
    """
    
    @abstractmethod
    async def execute(self, target: Any, params: Dict[str, Any]) -> ModuleResult:
        """
        Execute the attack module.
        
        Args:
            target: Target configuration
            params: Module parameters
            
        Returns:
            ModuleResult with execution results
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get module name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Get module description"""
        pass
    
    def get_parameters(self) -> Dict[str, Any]:
        """
        Get module parameter schema.
        
        Returns:
            Dictionary describing expected parameters
        """
        return {}


@dataclass
class LoadedPlugin:
    """Information about a loaded plugin"""
    plugin_id: str
    plugin: Plugin
    metadata: PluginMetadata
    modules: List[Type[AttackModule]] = field(default_factory=list)
    payloads: Dict[str, List[str]] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


class PluginSystem:
    """
    Plugin system for loading and managing plugins.
    
    Provides:
    - Plugin loading from Python files
    - Module registration
    - Payload integration
    - Configuration management
    - Core API access for plugins
    """
    
    def __init__(self, plugin_dir: Optional[Path] = None):
        """
        Initialize plugin system.
        
        Args:
            plugin_dir: Directory to search for plugins
        """
        self.plugin_dir = plugin_dir or Path("plugins")
        self.plugins: Dict[str, LoadedPlugin] = {}
        self.core_engine = None
        self._next_plugin_id = 1
    
    def set_core_engine(self, core_engine: Any):
        """
        Set core engine for plugin access.
        
        Args:
            core_engine: CoreEngine instance
        """
        self.core_engine = core_engine
    
    def load_plugin(self, plugin_path: Path) -> str:
        """
        Load a plugin from a Python file.
        
        Args:
            plugin_path: Path to plugin file
            
        Returns:
            Plugin ID
            
        Raises:
            ValueError: If plugin is invalid
            ImportError: If plugin cannot be loaded
        """
        if not plugin_path.exists():
            raise FileNotFoundError(f"Plugin file not found: {plugin_path}")
        
        # Generate plugin ID
        plugin_id = f"plugin_{self._next_plugin_id}"
        self._next_plugin_id += 1
        
        # Load the module
        spec = importlib.util.spec_from_file_location(plugin_id, plugin_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin from {plugin_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[plugin_id] = module
        spec.loader.exec_module(module)
        
        # Find Plugin class in the module
        plugin_class = None
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, Plugin) and 
                obj is not Plugin):
                plugin_class = obj
                break
        
        if plugin_class is None:
            raise ValueError(f"No Plugin class found in {plugin_path}")
        
        # Instantiate plugin
        plugin = plugin_class()
        
        # Get metadata
        metadata = plugin.get_metadata()
        
        # Initialize plugin with core engine
        if self.core_engine:
            plugin.initialize(self.core_engine)
        
        # Get modules and payloads
        modules = plugin.get_modules()
        payloads = plugin.get_payloads()
        
        # Store loaded plugin
        loaded_plugin = LoadedPlugin(
            plugin_id=plugin_id,
            plugin=plugin,
            metadata=metadata,
            modules=modules,
            payloads=payloads
        )
        
        self.plugins[plugin_id] = loaded_plugin
        
        return plugin_id
    
    def load_plugins_from_directory(self, directory: Optional[Path] = None) -> List[str]:
        """
        Load all plugins from a directory.
        
        Args:
            directory: Directory to search (default: self.plugin_dir)
            
        Returns:
            List of loaded plugin IDs
        """
        if directory is None:
            directory = self.plugin_dir
        
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            return []
        
        plugin_ids = []
        for plugin_file in directory.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue  # Skip private files
            
            try:
                plugin_id = self.load_plugin(plugin_file)
                plugin_ids.append(plugin_id)
            except Exception as e:
                print(f"Failed to load plugin {plugin_file}: {e}")
        
        return plugin_ids
    
    def unload_plugin(self, plugin_id: str):
        """
        Unload a plugin.
        
        Args:
            plugin_id: Plugin ID to unload
        """
        if plugin_id in self.plugins:
            # Remove from sys.modules
            if plugin_id in sys.modules:
                del sys.modules[plugin_id]
            
            # Remove from plugins dict
            del self.plugins[plugin_id]
    
    def get_plugin(self, plugin_id: str) -> Optional[LoadedPlugin]:
        """
        Get a loaded plugin by ID.
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            LoadedPlugin or None if not found
        """
        return self.plugins.get(plugin_id)
    
    def get_plugins(self) -> List[LoadedPlugin]:
        """
        Get all loaded plugins.
        
        Returns:
            List of LoadedPlugin objects
        """
        return list(self.plugins.values())
    
    def get_enabled_plugins(self) -> List[LoadedPlugin]:
        """
        Get all enabled plugins.
        
        Returns:
            List of enabled LoadedPlugin objects
        """
        return [p for p in self.plugins.values() if p.enabled]
    
    def enable_plugin(self, plugin_id: str):
        """
        Enable a plugin.
        
        Args:
            plugin_id: Plugin ID
        """
        if plugin_id in self.plugins:
            self.plugins[plugin_id].enabled = True
    
    def disable_plugin(self, plugin_id: str):
        """
        Disable a plugin.
        
        Args:
            plugin_id: Plugin ID
        """
        if plugin_id in self.plugins:
            self.plugins[plugin_id].enabled = False
    
    def register_module(self, module_class: Type[AttackModule], plugin_id: Optional[str] = None):
        """
        Register a custom attack module.
        
        Args:
            module_class: Attack module class
            plugin_id: Optional plugin ID to associate with
        """
        if plugin_id and plugin_id in self.plugins:
            self.plugins[plugin_id].modules.append(module_class)
        else:
            # Create a temporary plugin for standalone modules
            temp_plugin_id = f"standalone_{module_class.__name__}"
            if temp_plugin_id not in self.plugins:
                loaded_plugin = LoadedPlugin(
                    plugin_id=temp_plugin_id,
                    plugin=None,  # No plugin instance for standalone
                    metadata=PluginMetadata(
                        name=module_class.__name__,
                        version="1.0.0",
                        author="Unknown",
                        description="Standalone module"
                    ),
                    modules=[module_class]
                )
                self.plugins[temp_plugin_id] = loaded_plugin
            else:
                self.plugins[temp_plugin_id].modules.append(module_class)
    
    def get_all_modules(self) -> List[Type[AttackModule]]:
        """
        Get all registered attack modules from all enabled plugins.
        
        Returns:
            List of attack module classes
        """
        modules = []
        for plugin in self.get_enabled_plugins():
            modules.extend(plugin.modules)
        return modules
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """
        Get all payloads from all enabled plugins.
        
        Returns:
            Dictionary mapping categories to payload lists
        """
        all_payloads: Dict[str, List[str]] = {}
        
        for plugin in self.get_enabled_plugins():
            for category, payloads in plugin.payloads.items():
                if category not in all_payloads:
                    all_payloads[category] = []
                all_payloads[category].extend(payloads)
        
        return all_payloads
    
    def set_plugin_config(self, plugin_id: str, config: Dict[str, Any]):
        """
        Set configuration for a plugin.
        
        Args:
            plugin_id: Plugin ID
            config: Configuration dictionary
        """
        if plugin_id in self.plugins:
            loaded_plugin = self.plugins[plugin_id]
            loaded_plugin.config = config
            if loaded_plugin.plugin:
                loaded_plugin.plugin.set_config(config)
    
    def get_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """
        Get configuration for a plugin.
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            Configuration dictionary
        """
        if plugin_id in self.plugins:
            return self.plugins[plugin_id].config
        return {}
    
    def save_plugin_configs(self, config_file: Path):
        """
        Save all plugin configurations to a file.
        
        Args:
            config_file: Path to configuration file
        """
        configs = {}
        for plugin_id, loaded_plugin in self.plugins.items():
            configs[plugin_id] = {
                'enabled': loaded_plugin.enabled,
                'config': loaded_plugin.config
            }
        
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(configs, f, indent=2)
    
    def load_plugin_configs(self, config_file: Path):
        """
        Load plugin configurations from a file.
        
        Args:
            config_file: Path to configuration file
        """
        if not config_file.exists():
            return
        
        with open(config_file, 'r') as f:
            configs = json.load(f)
        
        for plugin_id, plugin_config in configs.items():
            if plugin_id in self.plugins:
                self.plugins[plugin_id].enabled = plugin_config.get('enabled', True)
                self.set_plugin_config(plugin_id, plugin_config.get('config', {}))
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a plugin.
        
        Args:
            plugin_id: Plugin ID
            
        Returns:
            Dictionary with plugin information
        """
        if plugin_id not in self.plugins:
            return None
        
        loaded_plugin = self.plugins[plugin_id]
        metadata = loaded_plugin.metadata
        
        return {
            'plugin_id': plugin_id,
            'name': metadata.name,
            'version': metadata.version,
            'author': metadata.author,
            'description': metadata.description,
            'dependencies': metadata.dependencies,
            'enabled': loaded_plugin.enabled,
            'modules_count': len(loaded_plugin.modules),
            'payload_categories': list(loaded_plugin.payloads.keys()),
            'config_schema': metadata.config_schema
        }
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all plugins with their information.
        
        Returns:
            List of plugin information dictionaries
        """
        return [
            self.get_plugin_info(plugin_id)
            for plugin_id in self.plugins.keys()
        ]
