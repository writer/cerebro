"""Plugin manager for dynamic loading and management."""

import importlib
import importlib.util
from pathlib import Path
from typing import Dict, List, Any, Optional, Type, Union
import logging

from cerebro.providers.base import BaseProvider
from cerebro.findings.producers.base import BaseFindingProducer

logger = logging.getLogger(__name__)


class PluginMetadata:
    """Metadata for a loaded plugin."""

    def __init__(
        self,
        name: str,
        version: str,
        description: str,
        author: str,
        plugin_type: str,  # provider, producer, rule, integration
        module_path: str,
        class_name: str,
        config_schema: Optional[Dict] = None,
    ):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.plugin_type = plugin_type
        self.module_path = module_path
        self.class_name = class_name
        self.config_schema = config_schema or {}


class PluginManager:
    """Manages plugin loading, validation, and lifecycle."""

    def __init__(self):
        """Initialize plugin manager."""
        self._loaded_plugins: Dict[str, PluginMetadata] = {}
        self._plugin_instances: Dict[str, Any] = {}
        self._plugin_paths: List[Path] = []

    def add_plugin_path(self, path: Union[str, Path]) -> None:
        """Add a directory to search for plugins."""
        plugin_path = Path(path)
        if plugin_path.exists() and plugin_path.is_dir():
            self._plugin_paths.append(plugin_path)
            logger.info(f"Added plugin path: {plugin_path}")
        else:
            logger.warning(f"Plugin path does not exist: {plugin_path}")

    def discover_plugins(self) -> List[PluginMetadata]:
        """Discover all available plugins in plugin paths."""
        discovered = []

        for plugin_path in self._plugin_paths:
            for plugin_dir in plugin_path.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith("."):
                    try:
                        plugin_metadata = self._load_plugin_metadata(plugin_dir)
                        if plugin_metadata:
                            discovered.append(plugin_metadata)
                    except Exception as e:
                        logger.warning(
                            f"Failed to discover plugin in {plugin_dir}: {e}"
                        )

        logger.info(f"Discovered {len(discovered)} plugins")
        return discovered

    def _load_plugin_metadata(self, plugin_dir: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from plugin.yaml or __init__.py."""
        plugin_yaml = plugin_dir / "plugin.yaml"

        if plugin_yaml.exists():
            import yaml

            with open(plugin_yaml) as f:
                metadata = yaml.safe_load(f)

            return PluginMetadata(
                name=metadata["name"],
                version=metadata["version"],
                description=metadata["description"],
                author=metadata["author"],
                plugin_type=metadata["type"],
                module_path=str(plugin_dir),
                class_name=metadata["class_name"],
                config_schema=metadata.get("config_schema"),
            )

        # Try to load from __init__.py
        init_file = plugin_dir / "__init__.py"
        if init_file.exists():
            spec = importlib.util.spec_from_file_location(
                f"plugin_{plugin_dir.name}", init_file
            )

            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Look for plugin metadata
                if hasattr(module, "PLUGIN_METADATA"):
                    metadata = module.PLUGIN_METADATA
                    return PluginMetadata(
                        name=metadata["name"],
                        version=metadata["version"],
                        description=metadata["description"],
                        author=metadata["author"],
                        plugin_type=metadata["type"],
                        module_path=str(plugin_dir),
                        class_name=metadata["class_name"],
                    )

        return None

    async def load_plugin(self, plugin_name: str) -> bool:
        """Load and validate a specific plugin."""
        if plugin_name in self._loaded_plugins:
            logger.info(f"Plugin {plugin_name} already loaded")
            return True

        # Find plugin metadata
        available_plugins = self.discover_plugins()
        plugin_metadata = next(
            (p for p in available_plugins if p.name == plugin_name), None
        )

        if not plugin_metadata:
            logger.error(f"Plugin {plugin_name} not found")
            return False

        try:
            # Load the plugin module
            spec = importlib.util.spec_from_file_location(
                plugin_name, Path(plugin_metadata.module_path) / "__init__.py"
            )

            if not spec or not spec.loader:
                raise ImportError(f"Could not load plugin spec for {plugin_name}")

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Get the plugin class
            plugin_class = getattr(module, plugin_metadata.class_name)

            # Validate plugin interface
            if not self._validate_plugin_interface(
                plugin_class, plugin_metadata.plugin_type
            ):
                raise ValueError(
                    f"Plugin {plugin_name} does not implement required interface"
                )

            # Register the plugin
            self._loaded_plugins[plugin_name] = plugin_metadata
            self._plugin_instances[plugin_name] = plugin_class

            logger.info(f"Successfully loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False

    def _validate_plugin_interface(self, plugin_class: Type, plugin_type: str) -> bool:
        """Validate that plugin implements required interface."""
        if plugin_type == "provider":
            return issubclass(plugin_class, BaseProvider)
        elif plugin_type == "producer":
            return issubclass(plugin_class, BaseFindingProducer)
        elif plugin_type == "integration":
            # Check for required methods
            required_methods = ["initialize", "process", "cleanup"]
            return all(hasattr(plugin_class, method) for method in required_methods)
        else:
            logger.warning(f"Unknown plugin type: {plugin_type}")
            return False

    def get_loaded_plugins(
        self, plugin_type: Optional[str] = None
    ) -> List[PluginMetadata]:
        """Get list of loaded plugins, optionally filtered by type."""
        plugins = list(self._loaded_plugins.values())

        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]

        return plugins

    def get_plugin_instance(self, plugin_name: str) -> Optional[Any]:
        """Get instance of a loaded plugin."""
        return self._plugin_instances.get(plugin_name)

    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin (useful for development)."""
        if plugin_name in self._loaded_plugins:
            # Unload first
            del self._loaded_plugins[plugin_name]
            del self._plugin_instances[plugin_name]

        return await self.load_plugin(plugin_name)

    def create_plugin_template(
        self, plugin_name: str, plugin_type: str, output_dir: Path
    ) -> bool:
        """Create a plugin template for development."""
        plugin_dir = output_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Create plugin.yaml
            plugin_yaml = {
                "name": plugin_name,
                "version": "0.1.0",
                "description": f"Custom {plugin_type} plugin",
                "author": "Your Name",
                "type": plugin_type,
                "class_name": f"{plugin_name.title()}Plugin",
                "config_schema": {"type": "object", "properties": {}, "required": []},
            }

            import yaml

            with open(plugin_dir / "plugin.yaml", "w") as f:
                yaml.dump(plugin_yaml, f, default_flow_style=False)

            # Create __init__.py with template
            template_content = self._get_template_content(plugin_name, plugin_type)
            with open(plugin_dir / "__init__.py", "w") as f:
                f.write(template_content)

            # Create README.md
            readme_content = f"""# {plugin_name} Plugin

## Description
{plugin_yaml['description']}

## Configuration
Add configuration in your .env file:

```env
# {plugin_name.upper()} configuration
{plugin_name.upper()}_PARAM=value
```

## Installation
Copy this directory to your Cerebro plugins directory and restart Cerebro.
"""

            with open(plugin_dir / "README.md", "w") as f:
                f.write(readme_content)

            logger.info(f"Created plugin template at {plugin_dir}")
            return True

        except Exception as e:
            logger.error(f"Failed to create plugin template: {e}")
            return False

    def _get_template_content(self, plugin_name: str, plugin_type: str) -> str:
        """Get template content for plugin type."""
        class_name = f"{plugin_name.title()}Plugin"

        if plugin_type == "provider":
            return f'''"""Custom provider plugin: {plugin_name}."""

from typing import AsyncGenerator, Optional, List, Dict, Any
from cerebro.providers.base import BaseProvider, ResourceInfo, PrincipalInfo, ConfigurationSnapshot, IamPermission

PLUGIN_METADATA = {{
    "name": "{plugin_name}",
    "version": "0.1.0", 
    "description": "Custom {plugin_type} plugin",
    "author": "Your Name",
    "type": "{plugin_type}",
    "class_name": "{class_name}"
}}


class {class_name}(BaseProvider):
    """Custom provider for {plugin_name}."""
    
    @property
    def name(self) -> str:
        return "{plugin_name}"
    
    async def authenticate(self) -> bool:
        """Authenticate with {plugin_name}."""
        # Implement authentication logic
        return True
    
    async def discover_resources(
        self, 
        resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover resources from {plugin_name}."""
        # Implement resource discovery
        return
        yield  # Make this an async generator
    
    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover principals from {plugin_name}."""
        # Implement principal discovery
        return
        yield  # Make this an async generator
    
    async def get_resource_configuration(
        self, 
        resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get resource configuration from {plugin_name}."""
        # Implement configuration collection
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={{}}
        )
    
    async def discover_iam_edges(
        self,
        resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover IAM permissions from {plugin_name}."""
        # Implement permission discovery
        return
        yield  # Make this an async generator
'''

        elif plugin_type == "producer":
            return f'''"""Custom finding producer plugin: {plugin_name}."""

from typing import Set, List, Optional, Dict, Any
from cerebro.findings.producers.base import BaseFindingProducer
from cerebro.findings.producers.registry import register_producer
from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity

PLUGIN_METADATA = {{
    "name": "{plugin_name}",
    "version": "0.1.0",
    "description": "Custom {plugin_type} plugin", 
    "author": "Your Name",
    "type": "{plugin_type}",
    "class_name": "{class_name}"
}}


@register_producer
class {class_name}(BaseFindingProducer):
    """Custom finding producer for {plugin_name}."""
    
    @property
    def desired_sources(self) -> Set[str]:
        return {{"custom_provider"}}
    
    @property
    def resource_types(self) -> Set[str]:
        return {{"custom.resource.type"}}
    
    @property
    def finding_name(self) -> str:
        return "Custom: {plugin_name} Security Issue"
    
    @property
    def rule_name(self) -> str:
        return "{plugin_name}_security_rule"
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def description(self) -> str:
        return "Detects {plugin_name} security issues"
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate resource for {plugin_name} security issues."""
        findings = []
        
        # Implement your security logic here
        # Example:
        # if config.normalized_config.get("insecure_setting"):
        #     finding = self.create_finding(
        #         resource=resource,
        #         rule_id=context.get("rule_id") if context else self._get_rule_id(),
        #         evidence={{"issue": "insecure_setting_detected"}}
        #     )
        #     findings.append(finding)
        
        return findings
'''

        return ""
