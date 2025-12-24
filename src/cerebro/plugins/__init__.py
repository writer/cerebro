"""Plugin ecosystem for extensible providers and rules."""

from .manager import PluginManager
from .loader import PluginLoader  # type: ignore[import-untyped]
from .registry import plugin_registry  # type: ignore[import-untyped]
from .decorators import plugin, provider_plugin, rule_plugin  # type: ignore[import-untyped]

__all__ = [
    "PluginManager",
    "PluginLoader",
    "plugin_registry",
    "plugin",
    "provider_plugin",
    "rule_plugin",
]
