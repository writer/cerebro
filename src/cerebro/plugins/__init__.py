"""Plugin ecosystem for extensible providers and rules."""

from .decorators import (  # type: ignore[import-untyped]
    plugin,
    provider_plugin,
    rule_plugin,
)
from .loader import PluginLoader  # type: ignore[import-untyped]
from .manager import PluginManager
from .registry import plugin_registry  # type: ignore[import-untyped]

__all__ = [
    "PluginLoader",
    "PluginManager",
    "plugin",
    "plugin_registry",
    "provider_plugin",
    "rule_plugin",
]
