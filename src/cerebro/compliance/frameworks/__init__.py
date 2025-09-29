"""
Compliance framework providers.

This module contains pluggable framework implementations that integrate
with the framework registry system.
"""

from .soc2_provider import SOC2FrameworkProvider
from .iso27001_provider import ISO27001FrameworkProvider

# Auto-register providers with the global registry
from ..framework_registry import register_framework_provider

# Register all providers
register_framework_provider(SOC2FrameworkProvider())
register_framework_provider(ISO27001FrameworkProvider())

__all__ = [
    "SOC2FrameworkProvider",
    "ISO27001FrameworkProvider"
]