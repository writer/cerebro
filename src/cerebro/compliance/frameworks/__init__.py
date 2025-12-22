"""
Compliance framework providers.

This module contains pluggable framework implementations that integrate
with the framework registry system.

IMPORTANT: This package shadows the sibling frameworks.py module.
We re-export key classes from frameworks.py to maintain backwards compatibility.
"""

# First import framework definitions from the sibling frameworks.py module
# We need to use parent import to avoid circular dependency
import importlib.util

# Load the frameworks.py module explicitly
spec = importlib.util.spec_from_file_location(
    "cerebro.compliance._frameworks_defs",
    __file__.rsplit("/", 1)[0] + "/../frameworks.py",
)
_frameworks_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_frameworks_module)

# Re-export key classes
ComplianceFramework = _frameworks_module.ComplianceFramework
ComplianceControl = _frameworks_module.ComplianceControl
EvidenceType = _frameworks_module.EvidenceType
ControlType = _frameworks_module.ControlType
SOC2Framework = _frameworks_module.SOC2Framework
ISO27001Framework = _frameworks_module.ISO27001Framework
PCIDSSFramework = _frameworks_module.PCIDSSFramework

# Import providers after the base classes are available
from .soc2_provider import SOC2FrameworkProvider
from .iso27001_provider import ISO27001FrameworkProvider

# Auto-register providers with the global registry
from ..framework_registry import (
    register_framework_provider,
    get_framework,
    list_frameworks,
)

# Register all providers
register_framework_provider(SOC2FrameworkProvider())
register_framework_provider(ISO27001FrameworkProvider())

__all__ = [
    "SOC2FrameworkProvider",
    "ISO27001FrameworkProvider",
    "get_framework",
    "list_frameworks",
    "ComplianceFramework",
    "ComplianceControl",
    "EvidenceType",
    "ControlType",
    "SOC2Framework",
    "ISO27001Framework",
    "PCIDSSFramework",
]
