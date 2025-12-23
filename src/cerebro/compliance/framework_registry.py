"""
Pluggable compliance framework registry.

Replaces hardcoded framework definitions with a flexible plugin system
that separates framework metadata from implementation details.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import importlib
import pkgutil

logger = logging.getLogger(__name__)


class ControlType(Enum):
    """Types of security controls."""

    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    ADMINISTRATIVE = "administrative"
    TECHNICAL = "technical"
    PHYSICAL = "physical"


class AutomationLevel(Enum):
    """Level of automation for controls."""

    MANUAL = "manual"
    SEMI_AUTOMATED = "semi_automated"
    AUTOMATED = "automated"


class TestingFrequency(Enum):
    """How often controls should be tested."""

    CONTINUOUS = "continuous"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"
    ON_DEMAND = "on_demand"


@dataclass
class ControlDefinition:
    """Definition of a compliance control."""

    # Core identification
    control_id: str
    title: str
    description: str
    category: str

    # Control properties
    control_type: ControlType
    automation_level: AutomationLevel
    testing_frequency: TestingFrequency

    # Implementation
    evidence_queries: List[str] = field(default_factory=list)
    evidence_collection_methods: List[str] = field(default_factory=list)

    # Guidance and context
    remediation_guidance: str = ""
    implementation_guidance: str = ""
    testing_procedures: List[str] = field(default_factory=list)

    # Risk and impact
    risk_level: str = "medium"  # "low", "medium", "high", "critical"
    business_impact: str = ""

    # Dependencies and relationships
    depends_on: List[str] = field(default_factory=list)
    related_controls: List[str] = field(default_factory=list)

    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    last_updated: Optional[str] = None
    version: str = "1.0"


@dataclass
class FrameworkDefinition:
    """Definition of a compliance framework."""

    # Core identification
    framework_id: str
    name: str
    version: str
    description: str

    # Framework properties
    issuing_organization: str
    framework_type: str = (
        "compliance"  # "compliance", "security", "privacy", "operational"
    )
    industry_focus: List[str] = field(default_factory=list)
    geographic_scope: List[str] = field(default_factory=list)

    # Controls
    controls: List[ControlDefinition] = field(default_factory=list)
    control_families: Dict[str, List[str]] = field(default_factory=dict)

    # Framework metadata
    effective_date: Optional[str] = None
    update_frequency: str = "annually"
    certification_available: bool = False

    # Implementation
    maturity_model: Dict[str, Any] = field(default_factory=dict)
    implementation_tiers: List[str] = field(default_factory=list)

    # Documentation
    references: List[str] = field(default_factory=list)
    documentation_urls: List[str] = field(default_factory=list)
    training_resources: List[str] = field(default_factory=list)

    def get_control(self, control_id: str) -> Optional[ControlDefinition]:
        """Get control by ID."""
        return next((c for c in self.controls if c.control_id == control_id), None)

    def get_controls_by_family(self, family: str) -> List[ControlDefinition]:
        """Get controls in a family/category."""
        family_control_ids = self.control_families.get(family, [])
        return [c for c in self.controls if c.control_id in family_control_ids]

    def get_automated_controls(self) -> List[ControlDefinition]:
        """Get fully automated controls."""
        return [
            c for c in self.controls if c.automation_level == AutomationLevel.AUTOMATED
        ]

    def get_controls_by_frequency(
        self, frequency: TestingFrequency
    ) -> List[ControlDefinition]:
        """Get controls with specific testing frequency."""
        return [c for c in self.controls if c.testing_frequency == frequency]


class FrameworkProvider(ABC):
    """Abstract base class for framework providers."""

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Unique framework identifier."""
        pass

    @property
    @abstractmethod
    def supported_versions(self) -> List[str]:
        """Supported framework versions."""
        pass

    @abstractmethod
    def get_framework_definition(
        self, version: Optional[str] = None
    ) -> FrameworkDefinition:
        """Get framework definition for specified version."""
        pass

    @abstractmethod
    def validate_control_implementation(
        self, control_id: str, evidence_data: Any
    ) -> bool:
        """Validate that control implementation meets framework requirements."""
        pass

    def get_evidence_queries(self, control_id: str) -> List[str]:
        """Get SQL queries for collecting control evidence."""
        framework = self.get_framework_definition()
        control = framework.get_control(control_id)
        return control.evidence_queries if control else []

    def get_control_guidance(self, control_id: str) -> Dict[str, str]:
        """Get implementation and remediation guidance for a control."""
        framework = self.get_framework_definition()
        control = framework.get_control(control_id)
        if not control:
            return {}

        return {
            "implementation": control.implementation_guidance,
            "remediation": control.remediation_guidance,
            "testing_procedures": "; ".join(control.testing_procedures),
        }


class FrameworkRegistry:
    """Registry for compliance framework providers."""

    def __init__(self):
        self._providers: Dict[str, FrameworkProvider] = {}
        self._framework_cache: Dict[str, FrameworkDefinition] = {}
        self._custom_query_handlers: Dict[str, Callable] = {}

    def register_provider(self, provider: FrameworkProvider):
        """Register a framework provider."""
        framework_id = provider.framework_id
        if framework_id in self._providers:
            logger.warning(f"Overriding existing framework provider: {framework_id}")

        self._providers[framework_id] = provider
        logger.info(f"Registered framework provider: {framework_id}")

    def register_query_handler(self, control_id: str, handler: Callable):
        """Register custom query handler for a control."""
        self._custom_query_handlers[control_id] = handler
        logger.info(f"Registered custom query handler for control: {control_id}")

    def get_framework(
        self, framework_id: str, version: Optional[str] = None
    ) -> Optional[FrameworkDefinition]:
        """Get framework definition."""
        cache_key = f"{framework_id}:{version or 'latest'}"

        if cache_key in self._framework_cache:
            return self._framework_cache[cache_key]

        provider = self._providers.get(framework_id)
        if not provider:
            return None

        framework = provider.get_framework_definition(version)
        self._framework_cache[cache_key] = framework
        return framework

    def list_frameworks(self) -> List[str]:
        """List all registered frameworks."""
        return list(self._providers.keys())

    def get_frameworks_by_type(self, framework_type: str) -> List[FrameworkDefinition]:
        """Get frameworks by type (compliance, security, privacy, etc.)."""
        frameworks = []
        for framework_id in self._providers:
            framework = self.get_framework(framework_id)
            if framework and framework.framework_type == framework_type:
                frameworks.append(framework)
        return frameworks

    def get_provider(self, framework_id: str) -> Optional[FrameworkProvider]:
        """Get framework provider."""
        return self._providers.get(framework_id)

    def validate_control_implementation(
        self, framework_id: str, control_id: str, evidence_data: Any
    ) -> bool:
        """Validate control implementation using framework provider."""
        provider = self._providers.get(framework_id)
        if not provider:
            return False

        return provider.validate_control_implementation(control_id, evidence_data)

    def get_evidence_queries(self, framework_id: str, control_id: str) -> List[str]:
        """Get evidence collection queries for a control."""
        provider = self._providers.get(framework_id)
        if not provider:
            return []

        # Check for custom query handler first
        if control_id in self._custom_query_handlers:
            try:
                return self._custom_query_handlers[control_id]()
            except Exception as e:
                logger.error(f"Custom query handler failed for {control_id}: {e}")

        return provider.get_evidence_queries(control_id)

    def auto_discover_providers(
        self, package_name: str = "cerebro.compliance.frameworks"
    ):
        """Auto-discover and register framework providers."""
        try:
            # Import the package
            package = importlib.import_module(package_name)
            package_path = package.__path__

            # Find all modules in the package
            for finder, module_name, ispkg in pkgutil.iter_modules(package_path):
                if ispkg:
                    continue

                try:
                    # Import module
                    full_module_name = f"{package_name}.{module_name}"
                    module = importlib.import_module(full_module_name)

                    # Look for provider classes
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, FrameworkProvider)
                            and attr != FrameworkProvider
                        ):

                            # Instantiate and register provider
                            provider_instance = attr()
                            self.register_provider(provider_instance)

                except Exception as e:
                    logger.error(
                        f"Failed to load framework provider from {module_name}: {e}"
                    )

        except ImportError as e:
            logger.warning(
                f"Failed to discover framework providers in {package_name}: {e}"
            )

    def get_control_matrix(self, framework_ids: List[str]) -> Dict[str, Any]:
        """Generate control mapping matrix across multiple frameworks."""
        matrix = {
            "frameworks": framework_ids,
            "control_mappings": {},
            "coverage_analysis": {},
        }

        # Get all frameworks
        frameworks = {}
        for framework_id in framework_ids:
            framework = self.get_framework(framework_id)
            if framework:
                frameworks[framework_id] = framework

        # Analyze control overlaps and gaps
        all_control_types: set[str] = set()
        framework_controls: Dict[str, Dict[str, Any]] = {}

        for framework_id, framework in frameworks.items():
            framework_controls[framework_id] = {
                control.control_id: control for control in framework.controls
            }
            all_control_types.update(control.category for control in framework.controls)

        # Build mapping matrix
        for control_type in all_control_types:
            matrix["control_mappings"][control_type] = {}

            for framework_id, controls in framework_controls.items():
                type_controls = [
                    c for c in controls.values() if c.category == control_type
                ]
                matrix["control_mappings"][control_type][framework_id] = [
                    {
                        "control_id": c.control_id,
                        "title": c.title,
                        "automation_level": c.automation_level.value,
                    }
                    for c in type_controls
                ]

        # Coverage analysis
        for framework_id, framework in frameworks.items():
            matrix["coverage_analysis"][framework_id] = {
                "total_controls": len(framework.controls),
                "automated_controls": len(framework.get_automated_controls()),
                "control_families": len(framework.control_families),
                "automation_percentage": (
                    round(
                        len(framework.get_automated_controls())
                        / len(framework.controls)
                        * 100,
                        1,
                    )
                    if framework.controls
                    else 0
                ),
            }

        return matrix

    def export_framework_config(self, framework_id: str, format: str = "json") -> str:
        """Export framework configuration for backup/sharing."""
        framework = self.get_framework(framework_id)
        if not framework:
            return ""

        if format == "json":
            import json

            return json.dumps(framework, default=lambda x: x.__dict__, indent=2)
        elif format == "yaml":
            try:
                import yaml

                return yaml.dump(framework, default_flow_style=False)
            except ImportError:
                logger.error("PyYAML not available for YAML export")
                return ""
        else:
            return str(framework)


# Global registry instance
_registry = FrameworkRegistry()


def get_framework_registry() -> FrameworkRegistry:
    """Get the global framework registry."""
    return _registry


def register_framework_provider(provider: FrameworkProvider):
    """Register a framework provider with the global registry."""
    _registry.register_provider(provider)


def get_framework(
    framework_id: str, version: Optional[str] = None
) -> Optional[FrameworkDefinition]:
    """Get framework from global registry."""
    return _registry.get_framework(framework_id, version)


def list_frameworks() -> List[str]:
    """List frameworks in global registry."""
    return _registry.list_frameworks()


# Auto-discovery helper
def discover_framework_providers(package_name: str = "cerebro.compliance.frameworks"):
    """Discover and register framework providers."""
    _registry.auto_discover_providers(package_name)


class FrameworkValidationError(Exception):
    """Raised when framework validation fails."""

    pass


def validate_framework_definition(framework: FrameworkDefinition) -> bool:
    """Validate framework definition for completeness and consistency."""
    errors = []

    # Basic validation
    if not framework.framework_id:
        errors.append("Framework ID is required")
    if not framework.name:
        errors.append("Framework name is required")
    if not framework.controls:
        errors.append("Framework must have at least one control")

    # Control validation
    control_ids = set()
    for control in framework.controls:
        if not control.control_id:
            errors.append("Control ID is required for all controls")
            continue

        if control.control_id in control_ids:
            errors.append(f"Duplicate control ID: {control.control_id}")
        control_ids.add(control.control_id)

        if not control.title:
            errors.append(f"Control {control.control_id} missing title")

        if not control.description:
            errors.append(f"Control {control.control_id} missing description")

    # Dependency validation
    for control in framework.controls:
        for dep_id in control.depends_on:
            if dep_id not in control_ids:
                errors.append(
                    f"Control {control.control_id} depends on non-existent control {dep_id}"
                )

    if errors:
        raise FrameworkValidationError(
            f"Framework validation failed: {'; '.join(errors)}"
        )

    return True
