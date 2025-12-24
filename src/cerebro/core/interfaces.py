"""Core interfaces to break circular dependencies."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

if TYPE_CHECKING:
    from ..rules.models import Rule
    from .models import Finding


class RuleInterface(ABC):
    """Interface for rule operations to break circular dependencies."""

    @abstractmethod
    async def get_rule_by_name(self, name: str, org_id: UUID) -> Optional["Rule"]:
        """Get a rule by name."""
        pass

    @abstractmethod
    async def get_rules_for_org(self, org_id: UUID) -> list["Rule"]:
        """Get all rules for an organization."""
        pass


class ProducerInterface(ABC):
    """Interface for finding producers to break circular dependencies."""

    @abstractmethod
    async def produce_findings(self, context: dict[str, Any]) -> list["Finding"]:
        """Produce findings for the given context."""
        pass

    @abstractmethod
    def get_required_rules(self) -> list[str]:
        """Get list of rule names this producer requires."""
        pass


class RuleRegistry:
    """Registry for rule operations to break circular dependencies."""

    def __init__(self):
        self._rule_service: RuleInterface | None = None

    def register_rule_service(self, service: RuleInterface) -> None:
        """Register the rule service implementation."""
        self._rule_service = service

    def get_rule_service(self) -> RuleInterface | None:
        """Get the registered rule service."""
        return self._rule_service


class ProducerRegistry:
    """Registry for producer operations to break circular dependencies."""

    def __init__(self):
        self._producers: dict[str, ProducerInterface] = {}

    def register_producer(self, name: str, producer: ProducerInterface) -> None:
        """Register a findings producer."""
        self._producers[name] = producer

    def get_producer(self, name: str) -> ProducerInterface | None:
        """Get a producer by name."""
        return self._producers.get(name)

    def list_producers(self) -> list[str]:
        """List all registered producer names."""
        return list(self._producers.keys())

    def get_all_required_rules(self) -> list[str]:
        """Get all rule names required by registered producers."""
        rules = set()
        for producer in self._producers.values():
            rules.update(producer.get_required_rules())
        return list(rules)


# Global registries
rule_registry = RuleRegistry()
producer_registry = ProducerRegistry()
