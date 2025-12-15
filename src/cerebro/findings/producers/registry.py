"""Producer registry with auto-discovery."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Iterable
from types import ModuleType

from .base import BaseFindingProducer, ProducerRegistry

logger = logging.getLogger(__name__)

# Global producer registry
producer_registry = ProducerRegistry()


def register_producer(
    producer_class: type[BaseFindingProducer],
) -> type[BaseFindingProducer]:
    """Decorator to register a producer class."""
    producer_instance = producer_class()
    producer_registry.register(producer_instance)
    return producer_class


def _iter_modules(package: ModuleType) -> Iterable[tuple[str, bool]]:
    for _, modname, ispkg in pkgutil.walk_packages(
        package.__path__, f"{package.__name__}."
    ):
        yield modname, ispkg


def auto_discover_producers(package_name: str = "cerebro.findings.producers") -> int:
    """Auto-discover producers in the producers package."""
    discovered = 0

    try:
        package = importlib.import_module(package_name)

        # Walk through all modules in the package
        for modname, _ in _iter_modules(package):
            # Skip certain modules
            if any(
                skip in modname for skip in ["__init__", "base", "registry", "tests"]
            ):
                continue

            try:
                module = importlib.import_module(modname)

                # Look for classes that inherit from BaseFindingProducer
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)

                    # Skip non-class attributes
                    if not isinstance(attr, type):
                        continue
                    
                    # Check if it's a subclass of BaseFindingProducer
                    # Use try-except because some type-like objects fail issubclass()
                    try:
                        is_producer = (
                            issubclass(attr, BaseFindingProducer)
                            and attr is not BaseFindingProducer
                            and not attr.__name__.startswith("Base")
                        )
                    except TypeError:
                        # Not a valid class for issubclass (e.g., generic alias)
                        continue

                    if is_producer:
                        try:
                            # Register the producer
                            register_producer(attr)
                            discovered += 1
                            logger.info("Auto-discovered producer: %s", attr_name)
                        except Exception:
                            logger.exception(
                                "Could not register producer %s",
                                attr_name,
                            )

            except ImportError as exc:
                logger.debug("Could not import %s: %s", modname, exc)

    except ImportError as exc:
        logger.warning("Could not discover producers in %s: %s", package_name, exc)

    logger.info("Auto-discovered %s producers", discovered)
    return discovered


def get_producer_registry() -> ProducerRegistry:
    """Get the global producer registry."""
    return producer_registry


def list_available_producers() -> list[str]:
    """List all available producers."""
    return producer_registry.list_producers()


def init_producers() -> None:
    """Initialize producer registry with auto-discovery."""
    # Auto-discover all producers
    auto_discover_producers()

    logger.info(
        "Producer registry initialized with %s producers",
        len(producer_registry.list_producers()),
    )
