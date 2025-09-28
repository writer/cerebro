"""Producer registry with auto-discovery."""

import importlib
import pkgutil
from typing import Type, List, Optional
import logging

from .base import BaseFindingProducer, ProducerRegistry

logger = logging.getLogger(__name__)

# Global producer registry
producer_registry = ProducerRegistry()


def register_producer(producer_class: Type[BaseFindingProducer]):
    """Decorator to register a producer class."""
    producer_instance = producer_class()
    producer_registry.register(producer_instance)
    return producer_class


def auto_discover_producers(package_name: str = "cerebro.findings.producers") -> int:
    """Auto-discover producers in the producers package."""
    discovered = 0
    
    try:
        package = importlib.import_module(package_name)
        
        # Walk through all modules in the package
        for importer, modname, ispkg in pkgutil.walk_packages(
            package.__path__, 
            package.__name__ + "."
        ):
            # Skip certain modules
            if any(skip in modname for skip in ["__init__", "base", "registry", "tests"]):
                continue
                
            try:
                module = importlib.import_module(modname)
                
                # Look for classes that inherit from BaseFindingProducer
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    if (isinstance(attr, type) and 
                        issubclass(attr, BaseFindingProducer) and
                        attr != BaseFindingProducer):
                        
                        try:
                            # Register the producer
                            register_producer(attr)
                            discovered += 1
                            logger.info(f"Auto-discovered producer: {attr_name}")
                        except Exception as e:
                            logger.warning(f"Could not register producer {attr_name}: {e}")
            
            except ImportError as e:
                logger.debug(f"Could not import {modname}: {e}")
                
    except ImportError as e:
        logger.warning(f"Could not discover producers in {package_name}: {e}")
    
    logger.info(f"Auto-discovered {discovered} producers")
    return discovered


def get_producer_registry() -> ProducerRegistry:
    """Get the global producer registry."""
    return producer_registry


def list_available_producers() -> List[str]:
    """List all available producers."""
    return producer_registry.list_producers()


def init_producers():
    """Initialize producer registry with auto-discovery."""
    # Auto-discover all producers
    auto_discover_producers()
    
    logger.info(f"Producer registry initialized with {len(producer_registry.list_producers())} producers")
