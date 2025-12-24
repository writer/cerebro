"""Configuration collectors for Cerebro."""

from .collector import CollectionResult, ConfigCollector
from .manager import CollectorManager

__all__ = ["CollectionResult", "CollectorManager", "ConfigCollector"]
