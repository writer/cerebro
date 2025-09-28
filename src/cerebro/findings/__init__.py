"""Findings management for Cerebro."""

from .manager import FindingManager, FindingResult
from .evaluator import RuleEvaluator
from .producers import producer_registry, register_producer, auto_discover_producers

# Auto-discover producers on import
auto_discover_producers()

__all__ = [
    "FindingManager", 
    "FindingResult", 
    "RuleEvaluator",
    "producer_registry",
    "register_producer",
]
