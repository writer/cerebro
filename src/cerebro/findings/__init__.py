"""Findings management for Cerebro."""

from .evaluator import RuleEvaluator
from .manager import FindingManager, FindingResult
from .producers import auto_discover_producers, producer_registry, register_producer

# Auto-discover producers on import
auto_discover_producers()

__all__ = [
    "FindingManager",
    "FindingResult",
    "RuleEvaluator",
    "producer_registry",
    "register_producer",
]
