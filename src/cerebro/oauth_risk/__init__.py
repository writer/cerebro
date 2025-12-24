"""
OAuth and third-party app risk management module.

Implements OAuth app registry across providers, toxic combination detection,
and auto-quarantine workflows for risky third-party applications.
"""

from .quarantine import QuarantineAction, QuarantineManager
from .registry import AppRiskLevel, OAuthApp, OAuthAppRegistry
from .toxic_combinations import ToxicCombinationDetector, ToxicPattern

__all__ = [
    "AppRiskLevel",
    "OAuthApp",
    "OAuthAppRegistry",
    "QuarantineAction",
    "QuarantineManager",
    "ToxicCombinationDetector",
    "ToxicPattern",
]
