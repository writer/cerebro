"""
OAuth and third-party app risk management module.

Implements OAuth app registry across providers, toxic combination detection,
and auto-quarantine workflows for risky third-party applications.
"""

from .registry import OAuthAppRegistry, OAuthApp, AppRiskLevel
from .toxic_combinations import ToxicCombinationDetector, ToxicPattern
from .quarantine import QuarantineManager, QuarantineAction

__all__ = [
    "OAuthAppRegistry",
    "OAuthApp",
    "AppRiskLevel",
    "ToxicCombinationDetector",
    "ToxicPattern",
    "QuarantineManager",
    "QuarantineAction",
]
