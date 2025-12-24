"""Advanced security analysis capabilities."""

from .blast_radius import BlastRadiusAnalyzer, CompromiseScenario, ImpactAssessment
from .change_replay import ChangeReplayEngine, RuleReplayResult
from .forensic_replay import ForensicReplayEngine, HistoricalState
from .identity_anomaly import (
    AnomalyResult,
    IdentityAnomalyDetector,
)  # sklearn is now installed

__all__ = [
    "AnomalyResult",
    "BlastRadiusAnalyzer",
    "ChangeReplayEngine",
    "CompromiseScenario",
    "ForensicReplayEngine",
    "HistoricalState",
    "IdentityAnomalyDetector",
    "ImpactAssessment",
    "RuleReplayResult",
]
