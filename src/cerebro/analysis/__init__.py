"""Advanced security analysis capabilities."""

from .blast_radius import BlastRadiusAnalyzer, CompromiseScenario, ImpactAssessment
from .forensic_replay import ForensicReplayEngine, HistoricalState
from .change_replay import ChangeReplayEngine, RuleReplayResult
# from .identity_anomaly import IdentityAnomalyDetector, AnomalyResult  # Requires sklearn

__all__ = [
    "BlastRadiusAnalyzer",
    "CompromiseScenario", 
    "ImpactAssessment",
    "ForensicReplayEngine",
    "HistoricalState",
    "ChangeReplayEngine",
    "RuleReplayResult",
    # "IdentityAnomalyDetector",  # Requires sklearn
    # "AnomalyResult",  # Requires sklearn
]
