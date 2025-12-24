"""
Attack path analysis and reachability module.

Implements graph model of principals → roles → resources across providers
with path queries, severity scoring, and service-to-service identity edges.
"""

from .graph_model import AttackEdge, AttackGraph, AttackNode
from .path_analysis import AttackPath, PathAnalyzer, PathQuery
from .reachability import ReachabilityAnalyzer, ReachabilityResult
from .service_identity import ServiceIdentityEdge, ServiceIdentityMapper

__all__ = [
    "AttackEdge",
    "AttackGraph",
    "AttackNode",
    "AttackPath",
    "PathAnalyzer",
    "PathQuery",
    "ReachabilityAnalyzer",
    "ReachabilityResult",
    "ServiceIdentityEdge",
    "ServiceIdentityMapper",
]
