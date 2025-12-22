"""
Attack path analysis and reachability module.

Implements graph model of principals → roles → resources across providers
with path queries, severity scoring, and service-to-service identity edges.
"""

from .graph_model import AttackGraph, AttackNode, AttackEdge
from .path_analysis import PathAnalyzer, AttackPath, PathQuery
from .service_identity import ServiceIdentityMapper, ServiceIdentityEdge
from .reachability import ReachabilityAnalyzer, ReachabilityResult

__all__ = [
    "AttackGraph",
    "AttackNode",
    "AttackEdge",
    "PathAnalyzer",
    "AttackPath",
    "PathQuery",
    "ServiceIdentityMapper",
    "ServiceIdentityEdge",
    "ReachabilityAnalyzer",
    "ReachabilityResult",
]
