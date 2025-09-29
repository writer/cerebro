"""Identity service for principal management and identity stitching."""

import logging
from typing import List, Dict, Optional
from uuid import UUID

from cerebro.core.identity import IdentityStitcher
from cerebro.analytics.identity_analytics import IdentityAnalyzer, PrivilegeSprawlDetector, RiskyIdentity

logger = logging.getLogger(__name__)


class IdentityService:
    """Service for managing identities and principal relationships."""

    def __init__(self, db_session=None):
        """Initialize identity service."""
        self.db_session = db_session
        self.stitcher = IdentityStitcher(db_session) if db_session else None
        self.identity_analyzer = IdentityAnalyzer(db_session) if db_session else None
        self.sprawl_detector = PrivilegeSprawlDetector(db_session) if db_session else None

    async def stitch_identities(self, org_id: UUID) -> Dict:
        """Stitch identities for an organization."""
        if not self.stitcher:
            logger.warning("Identity stitcher not available - database session required")
            return {"clusters": [], "total_identities": 0, "total_clusters": 0}

        try:
            # Call the actual identity stitcher
            stitching_result = await self.stitcher.stitch_organization_identities(org_id)

            return {
                "clusters": stitching_result.clusters,
                "total_identities": stitching_result.total_identities,
                "total_clusters": stitching_result.cluster_count,
                "confidence_scores": stitching_result.confidence_distribution,
                "stitching_method": "multi_factor_correlation",
                "processed_at": stitching_result.processed_at.isoformat()
            }

        except Exception as e:
            logger.error(f"Identity stitching failed for org {org_id}: {e}")
            return {
                "clusters": [],
                "total_identities": 0,
                "total_clusters": 0,
                "error": str(e)
            }

    async def get_risky_identities(self, org_id: UUID, limit: int = 20) -> List[Dict]:
        """Get identities with high risk scores using real analytics."""
        if not self.identity_analyzer:
            logger.warning("Identity analyzer not available - database session required")
            return []

        try:
            # Use real risk analysis algorithms
            risky_identities = await self.identity_analyzer.analyze_risky_identities(
                org_id=org_id,
                limit=limit
            )

            # Convert to serializable format
            results = []
            for identity in risky_identities:
                results.append({
                    "principal_id": str(identity.principal_id),
                    "display_name": identity.display_name,
                    "email": identity.email,
                    "risk_score": identity.risk_score,
                    "risk_level": identity.risk_level.value,
                    "risk_factors": {
                        "privilege_sprawl_score": identity.privilege_sprawl_score,
                        "cross_provider_access": identity.cross_provider_access,
                        "admin_access_count": identity.admin_access_count,
                        "stale_permissions_count": identity.stale_permissions_count,
                        "mfa_status": identity.mfa_status
                    },
                    "provider_breakdown": identity.provider_access,
                    "risk_indicators": identity.risk_factors,
                    "recommended_actions": identity.remediation_actions
                })

            logger.info(f"Found {len(results)} risky identities for org {org_id}")
            return results

        except Exception as e:
            logger.error(f"Risk analysis failed for org {org_id}: {e}")
            return []

    async def analyze_privilege_sprawl(self, org_id: UUID) -> Dict:
        """Analyze privilege sprawl across providers using real analytics."""
        if not self.sprawl_detector:
            logger.warning("Privilege sprawl detector not available - database session required")
            return {
                "total_identities": 0,
                "cross_provider_identities": 0,
                "high_privilege_count": 0,
                "sprawl_score": 0.0,
                "error": "Analytics unavailable"
            }

        try:
            # Use real privilege sprawl analysis
            sprawl_analysis = await self.sprawl_detector.analyze_privilege_sprawl(org_id)

            # Calculate overall sprawl score
            sprawl_score = self._calculate_sprawl_score(sprawl_analysis)

            # Convert to serializable format
            return {
                "org_id": str(sprawl_analysis.org_id),
                "analysis_date": sprawl_analysis.analysis_date.isoformat(),
                "metrics": {
                    "total_identities": sprawl_analysis.total_identities,
                    "high_privilege_identities": sprawl_analysis.high_privilege_identities,
                    "cross_provider_identities": sprawl_analysis.cross_provider_identities,
                    "avg_permissions_per_identity": sprawl_analysis.avg_permissions_per_identity,
                    "max_permissions_per_identity": sprawl_analysis.max_permissions_per_identity
                },
                "sprawl_score": sprawl_score,
                "risk_assessment": self._assess_sprawl_risk(sprawl_score),
                "privilege_distribution": sprawl_analysis.privilege_distribution,
                "top_risky_identities": [
                    {
                        "principal_id": str(identity.principal_id),
                        "display_name": identity.display_name,
                        "risk_score": identity.risk_score,
                        "risk_level": identity.risk_level.value
                    }
                    for identity in sprawl_analysis.top_risky_identities[:5]
                ],
                "provider_breakdown": sprawl_analysis.provider_privilege_breakdown,
                "recommendations": self._generate_sprawl_recommendations(sprawl_analysis)
            }

        except Exception as e:
            logger.error(f"Privilege sprawl analysis failed for org {org_id}: {e}")
            return {
                "total_identities": 0,
                "cross_provider_identities": 0,
                "high_privilege_count": 0,
                "sprawl_score": 0.0,
                "error": str(e)
            }

    def _calculate_sprawl_score(self, analysis) -> float:
        """Calculate overall privilege sprawl score (0-1)."""
        if analysis.total_identities == 0:
            return 0.0

        # Weighted scoring algorithm
        factors = {
            "cross_provider_ratio": analysis.cross_provider_identities / analysis.total_identities,
            "high_privilege_ratio": analysis.high_privilege_identities / analysis.total_identities,
            "avg_permissions_factor": min(analysis.avg_permissions_per_identity / 50.0, 1.0),
            "max_permissions_factor": min(analysis.max_permissions_per_identity / 200.0, 1.0)
        }

        # Weights for different risk factors
        weights = {
            "cross_provider_ratio": 0.3,
            "high_privilege_ratio": 0.4,
            "avg_permissions_factor": 0.2,
            "max_permissions_factor": 0.1
        }

        score = sum(factors[factor] * weights[factor] for factor in factors)
        return min(max(score, 0.0), 1.0)

    def _assess_sprawl_risk(self, sprawl_score: float) -> str:
        """Assess risk level based on sprawl score."""
        if sprawl_score >= 0.8:
            return "critical"
        elif sprawl_score >= 0.6:
            return "high"
        elif sprawl_score >= 0.4:
            return "medium"
        else:
            return "low"

    def _generate_sprawl_recommendations(self, analysis) -> List[str]:
        """Generate actionable recommendations for privilege sprawl reduction."""
        recommendations = []

        if analysis.cross_provider_identities > analysis.total_identities * 0.3:
            recommendations.append("Implement centralized identity federation to reduce cross-provider sprawl")

        if analysis.high_privilege_identities > analysis.total_identities * 0.1:
            recommendations.append("Review and revoke excessive administrative privileges")

        if analysis.avg_permissions_per_identity > 30:
            recommendations.append("Implement role-based access control to reduce individual permission grants")

        if analysis.max_permissions_per_identity > 100:
            recommendations.append("Audit identities with excessive permissions (>100 per identity)")

        recommendations.append("Schedule regular access reviews for high-privilege identities")
        recommendations.append("Implement just-in-time access for administrative operations")

        return recommendations
