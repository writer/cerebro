"""Identity-centric analytics for privilege sprawl and risk detection."""

import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func, text

from cerebro.core.models import Principal, IamEdge, Finding, Account

logger = logging.getLogger(__name__)


class IdentityRiskLevel(Enum):
    """Risk levels for identity assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PrivilegeType(Enum):
    """Types of privileges for analysis."""
    ADMIN = "admin"
    READ_WRITE = "read_write"
    READ_ONLY = "read_only"
    CUSTOM = "custom"


@dataclass
class RiskyIdentity:
    """Identity with elevated risk profile."""
    principal_id: UUID
    display_name: str
    email: Optional[str]
    risk_score: float
    risk_level: IdentityRiskLevel
    
    # Risk factors
    privilege_sprawl_score: float
    cross_provider_access: int
    admin_access_count: int
    stale_permissions_count: int
    mfa_status: str
    
    # Provider breakdown
    provider_access: Dict[str, Dict[str, Any]]
    
    # Recommendations
    risk_factors: List[str]
    remediation_actions: List[str]


@dataclass
class PrivilegeSprawlAnalysis:
    """Analysis of privilege sprawl across the organization."""
    org_id: UUID
    analysis_date: datetime
    
    # Overall statistics
    total_identities: int
    high_privilege_identities: int
    cross_provider_identities: int
    
    # Sprawl metrics
    avg_permissions_per_identity: float
    max_permissions_per_identity: int
    privilege_distribution: Dict[str, int]
    
    # Top risk identities
    top_risky_identities: List[RiskyIdentity]
    
    # Provider analysis
    provider_privilege_breakdown: Dict[str, Dict[str, Any]]


class IdentityAnalyzer:
    """Analyzer for identity-centric security insights."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize identity analyzer."""
        self.db = db_session
    
    async def analyze_risky_identities(
        self,
        org_id: UUID,
        limit: int = 20
    ) -> List[RiskyIdentity]:
        """Identify identities with highest risk profiles."""
        
        logger.info(f"Analyzing risky identities for org {org_id}")
        
        # Get all human identities with their privilege data
        identity_risk_query = text("""
            WITH identity_stats AS (
                SELECT 
                    p.principal_id,
                    p.display_name,
                    p.email,
                    COUNT(DISTINCT ie.provider) as provider_count,
                    COUNT(DISTINCT ie.permission) as permission_count,
                    COUNT(CASE WHEN ie.is_admin THEN 1 END) as admin_count,
                    COUNT(CASE WHEN ie.effective_at < NOW() - INTERVAL '90 days' THEN 1 END) as stale_count,
                    MAX(ie.effective_at) as last_permission_grant
                FROM principals p
                JOIN accounts a ON p.account_id = a.account_id
                LEFT JOIN iam_edges ie ON p.principal_id = ie.principal_id
                WHERE a.org_id = :org_id 
                    AND p.is_human = true
                    AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
                GROUP BY p.principal_id, p.display_name, p.email
            )
            SELECT *,
                -- Risk scoring algorithm
                (provider_count * 10.0 +           -- Cross-provider access risk
                 permission_count * 0.5 +          -- Permission volume risk
                 admin_count * 15.0 +              -- Admin access risk  
                 stale_count * 2.0) as risk_score  -- Stale permission risk
            FROM identity_stats
            WHERE permission_count > 0
            ORDER BY risk_score DESC
            LIMIT :limit
        """)
        
        result = await self.db.execute(identity_risk_query, {
            "org_id": org_id,
            "limit": limit
        })
        
        risky_identities = []
        
        for row in result.fetchall():
            # Determine risk level
            risk_score = row.risk_score
            if risk_score >= 80:
                risk_level = IdentityRiskLevel.CRITICAL
            elif risk_score >= 60:
                risk_level = IdentityRiskLevel.HIGH
            elif risk_score >= 40:
                risk_level = IdentityRiskLevel.MEDIUM
            else:
                risk_level = IdentityRiskLevel.LOW
            
            # Get MFA status
            mfa_status = await self._get_mfa_status(row.principal_id)
            
            # Get provider access breakdown
            provider_access = await self._get_provider_access_breakdown(row.principal_id)
            
            # Generate risk factors and remediation actions
            risk_factors = []
            remediation_actions = []
            
            if row.provider_count > 3:
                risk_factors.append(f"Access across {row.provider_count} providers")
                remediation_actions.append("Review cross-provider access necessity")
            
            if row.admin_count > 0:
                risk_factors.append(f"Administrative access to {row.admin_count} resources")
                remediation_actions.append("Implement just-in-time admin access")
            
            if row.stale_count > 5:
                risk_factors.append(f"{row.stale_count} stale permissions (>90 days)")
                remediation_actions.append("Remove unused permissions")
            
            if mfa_status != "enabled":
                risk_factors.append("Multi-factor authentication not enabled")
                remediation_actions.append("Enable MFA for this identity")
            
            risky_identity = RiskyIdentity(
                principal_id=row.principal_id,
                display_name=row.display_name or "Unknown",
                email=row.email,
                risk_score=risk_score,
                risk_level=risk_level,
                privilege_sprawl_score=row.permission_count * 0.5,
                cross_provider_access=row.provider_count,
                admin_access_count=row.admin_count,
                stale_permissions_count=row.stale_count,
                mfa_status=mfa_status,
                provider_access=provider_access,
                risk_factors=risk_factors,
                remediation_actions=remediation_actions
            )
            
            risky_identities.append(risky_identity)
        
        logger.info(f"Identified {len(risky_identities)} risky identities")
        return risky_identities
    
    async def _get_mfa_status(self, principal_id: UUID) -> str:
        """Get MFA status for a principal."""
        
        # Check if there are any MFA-related findings for this principal
        mfa_finding_query = text("""
            SELECT COUNT(*)
            FROM findings f
            JOIN rules r ON f.rule_id = r.rule_id
            WHERE f.principal_id = :principal_id
                AND f.status = 'open'
                AND (r.name ILIKE '%mfa%' OR r.description ILIKE '%multi-factor%')
        """)
        
        result = await self.db.execute(mfa_finding_query, {"principal_id": principal_id})
        mfa_violations = result.scalar() or 0
        
        return "disabled" if mfa_violations > 0 else "enabled"
    
    async def _get_provider_access_breakdown(self, principal_id: UUID) -> Dict[str, Dict[str, Any]]:
        """Get detailed provider access breakdown for a principal."""
        
        provider_query = text("""
            SELECT 
                ie.provider,
                COUNT(DISTINCT ie.permission) as permission_count,
                COUNT(CASE WHEN ie.is_admin THEN 1 END) as admin_count,
                MIN(ie.effective_at) as first_access,
                MAX(ie.effective_at) as last_access
            FROM iam_edges ie
            WHERE ie.principal_id = :principal_id
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY ie.provider
        """)
        
        result = await self.db.execute(provider_query, {"principal_id": principal_id})
        
        provider_breakdown = {}
        for row in result.fetchall():
            provider_breakdown[row.provider] = {
                "permission_count": row.permission_count,
                "admin_access": row.admin_count > 0,
                "first_access": row.first_access.isoformat() if row.first_access else None,
                "last_access": row.last_access.isoformat() if row.last_access else None,
                "risk_level": "high" if row.admin_count > 0 else "medium" if row.permission_count > 10 else "low"
            }
        
        return provider_breakdown


class PrivilegeSprawlDetector:
    """Detects and analyzes privilege sprawl across the organization."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize privilege sprawl detector."""
        self.db = db_session
    
    async def analyze_privilege_sprawl(self, org_id: UUID) -> PrivilegeSprawlAnalysis:
        """Comprehensive privilege sprawl analysis."""
        
        logger.info(f"Analyzing privilege sprawl for org {org_id}")
        
        # Overall statistics
        total_identities = await self._count_total_identities(org_id)
        high_privilege_identities = await self._count_high_privilege_identities(org_id)
        cross_provider_identities = await self._count_cross_provider_identities(org_id)
        
        # Permission statistics
        avg_permissions = await self._calculate_avg_permissions_per_identity(org_id)
        max_permissions = await self._get_max_permissions_per_identity(org_id)
        privilege_distribution = await self._get_privilege_distribution(org_id)
        
        # Top risky identities
        identity_analyzer = IdentityAnalyzer(self.db)
        top_risky = await identity_analyzer.analyze_risky_identities(org_id, limit=10)
        
        # Provider breakdown
        provider_breakdown = await self._analyze_provider_privilege_breakdown(org_id)
        
        return PrivilegeSprawlAnalysis(
            org_id=org_id,
            analysis_date=datetime.utcnow(),
            total_identities=total_identities,
            high_privilege_identities=high_privilege_identities,
            cross_provider_identities=cross_provider_identities,
            avg_permissions_per_identity=avg_permissions,
            max_permissions_per_identity=max_permissions,
            privilege_distribution=privilege_distribution,
            top_risky_identities=top_risky,
            provider_privilege_breakdown=provider_breakdown
        )
    
    async def _count_total_identities(self, org_id: UUID) -> int:
        """Count total human identities."""
        query = text("""
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.org_id = :org_id AND p.is_human = true
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return result.scalar() or 0
    
    async def _count_high_privilege_identities(self, org_id: UUID) -> int:
        """Count identities with high privileges (admin or >20 permissions)."""
        query = text("""
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id 
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id
            HAVING COUNT(DISTINCT ie.permission) > 20 OR bool_or(ie.is_admin)
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return len(result.fetchall())
    
    async def _count_cross_provider_identities(self, org_id: UUID) -> int:
        """Count identities with access across multiple providers."""
        query = text("""
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id 
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id
            HAVING COUNT(DISTINCT ie.provider) > 1
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return len(result.fetchall())
    
    async def _calculate_avg_permissions_per_identity(self, org_id: UUID) -> float:
        """Calculate average permissions per identity."""
        query = text("""
            SELECT AVG(permission_count::float)
            FROM (
                SELECT COUNT(DISTINCT ie.permission) as permission_count
                FROM principals p
                JOIN accounts a ON p.account_id = a.account_id
                JOIN iam_edges ie ON p.principal_id = ie.principal_id
                WHERE a.org_id = :org_id 
                    AND p.is_human = true
                    AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
                GROUP BY p.principal_id
            ) subq
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return result.scalar() or 0.0
    
    async def _get_max_permissions_per_identity(self, org_id: UUID) -> int:
        """Get maximum permissions held by any single identity."""
        query = text("""
            SELECT MAX(permission_count)
            FROM (
                SELECT COUNT(DISTINCT ie.permission) as permission_count
                FROM principals p
                JOIN accounts a ON p.account_id = a.account_id
                JOIN iam_edges ie ON p.principal_id = ie.principal_id
                WHERE a.org_id = :org_id 
                    AND p.is_human = true
                    AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
                GROUP BY p.principal_id
            ) subq
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return result.scalar() or 0
    
    async def _get_privilege_distribution(self, org_id: UUID) -> Dict[str, int]:
        """Get distribution of privilege levels."""
        query = text("""
            WITH identity_privilege_counts AS (
                SELECT 
                    p.principal_id,
                    COUNT(DISTINCT ie.permission) as permission_count,
                    bool_or(ie.is_admin) as has_admin
                FROM principals p
                JOIN accounts a ON p.account_id = a.account_id
                JOIN iam_edges ie ON p.principal_id = ie.principal_id
                WHERE a.org_id = :org_id 
                    AND p.is_human = true
                    AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
                GROUP BY p.principal_id
            )
            SELECT 
                CASE 
                    WHEN has_admin THEN 'admin'
                    WHEN permission_count > 50 THEN 'high_privilege'
                    WHEN permission_count > 20 THEN 'medium_privilege'
                    WHEN permission_count > 5 THEN 'low_privilege'
                    ELSE 'minimal_privilege'
                END as privilege_level,
                COUNT(*) as identity_count
            FROM identity_privilege_counts
            GROUP BY 
                CASE 
                    WHEN has_admin THEN 'admin'
                    WHEN permission_count > 50 THEN 'high_privilege'
                    WHEN permission_count > 20 THEN 'medium_privilege'
                    WHEN permission_count > 5 THEN 'low_privilege'
                    ELSE 'minimal_privilege'
                END
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        return {row.privilege_level: row.identity_count for row in result.fetchall()}
    
    async def _analyze_provider_privilege_breakdown(self, org_id: UUID) -> Dict[str, Dict[str, Any]]:
        """Analyze privilege distribution by provider."""
        query = text("""
            SELECT 
                ie.provider,
                COUNT(DISTINCT ie.principal_id) as identity_count,
                COUNT(DISTINCT ie.permission) as unique_permissions,
                COUNT(CASE WHEN ie.is_admin THEN 1 END) as admin_grants,
                AVG(CASE 
                    WHEN ie.effective_at > NOW() - INTERVAL '30 days' THEN 1.0
                    ELSE 0.0
                END) as recent_activity_ratio
            FROM iam_edges ie
            JOIN accounts a ON ie.account_id = a.account_id
            JOIN principals p ON ie.principal_id = p.principal_id
            WHERE a.org_id = :org_id 
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY ie.provider
            ORDER BY identity_count DESC
        """)
        
        result = await self.db.execute(query, {"org_id": org_id})
        
        breakdown = {}
        for row in result.fetchall():
            breakdown[row.provider] = {
                "identity_count": row.identity_count,
                "unique_permissions": row.unique_permissions,
                "admin_grants": row.admin_grants,
                "recent_activity_ratio": float(row.recent_activity_ratio or 0),
                "risk_level": "high" if row.admin_grants > 5 else "medium" if row.identity_count > 50 else "low"
            }
        
        return breakdown
    
    async def identify_privilege_anomalies(self, org_id: UUID) -> List[Dict[str, Any]]:
        """Identify privilege anomalies requiring investigation."""
        
        anomalies = []
        
        # Orphaned permissions (identities with permissions but no recent activity)
        orphaned_query = text("""
            SELECT 
                p.principal_id,
                p.display_name,
                p.email,
                COUNT(ie.permission) as permission_count,
                MAX(ie.effective_at) as last_permission_grant
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND ie.effective_at < :stale_threshold
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id, p.display_name, p.email
            HAVING COUNT(ie.permission) > 10
            ORDER BY permission_count DESC
            LIMIT 10
        """)
        
        stale_threshold = datetime.utcnow() - timedelta(days=180)
        result = await self.db.execute(orphaned_query, {
            "org_id": org_id,
            "stale_threshold": stale_threshold
        })
        
        for row in result.fetchall():
            anomalies.append({
                "type": "orphaned_permissions",
                "principal_id": str(row.principal_id),
                "principal_name": row.display_name,
                "description": f"Identity has {row.permission_count} permissions but no activity since {row.last_permission_grant.strftime('%Y-%m-%d')}",
                "risk_level": "medium",
                "recommendation": "Review and remove unused permissions"
            })
        
        # Unusual cross-provider admin access
        cross_admin_query = text("""
            SELECT 
                p.principal_id,
                p.display_name,
                COUNT(DISTINCT ie.provider) as admin_provider_count,
                array_agg(DISTINCT ie.provider) as admin_providers
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND ie.is_admin = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id, p.display_name
            HAVING COUNT(DISTINCT ie.provider) > 2
            ORDER BY admin_provider_count DESC
        """)
        
        result = await self.db.execute(cross_admin_query, {"org_id": org_id})
        
        for row in result.fetchall():
            anomalies.append({
                "type": "excessive_cross_provider_admin",
                "principal_id": str(row.principal_id),
                "principal_name": row.display_name,
                "description": f"Administrative access across {row.admin_provider_count} providers: {', '.join(row.admin_providers)}",
                "risk_level": "high",
                "recommendation": "Implement role-based access with provider-specific admins"
            })
        
        return anomalies
    
    async def generate_identity_dashboard_data(self, org_id: UUID) -> Dict[str, Any]:
        """Generate comprehensive identity analytics for dashboard."""
        
        # Get privilege sprawl analysis
        sprawl_analysis = await PrivilegeSprawlDetector(self.db).analyze_privilege_sprawl(org_id)
        
        # Get privilege anomalies
        anomalies = await self.identify_privilege_anomalies(org_id)
        
        # Get MFA compliance across providers
        mfa_compliance = await self._get_mfa_compliance_by_provider(org_id)
        
        return {
            "summary": {
                "total_identities": sprawl_analysis.total_identities,
                "high_privilege_identities": sprawl_analysis.high_privilege_identities,
                "cross_provider_identities": sprawl_analysis.cross_provider_identities,
                "avg_permissions_per_identity": round(sprawl_analysis.avg_permissions_per_identity, 1),
                "max_permissions_per_identity": sprawl_analysis.max_permissions_per_identity
            },
            "privilege_distribution": sprawl_analysis.privilege_distribution,
            "top_risky_identities": [
                {
                    "principal_id": str(identity.principal_id),
                    "display_name": identity.display_name,
                    "email": identity.email,
                    "risk_score": round(identity.risk_score, 1),
                    "risk_level": identity.risk_level.value,
                    "cross_provider_access": identity.cross_provider_access,
                    "admin_access_count": identity.admin_access_count,
                    "mfa_status": identity.mfa_status,
                    "top_risk_factor": identity.risk_factors[0] if identity.risk_factors else None
                }
                for identity in sprawl_analysis.top_risky_identities[:5]
            ],
            "privilege_anomalies": anomalies,
            "mfa_compliance_by_provider": mfa_compliance,
            "provider_breakdown": sprawl_analysis.provider_privilege_breakdown
        }
    
    async def _get_mfa_compliance_by_provider(self, org_id: UUID) -> Dict[str, Dict[str, Any]]:
        """Get MFA compliance status by provider."""
        
        # This is a simplified implementation - in practice you'd check provider-specific MFA settings
        mfa_query = text("""
            SELECT 
                ie.provider,
                COUNT(DISTINCT p.principal_id) as total_users,
                COUNT(DISTINCT CASE 
                    WHEN f.finding_id IS NULL THEN p.principal_id 
                END) as mfa_enabled_users
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            LEFT JOIN findings f ON p.principal_id = f.principal_id 
                AND f.rule_id IN (
                    SELECT rule_id FROM rules 
                    WHERE name ILIKE '%mfa%' OR description ILIKE '%multi-factor%'
                )
                AND f.status = 'open'
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY ie.provider
        """)
        
        result = await self.db.execute(mfa_query, {"org_id": org_id})
        
        compliance_data = {}
        for row in result.fetchall():
            total = row.total_users
            enabled = row.mfa_enabled_users
            compliance_rate = (enabled / total * 100) if total > 0 else 0
            
            compliance_data[row.provider] = {
                "total_users": total,
                "mfa_enabled_users": enabled,
                "compliance_rate": round(compliance_rate, 1),
                "status": "compliant" if compliance_rate >= 95 else "non_compliant" if compliance_rate < 80 else "partial"
            }
        
        return compliance_data


if not hasattr(IdentityAnalyzer, "identify_privilege_anomalies"):
    async def _identify_privilege_anomalies(self: IdentityAnalyzer, org_id: UUID) -> List[Dict[str, Any]]:
        """Identify privilege anomalies requiring investigation."""

        anomalies: List[Dict[str, Any]] = []

        orphaned_query = text(
            """
            SELECT
                p.principal_id,
                p.display_name,
                p.email,
                COUNT(ie.permission) as permission_count,
                MAX(ie.effective_at) as last_permission_grant
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND ie.effective_at < :stale_threshold
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id, p.display_name, p.email
            HAVING COUNT(ie.permission) > 10
            ORDER BY permission_count DESC
            LIMIT 10
            """
        )

        stale_threshold = datetime.utcnow() - timedelta(days=180)
        result = await self.db.execute(
            orphaned_query,
            {"org_id": org_id, "stale_threshold": stale_threshold},
        )

        for row in result.fetchall():
            anomalies.append(
                {
                    "type": "orphaned_permissions",
                    "principal_id": str(row.principal_id),
                    "principal_name": row.display_name,
                    "description": (
                        f"Identity has {row.permission_count} permissions but no activity since "
                        f"{row.last_permission_grant.strftime('%Y-%m-%d')}"
                    ),
                    "risk_level": "medium",
                    "recommendation": "Review and remove unused permissions",
                }
            )

        cross_admin_query = text(
            """
            SELECT
                p.principal_id,
                p.display_name,
                COUNT(DISTINCT ie.provider) as admin_provider_count,
                array_agg(DISTINCT ie.provider) as admin_providers
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND ie.is_admin = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY p.principal_id, p.display_name
            HAVING COUNT(DISTINCT ie.provider) > 2
            ORDER BY admin_provider_count DESC
            """
        )

        result = await self.db.execute(cross_admin_query, {"org_id": org_id})

        for row in result.fetchall():
            anomalies.append(
                {
                    "type": "excessive_cross_provider_admin",
                    "principal_id": str(row.principal_id),
                    "principal_name": row.display_name,
                    "description": (
                        "Administrative access across "
                        f"{row.admin_provider_count} providers: {', '.join(row.admin_providers)}"
                    ),
                    "risk_level": "high",
                    "recommendation": "Implement role-based access with provider-specific admins",
                }
            )

        return anomalies

    IdentityAnalyzer.identify_privilege_anomalies = _identify_privilege_anomalies


if not hasattr(IdentityAnalyzer, "_get_mfa_compliance_by_provider"):
    async def _get_mfa_compliance_by_provider(self: IdentityAnalyzer, org_id: UUID) -> Dict[str, Dict[str, Any]]:
        """Get MFA compliance status by provider."""

        mfa_query = text(
            """
            SELECT
                ie.provider,
                COUNT(DISTINCT p.principal_id) as total_users,
                COUNT(DISTINCT CASE WHEN f.finding_id IS NULL THEN p.principal_id END) as mfa_enabled_users
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            LEFT JOIN findings f ON p.principal_id = f.principal_id
                AND f.rule_id IN (
                    SELECT rule_id FROM rules
                    WHERE name ILIKE '%mfa%' OR description ILIKE '%multi-factor%'
                )
                AND f.status = 'open'
            WHERE a.org_id = :org_id
                AND p.is_human = true
                AND (ie.expires_at IS NULL OR ie.expires_at > NOW())
            GROUP BY ie.provider
            """
        )

        result = await self.db.execute(mfa_query, {"org_id": org_id})

        compliance_data: Dict[str, Dict[str, Any]] = {}
        for row in result.fetchall():
            total = row.total_users
            enabled = row.mfa_enabled_users
            compliance_rate = (enabled / total * 100) if total > 0 else 0

            compliance_data[row.provider] = {
                "total_users": total,
                "mfa_enabled_users": enabled,
                "compliance_rate": round(compliance_rate, 1),
                "status": (
                    "compliant"
                    if compliance_rate >= 95
                    else "non_compliant"
                    if compliance_rate < 80
                    else "partial"
                ),
            }

        return compliance_data

    IdentityAnalyzer._get_mfa_compliance_by_provider = _get_mfa_compliance_by_provider


async def _build_drilldown_identities(
    analyzer: IdentityAnalyzer, risky_identities: List[RiskyIdentity]
) -> List[Dict[str, Any]]:
    drilldown: List[Dict[str, Any]] = []

    permissions_query = text(
        """
        SELECT provider, permission, is_admin, effective_at
        FROM iam_edges
        WHERE principal_id = :principal_id
        ORDER BY effective_at DESC NULLS LAST
        LIMIT 12
        """
    )

    findings_query = text(
        """
        SELECT finding_id, title, severity, status, last_seen
        FROM findings
        WHERE principal_id = :principal_id AND status = 'open'
        ORDER BY severity DESC, last_seen DESC NULLS LAST
        LIMIT 6
        """
    )

    for identity in risky_identities:
        permissions_result = await analyzer.db.execute(
            permissions_query,
            {"principal_id": identity.principal_id},
        )
        permission_rows = permissions_result.fetchall()

        findings_result = await analyzer.db.execute(
            findings_query,
            {"principal_id": identity.principal_id},
        )
        finding_rows = findings_result.fetchall()

        providers = sorted({row.provider for row in permission_rows})

        drilldown.append(
            {
                "principal_id": str(identity.principal_id),
                "display_name": identity.display_name,
                "email": identity.email,
                "risk_score": round(identity.risk_score, 1),
                "risk_level": identity.risk_level.value,
                "providers": providers,
                "permissions": [
                    {
                        "provider": row.provider,
                        "permission": row.permission,
                        "is_admin": bool(row.is_admin),
                        "granted_at": row.effective_at.isoformat() if row.effective_at else None,
                    }
                    for row in permission_rows
                ],
                "open_findings": [
                    {
                        "finding_id": str(row.finding_id),
                        "title": row.title,
                        "severity": row.severity,
                        "status": row.status,
                        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                    }
                    for row in finding_rows
                ],
                "recommended_actions": identity.remediation_actions,
                "risk_factors": identity.risk_factors,
            }
        )

    return drilldown


if not hasattr(IdentityAnalyzer, "generate_identity_dashboard_data"):
    async def _generate_identity_dashboard_data(self: IdentityAnalyzer, org_id: UUID) -> Dict[str, Any]:
        """Generate comprehensive identity analytics for dashboard consumers."""

        sprawl_analysis = await PrivilegeSprawlDetector(self.db).analyze_privilege_sprawl(org_id)
        anomalies = await self.identify_privilege_anomalies(org_id)
        mfa_compliance = await self._get_mfa_compliance_by_provider(org_id)

        top_risky = sprawl_analysis.top_risky_identities[:5]
        drilldown_identities = await _build_drilldown_identities(self, top_risky)

        remediation_queue = []
        for entry in drilldown_identities:
            risk_level = entry["risk_level"]
            priority = "high" if risk_level in {"high", "critical"} else "medium" if risk_level == "medium" else "low"
            recommended_action = entry["recommended_actions"][0] if entry["recommended_actions"] else "Review access assignments"
            evidence = [finding["title"] for finding in entry["open_findings"]] or entry["providers"]

            remediation_queue.append(
                {
                    "principal_id": entry["principal_id"],
                    "priority": priority,
                    "summary": entry["display_name"] or entry["email"] or entry["principal_id"],
                    "recommended_action": recommended_action,
                    "evidence": evidence[:5],
                }
            )

        return {
            "summary": {
                "total_identities": sprawl_analysis.total_identities,
                "high_privilege_identities": sprawl_analysis.high_privilege_identities,
                "cross_provider_identities": sprawl_analysis.cross_provider_identities,
                "avg_permissions_per_identity": round(sprawl_analysis.avg_permissions_per_identity, 1),
                "max_permissions_per_identity": sprawl_analysis.max_permissions_per_identity,
            },
            "privilege_distribution": sprawl_analysis.privilege_distribution,
            "top_risky_identities": [
                {
                    "principal_id": str(identity.principal_id),
                    "display_name": identity.display_name,
                    "email": identity.email,
                    "risk_score": round(identity.risk_score, 1),
                    "risk_level": identity.risk_level.value,
                    "cross_provider_access": identity.cross_provider_access,
                    "admin_access_count": identity.admin_access_count,
                    "mfa_status": identity.mfa_status,
                    "top_risk_factor": identity.risk_factors[0] if identity.risk_factors else None,
                }
                for identity in top_risky
            ],
            "privilege_anomalies": anomalies,
            "mfa_compliance_by_provider": mfa_compliance,
            "provider_breakdown": sprawl_analysis.provider_privilege_breakdown,
            "drilldown_identities": drilldown_identities,
            "remediation_queue": remediation_queue,
        }

    IdentityAnalyzer.generate_identity_dashboard_data = _generate_identity_dashboard_data
