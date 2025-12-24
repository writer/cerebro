"""
Peer group baseline analysis for identity governance.

Implements peer group analysis (engineering vs finance) to highlight
outlier entitlements and detect privilege creep.
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from ..query.bootstrap import get_query_engine

logger = logging.getLogger(__name__)


class DepartmentType(Enum):
    """Standard department types for peer group analysis."""

    ENGINEERING = "engineering"
    FINANCE = "finance"
    SALES = "sales"
    MARKETING = "marketing"
    HR = "hr"
    LEGAL = "legal"
    OPERATIONS = "operations"
    SECURITY = "security"
    EXECUTIVE = "executive"
    SUPPORT = "support"
    UNKNOWN = "unknown"


@dataclass
class PeerGroupBaseline:
    """Baseline permissions for a peer group."""

    department: DepartmentType
    role_family: str  # "engineer", "manager", "analyst"
    typical_permissions: list[str]
    typical_resources: list[str]
    permission_frequency: dict[str, float]  # permission -> frequency in peer group
    elevated_permissions: list[str]  # Permissions requiring justification
    admin_permission_rate: float  # % of peer group with admin access
    total_principals: int
    baseline_date: datetime


@dataclass
class OutlierAnalysis:
    """Analysis of outlier permissions for a principal."""

    principal_id: str
    department: str
    role: str
    outlier_permissions: list[dict[str, Any]]
    missing_common_permissions: list[str]
    risk_score: float
    peer_group_size: int
    recommendations: list[str]


class PeerGroupAnalyzer:
    """
    Analyzes peer groups to detect outlier entitlements.

    Compares individual access patterns against department/role peers
    to identify privilege creep and access anomalies.
    """

    def __init__(self):
        self.query_engine = get_query_engine()
        self.baselines: dict[str, PeerGroupBaseline] = {}

    async def establish_peer_group_baselines(
        self, org_id: str
    ) -> dict[str, PeerGroupBaseline]:
        """
        Establish baseline permissions for each peer group.

        Analyzes current access patterns to create department/role baselines.
        """
        # Get all identity data with department/role information
        identity_data = await self._collect_identity_data(org_id)

        # Group by department and role
        peer_groups = self._group_by_peer_characteristics(identity_data)

        # Calculate baselines for each group
        baselines = {}
        for group_key, principals in peer_groups.items():
            baseline = await self._calculate_group_baseline(group_key, principals)
            baselines[group_key] = baseline

        self.baselines = baselines
        logger.info(f"Established {len(baselines)} peer group baselines")

        return baselines

    async def _collect_identity_data(self, org_id: str) -> list[dict[str, Any]]:
        """Collect identity and access data across all providers."""
        identity_data = []

        # Collect Okta identity data
        try:
            okta_result = await self.query_engine.execute_query(
                """
                SELECT user_id, username, email, display_name, status,
                       job_title, department, groups, attributes
                FROM okta_user
                WHERE status = 'active'
            """
            )

            for user in okta_result.rows:
                identity_data.append(
                    {
                        "principal_id": user["user_id"],
                        "provider": "okta",
                        "department": self._normalize_department(
                            user.get("department", "")
                        ),
                        "role": self._normalize_role(user.get("job_title", "")),
                        "email": user["email"],
                        "groups": user.get("groups", []),
                        "attributes": user.get("attributes", {}),
                    }
                )

        except Exception as e:
            logger.error(f"Failed to collect Okta identity data: {e}")

        # Collect M365 identity data
        try:
            m365_result = await self.query_engine.execute_query(
                """
                SELECT user_id, user_principal_name, display_name,
                       job_title, department, account_enabled
                FROM m365_user
                WHERE account_enabled = true
            """
            )

            for user in m365_result.rows:
                identity_data.append(
                    {
                        "principal_id": user["user_id"],
                        "provider": "m365",
                        "department": self._normalize_department(
                            user.get("department", "")
                        ),
                        "role": self._normalize_role(user.get("job_title", "")),
                        "email": user["user_principal_name"],
                        "groups": [],
                        "attributes": {},
                    }
                )

        except Exception as e:
            logger.error(f"Failed to collect M365 identity data: {e}")

        return identity_data

    def _normalize_department(self, department: str) -> DepartmentType:
        """Normalize department string to standard type."""
        if not department:
            return DepartmentType.UNKNOWN

        dept_lower = department.lower()

        # Map common variations to standard types
        if any(term in dept_lower for term in ["eng", "dev", "tech", "software"]):
            return DepartmentType.ENGINEERING
        elif any(term in dept_lower for term in ["finance", "accounting", "budget"]):
            return DepartmentType.FINANCE
        elif any(term in dept_lower for term in ["sales", "revenue", "business dev"]):
            return DepartmentType.SALES
        elif any(term in dept_lower for term in ["marketing", "growth", "brand"]):
            return DepartmentType.MARKETING
        elif any(term in dept_lower for term in ["hr", "human resources", "people"]):
            return DepartmentType.HR
        elif any(term in dept_lower for term in ["legal", "compliance", "regulatory"]):
            return DepartmentType.LEGAL
        elif any(
            term in dept_lower for term in ["ops", "operations", "infrastructure"]
        ):
            return DepartmentType.OPERATIONS
        elif any(
            term in dept_lower for term in ["security", "infosec", "cybersecurity"]
        ):
            return DepartmentType.SECURITY
        elif any(term in dept_lower for term in ["exec", "c-level", "leadership"]):
            return DepartmentType.EXECUTIVE
        elif any(
            term in dept_lower for term in ["support", "customer success", "help"]
        ):
            return DepartmentType.SUPPORT
        else:
            return DepartmentType.UNKNOWN

    def _normalize_role(self, role: str) -> str:
        """Normalize role string to standard family."""
        if not role:
            return "unknown"

        role_lower = role.lower()

        if "engineer" in role_lower or "developer" in role_lower:
            return "engineer"
        elif (
            "manager" in role_lower or "director" in role_lower or "lead" in role_lower
        ):
            return "manager"
        elif "analyst" in role_lower:
            return "analyst"
        elif "admin" in role_lower:
            return "admin"
        elif "specialist" in role_lower or "expert" in role_lower:
            return "specialist"
        else:
            return "individual_contributor"

    def _group_by_peer_characteristics(
        self, identity_data: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group principals by department and role for peer analysis."""
        groups: dict[str, list[dict[str, Any]]] = {}

        for identity in identity_data:
            department = identity["department"]
            role = identity["role"]
            group_key = f"{department.value}_{role}"

            if group_key not in groups:
                groups[group_key] = []

            groups[group_key].append(identity)

        # Filter out groups with too few members for meaningful analysis
        return {k: v for k, v in groups.items() if len(v) >= 3}

    async def _calculate_group_baseline(
        self, group_key: str, principals: list[dict[str, Any]]
    ) -> PeerGroupBaseline:
        """Calculate baseline permissions for a peer group."""
        department_str, role = group_key.split("_", 1)
        department = DepartmentType(department_str)

        # Collect all permissions for principals in this group
        all_permissions: list[str] = []
        permission_counts: dict[str, int] = {}
        admin_count = 0

        for principal in principals:
            principal_permissions = await self._get_principal_permissions(
                principal["principal_id"]
            )
            all_permissions.extend(principal_permissions)

            # Count permission frequencies
            for perm in principal_permissions:
                permission_counts[perm] = permission_counts.get(perm, 0) + 1

                # Count admin permissions
                if "admin" in perm.lower() or "owner" in perm.lower():
                    admin_count += 1

        # Calculate frequencies
        total_principals = len(principals)
        permission_frequency = {
            perm: count / total_principals for perm, count in permission_counts.items()
        }

        # Identify typical permissions (>50% of group has it)
        typical_permissions = [
            perm for perm, freq in permission_frequency.items() if freq > 0.5
        ]

        # Identify elevated permissions (admin-level access)
        elevated_permissions = [
            perm
            for perm in permission_frequency.keys()
            if any(
                term in perm.lower()
                for term in ["admin", "owner", "full", "delete", "create"]
            )
        ]

        # Get typical resources (simplified)
        typical_resources = list(
            {

                    perm.split(":")[0] if ":" in perm else perm
                    for perm in typical_permissions

            }
        )

        baseline = PeerGroupBaseline(
            department=department,
            role_family=role,
            typical_permissions=typical_permissions,
            typical_resources=typical_resources,
            permission_frequency=permission_frequency,
            elevated_permissions=elevated_permissions,
            admin_permission_rate=(
                admin_count / total_principals if total_principals > 0 else 0
            ),
            total_principals=total_principals,
            baseline_date=datetime.now(),
        )

        return baseline

    async def _get_principal_permissions(self, principal_id: str) -> list[str]:
        """Get all permissions for a principal across providers."""
        permissions = []

        # Query GitHub permissions
        try:
            github_result = await self.query_engine.execute_query(
                f"""
                SELECT repository, permissions
                FROM github_repository
                WHERE owner = (
                    SELECT username FROM github_user WHERE user_id = '{principal_id}'
                )
            """
            )

            for repo in github_result.rows:
                perms = repo.get("permissions", {})
                if isinstance(perms, dict):
                    for perm_type, has_perm in perms.items():
                        if has_perm:
                            permissions.append(
                                f"github:{perm_type}:{repo['repository']}"
                            )

        except Exception as e:
            logger.debug(f"Failed to get GitHub permissions for {principal_id}: {e}")

        # Query AWS permissions
        try:
            aws_result = await self.query_engine.execute_query(
                f"""
                SELECT user_name, attached_policies
                FROM aws_iam_user
                WHERE user_id = '{principal_id}'
            """
            )

            for user in aws_result.rows:
                policies = user.get("attached_policies", [])
                for policy in policies:
                    permissions.append(f"aws:{policy}")

        except Exception as e:
            logger.debug(f"Failed to get AWS permissions for {principal_id}: {e}")

        return permissions

    async def analyze_outliers(self, org_id: str) -> list[OutlierAnalysis]:
        """
        Analyze principals for outlier permissions compared to peers.

        Identifies individuals with unusual access patterns for their department/role.
        """
        if not self.baselines:
            await self.establish_peer_group_baselines(org_id)

        outliers = []
        identity_data = await self._collect_identity_data(org_id)

        for identity in identity_data:
            analysis = await self._analyze_principal_vs_peers(identity)
            if analysis and analysis.risk_score >= 0.6:  # Significant outlier
                outliers.append(analysis)

        # Sort by risk score
        outliers.sort(key=lambda x: x.risk_score, reverse=True)

        return outliers

    async def _analyze_principal_vs_peers(
        self, identity: dict[str, Any]
    ) -> OutlierAnalysis | None:
        """Analyze a principal against their peer group baseline."""
        department = identity["department"]
        role = identity["role"]
        group_key = f"{department.value}_{role}"

        baseline = self.baselines.get(group_key)
        if not baseline:
            return None  # No peer group baseline available

        principal_id = identity["principal_id"]
        principal_permissions = await self._get_principal_permissions(principal_id)

        # Find outlier permissions (principal has but peers typically don't)
        outlier_permissions = []
        for perm in principal_permissions:
            peer_frequency = baseline.permission_frequency.get(perm, 0)

            if peer_frequency < 0.1:  # Less than 10% of peers have this permission
                outlier_permissions.append(
                    {
                        "permission": perm,
                        "peer_frequency": peer_frequency,
                        "severity": "high" if peer_frequency == 0 else "medium",
                    }
                )

        # Find missing common permissions (peers have but principal doesn't)
        missing_permissions = []
        for perm, frequency in baseline.permission_frequency.items():
            if (
                frequency > 0.8 and perm not in principal_permissions
            ):  # 80%+ of peers have it
                missing_permissions.append(perm)

        # Calculate risk score
        risk_score = self._calculate_outlier_risk_score(
            outlier_permissions, missing_permissions, baseline
        )

        # Generate recommendations
        recommendations = self._generate_outlier_recommendations(
            outlier_permissions, missing_permissions, baseline
        )

        # Only return analysis if there are significant findings
        if outlier_permissions or (risk_score >= 0.6):
            return OutlierAnalysis(
                principal_id=principal_id,
                department=department.value,
                role=role,
                outlier_permissions=outlier_permissions,
                missing_common_permissions=missing_permissions,
                risk_score=risk_score,
                peer_group_size=baseline.total_principals,
                recommendations=recommendations,
            )

        return None

    def _calculate_outlier_risk_score(
        self,
        outlier_permissions: list[dict[str, Any]],
        missing_permissions: list[str],
        baseline: PeerGroupBaseline,
    ) -> float:
        """Calculate risk score for outlier analysis."""
        if not outlier_permissions:
            return 0.0

        # Base score from number of outlier permissions
        outlier_count_score = min(
            len(outlier_permissions) / 10, 1.0
        )  # Max at 10 outliers

        # Severity bonus for high-severity outliers
        high_severity_count = len(
            [p for p in outlier_permissions if p["severity"] == "high"]
        )
        severity_score = min(high_severity_count / 5, 1.0)  # Max at 5 high-severity

        # Admin permission bonus
        admin_outliers = [
            p
            for p in outlier_permissions
            if any(
                term in p["permission"].lower() for term in ["admin", "owner", "root"]
            )
        ]
        admin_score = min(len(admin_outliers) / 3, 1.0)  # Max at 3 admin outliers

        # Combine scores (weighted)
        risk_score = (
            outlier_count_score * 0.4 + severity_score * 0.4 + admin_score * 0.2
        )

        return min(risk_score, 1.0)

    def _generate_outlier_recommendations(
        self,
        outlier_permissions: list[dict[str, Any]],
        missing_permissions: list[str],
        baseline: PeerGroupBaseline,
    ) -> list[str]:
        """Generate recommendations for outlier principals."""
        recommendations = []

        if outlier_permissions:
            high_severity_outliers = [
                p for p in outlier_permissions if p["severity"] == "high"
            ]

            if high_severity_outliers:
                recommendations.append(
                    f"Review {len(high_severity_outliers)} unique permissions not typical for "
                    f"{baseline.department.value} {baseline.role_family}"
                )

            admin_outliers = [
                p
                for p in outlier_permissions
                if any(term in p["permission"].lower() for term in ["admin", "owner"])
            ]

            if admin_outliers:
                recommendations.append(
                    f"Justify {len(admin_outliers)} admin-level permissions - "
                    f"only {baseline.admin_permission_rate:.0%} of peers have admin access"
                )

        if missing_permissions:
            recommendations.append(
                f"Consider granting {len(missing_permissions)} common permissions "
                f"that 80%+ of peers have"
            )

        if not recommendations:
            recommendations.append("Access patterns align with peer group")

        return recommendations

    async def generate_peer_group_report(self, org_id: str) -> dict[str, Any]:
        """
        Generate comprehensive peer group analysis report.

        Returns department baselines and outlier analysis.
        """
        # Establish baselines
        baselines = await self.establish_peer_group_baselines(org_id)

        # Analyze outliers
        outliers = await self.analyze_outliers(org_id)

        # Create department summaries
        department_summaries: dict[str, dict[str, Any]] = {}
        for _group_key, baseline in baselines.items():
            dept_name = baseline.department.value

            if dept_name not in department_summaries:
                department_summaries[dept_name] = {
                    "total_principals": 0,
                    "role_families": [],
                    "typical_permissions": set(),
                    "admin_permission_rate": 0.0,
                    "outliers": [],
                }

            dept_summary = department_summaries[dept_name]
            dept_summary["total_principals"] = int(dept_summary["total_principals"]) + baseline.total_principals
            dept_summary["role_families"].append(baseline.role_family)
            dept_summary["typical_permissions"].update(baseline.typical_permissions)
            dept_summary["admin_permission_rate"] = max(
                float(dept_summary["admin_permission_rate"]), baseline.admin_permission_rate
            )

        # Add outliers to department summaries
        for outlier in outliers:
            dept_name = outlier.department
            if dept_name in department_summaries:
                department_summaries[dept_name]["outliers"].append(
                    {
                        "principal_id": outlier.principal_id,
                        "role": outlier.role,
                        "risk_score": outlier.risk_score,
                        "outlier_permission_count": len(outlier.outlier_permissions),
                        "recommendations": outlier.recommendations,
                    }
                )

        # Convert sets to lists for JSON serialization
        for dept_data in department_summaries.values():
            dept_data["typical_permissions"] = list(dept_data["typical_permissions"])

        return {
            "organization_id": org_id,
            "analysis_date": datetime.now().isoformat(),
            "summary": {
                "total_peer_groups": len(baselines),
                "total_outliers": len(outliers),
                "high_risk_outliers": len([o for o in outliers if o.risk_score >= 0.8]),
                "departments_analyzed": len(department_summaries),
            },
            "department_baselines": department_summaries,
            "top_outliers": [
                {
                    "principal_id": outlier.principal_id,
                    "department": outlier.department,
                    "role": outlier.role,
                    "risk_score": outlier.risk_score,
                    "outlier_permissions": outlier.outlier_permissions[:5],  # Top 5
                    "recommendations": outlier.recommendations,
                }
                for outlier in outliers[:10]  # Top 10 outliers
            ],
            "baselines": {
                group_key: {
                    "department": baseline.department.value,
                    "role_family": baseline.role_family,
                    "total_principals": baseline.total_principals,
                    "typical_permission_count": len(baseline.typical_permissions),
                    "elevated_permission_count": len(baseline.elevated_permissions),
                    "admin_permission_rate": baseline.admin_permission_rate,
                }
                for group_key, baseline in baselines.items()
            },
        }


# CEL rules for peer group violations
PEER_GROUP_CEL_RULES = {
    "finance_github_admin": """
        principal.department == "Finance" &&
        principal.has("GitHub:admin") &&
        peer_group_rate(principal.department, "GitHub:admin") < 0.1 ->
        violation("GitHub admin access unusual for Finance department")
    """,
    "engineering_aws_billing": """
        principal.department == "Engineering" &&
        principal.has("AWS:billing:*") &&
        peer_group_rate(principal.department, "AWS:billing") < 0.05 ->
        violation("AWS billing access unusual for Engineering")
    """,
    "excessive_admin_permissions": """
        count(principal.admin_permissions()) >
        peer_group_average(principal.department, "admin_count") * 2 ->
        violation("Excessive admin permissions compared to peer group")
    """,
}


# Global peer group analyzer
_peer_group_analyzer = PeerGroupAnalyzer()


def get_peer_group_analyzer() -> PeerGroupAnalyzer:
    """Get global peer group analyzer."""
    return _peer_group_analyzer
