"""Blast radius analysis for compromise scenarios."""

from typing import List, Dict, Set, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, text

from cerebro.core.models import Principal, Resource, IamEdge, ConfigSnapshot, Organization
from cerebro.core.identity_models import IdentityCluster, IdentityClusterMember
from cerebro.core.repositories_sqlalchemy import IdentityRepository
from cerebro.providers.base_edge_harvester import harvest_all_edges

logger = logging.getLogger(__name__)


@dataclass
class CompromiseScenario:
    """Represents a principal compromise scenario."""
    principal_id: UUID
    principal_name: str
    principal_type: str
    provider: str
    compromise_time: datetime = field(default_factory=datetime.utcnow)
    scenario_type: str = "credential_theft"  # credential_theft, privilege_escalation, insider_threat


@dataclass
class ImpactedResource:
    """A resource impacted by principal compromise."""
    resource_id: UUID
    resource_external_id: str
    resource_type: str
    provider: str
    access_level: str  # read, write, admin
    access_path: List[str]  # How the access is granted
    sensitivity_score: float  # 0-1 based on resource type and config
    potential_actions: List[str]  # What the attacker could do


@dataclass 
class ImpactAssessment:
    """Complete impact assessment for a compromise scenario."""
    scenario: CompromiseScenario
    directly_accessible: List[ImpactedResource]
    escalation_paths: List[Dict[str, Any]]
    cross_provider_impact: List[ImpactedResource]
    total_resources_at_risk: int
    max_sensitivity_score: float
    business_impact_score: float
    mitigation_recommendations: List[str]


class BlastRadiusAnalyzer:
    """Analyzes blast radius of principal compromise scenarios."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize blast radius analyzer."""
        self.db = db_session
        
        # Resource sensitivity scoring
        self.sensitivity_weights = {
            "aws.s3.bucket": 0.8,  # High - potential data exposure
            "aws.iam.role": 0.9,   # Very high - privilege escalation
            "github.repo": 0.7,    # High - code access
            "aws.ec2.instance": 0.6,  # Medium-high - compute access
            "gcp.storage.bucket": 0.8,
            "google_workspace.user": 0.5,
        }
    
    async def analyze_principal_compromise(
        self, 
        principal_id: UUID,
        scenario_type: str = "credential_theft",
        at_time: Optional[datetime] = None
    ) -> ImpactAssessment:
        """Analyze blast radius if a principal is compromised."""
        # Get principal information
        principal = await self.db.get(Principal, principal_id)
        if not principal:
            raise ValueError(f"Principal {principal_id} not found")
        
        compromise_time = at_time or datetime.utcnow()
        
        scenario = CompromiseScenario(
            principal_id=principal_id,
            principal_name=principal.display_name or principal.external_id,
            principal_type=principal.principal_type,
            provider=principal.provider,
            compromise_time=compromise_time,
            scenario_type=scenario_type
        )
        
        logger.info(f"Analyzing blast radius for {principal.external_id} at {compromise_time}")
        
        # 1. Find directly accessible resources
        directly_accessible = await self._find_directly_accessible_resources(
            principal_id, compromise_time
        )
        
        # 2. Find privilege escalation paths
        escalation_paths = await self._find_escalation_paths(
            principal_id, compromise_time
        )
        
        # 3. Find cross-provider impact via identity stitching
        cross_provider_impact = await self._find_cross_provider_impact(
            principal_id, compromise_time
        )
        
        # 4. Calculate business impact
        all_impacted = directly_accessible + cross_provider_impact
        total_resources = len(all_impacted)
        max_sensitivity = max([r.sensitivity_score for r in all_impacted], default=0.0)
        business_impact = self._calculate_business_impact(all_impacted, escalation_paths)
        
        # 5. Generate mitigation recommendations
        recommendations = self._generate_mitigations(scenario, all_impacted, escalation_paths)
        
        assessment = ImpactAssessment(
            scenario=scenario,
            directly_accessible=directly_accessible,
            escalation_paths=escalation_paths,
            cross_provider_impact=cross_provider_impact,
            total_resources_at_risk=total_resources,
            max_sensitivity_score=max_sensitivity,
            business_impact_score=business_impact,
            mitigation_recommendations=recommendations
        )
        
        logger.info(f"Blast radius analysis complete: {total_resources} resources at risk, "
                   f"impact score {business_impact:.2f}")
        
        return assessment
    
    async def _find_directly_accessible_resources(
        self, 
        principal_id: UUID, 
        at_time: datetime
    ) -> List[ImpactedResource]:
        """Find resources directly accessible to the principal."""
        # Query IAM edges that were effective at the compromise time
        stmt = select(IamEdge, Resource).join(Resource).where(
            and_(
                IamEdge.principal_id == principal_id,
                IamEdge.effective_at <= at_time,
                or_(
                    IamEdge.expires_at.is_(None),
                    IamEdge.expires_at > at_time
                )
            )
        )
        
        edges_and_resources = await self.db.execute(stmt)
        impacted = []
        
        for iam_edge, resource in edges_and_resources:
            # Get latest config for sensitivity scoring
            config = await self._get_latest_config_at_time(resource.resource_id, at_time)
            
            sensitivity_score = self._calculate_sensitivity_score(resource, config)
            access_level = self._determine_access_level(iam_edge.permission, iam_edge.is_admin)
            potential_actions = self._determine_potential_actions(resource, iam_edge, config)
            
            impacted_resource = ImpactedResource(
                resource_id=resource.resource_id,
                resource_external_id=resource.external_id,
                resource_type=resource.resource_type,
                provider=resource.provider,
                access_level=access_level,
                access_path=[iam_edge.via] if iam_edge.via else ["direct"],
                sensitivity_score=sensitivity_score,
                potential_actions=potential_actions
            )
            impacted.append(impacted_resource)
        
        return impacted
    
    async def _find_escalation_paths(
        self, 
        principal_id: UUID, 
        at_time: datetime
    ) -> List[Dict[str, Any]]:
        """Find privilege escalation paths from the principal."""
        escalation_paths = []
        
        # Find if principal can assume roles or escalate privileges
        stmt = select(IamEdge, Resource).join(Resource).where(
            and_(
                IamEdge.principal_id == principal_id,
                IamEdge.effective_at <= at_time,
                or_(
                    IamEdge.permission.contains("iam:AssumeRole"),
                    IamEdge.permission.contains("iam:PassRole"),
                    IamEdge.permission.contains("iam:CreateRole"),
                    IamEdge.permission.contains("admin"),
                    IamEdge.is_admin == True
                )
            )
        )
        
        escalation_edges = await self.db.execute(stmt)
        
        for iam_edge, resource in escalation_edges:
            if "AssumeRole" in iam_edge.permission or "PassRole" in iam_edge.permission:
                # Can assume/pass roles - find what those roles can access
                role_resources = await self._analyze_role_permissions(resource, at_time)
                
                escalation_paths.append({
                    "type": "role_assumption",
                    "intermediate_resource": {
                        "id": str(resource.resource_id),
                        "external_id": resource.external_id,
                        "type": resource.resource_type
                    },
                    "permission": iam_edge.permission,
                    "additional_resources": len(role_resources),
                    "escalation_score": 0.8 if "admin" in resource.name.lower() else 0.6,
                    "path": f"{iam_edge.via} -> {resource.external_id}"
                })
        
        return escalation_paths
    
    async def _find_cross_provider_impact(
        self, 
        principal_id: UUID, 
        at_time: datetime
    ) -> List[ImpactedResource]:
        """Find cross-provider impact via identity stitching."""
        impacted = []
        
        # Find identity cluster for this principal
        stmt = select(IdentityClusterMember, IdentityCluster).join(IdentityCluster).where(
            IdentityClusterMember.principal_id == principal_id
        )
        cluster_result = await self.db.execute(stmt)
        cluster_data = cluster_result.first()
        
        if not cluster_data:
            return impacted
        
        cluster_member, cluster = cluster_data
        
        # Get all principals in the same identity cluster
        stmt = select(IdentityClusterMember, Principal).join(Principal).where(
            and_(
                IdentityClusterMember.cluster_id == cluster.cluster_id,
                IdentityClusterMember.principal_id != principal_id
            )
        )
        
        related_principals = await self.db.execute(stmt)
        
        # For each related principal, find their accessible resources
        for cluster_member, related_principal in related_principals:
            related_resources = await self._find_directly_accessible_resources(
                related_principal.principal_id, at_time
            )
            
            # Tag these as cross-provider impact
            for resource in related_resources:
                resource.access_path = [f"identity_cluster:{cluster.cluster_name}"] + resource.access_path
                impacted.append(resource)
        
        return impacted
    
    def _calculate_sensitivity_score(self, resource: Resource, config: Optional[Dict]) -> float:
        """Calculate sensitivity score for a resource."""
        base_score = self.sensitivity_weights.get(resource.resource_type, 0.3)
        
        if not config:
            return base_score
        
        # Adjust based on configuration
        if resource.resource_type == "aws.s3.bucket":
            if config.get("policyAllowsPublic") or config.get("aclAllowsPublic"):
                base_score += 0.2  # Public buckets are more sensitive
            if not config.get("encryption", {}).get("enabled"):
                base_score += 0.1  # Unencrypted data
        
        elif resource.resource_type == "github.repo":
            if config.get("visibility") == "public":
                base_score += 0.1
            if config.get("hasSecrets"):
                base_score += 0.3  # Repos with secrets
        
        return min(base_score, 1.0)
    
    def _determine_access_level(self, permission: str, is_admin: bool) -> str:
        """Determine access level from permission."""
        if is_admin or "admin" in permission.lower():
            return "admin"
        elif any(verb in permission.lower() for verb in ["write", "put", "create", "delete"]):
            return "write"
        else:
            return "read"
    
    def _determine_potential_actions(
        self, 
        resource: Resource, 
        iam_edge: IamEdge, 
        config: Optional[Dict]
    ) -> List[str]:
        """Determine what actions an attacker could take."""
        actions = []
        
        if resource.resource_type == "aws.s3.bucket":
            if "s3:GetObject" in iam_edge.permission or iam_edge.is_admin:
                actions.append("download_data")
            if "s3:PutObject" in iam_edge.permission or iam_edge.is_admin:
                actions.append("upload_malicious_files")
            if "s3:DeleteObject" in iam_edge.permission or iam_edge.is_admin:
                actions.append("delete_data")
        
        elif resource.resource_type == "github.repo":
            if "push" in iam_edge.permission or iam_edge.is_admin:
                actions.extend(["modify_code", "insert_backdoors", "steal_secrets"])
            if "admin" in iam_edge.permission or iam_edge.is_admin:
                actions.extend(["modify_settings", "add_collaborators", "disable_protections"])
        
        elif resource.resource_type == "aws.ec2.instance":
            if iam_edge.is_admin or "ec2:RunInstances" in iam_edge.permission:
                actions.extend(["launch_instances", "lateral_movement", "cryptocurrency_mining"])
        
        return actions
    
    async def _get_latest_config_at_time(
        self, 
        resource_id: UUID, 
        at_time: datetime
    ) -> Optional[Dict]:
        """Get the latest configuration at a specific time."""
        stmt = select(ConfigSnapshot).where(
            and_(
                ConfigSnapshot.resource_id == resource_id,
                ConfigSnapshot.captured_at <= at_time
            )
        ).order_by(ConfigSnapshot.captured_at.desc()).limit(1)
        
        snapshot = await self.db.scalar(stmt)
        return snapshot.normalized_config if snapshot else None
    
    async def _analyze_role_permissions(
        self,
        role_resource: Resource,
        at_time: datetime
    ) -> List[Resource]:
        """Analyze what resources a role can access."""
        try:
            from sqlalchemy import select, and_
            from ..core.models import IamEdge, Principal

            # Find principals (users, services) that can assume this role
            role_principals_stmt = select(Principal).join(IamEdge).where(
                and_(
                    IamEdge.resource_id == role_resource.resource_id,
                    Principal.principal_id == IamEdge.principal_id,
                    # Look for assume role permissions
                    IamEdge.permission.in_(['sts:AssumeRole', 'assume_role', 'AssumeRole'])
                )
            )

            # Get resources this role can access through IAM edges
            accessible_resources_stmt = select(Resource).join(IamEdge).join(Principal).where(
                and_(
                    # Match role by resource ARN or name
                    Principal.provider_id == role_resource.provider_id,
                    Principal.display_name.like(f"%{role_resource.display_name}%"),
                    Resource.resource_id == IamEdge.resource_id,
                    # Exclude self-references
                    Resource.resource_id != role_resource.resource_id
                )
            )

            # Execute both queries
            accessible_resources = await self.db.scalars(accessible_resources_stmt)
            accessible_list = list(accessible_resources.all())

            # If no direct IAM edges found, try policy-based analysis
            if not accessible_list:
                policy_based_resources = await self._analyze_role_policies(role_resource)
                accessible_list.extend(policy_based_resources)

            logger.info(
                f"Role {role_resource.display_name} can access {len(accessible_list)} resources"
            )

            return accessible_list

        except Exception as e:
            logger.error(f"Failed to analyze role permissions for {role_resource.display_name}: {e}")
            # Return empty list if analysis fails, but log the issue
            return []

    async def _analyze_role_policies(self, role_resource: Resource) -> List[Resource]:
        """Analyze role policies to determine accessible resources."""
        try:
            # Get role configuration from latest snapshot
            role_config = await self._get_latest_resource_config(role_resource.resource_id)

            if not role_config or "attached_policies" not in role_config:
                return []

            # Analyze attached policies for resource access
            accessible_resources = []
            attached_policies = role_config.get("attached_policies", [])

            for policy in attached_policies:
                # Extract resource ARNs from policy statements
                if "policy_document" in policy:
                    policy_doc = policy["policy_document"]
                    if isinstance(policy_doc, dict) and "Statement" in policy_doc:
                        for statement in policy_doc["Statement"]:
                            if statement.get("Effect") == "Allow":
                                resources = statement.get("Resource", [])
                                if isinstance(resources, str):
                                    resources = [resources]

                                # Find resources matching policy ARNs
                                for resource_arn in resources:
                                    matching_resources = await self._find_resources_by_arn_pattern(resource_arn)
                                    accessible_resources.extend(matching_resources)

            return accessible_resources

        except Exception as e:
            logger.error(f"Failed to analyze role policies: {e}")
            return []

    async def _find_resources_by_arn_pattern(self, arn_pattern: str) -> List[Resource]:
        """Find resources matching an ARN pattern."""
        try:
            from sqlalchemy import select, or_

            # Handle wildcard patterns in ARNs
            if "*" in arn_pattern:
                # Convert AWS ARN wildcards to SQL LIKE patterns
                like_pattern = arn_pattern.replace("*", "%")
                stmt = select(Resource).where(
                    or_(
                        Resource.provider_id.like(like_pattern),
                        Resource.display_name.like(like_pattern)
                    )
                )
            else:
                # Exact match
                stmt = select(Resource).where(
                    or_(
                        Resource.provider_id == arn_pattern,
                        Resource.display_name == arn_pattern
                    )
                )

            resources = await self.db.scalars(stmt)
            return list(resources.all())

        except Exception as e:
            logger.error(f"Failed to find resources by ARN pattern {arn_pattern}: {e}")
            return []
    
    def _calculate_business_impact(
        self, 
        impacted_resources: List[ImpactedResource],
        escalation_paths: List[Dict[str, Any]]
    ) -> float:
        """Calculate overall business impact score (0-1)."""
        if not impacted_resources:
            return 0.0
        
        # Weight by sensitivity and access level
        total_impact = 0.0
        for resource in impacted_resources:
            access_multiplier = {"read": 0.3, "write": 0.7, "admin": 1.0}[resource.access_level]
            total_impact += resource.sensitivity_score * access_multiplier
        
        # Add escalation path impact
        escalation_impact = sum(path.get("escalation_score", 0) for path in escalation_paths)
        
        # Normalize to 0-1 scale
        raw_score = (total_impact / len(impacted_resources)) + (escalation_impact * 0.3)
        return min(raw_score, 1.0)
    
    def _generate_mitigations(
        self,
        scenario: CompromiseScenario,
        impacted_resources: List[ImpactedResource],
        escalation_paths: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate specific mitigation recommendations."""
        mitigations = []
        
        # Principal-specific mitigations
        if scenario.principal_type == "user":
            mitigations.append("Force password reset and MFA re-enrollment")
            mitigations.append("Revoke all active sessions and API tokens")
        elif scenario.principal_type == "service_account":
            mitigations.append("Rotate service account credentials immediately")
            mitigations.append("Review service account usage patterns")
        
        # Resource-specific mitigations
        admin_resources = [r for r in impacted_resources if r.access_level == "admin"]
        if admin_resources:
            mitigations.append(f"Review admin access to {len(admin_resources)} high-privilege resources")
        
        public_resources = [r for r in impacted_resources if "public" in str(r.potential_actions)]
        if public_resources:
            mitigations.append("Enable additional monitoring for public-facing resources")
        
        # Escalation-specific mitigations
        if escalation_paths:
            mitigations.append("Review and restrict role assumption permissions")
            mitigations.append("Enable CloudTrail/audit logging for privilege escalation detection")
        
        # Cross-provider mitigations
        cross_provider_resources = [r for r in impacted_resources if "identity_cluster" in r.access_path[0]]
        if cross_provider_resources:
            mitigations.append("Coordinate incident response across all linked provider accounts")
            mitigations.append("Consider temporarily disabling identity federation")
        
        return mitigations
    
    async def batch_analyze_high_risk_principals(
        self, 
        org_id: UUID,
        limit: int = 50
    ) -> List[ImpactAssessment]:
        """Analyze blast radius for high-risk principals in an organization."""
        # Find high-risk principals (admins, service accounts with broad access)
        stmt = text("""
            SELECT DISTINCT p.principal_id, p.external_id, COUNT(ie.edge_id) as permission_count
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            JOIN iam_edges ie ON p.principal_id = ie.principal_id
            WHERE a.org_id = :org_id
              AND (ie.is_admin = true OR p.principal_type = 'service_account')
            GROUP BY p.principal_id, p.external_id
            ORDER BY permission_count DESC, ie.is_admin DESC
            LIMIT :limit
        """)
        
        result = await self.db.execute(stmt, {"org_id": org_id, "limit": limit})
        high_risk_principals = result.fetchall()
        
        assessments = []
        for row in high_risk_principals:
            try:
                assessment = await self.analyze_principal_compromise(UUID(row.principal_id))
                assessments.append(assessment)
            except Exception as e:
                logger.error(f"Failed to analyze principal {row.external_id}: {e}")
        
        # Sort by business impact score
        assessments.sort(key=lambda a: a.business_impact_score, reverse=True)
        
        logger.info(f"Analyzed {len(assessments)} high-risk principals")
        return assessments
    
    async def generate_blast_radius_report(
        self,
        org_id: UUID,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """Generate comprehensive blast radius report for organization."""
        org = await self.db.get(Organization, org_id)
        if not org:
            raise ValueError(f"Organization {org_id} not found")
        
        # Analyze high-risk principals
        assessments = await self.batch_analyze_high_risk_principals(org_id)
        
        # Calculate organization-wide risk metrics
        total_principals_analyzed = len(assessments)
        high_impact_count = len([a for a in assessments if a.business_impact_score > 0.7])
        avg_resources_at_risk = sum(a.total_resources_at_risk for a in assessments) / max(total_principals_analyzed, 1)
        
        report = {
            "organization": org.name,
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_principals_analyzed": total_principals_analyzed,
                "high_impact_principals": high_impact_count,
                "average_resources_at_risk": round(avg_resources_at_risk, 1),
                "max_impact_score": max([a.business_impact_score for a in assessments], default=0.0)
            },
            "top_risk_principals": [
                {
                    "principal_name": a.scenario.principal_name,
                    "principal_type": a.scenario.principal_type,
                    "provider": a.scenario.provider,
                    "resources_at_risk": a.total_resources_at_risk,
                    "business_impact_score": a.business_impact_score,
                    "max_sensitivity": a.max_sensitivity_score,
                    "escalation_paths": len(a.escalation_paths),
                    "top_actions": [
                        action for resource in a.directly_accessible[:3] 
                        for action in resource.potential_actions[:2]
                    ]
                }
                for a in assessments[:10]  # Top 10
            ],
            "mitigation_priorities": self._prioritize_mitigations(assessments),
            "cross_provider_risks": self._analyze_cross_provider_risks(assessments)
        }
        
        logger.info(f"Generated blast radius report for {org.name}: "
                   f"{high_impact_count}/{total_principals_analyzed} high-impact principals")
        
        return report
    
    def _prioritize_mitigations(self, assessments: List[ImpactAssessment]) -> List[str]:
        """Prioritize mitigation actions across all assessments."""
        mitigation_counts = {}
        
        for assessment in assessments:
            for mitigation in assessment.mitigation_recommendations:
                mitigation_counts[mitigation] = mitigation_counts.get(mitigation, 0) + 1
        
        # Sort by frequency and return top recommendations
        sorted_mitigations = sorted(mitigation_counts.items(), key=lambda x: x[1], reverse=True)
        return [mitigation for mitigation, count in sorted_mitigations[:10]]
    
    def _analyze_cross_provider_risks(self, assessments: List[ImpactAssessment]) -> Dict[str, Any]:
        """Analyze cross-provider risk patterns."""
        cross_provider_count = 0
        provider_pairs = set()
        
        for assessment in assessments:
            cross_resources = [r for r in assessment.cross_provider_impact if r.access_path]
            if cross_resources:
                cross_provider_count += 1
                
                # Track provider combinations
                providers = {assessment.scenario.provider}
                providers.update(r.provider for r in cross_resources)
                if len(providers) > 1:
                    provider_pairs.add(tuple(sorted(providers)))
        
        return {
            "principals_with_cross_provider_access": cross_provider_count,
            "provider_combinations": [list(pair) for pair in provider_pairs],
            "risk_level": "high" if cross_provider_count > len(assessments) * 0.3 else "medium"
        }
