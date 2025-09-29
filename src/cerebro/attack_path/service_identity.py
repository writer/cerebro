"""
Service-to-service identity mapping and analysis.

Maps CI/CD runners, GitHub Actions, OIDC trust boundaries, and 
repository allow-lists for service identity attack path analysis.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..query.engine import QueryEngine
from ..providers.tables import register_all_provider_tables

logger = logging.getLogger(__name__)


class ServiceIdentityType(Enum):
    """Types of service identities."""
    GITHUB_ACTIONS = "github_actions"
    CI_CD_RUNNER = "ci_cd_runner"
    KUBERNETES_SERVICE_ACCOUNT = "kubernetes_service_account"
    AWS_SERVICE_ROLE = "aws_service_role"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_MANAGED_IDENTITY = "azure_managed_identity"
    CONTAINER_IDENTITY = "container_identity"


class TrustMechanism(Enum):
    """Trust mechanisms for service identity."""
    OIDC_FEDERATION = "oidc_federation"
    WORKLOAD_IDENTITY = "workload_identity"
    INSTANCE_METADATA = "instance_metadata"
    SECRET_INJECTION = "secret_injection"
    CERTIFICATE_BASED = "certificate_based"


@dataclass
class ServiceIdentityEdge:
    """Service-to-service identity relationship."""
    edge_id: str
    source_service: str
    target_service: str
    trust_mechanism: TrustMechanism
    provider_source: str
    provider_target: str
    
    # Configuration
    trust_policy: Dict[str, Any]
    allowed_repositories: List[str]
    allowed_branches: List[str]
    conditions: List[str]
    
    # Risk assessment
    risk_score: float
    exploitability: str  # "low", "medium", "high"
    
    # Metadata
    discovered_at: datetime
    last_verified: datetime
    metadata: Dict[str, Any]


class ServiceIdentityMapper:
    """
    Maps service-to-service identity relationships for attack path analysis.
    
    Discovers GitHub Actions → AWS STS, GCP WIF, Azure Entra federation,
    and other service identity trust boundaries.
    """
    
    def __init__(self):
        self.query_engine = QueryEngine()
        register_all_provider_tables()
        self.service_edges: Dict[str, ServiceIdentityEdge] = {}
    
    async def discover_service_identities(self, org_id: str) -> List[ServiceIdentityEdge]:
        """
        Discover service identity relationships across providers.
        
        Maps CI/CD systems, container platforms, and cloud service trusts.
        """
        service_edges = []
        
        # Discover GitHub Actions → AWS trust relationships
        github_aws_edges = await self._discover_github_aws_federation()
        service_edges.extend(github_aws_edges)
        
        # Discover GCP Workload Identity relationships
        gcp_workload_edges = await self._discover_gcp_workload_identity()
        service_edges.extend(gcp_workload_edges)
        
        # Discover Azure Managed Identity relationships
        azure_identity_edges = await self._discover_azure_managed_identity()
        service_edges.extend(azure_identity_edges)
        
        # Discover Kubernetes service account mappings
        k8s_service_edges = await self._discover_k8s_service_accounts()
        service_edges.extend(k8s_service_edges)
        
        # Update cache
        for edge in service_edges:
            self.service_edges[edge.edge_id] = edge
        
        logger.info(f"Discovered {len(service_edges)} service identity edges")
        
        return service_edges
    
    async def _discover_github_aws_federation(self) -> List[ServiceIdentityEdge]:
        """Discover GitHub OIDC → AWS STS role relationships."""
        edges = []
        
        try:
            # Query GitHub repositories with Actions workflows
            github_result = await self.query_engine.execute_query("""
                SELECT repository, topics, default_branch
                FROM github_repository
                WHERE topics LIKE '%ci%' OR topics LIKE '%deployment%'
            """)
            
            # Query AWS IAM roles that trust GitHub OIDC
            aws_result = await self.query_engine.execute_query("""
                SELECT user_name, arn, attached_policies
                FROM aws_iam_user
                WHERE arn LIKE '%role%'
            """)
            
            # Map GitHub repos to AWS roles (simplified mapping)
            for repo in github_result.rows:
                for aws_role in aws_result.rows:
                    # Simulate OIDC trust relationship detection
                    edge = ServiceIdentityEdge(
                        edge_id=f"github_aws_{repo['repository']}_{aws_role['user_name']}",
                        source_service=f"github_actions_{repo['repository']}",
                        target_service=f"aws_role_{aws_role['user_name']}",
                        trust_mechanism=TrustMechanism.OIDC_FEDERATION,
                        provider_source="github",
                        provider_target="aws",
                        trust_policy={
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Condition": {
                                    "StringEquals": {
                                        "token.actions.githubusercontent.com:sub": f"repo:{repo['repository']}:ref:refs/heads/{repo['default_branch']}"
                                    }
                                }
                            }]
                        },
                        allowed_repositories=[repo['repository']],
                        allowed_branches=[repo['default_branch']],
                        conditions=["GitHub OIDC token", "Specific repository", "Main branch only"],
                        risk_score=self._calculate_service_edge_risk(
                            "github_actions", "aws_role", ["oidc_federation"]
                        ),
                        exploitability="medium",
                        discovered_at=datetime.now(),
                        last_verified=datetime.now(),
                        metadata={
                            "repository": repo['repository'],
                            "aws_role_arn": aws_role['arn'],
                            "trust_type": "github_oidc"
                        }
                    )
                    
                    edges.append(edge)
                    break  # One role per repo for simplicity
                    
        except Exception as e:
            logger.error(f"Failed to discover GitHub-AWS federation: {e}")
        
        return edges
    
    async def _discover_gcp_workload_identity(self) -> List[ServiceIdentityEdge]:
        """Discover GCP Workload Identity Federation relationships."""
        edges = []
        
        try:
            # Query GCP service accounts
            gcp_result = await self.query_engine.execute_query("""
                SELECT member, role, resource
                FROM gcp_iam_policy
                WHERE member LIKE '%serviceAccount%'
            """)
            
            for binding in gcp_result.rows:
                # Simulate workload identity mapping
                edge = ServiceIdentityEdge(
                    edge_id=f"gcp_workload_{binding['member']}_{binding['resource']}",
                    source_service=f"k8s_service_account",
                    target_service=binding['member'],
                    trust_mechanism=TrustMechanism.WORKLOAD_IDENTITY,
                    provider_source="kubernetes",
                    provider_target="gcp",
                    trust_policy={
                        "workload_identity_pool": "projects/123456789/locations/global/workloadIdentityPools/github",
                        "service_account": binding['member']
                    },
                    allowed_repositories=["*"],  # Would be more specific in production
                    allowed_branches=["main", "develop"],
                    conditions=["Kubernetes service account", "Workload Identity enabled"],
                    risk_score=self._calculate_service_edge_risk(
                        "kubernetes", "gcp", ["workload_identity"]
                    ),
                    exploitability="low",
                    discovered_at=datetime.now(),
                    last_verified=datetime.now(),
                    metadata={
                        "gcp_service_account": binding['member'],
                        "gcp_role": binding['role'],
                        "trust_type": "workload_identity"
                    }
                )
                
                edges.append(edge)
                
        except Exception as e:
            logger.error(f"Failed to discover GCP Workload Identity: {e}")
        
        return edges
    
    async def _discover_azure_managed_identity(self) -> List[ServiceIdentityEdge]:
        """Discover Azure Managed Identity relationships."""
        edges = []
        
        # Mock Azure Managed Identity discovery
        # In production, would query Azure Resource Manager APIs
        
        mock_identities = [{
            "identity_id": "azure_webapp_identity",
            "resource_group": "production-rg",
            "assigned_roles": ["Storage Blob Data Contributor"],
            "target_resources": ["storage_account_prod"]
        }]
        
        for identity in mock_identities:
            edge = ServiceIdentityEdge(
                edge_id=f"azure_identity_{identity['identity_id']}",
                source_service=f"azure_webapp",
                target_service=f"azure_storage",
                trust_mechanism=TrustMechanism.INSTANCE_METADATA,
                provider_source="azure",
                provider_target="azure",
                trust_policy={
                    "managed_identity_type": "system_assigned",
                    "resource_group": identity["resource_group"]
                },
                allowed_repositories=[],
                allowed_branches=[],
                conditions=["Managed Identity enabled", "Resource in same subscription"],
                risk_score=0.6,
                exploitability="medium",
                discovered_at=datetime.now(),
                last_verified=datetime.now(),
                metadata=identity
            )
            
            edges.append(edge)
        
        return edges
    
    async def _discover_k8s_service_accounts(self) -> List[ServiceIdentityEdge]:
        """Discover Kubernetes service account mappings."""
        edges = []
        
        # Mock Kubernetes service account discovery
        # In production, would query Kubernetes API
        
        mock_k8s_accounts = [{
            "name": "github-actions-sa",
            "namespace": "github-runner",
            "annotations": {
                "iam.gke.io/gcp-service-account": "github-actions@project.iam.gserviceaccount.com"
            },
            "secrets": ["github-token"]
        }]
        
        for sa in mock_k8s_accounts:
            # Check if it has workload identity annotation
            if "iam.gke.io/gcp-service-account" in sa.get("annotations", {}):
                gcp_sa = sa["annotations"]["iam.gke.io/gcp-service-account"]
                
                edge = ServiceIdentityEdge(
                    edge_id=f"k8s_gcp_{sa['name']}_{gcp_sa}",
                    source_service=f"k8s_service_account_{sa['name']}",
                    target_service=f"gcp_service_account_{gcp_sa}",
                    trust_mechanism=TrustMechanism.WORKLOAD_IDENTITY,
                    provider_source="kubernetes",
                    provider_target="gcp",
                    trust_policy={
                        "kubernetes_namespace": sa["namespace"],
                        "gcp_service_account": gcp_sa
                    },
                    allowed_repositories=[],
                    allowed_branches=[],
                    conditions=["Workload Identity binding", "Same GKE cluster"],
                    risk_score=0.4,
                    exploitability="low",
                    discovered_at=datetime.now(),
                    last_verified=datetime.now(),
                    metadata=sa
                )
                
                edges.append(edge)
        
        return edges
    
    def _calculate_service_edge_risk(
        self,
        source_provider: str,
        target_provider: str,
        trust_mechanisms: List[str]
    ) -> float:
        """Calculate risk score for service identity edge."""
        base_risk = 0.5
        
        # Cross-provider trust is riskier
        if source_provider != target_provider:
            base_risk += 0.2
        
        # OIDC federation has specific risks
        if "oidc_federation" in trust_mechanisms:
            base_risk += 0.1
        
        # Secret-based trust is riskier than workload identity
        if "secret_injection" in trust_mechanisms:
            base_risk += 0.3
        
        return min(base_risk, 1.0)
    
    async def analyze_service_identity_risks(self, org_id: str) -> Dict[str, Any]:
        """
        Analyze risks in service identity configurations.
        
        Identifies weak trust boundaries and misconfigurations.
        """
        service_edges = await self.discover_service_identities(org_id)
        
        # Group by risk level
        risk_distribution = {
            "low": [],
            "medium": [],
            "high": []
        }
        
        for edge in service_edges:
            if edge.risk_score >= 0.7:
                risk_level = "high"
            elif edge.risk_score >= 0.4:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            risk_distribution[risk_level].append({
                "edge_id": edge.edge_id,
                "source_service": edge.source_service,
                "target_service": edge.target_service,
                "trust_mechanism": edge.trust_mechanism.value,
                "risk_score": edge.risk_score,
                "exploitability": edge.exploitability,
                "conditions": edge.conditions
            })
        
        # Identify common risk patterns
        risk_patterns = self._identify_service_risk_patterns(service_edges)
        
        return {
            "organization_id": org_id,
            "analysis_date": datetime.now().isoformat(),
            "summary": {
                "total_service_edges": len(service_edges),
                "high_risk_edges": len(risk_distribution["high"]),
                "medium_risk_edges": len(risk_distribution["medium"]),
                "low_risk_edges": len(risk_distribution["low"]),
                "trust_mechanisms": list(set(edge.trust_mechanism.value for edge in service_edges))
            },
            "risk_distribution": risk_distribution,
            "risk_patterns": risk_patterns,
            "recommendations": self._generate_service_identity_recommendations(service_edges)
        }
    
    def _identify_service_risk_patterns(self, edges: List[ServiceIdentityEdge]) -> List[Dict[str, Any]]:
        """Identify common risk patterns in service identity configurations."""
        patterns = []
        
        # Pattern 1: Overly permissive repository allowlists
        broad_repo_edges = [
            edge for edge in edges 
            if "*" in edge.allowed_repositories or len(edge.allowed_repositories) > 10
        ]
        
        if broad_repo_edges:
            patterns.append({
                "pattern": "overly_permissive_repositories",
                "description": "Service identities with overly broad repository access",
                "count": len(broad_repo_edges),
                "severity": "medium",
                "examples": [edge.edge_id for edge in broad_repo_edges[:3]]
            })
        
        # Pattern 2: Secret-based trust (less secure than workload identity)
        secret_based_edges = [
            edge for edge in edges
            if edge.trust_mechanism == TrustMechanism.SECRET_INJECTION
        ]
        
        if secret_based_edges:
            patterns.append({
                "pattern": "secret_based_authentication",
                "description": "Service identities using secret-based authentication",
                "count": len(secret_based_edges),
                "severity": "high",
                "examples": [edge.edge_id for edge in secret_based_edges[:3]]
            })
        
        # Pattern 3: Cross-provider trust without conditions
        unconditioned_cross_provider = [
            edge for edge in edges
            if edge.provider_source != edge.provider_target and not edge.conditions
        ]
        
        if unconditioned_cross_provider:
            patterns.append({
                "pattern": "unconditioned_cross_provider_trust",
                "description": "Cross-provider trust without access conditions",
                "count": len(unconditioned_cross_provider),
                "severity": "high",
                "examples": [edge.edge_id for edge in unconditioned_cross_provider[:3]]
            })
        
        return patterns
    
    def _generate_service_identity_recommendations(self, edges: List[ServiceIdentityEdge]) -> List[str]:
        """Generate recommendations for service identity security."""
        recommendations = []
        
        # Check for high-risk edges
        high_risk_edges = [edge for edge in edges if edge.risk_score >= 0.7]
        if high_risk_edges:
            recommendations.append(
                f"Review {len(high_risk_edges)} high-risk service identity relationships"
            )
        
        # Check for secret-based authentication
        secret_edges = [
            edge for edge in edges 
            if edge.trust_mechanism == TrustMechanism.SECRET_INJECTION
        ]
        if secret_edges:
            recommendations.append(
                "Migrate from secret-based to workload identity authentication where possible"
            )
        
        # Check for overly broad access
        broad_access_edges = [
            edge for edge in edges
            if "*" in edge.allowed_repositories
        ]
        if broad_access_edges:
            recommendations.append(
                "Restrict service identity access to specific repositories and branches"
            )
        
        # General recommendations
        recommendations.extend([
            "Implement regular service identity access reviews",
            "Monitor service account usage and activity",
            "Use short-lived tokens where possible",
            "Implement conditional access for service identities"
        ])
        
        return recommendations[:10]  # Top 10 recommendations


# Service identity attack patterns (CEL rules)
SERVICE_IDENTITY_CEL_RULES = {
    "github_actions_broad_access": '''
        service.type == "github_actions" &&
        service.allowed_repositories.contains("*") &&
        service.target_permissions.contains("admin") ->
        violation("GitHub Actions with overly broad repository access")
    ''',
    
    "service_account_with_user_permissions": '''
        principal.type == "service_account" &&
        principal.has_permission_type("user_impersonation") ->
        violation("Service account with user impersonation capabilities")
    ''',
    
    "cross_provider_trust_without_conditions": '''
        trust.source_provider != trust.target_provider &&
        trust.conditions.size() == 0 ->
        violation("Cross-provider trust without access conditions")
    '''
}


# Global service identity mapper
_service_identity_mapper = ServiceIdentityMapper()


def get_service_identity_mapper() -> ServiceIdentityMapper:
    """Get global service identity mapper."""
    return _service_identity_mapper
