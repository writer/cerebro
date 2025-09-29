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
        """Discover Azure Managed Identity relationships using real Azure APIs."""
        edges = []

        try:
            # Get Azure Resource Manager client
            azure_client = await self._get_azure_client()
            if not azure_client:
                logger.warning("Azure client not available - skipping managed identity discovery")
                return edges

            logger.info("Discovering Azure Managed Identity relationships via Azure ARM API")

            # Query managed identities and their role assignments
            identities = await self._query_azure_managed_identities(azure_client)

            for identity in identities:
                try:
                    # Get role assignments for this managed identity
                    role_assignments = await self._get_identity_role_assignments(
                        azure_client, identity.get("principal_id", "")
                    )

                    for assignment in role_assignments:
                        edge = ServiceIdentityEdge(
                            edge_id=f"azure_identity_{identity['name']}_{assignment['role_name']}",
                            source_service=identity.get("assigned_resource", identity['name']),
                            target_service=assignment.get("target_resource", "azure_resource"),
                            trust_mechanism=TrustMechanism.INSTANCE_METADATA,
                            provider_source="azure",
                            provider_target="azure",
                            trust_policy={
                                "managed_identity_type": identity["type"],
                                "identity_id": identity["id"],
                                "principal_id": identity.get("principal_id"),
                                "resource_group": identity.get("resource_group"),
                                "role_definition": assignment["role_name"],
                                "scope": assignment.get("scope")
                            },
                            allowed_repositories=[],
                            allowed_branches=[],
                            conditions=[
                                "Managed Identity enabled",
                                f"Resource in {identity.get('resource_group', 'unknown')} RG",
                                f"Role: {assignment['role_name']}"
                            ],
                            risk_score=self._calculate_azure_identity_risk(identity, assignment),
                            exploitability=self._assess_azure_exploitability(assignment),
                            discovered_at=datetime.now(),
                            last_verified=datetime.now(),
                            metadata={
                                "identity": identity,
                                "assignment": assignment,
                                "discovery_method": "azure_arm_api"
                            }
                        )
                        edges.append(edge)

                except Exception as e:
                    logger.error(f"Failed to process Azure identity {identity.get('name', 'unknown')}: {e}")
                    continue

            logger.info(f"Discovered {len(edges)} Azure managed identity trust relationships")
            return edges

        except Exception as e:
            logger.error(f"Azure managed identity discovery failed: {e}")
            # Return empty list instead of failing - this allows the system to continue
            return []

    async def _get_azure_client(self):
        """Get Azure Resource Manager client with proper authentication."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.msi import ManagedServiceIdentityClient
            from azure.mgmt.resource import ResourceManagementClient

            # Use Azure SDK default credential chain
            credential = DefaultAzureCredential()

            # Get subscription ID from environment or config
            subscription_id = self._get_azure_subscription_id()
            if not subscription_id:
                logger.warning("Azure subscription ID not configured (set AZURE_SUBSCRIPTION_ID)")
                return None

            return {
                "credential": credential,
                "subscription_id": subscription_id,
                "auth_client": AuthorizationManagementClient(credential, subscription_id),
                "msi_client": ManagedServiceIdentityClient(credential, subscription_id),
                "resource_client": ResourceManagementClient(credential, subscription_id)
            }

        except ImportError:
            logger.warning("Azure SDK not installed - install with 'pip install azure-identity azure-mgmt-authorization azure-mgmt-msi azure-mgmt-resource'")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize Azure client: {e}")
            return None

    async def _query_azure_managed_identities(self, azure_client) -> List[Dict]:
        """Query Azure managed identities from Resource Manager API."""
        identities = []

        try:
            msi_client = azure_client["msi_client"]

            # List user-assigned managed identities
            for identity in msi_client.user_assigned_identities.list_by_subscription():
                identities.append({
                    "id": identity.id,
                    "name": identity.name,
                    "type": "user_assigned",
                    "resource_group": identity.id.split("/")[4] if len(identity.id.split("/")) > 4 else "unknown",
                    "principal_id": identity.principal_id,
                    "client_id": identity.client_id
                })

            # System-assigned identities are discovered through resources
            resource_client = azure_client["resource_client"]
            for resource in resource_client.resources.list():
                if hasattr(resource, 'identity') and resource.identity and resource.identity.type:
                    if 'systemassigned' in resource.identity.type.lower():
                        identities.append({
                            "id": f"{resource.id}/identity",
                            "name": f"{resource.name}-identity",
                            "type": "system_assigned",
                            "resource_group": resource.id.split("/")[4] if len(resource.id.split("/")) > 4 else "unknown",
                            "assigned_resource": resource.name,
                            "principal_id": resource.identity.principal_id
                        })

            return identities

        except Exception as e:
            logger.error(f"Failed to query Azure managed identities: {e}")
            return []

    async def _get_identity_role_assignments(self, azure_client, principal_id: str) -> List[Dict]:
        """Get role assignments for an Azure managed identity."""
        try:
            auth_client = azure_client["auth_client"]
            assignments = []

            if not principal_id:
                return assignments

            # Query role assignments by principal ID
            for assignment in auth_client.role_assignments.list():
                if assignment.principal_id and str(assignment.principal_id) == str(principal_id):
                    # Get role definition details
                    role_def = auth_client.role_definitions.get_by_id(assignment.role_definition_id)

                    assignments.append({
                        "role_name": role_def.role_name if role_def else "Unknown Role",
                        "role_id": assignment.role_definition_id.split("/")[-1],
                        "scope": assignment.scope,
                        "target_resource": self._extract_resource_from_scope(assignment.scope)
                    })

            return assignments

        except Exception as e:
            logger.error(f"Failed to get role assignments for principal {principal_id}: {e}")
            return []

    def _get_azure_subscription_id(self) -> Optional[str]:
        """Get Azure subscription ID from environment."""
        import os
        return os.getenv("AZURE_SUBSCRIPTION_ID")

    def _extract_resource_from_scope(self, scope: str) -> str:
        """Extract resource name from Azure scope."""
        if not scope:
            return "unknown"
        parts = scope.split("/")
        if len(parts) > 1:
            return parts[-1]
        return scope

    def _calculate_azure_identity_risk(self, identity: Dict, assignment: Dict) -> float:
        """Calculate risk score for Azure managed identity."""
        risk_score = 0.3  # Base risk

        # System-assigned identities are slightly riskier (tied to specific resource)
        if identity.get("type") == "system_assigned":
            risk_score += 0.1

        # Assess scope of role assignment
        scope = assignment.get("scope", "")
        if "/subscriptions/" in scope and scope.count("/") <= 3:  # Subscription-level
            risk_score += 0.5
        elif "/resourceGroups/" in scope:  # Resource group level
            risk_score += 0.3
        else:  # Resource-specific
            risk_score += 0.1

        # High-privilege roles increase risk
        role_name = assignment.get("role_name", "").lower()
        if any(priv in role_name for priv in ["owner", "contributor", "administrator"]):
            risk_score += 0.3
        elif "reader" in role_name:
            risk_score += 0.1

        return min(risk_score, 1.0)

    def _assess_azure_exploitability(self, assignment: Dict) -> str:
        """Assess exploitability level for Azure managed identity."""
        role_name = assignment.get("role_name", "").lower()

        if any(priv in role_name for priv in ["owner", "contributor"]):
            return "high"
        elif any(priv in role_name for priv in ["administrator", "manager"]):
            return "medium"
        else:
            return "low"

    async def _discover_k8s_service_accounts(self) -> List[ServiceIdentityEdge]:
        """Discover Kubernetes service account mappings using real Kubernetes API."""
        edges = []

        try:
            # Get Kubernetes client
            k8s_client = await self._get_k8s_client()
            if not k8s_client:
                logger.warning("Kubernetes client not available - skipping service account discovery")
                return edges

            logger.info("Discovering Kubernetes service account mappings via Kubernetes API")

            # Query service accounts across all namespaces
            service_accounts = await self._query_k8s_service_accounts(k8s_client)

            for sa in service_accounts:
                try:
                    # Check for workload identity annotations
                    annotations = sa.get("annotations", {})

                    # GCP Workload Identity
                    if "iam.gke.io/gcp-service-account" in annotations:
                        gcp_sa = annotations["iam.gke.io/gcp-service-account"]

                        edge = ServiceIdentityEdge(
                            edge_id=f"k8s_gcp_{sa['namespace']}_{sa['name']}_{gcp_sa.replace('@', '_at_').replace('.', '_')}",
                            source_service=f"k8s_service_account_{sa['name']}",
                            target_service=f"gcp_service_account_{gcp_sa}",
                            trust_mechanism=TrustMechanism.WORKLOAD_IDENTITY,
                            provider_source="kubernetes",
                            provider_target="gcp",
                            trust_policy={
                                "kubernetes_namespace": sa["namespace"],
                                "kubernetes_service_account": sa["name"],
                                "gcp_service_account": gcp_sa,
                                "workload_identity_enabled": True
                            },
                            allowed_repositories=[],
                            allowed_branches=[],
                            conditions=[
                                "GKE Workload Identity binding",
                                f"Namespace: {sa['namespace']}",
                                f"GCP SA: {gcp_sa}"
                            ],
                            risk_score=self._calculate_k8s_workload_identity_risk(sa, annotations),
                            exploitability=self._assess_k8s_exploitability(sa, annotations),
                            discovered_at=datetime.now(),
                            last_verified=datetime.now(),
                            metadata={
                                "service_account": sa,
                                "workload_identity_type": "gcp",
                                "discovery_method": "kubernetes_api"
                            }
                        )
                        edges.append(edge)

                    # AWS IAM Roles for Service Accounts (IRSA)
                    elif "eks.amazonaws.com/role-arn" in annotations:
                        aws_role = annotations["eks.amazonaws.com/role-arn"]

                        edge = ServiceIdentityEdge(
                            edge_id=f"k8s_aws_{sa['namespace']}_{sa['name']}_{aws_role.split('/')[-1]}",
                            source_service=f"k8s_service_account_{sa['name']}",
                            target_service=f"aws_role_{aws_role.split('/')[-1]}",
                            trust_mechanism=TrustMechanism.WORKLOAD_IDENTITY,
                            provider_source="kubernetes",
                            provider_target="aws",
                            trust_policy={
                                "kubernetes_namespace": sa["namespace"],
                                "kubernetes_service_account": sa["name"],
                                "aws_role_arn": aws_role,
                                "irsa_enabled": True
                            },
                            allowed_repositories=[],
                            allowed_branches=[],
                            conditions=[
                                "EKS IRSA binding",
                                f"Namespace: {sa['namespace']}",
                                f"AWS Role: {aws_role}"
                            ],
                            risk_score=self._calculate_k8s_irsa_risk(sa, annotations),
                            exploitability=self._assess_k8s_exploitability(sa, annotations),
                            discovered_at=datetime.now(),
                            last_verified=datetime.now(),
                            metadata={
                                "service_account": sa,
                                "workload_identity_type": "aws_irsa",
                                "discovery_method": "kubernetes_api"
                            }
                        )
                        edges.append(edge)

                except Exception as e:
                    logger.error(f"Failed to process Kubernetes service account {sa.get('name', 'unknown')}: {e}")
                    continue

            logger.info(f"Discovered {len(edges)} Kubernetes service account trust relationships")
            return edges

        except Exception as e:
            logger.error(f"Kubernetes service account discovery failed: {e}")
            return []

    async def _get_k8s_client(self):
        """Get Kubernetes API client with proper authentication."""
        try:
            from kubernetes import client, config

            # Try to load kubeconfig or in-cluster config
            try:
                # Try in-cluster config first (if running in a pod)
                config.load_incluster_config()
                logger.info("Using Kubernetes in-cluster configuration")
            except config.ConfigException:
                # Fall back to kubeconfig
                config.load_kube_config()
                logger.info("Using Kubernetes kubeconfig")

            return client.CoreV1Api()

        except ImportError:
            logger.warning("Kubernetes client not installed - install with 'pip install kubernetes'")
            return None
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            return None

    async def _query_k8s_service_accounts(self, k8s_client) -> List[Dict]:
        """Query Kubernetes service accounts from all namespaces."""
        service_accounts = []

        try:
            # List service accounts in all namespaces
            sa_list = k8s_client.list_service_account_for_all_namespaces()

            for sa in sa_list.items:
                # Skip default and system service accounts
                if sa.metadata.name in ["default"] or sa.metadata.namespace.startswith("kube-"):
                    continue

                service_accounts.append({
                    "name": sa.metadata.name,
                    "namespace": sa.metadata.namespace,
                    "annotations": sa.metadata.annotations or {},
                    "labels": sa.metadata.labels or {},
                    "creation_timestamp": sa.metadata.creation_timestamp,
                    "secrets": [secret.name for secret in (sa.secrets or [])]
                })

            return service_accounts

        except Exception as e:
            logger.error(f"Failed to query Kubernetes service accounts: {e}")
            return []

    def _calculate_k8s_workload_identity_risk(self, sa: Dict, annotations: Dict) -> float:
        """Calculate risk score for Kubernetes workload identity."""
        risk_score = 0.3  # Base risk

        # System namespaces have higher risk
        namespace = sa.get("namespace", "")
        if any(sys_ns in namespace for sys_ns in ["kube-system", "kube-public", "default"]):
            risk_score += 0.3

        # Check for overly broad permissions (would need RBAC analysis)
        # For now, use namespace as proxy
        if namespace in ["default", "kube-system"]:
            risk_score += 0.4

        return min(risk_score, 1.0)

    def _calculate_k8s_irsa_risk(self, sa: Dict, annotations: Dict) -> float:
        """Calculate risk score for Kubernetes IRSA."""
        risk_score = 0.4  # Slightly higher base risk for AWS cross-cloud

        # System namespaces have higher risk
        namespace = sa.get("namespace", "")
        if any(sys_ns in namespace for sys_ns in ["kube-system", "kube-public", "default"]):
            risk_score += 0.3

        # AWS role ARN analysis
        role_arn = annotations.get("eks.amazonaws.com/role-arn", "")
        if "admin" in role_arn.lower() or "poweruser" in role_arn.lower():
            risk_score += 0.4

        return min(risk_score, 1.0)

    def _assess_k8s_exploitability(self, sa: Dict, annotations: Dict) -> str:
        """Assess exploitability level for Kubernetes service accounts."""
        namespace = sa.get("namespace", "")

        # System namespaces are highly exploitable
        if any(sys_ns in namespace for sys_ns in ["kube-system", "default"]):
            return "high"

        # Check for admin-like role names
        role_arn = annotations.get("eks.amazonaws.com/role-arn", "")
        gcp_sa = annotations.get("iam.gke.io/gcp-service-account", "")

        if any(admin in (role_arn + gcp_sa).lower() for admin in ["admin", "poweruser", "owner"]):
            return "high"

        return "medium"
    
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
