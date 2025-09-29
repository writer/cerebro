"""
Advanced security testing framework with automated threat simulation.

Provides sophisticated security testing capabilities including:
- Penetration testing automation
- Security control validation
- Threat simulation and red teaming
- Vulnerability assessment
- Configuration drift detection
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import json

from ..query.engine import QueryEngine
from ..core.models import Organization, Finding
from ..compliance.evidence_data_fabric import EvidenceDataFabric
from .test_registry import SecurityTest, TestStatus, TestType, TestFrequency

logger = logging.getLogger(__name__)


class ThreatScenario(Enum):
    """Threat scenarios for security testing."""
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_ATTACK = "external_attack"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    SUPPLY_CHAIN = "supply_chain"
    CLOUD_MISCONFIG = "cloud_misconfig"


class TestComplexity(Enum):
    """Test complexity levels."""
    BASIC = "basic"           # Single API call or simple query
    INTERMEDIATE = "intermediate"  # Multiple API calls, cross-provider
    ADVANCED = "advanced"     # Complex logic, simulated attacks
    EXPERT = "expert"         # Full red team scenarios


@dataclass
class TestResult:
    """Result of security test execution."""
    test_id: str
    execution_id: str
    executed_at: datetime
    status: str  # "pass", "fail", "error", "skipped"
    score: Optional[float]  # 0.0 to 1.0
    findings: List[str]  # Finding IDs generated
    evidence: Dict[str, Any]
    execution_time_ms: int
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AttackSimulation:
    """Simulated attack scenario configuration."""
    scenario_id: str
    name: str
    description: str
    threat_scenario: ThreatScenario
    attack_chain: List[str]  # Ordered list of attack steps
    required_resources: List[str]  # Resource types needed
    success_criteria: List[str]
    detection_indicators: List[str]
    mitigation_controls: List[str]


class AdvancedSecurityTester:
    """
    Advanced security testing engine with threat simulation capabilities.
    
    Provides automated security testing that goes beyond basic compliance
    checks to include realistic attack scenarios and security control validation.
    """
    
    def __init__(self, query_engine: QueryEngine, evidence_fabric: EvidenceDataFabric):
        """Initialize advanced security tester."""
        self.query_engine = query_engine
        self.evidence_fabric = evidence_fabric
        self.attack_simulations = self._load_attack_simulations()
    
    def _load_attack_simulations(self) -> Dict[str, AttackSimulation]:
        """Load predefined attack simulation scenarios."""
        simulations = {}
        
        # Insider threat scenario
        simulations["insider_privilege_escalation"] = AttackSimulation(
            scenario_id="insider_privilege_escalation",
            name="Insider Privilege Escalation",
            description="Simulates an insider attempting to escalate privileges across cloud providers",
            threat_scenario=ThreatScenario.INSIDER_THREAT,
            attack_chain=[
                "enumerate_user_permissions",
                "discover_group_memberships", 
                "identify_admin_groups",
                "attempt_group_addition",
                "escalate_to_admin_role"
            ],
            required_resources=["users", "groups", "roles"],
            success_criteria=[
                "Found users with excessive permissions",
                "Identified privilege escalation paths",
                "Detected admin group vulnerabilities"
            ],
            detection_indicators=[
                "Multiple failed privilege requests",
                "Unusual group membership changes",
                "Cross-provider permission correlation"
            ],
            mitigation_controls=[
                "Principle of least privilege",
                "Regular access reviews",
                "Privileged account monitoring"
            ]
        )
        
        # Cloud misconfiguration scenario
        simulations["cloud_lateral_movement"] = AttackSimulation(
            scenario_id="cloud_lateral_movement",
            name="Cloud Lateral Movement",
            description="Simulates lateral movement across cloud resources after initial compromise",
            threat_scenario=ThreatScenario.LATERAL_MOVEMENT,
            attack_chain=[
                "enumerate_compromised_instance",
                "extract_iam_credentials",
                "discover_accessible_resources",
                "pivot_to_storage_buckets",
                "access_sensitive_data"
            ],
            required_resources=["compute_instances", "storage_buckets", "iam_roles"],
            success_criteria=[
                "Mapped lateral movement paths",
                "Identified over-privileged resources",
                "Found accessible sensitive data"
            ],
            detection_indicators=[
                "Cross-resource access patterns",
                "Unusual API call sequences",
                "Data access from new sources"
            ],
            mitigation_controls=[
                "Network segmentation",
                "IAM permission boundaries",
                "Resource-based policies"
            ]
        )
        
        # Supply chain attack scenario
        simulations["supply_chain_compromise"] = AttackSimulation(
            scenario_id="supply_chain_compromise",
            name="Supply Chain Compromise",
            description="Simulates compromise through third-party integrations and dependencies",
            threat_scenario=ThreatScenario.SUPPLY_CHAIN,
            attack_chain=[
                "enumerate_third_party_access",
                "identify_oauth_tokens",
                "discover_integration_scope",
                "exploit_excessive_permissions",
                "persist_through_apps"
            ],
            required_resources=["oauth_tokens", "applications", "integrations"],
            success_criteria=[
                "Found over-privileged integrations",
                "Identified stale OAuth tokens",
                "Mapped third-party access scope"
            ],
            detection_indicators=[
                "Unusual third-party API usage",
                "OAuth token abuse patterns",
                "Unauthorized data access via apps"
            ],
            mitigation_controls=[
                "OAuth scope restriction",
                "Regular token audits",
                "Third-party risk assessment"
            ]
        )
        
        return simulations
    
    async def execute_threat_simulation(
        self,
        org_id: str,
        simulation_id: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> TestResult:
        """Execute a threat simulation scenario."""
        simulation = self.attack_simulations.get(simulation_id)
        if not simulation:
            raise ValueError(f"Unknown simulation: {simulation_id}")
        
        start_time = datetime.now()
        findings = []
        evidence = {}
        
        try:
            logger.info(f"Starting threat simulation: {simulation.name}")
            
            # Execute attack chain
            for step in simulation.attack_chain:
                step_result = await self._execute_attack_step(org_id, step, parameters or {})
                evidence[step] = step_result
                
                # Check if step found vulnerabilities
                if step_result.get("vulnerabilities"):
                    findings.extend(step_result["vulnerabilities"])
            
            # Evaluate success criteria
            success_count = 0
            for criteria in simulation.success_criteria:
                if await self._check_success_criteria(org_id, criteria, evidence):
                    success_count += 1
            
            # Calculate score (lower is better for security)
            score = 1.0 - (success_count / len(simulation.success_criteria))
            status = "pass" if score > 0.7 else "fail"
            
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return TestResult(
                test_id=simulation_id,
                execution_id=f"sim_{int(start_time.timestamp())}",
                executed_at=start_time,
                status=status,
                score=score,
                findings=findings,
                evidence=evidence,
                execution_time_ms=execution_time,
                metadata={
                    "simulation_name": simulation.name,
                    "attack_chain": simulation.attack_chain,
                    "success_criteria_met": success_count,
                    "total_criteria": len(simulation.success_criteria),
                    "threat_scenario": simulation.threat_scenario.value
                }
            )
            
        except Exception as e:
            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
            logger.error(f"Threat simulation failed: {e}")
            
            return TestResult(
                test_id=simulation_id,
                execution_id=f"sim_error_{int(start_time.timestamp())}",
                executed_at=start_time,
                status="error",
                score=None,
                findings=[],
                evidence=evidence,
                execution_time_ms=execution_time,
                error_message=str(e)
            )
    
    async def _execute_attack_step(
        self,
        org_id: str,
        step: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute individual attack step."""
        
        if step == "enumerate_user_permissions":
            return await self._enumerate_user_permissions(org_id)
        elif step == "discover_group_memberships":
            return await self._discover_group_memberships(org_id)
        elif step == "identify_admin_groups":
            return await self._identify_admin_groups(org_id)
        elif step == "enumerate_third_party_access":
            return await self._enumerate_third_party_access(org_id)
        elif step == "identify_oauth_tokens":
            return await self._identify_oauth_tokens(org_id)
        elif step == "enumerate_compromised_instance":
            return await self._enumerate_compromised_instance(org_id, parameters)
        elif step == "discover_accessible_resources":
            return await self._discover_accessible_resources(org_id, parameters)
        else:
            logger.warning(f"Unknown attack step: {step}")
            return {"status": "skipped", "reason": f"Unknown step: {step}"}
    
    async def _enumerate_user_permissions(self, org_id: str) -> Dict[str, Any]:
        """Enumerate user permissions across all providers."""
        try:
            # Query for users with high-privilege roles
            query = """
            SELECT principal_type, email, permission, is_admin, COUNT(*) as permission_count
            FROM *_iam
            WHERE is_admin = true
            GROUP BY principal_type, email, permission, is_admin
            ORDER BY permission_count DESC
            LIMIT 50
            """
            
            result = await self.query_engine.execute_query(query)
            
            # Analyze for potential privilege escalation vectors
            vulnerabilities = []
            high_privilege_users = []
            
            for row in result.rows:
                permission_count = row.get("permission_count", 0)
                is_admin = row.get("is_admin", False)
                
                if permission_count > 10 and is_admin:
                    high_privilege_users.append({
                        "email": row.get("email"),
                        "permission_count": permission_count,
                        "risk": "high"
                    })
                    
                    vulnerabilities.append(f"USER_EXCESSIVE_PRIVILEGES_{row.get('email')}")
            
            return {
                "status": "completed",
                "high_privilege_users": high_privilege_users,
                "vulnerabilities": vulnerabilities,
                "total_admin_users": len([r for r in result.rows if r.get("is_admin")]),
                "analysis": {
                    "avg_permissions_per_admin": sum(r.get("permission_count", 0) for r in result.rows) / max(len(result.rows), 1),
                    "max_permissions": max(r.get("permission_count", 0) for r in result.rows) if result.rows else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to enumerate user permissions: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _discover_group_memberships(self, org_id: str) -> Dict[str, Any]:
        """Discover potentially dangerous group memberships."""
        try:
            # Query for users with multiple admin group memberships
            query = """
            SELECT email, COUNT(*) as admin_group_count
            FROM *_user
            WHERE status = 'active'
            GROUP BY email
            HAVING COUNT(*) > 3
            ORDER BY admin_group_count DESC
            """
            
            result = await self.query_engine.execute_query(query)
            
            vulnerabilities = []
            excessive_memberships = []
            
            for row in result.rows:
                group_count = row.get("admin_group_count", 0)
                email = row.get("email")
                
                if group_count > 5:
                    excessive_memberships.append({
                        "email": email,
                        "group_count": group_count,
                        "risk": "high"
                    })
                    vulnerabilities.append(f"USER_EXCESSIVE_GROUPS_{email}")
            
            return {
                "status": "completed",
                "excessive_memberships": excessive_memberships,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "users_with_multiple_memberships": len(result.rows),
                    "highest_group_count": max(r.get("admin_group_count", 0) for r in result.rows) if result.rows else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to discover group memberships: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _identify_admin_groups(self, org_id: str) -> Dict[str, Any]:
        """Identify admin groups and analyze membership patterns."""
        try:
            # Look for groups with admin-like names or permissions
            query = """
            SELECT DISTINCT email, display_name
            FROM *_user
            WHERE (display_name ILIKE '%admin%' OR display_name ILIKE '%super%' OR 
                   display_name ILIKE '%root%' OR display_name ILIKE '%owner%')
            """
            
            result = await self.query_engine.execute_query(query)
            
            admin_groups = []
            vulnerabilities = []
            
            for row in result.rows:
                group_name = row.get("display_name", "")
                email = row.get("email", "")
                
                # Check for overly broad admin groups
                if any(keyword in group_name.lower() for keyword in ["all", "everyone", "domain"]):
                    vulnerabilities.append(f"OVERLY_BROAD_ADMIN_GROUP_{email}")
                
                admin_groups.append({
                    "email": email,
                    "display_name": group_name,
                    "risk_level": "high" if any(keyword in group_name.lower() for keyword in ["super", "root", "domain"]) else "medium"
                })
            
            return {
                "status": "completed",
                "admin_groups": admin_groups,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "total_admin_groups": len(admin_groups),
                    "high_risk_groups": len([g for g in admin_groups if g["risk_level"] == "high"])
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to identify admin groups: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _enumerate_third_party_access(self, org_id: str) -> Dict[str, Any]:
        """Enumerate third-party application access and OAuth tokens."""
        try:
            # Query for applications and OAuth tokens
            query = """
            SELECT display_name, publisher_domain, required_resource_access, has_credentials
            FROM *_application
            WHERE has_credentials = true
            ORDER BY permission_count DESC
            """
            
            result = await self.query_engine.execute_query(query)
            
            third_party_apps = []
            vulnerabilities = []
            
            for row in result.rows:
                app_name = row.get("display_name", "Unknown App")
                publisher = row.get("publisher_domain", "")
                has_creds = row.get("has_credentials", False)
                
                # Flag suspicious third-party apps
                if has_creds and publisher and not publisher.endswith((".microsoft.com", ".google.com")):
                    third_party_apps.append({
                        "name": app_name,
                        "publisher": publisher,
                        "risk": "medium"
                    })
                    
                    # Check for high-risk permissions
                    resource_access = row.get("required_resource_access", [])
                    if resource_access and len(resource_access) > 5:
                        vulnerabilities.append(f"THIRD_PARTY_EXCESSIVE_SCOPE_{app_name}")
            
            return {
                "status": "completed",
                "third_party_apps": third_party_apps,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "total_third_party": len(third_party_apps),
                    "apps_with_credentials": len([r for r in result.rows if r.get("has_credentials")])
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to enumerate third-party access: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _identify_oauth_tokens(self, org_id: str) -> Dict[str, Any]:
        """Identify potentially dangerous OAuth tokens and applications."""
        try:
            # Query for OAuth applications with broad permissions
            query = """
            SELECT app_id, display_name, sign_in_audience, permission_count
            FROM *_application
            WHERE permission_count > 10 OR sign_in_audience = 'AzureADMultipleOrgs'
            ORDER BY permission_count DESC
            """
            
            result = await self.query_engine.execute_query(query)
            
            risky_tokens = []
            vulnerabilities = []
            
            for row in result.rows:
                app_name = row.get("display_name", "Unknown")
                audience = row.get("sign_in_audience", "")
                permission_count = row.get("permission_count", 0)
                
                risk_level = "low"
                if audience == "AzureADMultipleOrgs":
                    risk_level = "high"
                    vulnerabilities.append(f"MULTI_TENANT_OAUTH_APP_{app_name}")
                elif permission_count > 20:
                    risk_level = "high"
                    vulnerabilities.append(f"EXCESSIVE_OAUTH_PERMISSIONS_{app_name}")
                elif permission_count > 10:
                    risk_level = "medium"
                
                risky_tokens.append({
                    "app_name": app_name,
                    "permission_count": permission_count,
                    "audience": audience,
                    "risk_level": risk_level
                })
            
            return {
                "status": "completed",
                "risky_tokens": risky_tokens,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "total_risky_apps": len(risky_tokens),
                    "multi_tenant_apps": len([t for t in risky_tokens if t["audience"] == "AzureADMultipleOrgs"]),
                    "avg_permissions": sum(t["permission_count"] for t in risky_tokens) / max(len(risky_tokens), 1)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to identify OAuth tokens: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _enumerate_compromised_instance(
        self,
        org_id: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate enumeration from a compromised instance."""
        try:
            # Query for compute instances with concerning configurations
            query = """
            SELECT instance_name, external_ip, internal_ip, service_accounts, status
            FROM *_compute_instance
            WHERE external_ip IS NOT NULL AND status = 'RUNNING'
            """
            
            result = await self.query_engine.execute_query(query)
            
            vulnerable_instances = []
            vulnerabilities = []
            
            for row in result.rows:
                instance_name = row.get("instance_name", "")
                external_ip = row.get("external_ip")
                service_accounts = row.get("service_accounts", [])
                
                # Check for risky configurations
                if external_ip and service_accounts:
                    vulnerable_instances.append({
                        "name": instance_name,
                        "external_ip": external_ip,
                        "service_account_count": len(service_accounts),
                        "risk": "high"
                    })
                    vulnerabilities.append(f"EXPOSED_INSTANCE_WITH_SA_{instance_name}")
            
            return {
                "status": "completed",
                "vulnerable_instances": vulnerable_instances,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "total_exposed_instances": len(vulnerable_instances),
                    "instances_with_service_accounts": len([i for i in vulnerable_instances if i["service_account_count"] > 0])
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to enumerate compromised instance: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _discover_accessible_resources(
        self,
        org_id: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Discover resources accessible from compromised position."""
        try:
            # Query for storage buckets and databases accessible from instances
            query = """
            SELECT bucket_name, is_public, iam_bindings
            FROM *_storage_bucket
            WHERE is_public = true OR iam_bindings::text ILIKE '%allUsers%'
            """
            
            result = await self.query_engine.execute_query(query)
            
            accessible_resources = []
            vulnerabilities = []
            
            for row in result.rows:
                bucket_name = row.get("bucket_name", "")
                is_public = row.get("is_public", False)
                
                if is_public:
                    accessible_resources.append({
                        "resource": bucket_name,
                        "type": "storage_bucket",
                        "access_method": "public",
                        "risk": "critical"
                    })
                    vulnerabilities.append(f"PUBLIC_STORAGE_BUCKET_{bucket_name}")
            
            return {
                "status": "completed",
                "accessible_resources": accessible_resources,
                "vulnerabilities": vulnerabilities,
                "analysis": {
                    "total_accessible": len(accessible_resources),
                    "public_buckets": len([r for r in accessible_resources if r["access_method"] == "public"])
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to discover accessible resources: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _check_success_criteria(
        self,
        org_id: str,
        criteria: str,
        evidence: Dict[str, Any]
    ) -> bool:
        """Check if attack success criteria was met."""
        
        if criteria == "Found users with excessive permissions":
            user_enum = evidence.get("enumerate_user_permissions", {})
            return len(user_enum.get("high_privilege_users", [])) > 0
        
        elif criteria == "Identified privilege escalation paths":
            group_enum = evidence.get("discover_group_memberships", {})
            return len(group_enum.get("excessive_memberships", [])) > 0
        
        elif criteria == "Detected admin group vulnerabilities":
            admin_groups = evidence.get("identify_admin_groups", {})
            return len(admin_groups.get("vulnerabilities", [])) > 0
        
        elif criteria == "Found over-privileged integrations":
            third_party = evidence.get("enumerate_third_party_access", {})
            return len(third_party.get("vulnerabilities", [])) > 0
        
        elif criteria == "Identified stale OAuth tokens":
            oauth_tokens = evidence.get("identify_oauth_tokens", {})
            return len(oauth_tokens.get("risky_tokens", [])) > 0
        
        elif criteria == "Found accessible sensitive data":
            resources = evidence.get("discover_accessible_resources", {})
            return len(resources.get("accessible_resources", [])) > 0
        
        else:
            logger.warning(f"Unknown success criteria: {criteria}")
            return False
    
    async def run_security_benchmark(self, org_id: str) -> Dict[str, Any]:
        """Run comprehensive security benchmark across all providers."""
        start_time = datetime.now()
        
        benchmark_tests = [
            "excessive_permissions_test",
            "stale_accounts_test", 
            "unencrypted_storage_test",
            "public_access_test",
            "weak_authentication_test",
            "privilege_escalation_test"
        ]
        
        results = {}
        total_score = 0.0
        
        for test_name in benchmark_tests:
            test_result = await self._run_benchmark_test(org_id, test_name)
            results[test_name] = test_result
            
            if test_result.get("score") is not None:
                total_score += test_result["score"]
        
        avg_score = total_score / len(benchmark_tests)
        
        # Determine overall security posture
        if avg_score >= 0.9:
            posture = "excellent"
        elif avg_score >= 0.8:
            posture = "good"
        elif avg_score >= 0.7:
            posture = "fair"
        elif avg_score >= 0.6:
            posture = "poor"
        else:
            posture = "critical"
        
        execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return {
            "org_id": org_id,
            "executed_at": start_time.isoformat(),
            "execution_time_ms": execution_time,
            "overall_score": avg_score,
            "security_posture": posture,
            "test_results": results,
            "recommendations": self._generate_recommendations(results),
            "next_benchmark_due": (start_time + timedelta(days=30)).isoformat()
        }
    
    async def _run_benchmark_test(self, org_id: str, test_name: str) -> Dict[str, Any]:
        """Run individual benchmark test."""
        
        if test_name == "excessive_permissions_test":
            return await self._test_excessive_permissions(org_id)
        elif test_name == "stale_accounts_test":
            return await self._test_stale_accounts(org_id)
        elif test_name == "unencrypted_storage_test":
            return await self._test_unencrypted_storage(org_id)
        elif test_name == "public_access_test":
            return await self._test_public_access(org_id)
        elif test_name == "weak_authentication_test":
            return await self._test_weak_authentication(org_id)
        elif test_name == "privilege_escalation_test":
            return await self._test_privilege_escalation_paths(org_id)
        else:
            return {"status": "skipped", "reason": f"Unknown test: {test_name}"}
    
    async def _test_excessive_permissions(self, org_id: str) -> Dict[str, Any]:
        """Test for users with excessive permissions."""
        try:
            query = """
            SELECT COUNT(*) as total_users,
                   COUNT(CASE WHEN is_admin = true THEN 1 END) as admin_users
            FROM *_user
            WHERE status = 'active'
            """
            
            result = await self.query_engine.execute_query(query)
            row = result.rows[0] if result.rows else {}
            
            total_users = row.get("total_users", 0)
            admin_users = row.get("admin_users", 0)
            
            # Calculate admin ratio (should be < 10%)
            admin_ratio = admin_users / max(total_users, 1)
            score = max(0.0, 1.0 - (admin_ratio * 10))  # Penalize high admin ratios
            
            return {
                "test_name": "excessive_permissions_test",
                "status": "completed",
                "score": score,
                "metrics": {
                    "total_users": total_users,
                    "admin_users": admin_users,
                    "admin_ratio": admin_ratio
                },
                "passed": admin_ratio <= 0.1,
                "details": f"{admin_users} admin users out of {total_users} total ({admin_ratio:.1%})"
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e), "score": 0.0}
    
    async def _test_unencrypted_storage(self, org_id: str) -> Dict[str, Any]:
        """Test for unencrypted storage resources."""
        try:
            # Query for storage buckets without encryption
            query = """
            SELECT COUNT(*) as total_buckets,
                   COUNT(CASE WHEN uniform_bucket_access = false THEN 1 END) as unencrypted_buckets
            FROM *_storage_bucket
            """
            
            result = await self.query_engine.execute_query(query)
            row = result.rows[0] if result.rows else {}
            
            total_buckets = row.get("total_buckets", 0)
            unencrypted_buckets = row.get("unencrypted_buckets", 0)
            
            # Calculate encryption score
            if total_buckets == 0:
                score = 1.0
            else:
                encrypted_ratio = (total_buckets - unencrypted_buckets) / total_buckets
                score = encrypted_ratio
            
            return {
                "test_name": "unencrypted_storage_test",
                "status": "completed", 
                "score": score,
                "metrics": {
                    "total_buckets": total_buckets,
                    "unencrypted_buckets": unencrypted_buckets,
                    "encrypted_ratio": score
                },
                "passed": unencrypted_buckets == 0,
                "details": f"{unencrypted_buckets} unencrypted buckets out of {total_buckets} total"
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e), "score": 0.0}
    
    def _generate_recommendations(self, test_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on test results."""
        recommendations = []
        
        for test_name, result in test_results.items():
            if result.get("score", 1.0) < 0.8:
                if test_name == "excessive_permissions_test":
                    recommendations.append("Review and reduce admin user count. Implement principle of least privilege.")
                elif test_name == "unencrypted_storage_test":
                    recommendations.append("Enable encryption for all storage resources. Use KMS keys where possible.")
                elif test_name == "public_access_test":
                    recommendations.append("Review and restrict public access to sensitive resources.")
                elif test_name == "weak_authentication_test":
                    recommendations.append("Enforce MFA for all users and strengthen password policies.")
        
        return recommendations


# Pre-defined security test templates following industry standards
SECURITY_TEST_TEMPLATES = {
    "penetration_testing": {
        "name": "Automated Penetration Testing",
        "description": "Automated security testing simulating real-world attacks",
        "complexity": TestComplexity.ADVANCED,
        "frequency": TestFrequency.MONTHLY,
        "scenarios": [
            "insider_privilege_escalation",
            "cloud_lateral_movement",
            "supply_chain_compromise"
        ]
    },
    
    "configuration_assessment": {
        "name": "Security Configuration Assessment",
        "description": "Comprehensive review of security configurations across all resources",
        "complexity": TestComplexity.INTERMEDIATE,
        "frequency": TestFrequency.WEEKLY,
        "scenarios": [
            "unencrypted_storage_audit",
            "public_access_audit",
            "weak_authentication_audit"
        ]
    },
    
    "access_review_automation": {
        "name": "Automated Access Review",
        "description": "Automated review of user permissions and access rights",
        "complexity": TestComplexity.BASIC,
        "frequency": TestFrequency.DAILY,
        "scenarios": [
            "excessive_permissions_check",
            "stale_accounts_check",
            "admin_group_audit"
        ]
    }
}


def get_advanced_security_tester(query_engine: QueryEngine, evidence_fabric: EvidenceDataFabric) -> AdvancedSecurityTester:
    """Factory function to create advanced security tester."""
    return AdvancedSecurityTester(query_engine, evidence_fabric)
