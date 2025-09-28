"""Prebuilt security rules library."""

from typing import Dict, List
from dataclasses import dataclass

@dataclass
class RuleTemplate:
    """Template for a security rule."""
    name: str
    description: str
    provider: List[str]
    resource_types: List[str]
    expression: str
    severity: str
    framework_mappings: Dict[str, List[str]]
    rationale: str
    remediation: str


class RuleLibrary:
    """Library of prebuilt security rules."""
    
    @staticmethod
    def get_all_rules() -> List[RuleTemplate]:
        """Get all prebuilt rules."""
        return [
            # GitHub Rules
            RuleTemplate(
                name="GitHub: Public Repository Without Branch Protection",
                description="Public GitHub repository lacks required branch protection rules",
                provider=["github"],
                resource_types=["github.repo"],
                expression="resource.resource_type == 'github.repo' && config.visibility == 'public' && !(config.branchProtection.requirePR ?? false)",
                severity="high",
                framework_mappings={
                    "cis": ["5.1.4"],
                    "nist_800_53": ["CM-3"],
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.12.1.1"],
                    "pci_dss": ["2.1"]
                },
                rationale="Public repositories without branch protection allow direct pushes to main branches, bypassing code review",
                remediation="Enable branch protection with required pull request reviews for the default branch"
            ),
            
            RuleTemplate(
                name="GitHub: Repository Admin Without 2FA",
                description="GitHub repository admin user does not have 2FA enabled",
                provider=["github"],
                resource_types=["github.repo"],
                expression="iam_edge.is_admin == true && principal.is_human == true && !(user_config.mfa.enabled ?? false)",
                severity="critical",
                framework_mappings={
                    "cis": ["5.1.1"],
                    "nist_800_53": ["IA-2(1)"],
                    "cwe": ["CWE-287"],
                    "soc2": ["CC6.1", "CC6.2"],
                    "iso27001": ["A.9.2.1", "A.9.4.2"],
                    "pci_dss": ["7.1.1", "8.3.1"]
                },
                rationale="Admin users without 2FA present high risk of account compromise",
                remediation="Enable two-factor authentication for all admin users"
            ),
            
            # AWS S3 Rules
            RuleTemplate(
                name="AWS: S3 Bucket Publicly Readable",
                description="S3 bucket allows public read access",
                provider=["aws"],
                resource_types=["aws.s3.bucket"],
                expression="""resource.resource_type == 'aws.s3.bucket' && (
                    config.policyAllowsPublic == true ||
                    config.aclAllowsPublic == true ||
                    (config.blockPublicAccess.effective ?? true) == false
                )""",
                severity="high",
                framework_mappings={
                    "cis": ["2.1.1"],
                    "nist_800_53": ["AC-3"],
                    "cwe": ["CWE-200"],
                },
                rationale="Publicly accessible S3 buckets can lead to data exposure and privacy violations",
                remediation="Enable S3 Block Public Access settings and review bucket policies"
            ),
            
            RuleTemplate(
                name="AWS: S3 Bucket Without Encryption",
                description="S3 bucket does not have default encryption enabled",
                provider=["aws"],
                resource_types=["aws.s3.bucket"],
                expression="resource.resource_type == 'aws.s3.bucket' && !(config.encryption.enabled ?? false)",
                severity="medium",
                framework_mappings={
                    "cis": ["2.1.1"],
                    "nist_800_53": ["SC-28"],
                },
                rationale="Unencrypted S3 buckets expose sensitive data at rest",
                remediation="Enable default encryption with AES-256 or KMS"
            ),
            
            # AWS IAM Rules
            RuleTemplate(
                name="AWS: IAM User Without MFA",
                description="IAM user with console access does not have MFA enabled",
                provider=["aws"],
                resource_types=[],
                expression="principal.principal_type == 'user' && !(user_config.mfa.enabled ?? false) && (user_config.console_access ?? false)",
                severity="high",
                framework_mappings={
                    "cis": ["1.2"],
                    "nist_800_53": ["IA-2(1)"],
                    "cwe": ["CWE-287"],
                },
                rationale="IAM users without MFA are vulnerable to credential compromise",
                remediation="Enable MFA for all IAM users with console access"
            ),
            
            RuleTemplate(
                name="AWS: Overprivileged IAM User",
                description="IAM user has administrative privileges",
                provider=["aws"],
                resource_types=[],
                expression="iam_edge.is_admin == true && principal.principal_type == 'user'",
                severity="medium",
                framework_mappings={
                    "cis": ["1.16"],
                    "nist_800_53": ["AC-6"],
                },
                rationale="Direct admin access to IAM users violates principle of least privilege",
                remediation="Use IAM roles for administrative access instead of direct user permissions"
            ),
            
            # GCP Rules
            RuleTemplate(
                name="GCP: Default VPC Network Exists",
                description="Default VPC network exists in GCP project",
                provider=["gcp"],
                resource_types=["gcp.compute.network"],
                expression="resource.provider == 'gcp' && resource.resource_type == 'gcp.compute.network' && resource.name == 'default'",
                severity="low",
                framework_mappings={
                    "cis": ["3.1"],
                },
                rationale="Default VPC networks have overly permissive firewall rules",
                remediation="Delete default VPC and create custom networks with specific firewall rules"
            ),
            
            RuleTemplate(
                name="GCP: Storage Bucket Publicly Accessible",
                description="GCP Storage bucket allows public access",
                provider=["gcp"],
                resource_types=["gcp.storage.bucket"],
                expression="""resource.resource_type == 'gcp.storage.bucket' && (
                    (config.iam.allUsersReader ?? false) == true ||
                    (config.iam.allAuthenticatedUsersReader ?? false) == true
                )""",
                severity="high",
                framework_mappings={
                    "cis": ["5.1"],
                    "nist_800_53": ["AC-3"],
                    "cwe": ["CWE-200"],
                },
                rationale="Publicly accessible storage buckets can lead to data exposure",
                remediation="Remove public access from bucket IAM policies"
            ),
            
            # Google Workspace Rules
            RuleTemplate(
                name="Google Workspace: User Without 2-Step Verification",
                description="Google Workspace user does not have 2-step verification enabled",
                provider=["google_workspace"],
                resource_types=[],
                expression="principal.principal_type == 'user' && org_config.security.require2sv == true && !(user_config.mfa.enabled ?? false)",
                severity="high",
                framework_mappings={
                    "nist_800_53": ["IA-2(1)"],
                    "cwe": ["CWE-287"],
                },
                rationale="Users without 2-step verification are vulnerable to credential compromise",
                remediation="Enforce 2-step verification for all users"
            ),
            
            # Cross-Provider Identity Rules
            RuleTemplate(
                name="Cross-Provider: Inconsistent MFA Enforcement",
                description="User has MFA enabled in one provider but not others",
                provider=["github", "aws", "gcp", "google_workspace"],
                resource_types=[],
                expression="principal.principal_type == 'user' && principal.is_human == true",  # Complex logic would need custom function
                severity="medium",
                framework_mappings={
                    "nist_800_53": ["IA-2(1)"],
                },
                rationale="Inconsistent MFA enforcement across providers creates security gaps",
                remediation="Enable MFA consistently across all platforms for the same user"
            ),
        ]
    
    @staticmethod
    def get_rules_by_framework(framework: str) -> List[RuleTemplate]:
        """Get rules that map to a specific compliance framework."""
        all_rules = RuleLibrary.get_all_rules()
        return [rule for rule in all_rules if framework.lower() in rule.framework_mappings]
    
    @staticmethod
    def get_rules_by_provider(provider: str) -> List[RuleTemplate]:
        """Get rules for a specific provider."""
        all_rules = RuleLibrary.get_all_rules()
        return [rule for rule in all_rules if provider in rule.provider]
    
    @staticmethod
    def get_rules_by_severity(severity: str) -> List[RuleTemplate]:
        """Get rules by severity level."""
        all_rules = RuleLibrary.get_all_rules()
        return [rule for rule in all_rules if rule.severity == severity]
    
    @staticmethod
    def create_control_pack(name: str, framework: str) -> Dict:
        """Create a control pack for a specific framework."""
        rules = RuleLibrary.get_rules_by_framework(framework)
        
        return {
            "name": f"{framework.upper()} Control Pack",
            "description": f"Security rules mapped to {framework.upper()} controls",
            "framework": framework,
            "rules": rules,
            "rule_count": len(rules),
            "coverage": {
                "providers": list(set(provider for rule in rules for provider in rule.provider)),
                "severities": list(set(rule.severity for rule in rules)),
            }
        }
