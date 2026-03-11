package graph

import "sync"

var registerRulesOnce sync.Once

// RegisterAllRules registers all toxic combination rules with the global registry.
// This is called automatically when NewToxicCombinationEngine is created.
func RegisterAllRules() {
	registerRulesOnce.Do(func() {
		reg := GlobalRegistry()
		engine := &ToxicCombinationEngine{}

		// Core cloud rules
		reg.MustRegister(engine.rulePublicExposedWithVuln(), RuleMetadata{
			ID:       "TC001",
			Name:     "Public Exposure + Vulnerability",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1190"},
			Enabled:  true,
		})

		reg.MustRegister(engine.rulePublicExposedWithSensitiveData(), RuleMetadata{
			ID:       "TC002",
			Name:     "Public Exposure + Sensitive Data Access",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1530"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleOverprivilegedWithCrownJewels(), RuleMetadata{
			ID:       "TC003",
			Name:     "Overprivileged Identity with Crown Jewels Access",
			Category: RuleCategoryIdentity,
			MITREIDs: []string{"T1078"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleCrossAccountWithAdmin(), RuleMetadata{
			ID:       "TC004",
			Name:     "Cross-Account Access with Admin Privileges",
			Category: RuleCategoryIdentity,
			MITREIDs: []string{"T1078.004"},
			Enabled:  true,
		})

		reg.MustRegister(engine.rulePrivilegeEscalationPath(), RuleMetadata{
			ID:       "TC005",
			Name:     "Privilege Escalation Path",
			Category: RuleCategoryIdentity,
			MITREIDs: []string{"T1548"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleLateralMovementToData(), RuleMetadata{
			ID:       "TC006",
			Name:     "Lateral Movement to Sensitive Data",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1021"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleSecretsExposure(), RuleMetadata{
			ID:       "TC007",
			Name:     "Secrets Exposure",
			Category: RuleCategoryData,
			MITREIDs: []string{"T1552"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleAdminWithNoMFA(), RuleMetadata{
			ID:       "TC008",
			Name:     "Admin Without MFA",
			Category: RuleCategoryIdentity,
			MITREIDs: []string{"T1078"},
			Enabled:  true,
		})

		reg.MustRegister(engine.rulePublicDatabaseAccess(), RuleMetadata{
			ID:       "TC009",
			Name:     "Public Database Access",
			Category: RuleCategoryData,
			MITREIDs: []string{"T1190"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleServiceAccountKeyExposure(), RuleMetadata{
			ID:       "TC010",
			Name:     "Service Account Key Exposure",
			Category: RuleCategoryIdentity,
			MITREIDs: []string{"T1552.001"},
			Enabled:  true,
		})

		// AWS-specific rules
		reg.MustRegister(engine.ruleIMDSv1WithSensitiveRole(), RuleMetadata{
			ID:          "TC-AWS-001",
			Name:        "IMDSv1 with Sensitive IAM Role",
			Category:    RuleCategoryAWS,
			Provider:    "aws",
			MITREIDs:    []string{"T1552.005"},
			CISControls: []string{"CIS-AWS-5.6"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleS3PublicBucketWithSensitiveData(), RuleMetadata{
			ID:          "TC-AWS-002",
			Name:        "Public S3 Bucket with Sensitive Data",
			Category:    RuleCategoryAWS,
			Provider:    "aws",
			MITREIDs:    []string{"T1530"},
			CISControls: []string{"CIS-AWS-2.1.1"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleLambdaVPCSecretsAccess(), RuleMetadata{
			ID:       "TC-AWS-003",
			Name:     "Lambda in VPC with Secrets Access",
			Category: RuleCategoryAWS,
			Provider: "aws",
			MITREIDs: []string{"T1552"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleLambdaPublicInlinePolicyDynamoTrigger(), RuleMetadata{
			ID:       "TC-AWS-004",
			Name:     "Public Lambda with Inline Policy and DynamoDB Trigger",
			Category: RuleCategoryAWS,
			Provider: "aws",
			MITREIDs: []string{"T1195.002"},
			Enabled:  true,
		})

		reg.MustRegister(engine.rulePublicRDSUnencryptedHighBlastRadius(), RuleMetadata{
			ID:          "TC-AWS-005",
			Name:        "Public Unencrypted RDS with High Blast Radius",
			Category:    RuleCategoryAWS,
			Provider:    "aws",
			MITREIDs:    []string{"T1530"},
			CISControls: []string{"CIS-AWS-2.3.2"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleCrossAccountTransitiveTrustChain(), RuleMetadata{
			ID:       "TC-AWS-006",
			Name:     "Transitive Cross-Account Trust Chain",
			Category: RuleCategoryAWS,
			Provider: "aws",
			MITREIDs: []string{"T1078.004"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleExposedComputeWithKeyedAdminIdentity(), RuleMetadata{
			ID:       "TC-AWS-007",
			Name:     "Exposed Compute with Keyed Admin Identity",
			Category: RuleCategoryAWS,
			Provider: "aws",
			MITREIDs: []string{"T1552.001"},
			Enabled:  true,
		})

		// GCP-specific rules
		reg.MustRegister(engine.ruleGCPServiceAccountKeyExposed(), RuleMetadata{
			ID:          "TC-GCP-001",
			Name:        "GCP Service Account Key Exposed",
			Category:    RuleCategoryGCP,
			Provider:    "gcp",
			MITREIDs:    []string{"T1552.001"},
			CISControls: []string{"CIS-GCP-1.4"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleGCPPublicGCSBucket(), RuleMetadata{
			ID:          "TC-GCP-002",
			Name:        "Public GCS Bucket",
			Category:    RuleCategoryGCP,
			Provider:    "gcp",
			MITREIDs:    []string{"T1530"},
			CISControls: []string{"CIS-GCP-5.1"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleGCPComputeDefaultSA(), RuleMetadata{
			ID:          "TC-GCP-003",
			Name:        "GCE Instance with Default Service Account",
			Category:    RuleCategoryGCP,
			Provider:    "gcp",
			MITREIDs:    []string{"T1078.004"},
			CISControls: []string{"CIS-GCP-4.1"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleGCPDefaultSAProjectWidePermissions(), RuleMetadata{
			ID:       "TC-GCP-004",
			Name:     "Default Compute SA with Project-Wide Permissions",
			Category: RuleCategoryGCP,
			Provider: "gcp",
			MITREIDs: []string{"T1078.004"},
			Enabled:  true,
		})

		// Azure-specific rules
		reg.MustRegister(engine.ruleAzureManagedIdentityOverprivileged(), RuleMetadata{
			ID:          "TC-AZURE-001",
			Name:        "Overprivileged Azure Managed Identity",
			Category:    RuleCategoryAzure,
			Provider:    "azure",
			MITREIDs:    []string{"T1078.004"},
			CISControls: []string{"CIS-Azure-1.21"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleAzurePublicStorageBlob(), RuleMetadata{
			ID:          "TC-AZURE-002",
			Name:        "Public Azure Blob Container",
			Category:    RuleCategoryAzure,
			Provider:    "azure",
			MITREIDs:    []string{"T1530"},
			CISControls: []string{"CIS-Azure-3.5"},
			Enabled:     true,
		})

		// Kubernetes rules
		reg.MustRegister(engine.rulePrivilegedPodWithHostPath(), RuleMetadata{
			ID:          "TC-K8S-001",
			Name:        "Privileged Pod with Host Path",
			Category:    RuleCategoryKubernetes,
			Provider:    "k8s",
			MITREIDs:    []string{"T1611"},
			CISControls: []string{"CIS-K8S-5.2.1"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleRBACWildcardSecrets(), RuleMetadata{
			ID:          "TC-K8S-002",
			Name:        "RBAC Wildcard Access to Secrets",
			Category:    RuleCategoryKubernetes,
			Provider:    "k8s",
			MITREIDs:    []string{"T1552"},
			CISControls: []string{"CIS-K8S-5.1.2"},
			Enabled:     true,
		})

		reg.MustRegister(engine.ruleServiceAccountClusterAdmin(), RuleMetadata{
			ID:          "TC-K8S-003",
			Name:        "Service Account with Cluster-Admin",
			Category:    RuleCategoryKubernetes,
			Provider:    "k8s",
			MITREIDs:    []string{"T1078.001"},
			CISControls: []string{"CIS-K8S-5.1.1"},
			Enabled:     true,
		})

		reg.MustRegister(engine.rulePodServiceAccountTokenMount(), RuleMetadata{
			ID:          "TC-K8S-004",
			Name:        "Pod with Service Account Token Auto-Mount",
			Category:    RuleCategoryKubernetes,
			Provider:    "k8s",
			MITREIDs:    []string{"T1552.007"},
			CISControls: []string{"CIS-K8S-5.1.6"},
			Enabled:     true,
		})

		// CI/CD supply chain rules
		reg.MustRegister(engine.ruleGitHubActionsOIDCOverprivileged(), RuleMetadata{
			ID:       "TC-CICD-001",
			Name:     "GitHub Actions OIDC with Overprivileged Role",
			Category: RuleCategoryCICD,
			Provider: "github",
			MITREIDs: []string{"T1195.002"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleEKSNodeRoleECRPush(), RuleMetadata{
			ID:       "TC-CICD-002",
			Name:     "EKS Node Role with ECR Push",
			Category: RuleCategoryCICD,
			Provider: "aws",
			MITREIDs: []string{"T1525"},
			Enabled:  true,
		})

		// Cross-system business rules
		reg.MustRegister(engine.ruleChurnCompoundSignal(), RuleMetadata{
			ID:       "TC-BIZ-001",
			Name:     "Churn Compound Signal",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1199"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleTrajectoryDeterioration(), RuleMetadata{
			ID:       "TC-BIZ-006",
			Name:     "Trajectory Deterioration",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1566"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleRevenueAtRisk(), RuleMetadata{
			ID:       "TC-BIZ-002",
			Name:     "Revenue-at-Risk",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1566"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleSecurityMeetsBusiness(), RuleMetadata{
			ID:       "TC-BIZ-003",
			Name:     "Security-Meets-Business",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1190"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleOperationalBlastRadius(), RuleMetadata{
			ID:       "TC-BIZ-004",
			Name:     "Operational Blast Radius",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1499"},
			Enabled:  true,
		})

		reg.MustRegister(engine.ruleFinancialGuardrail(), RuleMetadata{
			ID:       "TC-BIZ-005",
			Name:     "Financial Guardrail",
			Category: RuleCategoryCore,
			MITREIDs: []string{"T1657"},
			Enabled:  true,
		})
	})
}

// NewToxicCombinationEngineFromRegistry creates an engine using the global registry
func NewToxicCombinationEngineFromRegistry() *ToxicCombinationEngine {
	RegisterAllRules()

	engine := &ToxicCombinationEngine{
		rules: GlobalRegistry().GetEnabledRules(),
	}
	return engine
}
