package graph

import (
	"fmt"
	"strings"
)

func (e *ToxicCombinationEngine) ruleGCPServiceAccountKeyExposed() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-001",
		Name:        "GCP Service Account Key Exposed",
		Description: "GCP service account has user-managed keys that may be exposed",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "service-account", "credential-theft", "key-management"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindServiceAccount || node.Provider != "gcp" {
				return nil
			}

			// Check for user-managed keys
			hasUserKeys, _ := node.Properties["has_user_managed_keys"].(bool)
			keyCount, _ := node.Properties["key_count"].(int)
			oldestKeyAge, _ := node.Properties["oldest_key_age_days"].(int)

			if !hasUserKeys && keyCount == 0 {
				return nil
			}

			// Check if SA has elevated permissions
			hasElevatedPerms := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin || edge.Kind == EdgeKindCanWrite {
					hasElevatedPerms = true
					break
				}
			}

			// Also check for dangerous IAM roles
			roles, _ := node.Properties["roles"].([]any)
			for _, r := range roles {
				role, _ := r.(string)
				if strings.Contains(role, "owner") ||
					strings.Contains(role, "editor") ||
					strings.Contains(role, "admin") {
					hasElevatedPerms = true
					break
				}
			}

			if !hasElevatedPerms {
				return nil
			}

			score := 85.0
			if oldestKeyAge > 90 {
				score = 95.0 // Old keys are higher risk
			}

			factors := []*RiskFactor{
				{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: "User-managed service account keys exist", Severity: SeverityCritical},
				{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Service account has elevated permissions", Severity: SeverityHigh},
			}
			if oldestKeyAge > 90 {
				factors = append(factors, &RiskFactor{
					Type: RiskFactorMisconfiguration, NodeID: node.ID,
					Description: fmt.Sprintf("Key not rotated in %d days", oldestKeyAge), Severity: SeverityHigh,
				})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-001-%s", node.ID),
				Name:        "Privileged Service Account with User Keys",
				Description: fmt.Sprintf("Service account %s has user-managed keys with elevated permissions - key theft enables account takeover", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Delete user-managed keys and use workload identity", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "If keys required, rotate immediately and set 90-day expiry", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Apply least-privilege IAM bindings", Resource: node.ID, Effort: "medium"},
					{Priority: 4, Action: "Enable Cloud Audit Logs for service account usage", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "service-account", "credential-theft"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPPublicGCSBucket() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-002",
		Name:        "Public GCS Bucket with Sensitive Data",
		Description: "GCS bucket is publicly accessible and may contain sensitive data",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "gcs", "storage", "data-exposure", "public-access"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindBucket || node.Provider != "gcp" {
				return nil
			}

			// Check if bucket is public
			isPublic, _ := node.Properties["public_access"].(bool)
			allUsers, _ := node.Properties["all_users_access"].(bool)
			allAuthUsers, _ := node.Properties["all_authenticated_users_access"].(bool)

			if !isPublic && !allUsers && !allAuthUsers {
				return nil
			}

			// Check for sensitive data indicators
			hasSensitiveData := false
			dataClassification := node.PropertyString("data_classification")
			containsPII, _ := node.PropertyBool("contains_pii")

			if dataClassification == "confidential" || dataClassification == "restricted" || containsPII {
				hasSensitiveData = true
			}

			// Check bucket name for sensitive patterns
			bucketName := strings.ToLower(node.Name)
			for _, pattern := range sensitiveDataPatterns {
				if strings.Contains(bucketName, pattern) {
					hasSensitiveData = true
					break
				}
			}

			if !hasSensitiveData {
				return nil
			}

			score := 90.0
			if allUsers {
				score = 98.0 // allUsers is worse than allAuthenticatedUsers
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-002-%s", node.ID),
				Name:        "Public GCS Bucket with Sensitive Data",
				Description: fmt.Sprintf("GCS bucket %s is publicly accessible and likely contains sensitive data", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Bucket allows public/anonymous access", Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Bucket name or content indicates sensitive data", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove allUsers and allAuthenticatedUsers IAM bindings", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Enable uniform bucket-level access", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Enable organization policy to prevent public access", Resource: "organization", Effort: "medium"},
					{Priority: 4, Action: "Enable Cloud Audit Logs and set up alerts", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "gcs", "data-exposure", "compliance"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPComputeDefaultSA() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-003",
		Name:        "Compute Instance with Default Service Account",
		Description: "GCE instance uses the default compute service account with broad permissions",
		Severity:    SeverityHigh,
		Tags:        []string{"gcp", "compute", "service-account", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindInstance || node.Provider != "gcp" {
				return nil
			}

			// Check if using default service account
			saEmail, _ := node.Properties["service_account_email"].(string)
			isDefault := strings.Contains(saEmail, "-compute@developer.gserviceaccount.com")

			if !isDefault {
				return nil
			}

			// Check scopes - default SA with cloud-platform scope is dangerous
			scopes, _ := node.Properties["service_account_scopes"].([]any)
			hasFullScope := false
			for _, s := range scopes {
				scope, _ := s.(string)
				if strings.Contains(scope, "cloud-platform") || scope == "https://www.googleapis.com/auth/cloud-platform" {
					hasFullScope = true
					break
				}
			}

			if !hasFullScope {
				return nil
			}

			// Check if instance is externally accessible
			isPublic := false
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind == EdgeKindExposedTo {
					source, ok := g.GetNode(edge.Source)
					if ok && source.Kind == NodeKindInternet {
						isPublic = true
						break
					}
				}
			}

			score := 75.0
			if isPublic {
				score = 90.0
			}

			factors := []*RiskFactor{
				{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Uses default compute service account", Severity: SeverityHigh},
				{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Has cloud-platform scope (full API access)", Severity: SeverityHigh},
			}
			if isPublic {
				factors = append(factors, &RiskFactor{
					Type: RiskFactorExposure, NodeID: node.ID,
					Description: "Instance is publicly accessible", Severity: SeverityHigh,
				})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-003-%s", node.ID),
				Name:        "Default SA with Full Cloud Access",
				Description: fmt.Sprintf("Instance %s uses default service account with cloud-platform scope - compromise grants full project access", node.Name),
				Severity:    SeverityHigh,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Create dedicated service account with minimal permissions", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "Restrict scopes to only required APIs", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Disable default service account at project level", Resource: "project", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "compute", "service-account"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPDefaultSAProjectWidePermissions() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-004",
		Name:        "Default Compute Service Account with Project-Wide Permissions",
		Description: "Default compute service account is attached to instances and has project-wide IAM privileges",
		Severity:    SeverityHigh,
		Tags:        []string{"gcp", "service-account", "project-iam", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindServiceAccount || node.Provider != "gcp" {
				return nil
			}

			saIdentity := strings.ToLower(readString(node.Properties, "email", "service_account_email"))
			if saIdentity == "" {
				saIdentity = strings.ToLower(node.Name)
			}
			isDefaultComputeSA := strings.Contains(saIdentity, "-compute@developer.gserviceaccount.com") ||
				readBool(node.Properties, "is_default_compute_sa")
			if !isDefaultComputeSA {
				return nil
			}

			projectWide := readBool(node.Properties, "project_wide_permissions", "project_level_binding", "broad_project_access")
			roles, _ := node.Properties["roles"].([]any)
			for _, roleValue := range roles {
				role, _ := roleValue.(string)
				normalized := strings.ToLower(role)
				if normalized == "roles/owner" ||
					normalized == "roles/editor" ||
					normalized == "roles/resourcemanager.projectiamadmin" ||
					normalized == "roles/iam.securityadmin" ||
					normalized == "roles/compute.admin" {
					projectWide = true
					break
				}
			}
			if !projectWide {
				return nil
			}

			attachedInstances := make([]string, 0)
			hasPublicCompute := false
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind != EdgeKindCanAssume || edge.IsDeny() {
					continue
				}
				instance, ok := g.GetNode(edge.Source)
				if !ok || instance.Kind != NodeKindInstance || instance.Provider != "gcp" {
					continue
				}
				attachedInstances = append(attachedInstances, instance.ID)
				if isExposedToInternet(g, instance.ID) {
					hasPublicCompute = true
				}
			}
			if len(attachedInstances) == 0 {
				return nil
			}

			severity := SeverityHigh
			score := 82.0
			if hasPublicCompute {
				severity = SeverityCritical
				score = 92.0
			}

			affected := append([]string{node.ID}, attachedInstances...)
			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-004-%s", node.ID),
				Name:        "Default Compute SA with Project-Wide IAM",
				Description: fmt.Sprintf("Default service account %s is attached to compute and has project-wide privileges", node.Name),
				Severity:    severity,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Default compute service account has project-wide permissions", Severity: SeverityHigh},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: fmt.Sprintf("Attached to %d compute instances", len(attachedInstances)), Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Replace default SA with dedicated least-privilege service account", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "Remove owner/editor style project-level role bindings", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Constrain instance-to-SA attachment and rotate credentials", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: dedupeStrings(affected),
				Tags:           []string{"gcp", "service-account", "project-iam"},
			}
		},
	}
}
