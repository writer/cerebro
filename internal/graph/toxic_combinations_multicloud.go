package graph

import (
	"fmt"
	"strings"
)

// RegisterMultiCloudRules adds GCP and Azure specific toxic combination rules
func (e *ToxicCombinationEngine) RegisterMultiCloudRules() {
	// GCP Rules
	e.rules = append(e.rules,
		e.ruleGCPServiceAccountKeyExposed(),
		e.ruleGCPPublicBucket(),
		e.ruleGCPPrivilegeEscalation(),
		e.ruleGCPCrossProjectAccess(),
		e.ruleGCPComputeDefaultServiceAccount(),
		e.ruleGCPCloudFunctionPublicInvoke(),
		e.ruleGCPBigQueryPublicDataset(),
		e.ruleGCPIAMBindingAllUsers(),
	)

	// Azure Rules
	e.rules = append(e.rules,
		e.ruleAzurePublicBlob(),
		e.ruleAzurePrivilegeEscalation(),
		e.ruleAzureManagedIdentityOverPrivileged(),
		e.ruleAzureKeyVaultWeakAccess(),
		e.ruleAzureSQLPublicAccess(),
		e.ruleAzureADExternalGuest(),
		e.ruleAzureOwnerWithNoMFA(),
		e.ruleAzureFunctionPublicInvoke(),
	)
}

// GCP Rules

func (e *ToxicCombinationEngine) ruleGCPServiceAccountKeyExposed() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-001",
		Name:        "GCP Service Account Key + High Privileges",
		Description: "GCP service account with exported key and elevated permissions",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "credential", "service-account"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || node.Kind != NodeKindServiceAccount {
				return nil
			}

			// Check for exported keys
			hasKeys := false
			if keys, ok := node.Properties["keys"].([]any); ok && len(keys) > 0 {
				hasKeys = true
			}
			if _, hasKeyProp := node.Properties["has_user_managed_keys"]; hasKeyProp {
				hasKeys = true
			}

			if !hasKeys {
				return nil
			}

			// Check for elevated permissions
			hasElevated := false
			elevatedRoles := []string{"owner", "editor", "admin", "iam.securityAdmin", "iam.serviceAccountAdmin"}
			if roles, ok := node.Properties["roles"].([]any); ok {
				for _, role := range roles {
					roleStr, _ := role.(string)
					for _, elevated := range elevatedRoles {
						if strings.Contains(strings.ToLower(roleStr), elevated) {
							hasElevated = true
							break
						}
					}
				}
			}

			if !hasElevated {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-001-%s", node.ID),
				Name:        "Service Account Key with High Privileges",
				Description: fmt.Sprintf("Service account %s has exported keys and elevated permissions, enabling credential theft attacks", node.Name),
				Severity:    SeverityCritical,
				Score:       92.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: "User-managed service account keys exist", Severity: SeverityHigh},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has elevated project-level permissions", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Delete user-managed keys and use workload identity", Resource: node.ID, Impact: "Eliminates credential theft vector", Effort: "medium"},
					{Priority: 2, Action: "Apply least-privilege permissions", Resource: node.ID, Impact: "Reduces blast radius", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "credential-exposure", "privilege-escalation"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPPublicBucket() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-002",
		Name:        "GCP Public Cloud Storage + Sensitive Data",
		Description: "Public GCS bucket containing sensitive data",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "storage", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || node.Kind != NodeKindBucket {
				return nil
			}

			// Check for public access
			isPublic := false
			if public, ok := node.Properties["public"].(bool); ok && public {
				isPublic = true
			}
			if iamPolicy, ok := node.Properties["iam_policy"].(string); ok {
				if strings.Contains(iamPolicy, "allUsers") || strings.Contains(iamPolicy, "allAuthenticatedUsers") {
					isPublic = true
				}
			}

			if !isPublic {
				return nil
			}

			// Check for sensitive data indicators
			hasSensitive := node.Risk == RiskCritical || node.Risk == RiskHigh
			if _, ok := node.Properties["contains_pii"]; ok {
				hasSensitive = true
			}
			if tags, ok := node.Tags["classification"]; ok && (tags == "confidential" || tags == "pii") {
				hasSensitive = true
			}

			if !hasSensitive {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-002-%s", node.ID),
				Name:        "Public Bucket with Sensitive Data",
				Description: fmt.Sprintf("GCS bucket %s is publicly accessible and contains sensitive data", node.Name),
				Severity:    SeverityCritical,
				Score:       98.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Bucket allows public access", Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Contains sensitive or classified data", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove allUsers and allAuthenticatedUsers from IAM", Resource: node.ID, Impact: "Blocks public access immediately", Effort: "low"},
					{Priority: 2, Action: "Enable uniform bucket-level access", Resource: node.ID, Impact: "Simplifies access control", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "data-exposure", "compliance"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPPrivilegeEscalation() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-003",
		Name:        "GCP Privilege Escalation Path",
		Description: "Principal with permissions enabling privilege escalation",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "iam", "privilege-escalation"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || !node.IsIdentity() {
				return nil
			}

			permissions := getNodePermissions(node)

			// GCP privilege escalation paths
			escalationPaths := []struct {
				name  string
				perms []string
			}{
				{"setIamPolicy on project", []string{"resourcemanager.projects.setIamPolicy"}},
				{"actAs + compute", []string{"iam.serviceAccounts.actAs", "compute.instances.create"}},
				{"actAs + cloud functions", []string{"iam.serviceAccounts.actAs", "cloudfunctions.functions.create"}},
				{"getAccessToken", []string{"iam.serviceAccounts.getAccessToken"}},
				{"signBlob + signJwt", []string{"iam.serviceAccounts.signBlob"}},
				{"createServiceAccountKey", []string{"iam.serviceAccountKeys.create"}},
				{"deploymentManager", []string{"deploymentmanager.deployments.create"}},
				{"cloudBuild", []string{"cloudbuild.builds.create"}},
			}

			var detectedPath string
			for _, path := range escalationPaths {
				hasAll := true
				for _, perm := range path.perms {
					if !containsPermission(permissions, perm) {
						hasAll = false
						break
					}
				}
				if hasAll {
					detectedPath = path.name
					break
				}
			}

			if detectedPath == "" {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-003-%s", node.ID),
				Name:        "GCP Privilege Escalation Capability",
				Description: fmt.Sprintf("%s can escalate privileges via %s", node.Name, detectedPath),
				Severity:    SeverityCritical,
				Score:       88.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorPrivEscalation, NodeID: node.ID, Description: fmt.Sprintf("Can escalate via %s", detectedPath), Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove dangerous permission combinations", Resource: node.ID, Impact: "Blocks escalation path", Effort: "medium"},
					{Priority: 2, Action: "Implement organization policy constraints", Resource: "organization", Impact: "Prevents future misconfigurations", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "privilege-escalation", "iam"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPCrossProjectAccess() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-004",
		Name:        "GCP Cross-Project Admin Access",
		Description: "Service account from one project with admin access to another",
		Severity:    SeverityHigh,
		Tags:        []string{"gcp", "cross-project", "lateral-movement"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || !node.IsIdentity() {
				return nil
			}

			sourceProject := ""
			if proj, ok := node.Properties["project"].(string); ok {
				sourceProject = proj
			}

			// Check for cross-project edges with admin
			var crossProjectTargets []string
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin || edge.Kind == EdgeKindCanWrite {
					targetNode, ok := g.GetNode(edge.Target)
					if !ok {
						continue
					}
					if targetProject, ok := targetNode.Properties["project"].(string); ok {
						if targetProject != "" && targetProject != sourceProject {
							crossProjectTargets = append(crossProjectTargets, targetNode.ID)
						}
					}
				}
			}

			if len(crossProjectTargets) == 0 {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-004-%s", node.ID),
				Name:        "Cross-Project Admin Access",
				Description: fmt.Sprintf("%s from project %s has admin access to resources in other projects", node.Name, sourceProject),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorCrossAccount, NodeID: node.ID, Description: fmt.Sprintf("Admin access to %d resources in other projects", len(crossProjectTargets)), Severity: SeverityHigh},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: "Enables lateral movement across project boundary", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Review and restrict cross-project IAM bindings", Resource: node.ID, Impact: "Limits blast radius", Effort: "medium"},
					{Priority: 2, Action: "Use VPC Service Controls", Resource: "organization", Impact: "Prevents data exfiltration", Effort: "high"},
				},
				AffectedAssets: append([]string{node.ID}, crossProjectTargets...),
				Tags:           []string{"gcp", "cross-project", "lateral-movement"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPComputeDefaultServiceAccount() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-005",
		Name:        "GCP Compute Default Service Account",
		Description: "Compute instance using default service account with broad scope",
		Severity:    SeverityHigh,
		Tags:        []string{"gcp", "compute", "misconfiguration"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || node.Kind != NodeKindInstance {
				return nil
			}

			// Check for default service account
			saEmail := ""
			if sa, ok := node.Properties["service_account"].(string); ok {
				saEmail = sa
			}

			isDefault := strings.Contains(saEmail, "-compute@developer.gserviceaccount.com")
			if !isDefault {
				return nil
			}

			// Check for broad scopes
			hasBroadScope := false
			if scopes, ok := node.Properties["scopes"].([]any); ok {
				for _, scope := range scopes {
					scopeStr, _ := scope.(string)
					if strings.Contains(scopeStr, "cloud-platform") || strings.Contains(scopeStr, "devstorage.full_control") {
						hasBroadScope = true
						break
					}
				}
			}

			if !hasBroadScope {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-005-%s", node.ID),
				Name:        "Default Service Account with Broad Scope",
				Description: fmt.Sprintf("Instance %s uses the default compute service account with cloud-platform scope", node.Name),
				Severity:    SeverityHigh,
				Score:       70.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Uses default compute service account", Severity: SeverityMedium},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has cloud-platform or full_control scope", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Create dedicated service account with minimal permissions", Resource: node.ID, Impact: "Reduces attack surface", Effort: "medium"},
					{Priority: 2, Action: "Use specific scopes instead of cloud-platform", Resource: node.ID, Impact: "Limits API access", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "compute", "best-practice"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPCloudFunctionPublicInvoke() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-006",
		Name:        "GCP Cloud Function Public Invoke",
		Description: "Cloud Function allowing unauthenticated invocation",
		Severity:    SeverityHigh,
		Tags:        []string{"gcp", "serverless", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || node.Kind != NodeKindFunction {
				return nil
			}

			// Check for public invoke
			isPublic := false
			if allowUnauth, ok := node.Properties["allow_unauthenticated"].(bool); ok && allowUnauth {
				isPublic = true
			}
			if invoker, ok := node.Properties["invoker"].(string); ok {
				if strings.Contains(invoker, "allUsers") || strings.Contains(invoker, "allAuthenticatedUsers") {
					isPublic = true
				}
			}

			if !isPublic {
				return nil
			}

			// Check for sensitive access
			hasSensitiveAccess := false
			for _, edge := range g.GetOutEdges(node.ID) {
				targetNode, ok := g.GetNode(edge.Target)
				if !ok {
					continue
				}
				if targetNode.Kind == NodeKindDatabase || targetNode.Kind == NodeKindSecret {
					hasSensitiveAccess = true
					break
				}
			}

			severity := SeverityMedium
			score := 60.0
			if hasSensitiveAccess {
				severity = SeverityHigh
				score = 80.0
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-006-%s", node.ID),
				Name:        "Public Cloud Function",
				Description: fmt.Sprintf("Cloud Function %s allows unauthenticated invocation", node.Name),
				Severity:    severity,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Allows unauthenticated invocation", Severity: severity},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Require authentication for Cloud Function", Resource: node.ID, Impact: "Blocks unauthorized access", Effort: "low"},
					{Priority: 2, Action: "Use Cloud IAM invoker role", Resource: node.ID, Impact: "Enables fine-grained access control", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "serverless", "public"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPBigQueryPublicDataset() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-007",
		Name:        "GCP BigQuery Public Dataset",
		Description: "BigQuery dataset with public access containing sensitive data",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "bigquery", "data-exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" || node.Kind != NodeKindDatabase {
				return nil
			}

			// Check if it's BigQuery
			if svc, ok := node.Properties["service"].(string); !ok || svc != "bigquery" {
				return nil
			}

			// Check for public access
			isPublic := false
			if access, ok := node.Properties["access"].([]any); ok {
				for _, a := range access {
					if aStr, ok := a.(string); ok {
						if strings.Contains(aStr, "allUsers") || strings.Contains(aStr, "allAuthenticatedUsers") {
							isPublic = true
							break
						}
					}
				}
			}

			if !isPublic {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-GCP-007-%s", node.ID),
				Name:        "Public BigQuery Dataset",
				Description: fmt.Sprintf("BigQuery dataset %s is publicly accessible", node.Name),
				Severity:    SeverityCritical,
				Score:       95.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Dataset allows public read access", Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "May contain queryable business data", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove public access from dataset", Resource: node.ID, Impact: "Blocks unauthorized queries", Effort: "low"},
					{Priority: 2, Action: "Implement column-level security", Resource: node.ID, Impact: "Protects sensitive columns", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"gcp", "bigquery", "compliance"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGCPIAMBindingAllUsers() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-GCP-008",
		Name:        "GCP IAM Binding to allUsers/allAuthenticatedUsers",
		Description: "Resource with IAM binding granting access to all users",
		Severity:    SeverityCritical,
		Tags:        []string{"gcp", "iam", "public-access"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "gcp" {
				return nil
			}

			// Check incoming edges for public principals
			for _, edge := range g.GetInEdges(node.ID) {
				sourceNode, ok := g.GetNode(edge.Source)
				if !ok {
					continue
				}
				if sourceNode.Name == "allUsers" || sourceNode.Name == "allAuthenticatedUsers" {
					return &ToxicCombination{
						ID:          fmt.Sprintf("TC-GCP-008-%s", node.ID),
						Name:        "Public IAM Binding",
						Description: fmt.Sprintf("Resource %s has IAM binding to %s", node.Name, sourceNode.Name),
						Severity:    SeverityCritical,
						Score:       90.0,
						Factors: []*RiskFactor{
							{Type: RiskFactorExposure, NodeID: node.ID, Description: fmt.Sprintf("Accessible to %s", sourceNode.Name), Severity: SeverityCritical},
						},
						Remediation: []*RemediationStep{
							{Priority: 1, Action: "Remove public IAM binding", Resource: node.ID, Impact: "Removes public access", Effort: "low"},
						},
						AffectedAssets: []string{node.ID},
						Tags:           []string{"gcp", "public", "iam"},
					}
				}
			}

			return nil
		},
	}
}

// Azure Rules

func (e *ToxicCombinationEngine) ruleAzurePublicBlob() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-001",
		Name:        "Azure Public Blob Container",
		Description: "Azure Storage container with public access",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "storage", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindBucket {
				return nil
			}

			// Check for public access
			isPublic := false
			if access, ok := node.Properties["public_access"].(string); ok {
				if access == "blob" || access == "container" {
					isPublic = true
				}
			}
			if public, ok := node.Properties["public"].(bool); ok && public {
				isPublic = true
			}

			if !isPublic {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-001-%s", node.ID),
				Name:        "Public Blob Container",
				Description: fmt.Sprintf("Azure container %s allows public access", node.Name),
				Severity:    SeverityCritical,
				Score:       95.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Container has public access enabled", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Disable public access on container", Resource: node.ID, Impact: "Blocks anonymous access", Effort: "low"},
					{Priority: 2, Action: "Enable 'Require secure transfer'", Resource: node.ID, Impact: "Ensures HTTPS only", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "storage", "public"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzurePrivilegeEscalation() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-002",
		Name:        "Azure Privilege Escalation Path",
		Description: "Principal with permissions enabling Azure privilege escalation",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "rbac", "privilege-escalation"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || !node.IsIdentity() {
				return nil
			}

			permissions := getNodePermissions(node)

			// Azure privilege escalation paths
			escalationPaths := []struct {
				name  string
				perms []string
			}{
				{"Role Assignment", []string{"Microsoft.Authorization/roleAssignments/write"}},
				{"Custom Role Create", []string{"Microsoft.Authorization/roleDefinitions/write"}},
				{"Automation Runbook", []string{"Microsoft.Automation/automationAccounts/runbooks/write", "Microsoft.Automation/automationAccounts/runbooks/publish/action"}},
				{"VM Command Execute", []string{"Microsoft.Compute/virtualMachines/runCommand/action"}},
				{"Key Vault Secrets", []string{"Microsoft.KeyVault/vaults/secrets/getSecret/action"}},
				{"App Registration Credentials", []string{"microsoft.directory/applications/credentials/update"}},
			}

			var detectedPath string
			for _, path := range escalationPaths {
				hasAll := true
				for _, perm := range path.perms {
					if !containsPermission(permissions, perm) {
						hasAll = false
						break
					}
				}
				if hasAll {
					detectedPath = path.name
					break
				}
			}

			if detectedPath == "" {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-002-%s", node.ID),
				Name:        "Azure Privilege Escalation Capability",
				Description: fmt.Sprintf("%s can escalate privileges via %s", node.Name, detectedPath),
				Severity:    SeverityCritical,
				Score:       88.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorPrivEscalation, NodeID: node.ID, Description: fmt.Sprintf("Can escalate via %s", detectedPath), Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove dangerous permission combinations", Resource: node.ID, Impact: "Blocks escalation path", Effort: "medium"},
					{Priority: 2, Action: "Use Azure PIM for just-in-time access", Resource: "subscription", Impact: "Reduces standing privileges", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "privilege-escalation", "rbac"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureManagedIdentityOverPrivileged() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-003",
		Name:        "Azure Managed Identity Over-Privileged",
		Description: "Managed identity with Owner or Contributor role at subscription level",
		Severity:    SeverityHigh,
		Tags:        []string{"azure", "managed-identity", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindServiceAccount {
				return nil
			}

			// Check for managed identity
			isManagedIdentity := false
			if idType, ok := node.Properties["type"].(string); ok {
				if strings.Contains(strings.ToLower(idType), "managedidentity") {
					isManagedIdentity = true
				}
			}

			if !isManagedIdentity {
				return nil
			}

			// Check for over-privileged roles
			hasElevated := false
			if roles, ok := node.Properties["roles"].([]any); ok {
				for _, role := range roles {
					roleStr, _ := role.(string)
					if strings.Contains(roleStr, "Owner") || strings.Contains(roleStr, "Contributor") {
						hasElevated = true
						break
					}
				}
			}

			if !hasElevated {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-003-%s", node.ID),
				Name:        "Over-Privileged Managed Identity",
				Description: fmt.Sprintf("Managed identity %s has Owner/Contributor role", node.Name),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has Owner or Contributor role", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Assign specific role instead of Owner/Contributor", Resource: node.ID, Impact: "Reduces blast radius", Effort: "medium"},
					{Priority: 2, Action: "Scope role assignment to resource group", Resource: node.ID, Impact: "Limits scope of access", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "managed-identity", "least-privilege"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureKeyVaultWeakAccess() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-004",
		Name:        "Azure Key Vault Weak Access Control",
		Description: "Key Vault with overly permissive access policies",
		Severity:    SeverityHigh,
		Tags:        []string{"azure", "keyvault", "secrets"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindSecret {
				return nil
			}

			// Check if it's a Key Vault
			if svc, ok := node.Properties["service"].(string); !ok || svc != "keyvault" {
				return nil
			}

			// Check for weak access
			hasWeakAccess := false
			accessorCount := 0
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind == EdgeKindCanRead || edge.Kind == EdgeKindCanAdmin {
					accessorCount++
				}
			}

			if accessorCount > 10 {
				hasWeakAccess = true
			}

			// Check for no RBAC
			if rbac, ok := node.Properties["enable_rbac"].(bool); ok && !rbac {
				hasWeakAccess = true
			}

			if !hasWeakAccess {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-004-%s", node.ID),
				Name:        "Key Vault with Weak Access Control",
				Description: fmt.Sprintf("Key Vault %s has %d accessors or uses legacy access policies", node.Name, accessorCount),
				Severity:    SeverityHigh,
				Score:       72.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: fmt.Sprintf("%d principals have access", accessorCount), Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Enable RBAC for data plane access", Resource: node.ID, Impact: "Enables fine-grained access control", Effort: "medium"},
					{Priority: 2, Action: "Review and remove unnecessary access policies", Resource: node.ID, Impact: "Reduces access surface", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "keyvault", "access-control"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureSQLPublicAccess() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-005",
		Name:        "Azure SQL Public Network Access",
		Description: "Azure SQL with public endpoint and weak firewall rules",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "sql", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindDatabase {
				return nil
			}

			// Check for public access
			isPublic := false
			if publicAccess, ok := node.Properties["public_network_access"].(bool); ok && publicAccess {
				isPublic = true
			}

			// Check for 0.0.0.0 firewall rule
			if fwRules, ok := node.Properties["firewall_rules"].([]any); ok {
				for _, rule := range fwRules {
					if ruleStr, ok := rule.(string); ok {
						if strings.Contains(ruleStr, "0.0.0.0") || strings.Contains(ruleStr, "AllowAllAzureIps") {
							isPublic = true
							break
						}
					}
				}
			}

			if !isPublic {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-005-%s", node.ID),
				Name:        "Azure SQL Public Access",
				Description: fmt.Sprintf("Azure SQL %s is accessible from the internet", node.Name),
				Severity:    SeverityCritical,
				Score:       90.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Public network access enabled", Severity: SeverityCritical},
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Has permissive firewall rules", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Disable public network access", Resource: node.ID, Impact: "Blocks internet access", Effort: "medium"},
					{Priority: 2, Action: "Use Private Endpoints", Resource: node.ID, Impact: "Enables private connectivity", Effort: "medium"},
					{Priority: 3, Action: "Remove 0.0.0.0 firewall rule", Resource: node.ID, Impact: "Restricts allowed IPs", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "sql", "network"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureADExternalGuest() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-006",
		Name:        "Azure AD External Guest with Elevated Access",
		Description: "External guest user with admin or owner role",
		Severity:    SeverityHigh,
		Tags:        []string{"azure", "ad", "guest"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindUser {
				return nil
			}

			// Check if guest
			isGuest := false
			if userType, ok := node.Properties["user_type"].(string); ok {
				if strings.ToLower(userType) == "guest" {
					isGuest = true
				}
			}

			if !isGuest {
				return nil
			}

			// Check for elevated roles
			hasElevated := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin {
					hasElevated = true
					break
				}
			}

			if !hasElevated {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-006-%s", node.ID),
				Name:        "External Guest with Admin Access",
				Description: fmt.Sprintf("Guest user %s has administrative access", node.Name),
				Severity:    SeverityHigh,
				Score:       78.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorCrossAccount, NodeID: node.ID, Description: "External guest user", Severity: SeverityMedium},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has admin-level access", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Review and reduce guest permissions", Resource: node.ID, Impact: "Limits external access", Effort: "medium"},
					{Priority: 2, Action: "Convert to B2B collaboration if long-term", Resource: node.ID, Impact: "Better governance", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "ad", "guest", "external"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureOwnerWithNoMFA() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-007",
		Name:        "Azure Owner Without MFA",
		Description: "User with Owner role but MFA not enabled",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "mfa", "owner"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindUser {
				return nil
			}

			// Check MFA status
			hasMFA := true
			if mfa, ok := node.Properties["mfa_enabled"].(bool); ok && !mfa {
				hasMFA = false
			}

			if hasMFA {
				return nil
			}

			// Check for owner role
			isOwner := false
			if roles, ok := node.Properties["roles"].([]any); ok {
				for _, role := range roles {
					roleStr, _ := role.(string)
					if strings.Contains(roleStr, "Owner") {
						isOwner = true
						break
					}
				}
			}

			if !isOwner {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-007-%s", node.ID),
				Name:        "Owner Without MFA",
				Description: fmt.Sprintf("Owner %s does not have MFA enabled", node.Name),
				Severity:    SeverityCritical,
				Score:       92.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: "MFA not enabled", Severity: SeverityCritical},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has Owner role", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Enable MFA immediately", Resource: node.ID, Impact: "Prevents credential compromise", Effort: "low"},
					{Priority: 2, Action: "Create Conditional Access policy requiring MFA", Resource: "tenant", Impact: "Enforces MFA for all admins", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "mfa", "critical"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzureFunctionPublicInvoke() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZ-008",
		Name:        "Azure Function Public HTTP Trigger",
		Description: "Azure Function with anonymous HTTP trigger",
		Severity:    SeverityMedium,
		Tags:        []string{"azure", "function", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Provider != "azure" || node.Kind != NodeKindFunction {
				return nil
			}

			// Check for anonymous auth
			isPublic := false
			if authLevel, ok := node.Properties["auth_level"].(string); ok {
				if strings.ToLower(authLevel) == "anonymous" {
					isPublic = true
				}
			}

			if !isPublic {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZ-008-%s", node.ID),
				Name:        "Public Azure Function",
				Description: fmt.Sprintf("Azure Function %s allows anonymous HTTP invocation", node.Name),
				Severity:    SeverityMedium,
				Score:       55.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Anonymous auth level", Severity: SeverityMedium},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Change auth level to 'function' or 'admin'", Resource: node.ID, Impact: "Requires API key", Effort: "low"},
					{Priority: 2, Action: "Use Azure AD authentication", Resource: node.ID, Impact: "Enables identity-based access", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "function", "auth"},
			}
		},
	}
}
