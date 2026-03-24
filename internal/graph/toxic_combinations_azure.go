package graph

import (
	"fmt"
	"strings"
)

func (e *ToxicCombinationEngine) ruleAzureManagedIdentityOverprivileged() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZURE-001",
		Name:        "Overprivileged Managed Identity",
		Description: "Azure managed identity has Owner or Contributor role at subscription scope",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "managed-identity", "rbac", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindServiceAccount || node.Provider != "azure" {
				return nil
			}

			// Check if this is a managed identity
			identityType := node.PropertyString("identity_type")
			if identityType != "SystemAssigned" && identityType != "UserAssigned" {
				return nil
			}

			// Check role assignments
			roleAssignments, _ := node.Properties["role_assignments"].([]any)
			hasOverprivilegedRole := false
			var dangerousRole string
			var scope string

			for _, ra := range roleAssignments {
				assignment, _ := ra.(map[string]any)
				role, _ := assignment["role_definition_name"].(string)
				assignmentScope, _ := assignment["scope"].(string)

				// Check for dangerous roles
				if role == "Owner" || role == "Contributor" || role == "User Access Administrator" {
					// Check if scope is subscription or management group level
					if strings.HasPrefix(assignmentScope, "/subscriptions/") &&
						!strings.Contains(assignmentScope, "/resourceGroups/") {
						hasOverprivilegedRole = true
						dangerousRole = role
						scope = assignmentScope
						break
					}
				}
			}

			if !hasOverprivilegedRole {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZURE-001-%s", node.ID),
				Name:        "Managed Identity with Subscription-Level Privileges",
				Description: fmt.Sprintf("Managed identity %s has %s role at subscription scope - compromise grants full subscription access", node.Name, dangerousRole),
				Severity:    SeverityCritical,
				Score:       92.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: fmt.Sprintf("Has %s role at subscription level", dangerousRole), Severity: SeverityCritical},
					{Type: RiskFactorPrivEscalation, NodeID: node.ID, Description: "Can escalate privileges across subscription", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Scope role assignment to specific resource group", Resource: scope, Effort: "medium"},
					{Priority: 2, Action: "Replace Owner/Contributor with specific roles (e.g., Storage Blob Data Contributor)", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Implement PIM for just-in-time access if elevated access is needed", Resource: node.ID, Effort: "high"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "managed-identity", "rbac"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleAzurePublicStorageBlob() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AZURE-002",
		Name:        "Public Azure Blob Container",
		Description: "Azure blob container allows anonymous public access",
		Severity:    SeverityCritical,
		Tags:        []string{"azure", "storage", "blob", "data-exposure", "public-access"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindBucket || node.Provider != "azure" {
				return nil
			}

			// Check public access level
			publicAccess, _ := node.Properties["public_access"].(string)
			allowBlobPublicAccess, _ := node.Properties["allow_blob_public_access"].(bool)

			// Public access can be "blob", "container", or "" (none)
			if publicAccess == "" && !allowBlobPublicAccess {
				return nil
			}

			isPublic := publicAccess == "blob" || publicAccess == "container" || allowBlobPublicAccess

			if !isPublic {
				return nil
			}

			// Check for sensitive data indicators
			hasSensitiveData := false
			dataClassification := node.PropertyString("data_classification")
			if dataClassification == "confidential" || dataClassification == "restricted" {
				hasSensitiveData = true
			}

			// Check container name for sensitive patterns
			containerName := strings.ToLower(node.Name)
			for _, pattern := range sensitiveDataPatterns {
				if strings.Contains(containerName, pattern) {
					hasSensitiveData = true
					break
				}
			}

			if !hasSensitiveData {
				return nil
			}

			score := 88.0
			if publicAccess == "container" {
				score = 95.0 // Container-level access is worse than blob-level
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AZURE-002-%s", node.ID),
				Name:        "Public Blob Container with Sensitive Data",
				Description: fmt.Sprintf("Blob container %s allows public access and likely contains sensitive data", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: fmt.Sprintf("Container has public access level: %s", publicAccess), Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Container name or classification indicates sensitive data", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Set public access level to 'None' on the container", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Disable 'Allow Blob public access' on storage account", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Use Azure Policy to enforce private access", Resource: "subscription", Effort: "medium"},
					{Priority: 4, Action: "Enable diagnostic logging and alerts", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"azure", "storage", "data-exposure", "compliance"},
			}
		},
	}
}
