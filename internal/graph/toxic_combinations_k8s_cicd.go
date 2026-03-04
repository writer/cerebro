package graph

import (
	"fmt"
	"strings"
)

func (e *ToxicCombinationEngine) rulePrivilegedPodWithHostPath() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-K8S-001",
		Name:        "Privileged Pod with Host Path Mount",
		Description: "Pod runs privileged with host filesystem mounted, enabling container escape",
		Severity:    SeverityCritical,
		Tags:        []string{"kubernetes", "container-escape", "privileged", "mitre-t1611"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindPod {
				return nil
			}

			isPrivileged, _ := node.Properties["privileged"].(bool)
			hasHostPath, _ := node.Properties["host_path_volumes"].(bool)
			runAsRoot, _ := node.Properties["run_as_root"].(bool)

			if !isPrivileged || !hasHostPath {
				return nil
			}

			score := 85.0
			if runAsRoot {
				score = 95.0
			}

			factors := []*RiskFactor{
				{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Privileged security context", Severity: SeverityCritical},
				{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Host filesystem mounted via hostPath", Severity: SeverityCritical},
			}
			if runAsRoot {
				factors = append(factors, &RiskFactor{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Running as root user", Severity: SeverityHigh})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-K8S-001-%s", node.ID),
				Name:        "Privileged Container with Host Access",
				Description: fmt.Sprintf("Pod %s runs privileged with hostPath mount - trivial container escape possible", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove privileged: true from security context", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Replace hostPath volumes with PVC or ConfigMap", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Enable Pod Security Standards (restricted profile)", Resource: "namespace", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"kubernetes", "container-escape", "mitre-t1611"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleRBACWildcardSecrets() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-K8S-002",
		Name:        "RBAC Wildcard on Secrets",
		Description: "ClusterRole grants wildcard permissions on secrets resources",
		Severity:    SeverityCritical,
		Tags:        []string{"kubernetes", "rbac", "secrets", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindClusterRole {
				return nil
			}

			// Check for wildcard verbs on secrets
			rules, ok := node.Properties["rules"].([]any)
			if !ok {
				return nil
			}

			hasSecretWildcard := false
			for _, r := range rules {
				rule, ok := r.(map[string]any)
				if !ok {
					continue
				}
				resources, _ := rule["resources"].([]any)
				verbs, _ := rule["verbs"].([]any)

				hasSecrets := false
				hasWildcardVerb := false
				for _, res := range resources {
					if res == "secrets" || res == "*" {
						hasSecrets = true
						break
					}
				}
				for _, verb := range verbs {
					if verb == "*" {
						hasWildcardVerb = true
						break
					}
				}
				if hasSecrets && hasWildcardVerb {
					hasSecretWildcard = true
					break
				}
			}

			if !hasSecretWildcard {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-K8S-002-%s", node.ID),
				Name:        "Overprivileged RBAC - Secret Access",
				Description: fmt.Sprintf("ClusterRole %s grants wildcard (*) access to secrets - credential theft risk", node.Name),
				Severity:    SeverityCritical,
				Score:       90.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Wildcard verbs on secrets resource", Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Can access all secrets in cluster", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Replace wildcard verbs with specific verbs (get, list)", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Limit to specific secret names using resourceNames", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Use namespaced Role instead of ClusterRole", Resource: node.ID, Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"kubernetes", "rbac", "secrets"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleServiceAccountClusterAdmin() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-K8S-003",
		Name:        "Service Account with Cluster-Admin",
		Description: "Service account bound to cluster-admin role used by workload",
		Severity:    SeverityCritical,
		Tags:        []string{"kubernetes", "rbac", "cluster-admin", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindServiceAccount {
				return nil
			}

			// Check if SA has cluster-admin binding
			hasClusterAdmin := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAssume {
					target, ok := g.GetNode(edge.Target)
					if ok && target.Kind == NodeKindClusterRole && target.Name == "cluster-admin" {
						hasClusterAdmin = true
						break
					}
				}
			}

			if !hasClusterAdmin {
				return nil
			}

			// Find pods using this service account
			var affectedPods []string
			for _, inEdge := range g.GetInEdges(node.ID) {
				source, ok := g.GetNode(inEdge.Source)
				if ok && source.Kind == NodeKindPod {
					affectedPods = append(affectedPods, source.ID)
				}
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-K8S-003-%s", node.ID),
				Name:        "Cluster-Admin Service Account",
				Description: fmt.Sprintf("Service account %s has cluster-admin privileges - full cluster compromise if workload is breached", node.Name),
				Severity:    SeverityCritical,
				Score:       95.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Bound to cluster-admin role", Severity: SeverityCritical},
					{Type: RiskFactorPrivEscalation, NodeID: node.ID, Description: "Can escalate to any privilege in cluster", Severity: SeverityCritical},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Create dedicated Role with minimum required permissions", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "Remove cluster-admin binding", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Enable audit logging for this service account", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: append([]string{node.ID}, affectedPods...),
				Tags:           []string{"kubernetes", "rbac", "cluster-admin"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) rulePodServiceAccountTokenMount() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-K8S-004",
		Name:        "Service Account Token Auto-Mount with Secrets Access",
		Description: "Pod automounts SA token where SA has secrets read access",
		Severity:    SeverityHigh,
		Tags:        []string{"kubernetes", "service-account", "secrets", "credential-theft"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindPod {
				return nil
			}

			// Check if automountServiceAccountToken is enabled (default: true)
			autoMount, ok := node.Properties["automount_service_account_token"].(bool)
			if ok && !autoMount {
				return nil // Explicitly disabled
			}

			// Find the service account
			var saNode *Node
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAssume {
					target, ok := g.GetNode(edge.Target)
					if ok && target.Kind == NodeKindServiceAccount {
						saNode = target
						break
					}
				}
			}

			if saNode == nil {
				return nil
			}

			// Check if SA has secrets access
			hasSecretsAccess := false
			for _, edge := range g.GetOutEdges(saNode.ID) {
				if edge.Kind == EdgeKindCanRead || edge.Kind == EdgeKindCanWrite {
					target, ok := g.GetNode(edge.Target)
					if ok && target.Kind == NodeKindSecret {
						hasSecretsAccess = true
						break
					}
				}
			}

			if !hasSecretsAccess {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-K8S-004-%s", node.ID),
				Name:        "Auto-Mounted Token with Secrets Access",
				Description: fmt.Sprintf("Pod %s automounts SA token that has secrets access - credential theft via pod compromise", node.Name),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "automountServiceAccountToken not disabled", Severity: SeverityMedium},
					{Type: RiskFactorSensitiveData, NodeID: saNode.ID, Description: "Service account can read secrets", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Set automountServiceAccountToken: false in pod spec", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Use projected service account tokens with audience binding", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Remove unnecessary secrets permissions from service account", Resource: saNode.ID, Effort: "medium"},
				},
				AffectedAssets: []string{node.ID, saNode.ID},
				Tags:           []string{"kubernetes", "service-account", "secrets"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleGitHubActionsOIDCOverprivileged() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-CICD-001",
		Name:        "GitHub Actions OIDC with Admin Permissions",
		Description: "GitHub workflow can assume AWS role with admin permissions",
		Severity:    SeverityCritical,
		Tags:        []string{"cicd", "github-actions", "oidc", "supply-chain"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindRole || node.Provider != "aws" {
				return nil
			}

			// Check if role trusts GitHub OIDC
			trustPolicy, _ := node.Properties["trust_policy"].(string)
			if !strings.Contains(trustPolicy, "token.actions.githubusercontent.com") {
				return nil
			}

			// Check if role has admin permissions
			hasAdmin := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin {
					hasAdmin = true
					break
				}
			}

			if !hasAdmin {
				return nil
			}

			// Check for weak subject conditions
			hasWeakCondition := strings.Contains(trustPolicy, "repo:*") ||
				!strings.Contains(trustPolicy, "StringEquals")

			score := 80.0
			if hasWeakCondition {
				score = 95.0
			}

			factors := []*RiskFactor{
				{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Role has admin-level permissions", Severity: SeverityCritical},
				{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: "Trusts external CI/CD provider (GitHub)", Severity: SeverityHigh},
			}
			if hasWeakCondition {
				factors = append(factors, &RiskFactor{
					Type: RiskFactorMisconfiguration, NodeID: node.ID,
					Description: "Weak or missing OIDC subject conditions", Severity: SeverityCritical,
				})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-CICD-001-%s", node.ID),
				Name:        "Overprivileged GitHub Actions Role",
				Description: fmt.Sprintf("Role %s trusts GitHub Actions OIDC with admin permissions - supply chain attack vector", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Restrict OIDC subject condition to specific repo and branch", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Apply least-privilege permissions to the role", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Add environment protection rules in GitHub", Resource: "github", Effort: "low"},
					{Priority: 4, Action: "Enable CloudTrail logging for role assumption", Resource: node.ID, Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"cicd", "github-actions", "supply-chain", "mitre-t1195"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleEKSNodeRoleECRPush() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-CICD-002",
		Name:        "EKS Node Role with ECR Push",
		Description: "EKS worker node role can push to ECR - supply chain compromise risk",
		Severity:    SeverityHigh,
		Tags:        []string{"eks", "ecr", "supply-chain", "over-privilege"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindRole || node.Provider != "aws" {
				return nil
			}

			// Check if this is an EKS node role
			roleName, _ := node.Properties["name"].(string)
			isNodeRole := strings.Contains(strings.ToLower(roleName), "node") &&
				(strings.Contains(strings.ToLower(roleName), "eks") ||
					strings.Contains(strings.ToLower(roleName), "kubernetes"))

			trustPolicy, _ := node.Properties["trust_policy"].(string)
			trustsEC2 := strings.Contains(trustPolicy, "ec2.amazonaws.com")

			if !isNodeRole && !trustsEC2 {
				return nil
			}

			// Check for ECR push permissions
			hasECRPush := false
			perms := getNodePermissions(node)
			for _, p := range perms {
				if strings.Contains(p, "ecr:PutImage") ||
					strings.Contains(p, "ecr:BatchCheckLayerAvailability") ||
					strings.Contains(p, "ecr:InitiateLayerUpload") ||
					strings.Contains(p, "ecr:*") {
					hasECRPush = true
					break
				}
			}

			if !hasECRPush {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-CICD-002-%s", node.ID),
				Name:        "EKS Node with ECR Push Permissions",
				Description: fmt.Sprintf("EKS node role %s can push images to ECR - compromised node could inject malicious images", node.Name),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Node role has ECR push permissions", Severity: SeverityHigh},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: "Could inject malicious container images", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove ECR push permissions from node role", Resource: node.ID, Effort: "low"},
					{Priority: 2, Action: "Use dedicated CI/CD role for image pushing", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Enable ECR image scanning and signing", Resource: "ecr", Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"eks", "ecr", "supply-chain"},
			}
		},
	}
}
