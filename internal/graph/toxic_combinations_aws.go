package graph

import (
	"fmt"
	"strings"
)

func (e *ToxicCombinationEngine) ruleIMDSv1WithSensitiveRole() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-001",
		Name:        "IMDSv1 Enabled with Sensitive Role",
		Description: "EC2 instance with IMDSv1 (no hop limit) and privileged IAM role",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "imds", "ssrf", "credential-theft", "mitre-t1552"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindInstance || node.Provider != "aws" {
				return nil
			}

			// Default to unsafe if IMDSv2 settings are missing.
			imdsV2Required := readBool(node.Properties, "imdsv2_required")
			httpTokens := strings.ToLower(readString(node.Properties, "http_tokens"))
			if imdsV2Required || httpTokens == "required" {
				return nil
			}

			// Check if instance has a sensitive role attached
			hasSensitiveRole := false
			var roleID string
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAssume {
					roleNode, ok := g.GetNode(edge.Target)
					if !ok || roleNode.Kind != NodeKindRole {
						continue
					}
					roleID = roleNode.ID

					// Check if role has sensitive permissions
					for _, roleEdge := range g.GetOutEdges(roleNode.ID) {
						if roleEdge.Kind == EdgeKindCanAdmin ||
							roleEdge.Kind == EdgeKindCanWrite {
							hasSensitiveRole = true
							break
						}
					}

					// Also check for specific dangerous permissions
					perms := getNodePermissions(roleNode)
					for _, p := range perms {
						if strings.Contains(p, "iam:") ||
							strings.Contains(p, "sts:AssumeRole") ||
							strings.Contains(p, "secretsmanager:") ||
							strings.Contains(p, "ssm:GetParameter") ||
							p == "*" {
							hasSensitiveRole = true
							break
						}
					}
				}
				if hasSensitiveRole {
					break
				}
			}

			if !hasSensitiveRole {
				return nil
			}

			// Check if publicly exposed (increases severity)
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

			score := 85.0
			if isPublic {
				score = 95.0
			}

			factors := []*RiskFactor{
				{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "IMDSv1 enabled (HttpTokens not required)", Severity: SeverityCritical},
				{Type: RiskFactorOverPrivilege, NodeID: roleID, Description: "Instance role has sensitive permissions", Severity: SeverityHigh},
			}
			if isPublic {
				factors = append(factors, &RiskFactor{
					Type: RiskFactorExposure, NodeID: node.ID,
					Description: "Instance is publicly accessible", Severity: SeverityCritical,
				})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-001-%s", node.ID),
				Name:        "SSRF-Vulnerable Instance with Privileged Role",
				Description: fmt.Sprintf("Instance %s has IMDSv1 enabled with sensitive IAM role - SSRF attacks can steal credentials", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Enable IMDSv2 by setting HttpTokens=required", Resource: node.ID, Effort: "low", Automated: true},
					{Priority: 2, Action: "Set HttpPutResponseHopLimit=1 to prevent container escapes", Resource: node.ID, Effort: "low", Automated: true},
					{Priority: 3, Action: "Review and minimize instance role permissions", Resource: roleID, Effort: "medium"},
				},
				AffectedAssets: []string{node.ID, roleID},
				Tags:           []string{"aws", "imds", "ssrf", "mitre-t1552"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleS3PublicBucketWithSensitiveData() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-002",
		Name:        "Public S3 Bucket with Sensitive Data",
		Description: "S3 bucket is publicly accessible and contains sensitive data",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "s3", "data-exposure", "public-access"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindBucket || node.Provider != "aws" {
				return nil
			}

			// Check if bucket is public
			isPublic, _ := node.Properties["public_access"].(bool)
			publicACL, _ := node.Properties["public_acl"].(bool)
			blockPublicAccess, _ := node.Properties["block_public_access"].(bool)

			if !isPublic && !publicACL && blockPublicAccess {
				return nil
			}

			// Check if bucket contains sensitive data
			hasSensitiveData := false
			dataClassification := node.PropertyString("data_classification")
			containsPII, _ := node.PropertyBool("contains_pii")
			containsSecrets, _ := node.PropertyBool("contains_secrets")

			if dataClassification == "confidential" || dataClassification == "restricted" ||
				containsPII || containsSecrets {
				hasSensitiveData = true
			}

			// Also check via graph edges for secrets that bucket can read
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanRead || edge.Kind == EdgeKindConnectsTo {
					target, ok := g.GetNode(edge.Target)
					if ok && target.Kind == NodeKindSecret {
						hasSensitiveData = true
						break
					}
				}
			}

			if !hasSensitiveData {
				return nil
			}

			// Check encryption status
			encrypted, _ := node.Properties["encrypted"].(bool)

			score := 90.0
			if !encrypted {
				score = 98.0
			}

			factors := []*RiskFactor{
				{Type: RiskFactorExposure, NodeID: node.ID, Description: "Bucket allows public access", Severity: SeverityCritical},
				{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Contains sensitive/classified data", Severity: SeverityCritical},
			}
			if !encrypted {
				factors = append(factors, &RiskFactor{
					Type: RiskFactorMisconfiguration, NodeID: node.ID,
					Description: "Bucket is not encrypted", Severity: SeverityHigh,
				})
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-002-%s", node.ID),
				Name:        "Public Bucket with Sensitive Data",
				Description: fmt.Sprintf("S3 bucket %s is publicly accessible and contains sensitive data - data breach risk", node.Name),
				Severity:    SeverityCritical,
				Score:       score,
				Factors:     factors,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Enable S3 Block Public Access at bucket level", Resource: node.ID, Effort: "low", Automated: true},
					{Priority: 2, Action: "Review and remove public ACLs", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Enable server-side encryption (SSE-S3 or SSE-KMS)", Resource: node.ID, Effort: "low", Automated: true},
					{Priority: 4, Action: "Enable access logging and configure alerts", Resource: node.ID, Effort: "medium"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"aws", "s3", "data-exposure", "compliance"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleLambdaVPCSecretsAccess() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-003",
		Name:        "Lambda VPC with Secrets Access",
		Description: "Lambda in VPC can access secrets and has internet egress",
		Severity:    SeverityHigh,
		Tags:        []string{"aws", "lambda", "secrets", "vpc", "data-exfiltration"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindFunction || node.Provider != "aws" {
				return nil
			}

			// Check if Lambda is in VPC
			inVPC, _ := node.Properties["vpc_config"].(bool)
			vpcID, hasVPC := node.Properties["vpc_id"].(string)
			if !inVPC && !hasVPC {
				return nil
			}
			if vpcID == "" && !inVPC {
				return nil
			}

			// Check if Lambda has secrets access
			hasSecretsAccess := false
			var roleID string
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAssume {
					roleNode, ok := g.GetNode(edge.Target)
					if !ok || roleNode.Kind != NodeKindRole {
						continue
					}
					roleID = roleNode.ID

					perms := getNodePermissions(roleNode)
					for _, p := range perms {
						if strings.Contains(p, "secretsmanager:GetSecretValue") ||
							strings.Contains(p, "secretsmanager:*") ||
							strings.Contains(p, "ssm:GetParameter") ||
							strings.Contains(p, "ssm:GetParameters") {
							hasSecretsAccess = true
							break
						}
					}
				}
				if hasSecretsAccess {
					break
				}
			}

			if !hasSecretsAccess {
				return nil
			}

			// Check for internet egress (NAT Gateway or Internet Gateway)
			hasInternetEgress, _ := node.Properties["has_internet_egress"].(bool)
			hasNATGateway, _ := node.Properties["has_nat_gateway"].(bool)

			if !hasInternetEgress && !hasNATGateway {
				return nil // No egress path, lower risk
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-003-%s", node.ID),
				Name:        "Lambda with Secrets Access and Internet Egress",
				Description: fmt.Sprintf("Lambda %s can read secrets and has internet egress - potential data exfiltration path", node.Name),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorSensitiveData, NodeID: roleID, Description: "Can access secrets (SecretsManager/SSM)", Severity: SeverityHigh},
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Has internet egress via NAT/IGW", Severity: SeverityMedium},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: "Potential data exfiltration path", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Use VPC endpoints for SecretsManager/SSM instead of NAT", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "Restrict Lambda security group egress rules", Resource: node.ID, Effort: "low"},
					{Priority: 3, Action: "Implement least-privilege for secrets access", Resource: roleID, Effort: "medium"},
					{Priority: 4, Action: "Enable VPC Flow Logs for monitoring", Resource: vpcID, Effort: "low"},
				},
				AffectedAssets: []string{node.ID, roleID},
				Tags:           []string{"aws", "lambda", "secrets", "exfiltration"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleLambdaPublicInlinePolicyDynamoTrigger() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-004",
		Name:        "Public Lambda URL with Inline Policy and DynamoDB Trigger",
		Description: "Publicly callable Lambda has inline policy and DynamoDB-triggered write path",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "lambda", "dynamodb", "supply-chain", "cross-service"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindFunction || node.Provider != "aws" {
				return nil
			}

			functionURL := readString(node.Properties, "function_url", "public_function_url", "public_url")
			hasPublicURL := functionURL != "" ||
				readBool(node.Properties, "public_function_url_enabled", "url_public", "public_access")
			if !hasPublicURL {
				return nil
			}

			hasInlinePolicy := readBool(node.Properties, "has_inline_policy", "inline_policy", "uses_inline_policy")
			if !hasInlinePolicy {
				policyType := strings.ToLower(readString(node.Properties, "policy_type", "policy_source"))
				hasInlinePolicy = strings.Contains(policyType, "inline")
			}
			if !hasInlinePolicy {
				return nil
			}

			// Detect DynamoDB trigger/event mapping attached to the function.
			triggeredDatabases := make([]string, 0)
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind != EdgeKindConnectsTo {
					continue
				}
				target, ok := g.GetNode(edge.Target)
				if !ok || target.Kind != NodeKindDatabase || !isDynamoDBNode(target) {
					continue
				}
				eventSource := strings.ToLower(readString(edge.Properties, "event_source", "source", "service"))
				if eventSource == "" || strings.Contains(eventSource, "dynamodb") || strings.Contains(eventSource, "stream") {
					triggeredDatabases = append(triggeredDatabases, target.ID)
				}
			}
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind != EdgeKindConnectsTo {
					continue
				}
				source, ok := g.GetNode(edge.Source)
				if !ok || source.Kind != NodeKindDatabase || !isDynamoDBNode(source) {
					continue
				}
				eventSource := strings.ToLower(readString(edge.Properties, "event_source", "source", "service"))
				if eventSource == "" || strings.Contains(eventSource, "dynamodb") || strings.Contains(eventSource, "stream") {
					triggeredDatabases = append(triggeredDatabases, source.ID)
				}
			}
			triggeredDatabases = dedupeStrings(triggeredDatabases)
			if len(triggeredDatabases) == 0 {
				return nil
			}

			// Validate attached role can modify DynamoDB data.
			hasDynamoWrite := false
			roleID := ""
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind != EdgeKindCanAssume {
					continue
				}
				role, ok := g.GetNode(edge.Target)
				if !ok || !role.IsIdentity() {
					continue
				}
				roleID = role.ID
				if hasDynamoDBWriteAccess(g, role) {
					hasDynamoWrite = true
					break
				}
			}
			if !hasDynamoWrite {
				return nil
			}

			affected := append([]string{node.ID, roleID}, triggeredDatabases...)
			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-004-%s", node.ID),
				Name:        "Public Lambda with Inline Policy + DynamoDB Trigger",
				Description: fmt.Sprintf("Lambda %s is public, inline-policy managed, and can modify DynamoDB via trigger path", node.Name),
				Severity:    SeverityCritical,
				Score:       93.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Lambda Function URL is publicly reachable", Severity: SeverityCritical},
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Function uses inline IAM policy", Severity: SeverityHigh},
					{Type: RiskFactorLateralMove, NodeID: roleID, Description: "Execution role can write DynamoDB data", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Disable public Function URL or enforce auth_type=AWS_IAM", Resource: node.ID, Effort: "low", Automated: true},
					{Priority: 2, Action: "Replace inline IAM policy with tightly scoped managed policy", Resource: roleID, Effort: "medium"},
					{Priority: 3, Action: "Restrict DynamoDB write actions to required tables/keys only", Resource: roleID, Effort: "medium"},
				},
				AffectedAssets: dedupeStrings(affected),
				Tags:           []string{"aws", "lambda", "dynamodb", "supply-chain"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) rulePublicRDSUnencryptedHighBlastRadius() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-005",
		Name:        "Public Unencrypted RDS with High Blast Radius",
		Description: "Publicly reachable unencrypted RDS instance is accessible by many identities",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "rds", "encryption", "data-exposure", "blast-radius"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindDatabase || node.Provider != "aws" {
				return nil
			}

			isPublic := readBool(node.Properties, "publicly_accessible", "public_access", "internet_accessible")
			if !isPublic && !isExposedToInternet(g, node.ID) {
				return nil
			}

			encrypted := readBool(node.Properties, "encrypted", "storage_encrypted", "at_rest_encryption_enabled", "kms_encrypted")
			if encrypted {
				return nil
			}

			accessors := ReverseAccess(g, node.ID, 3)
			if accessors.TotalCount == 0 {
				return nil
			}

			// High blast radius: many accessors or cross-account accessor spread.
			foreignAccounts := make(map[string]bool)
			for _, accessor := range accessors.AccessibleBy {
				if accessor.Node == nil || accessor.Node.Account == "" || accessor.Node.Account == node.Account {
					continue
				}
				foreignAccounts[accessor.Node.Account] = true
			}
			if accessors.TotalCount < 5 && len(foreignAccounts) == 0 {
				return nil
			}

			score := 89.0
			if accessors.TotalCount >= 10 || len(foreignAccounts) > 0 {
				score = 96.0
			}

			affected := []string{node.ID}
			for _, accessor := range accessors.AccessibleBy {
				if accessor.Node != nil {
					affected = append(affected, accessor.Node.ID)
				}
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-005-%s", node.ID),
				Name:        "Public Unencrypted RDS with Broad Reachability",
				Description: fmt.Sprintf("Database %s is public, unencrypted, and reachable by %d identities", node.Name, accessors.TotalCount),
				Severity:    SeverityCritical,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "RDS instance is publicly reachable", Severity: SeverityCritical},
					{Type: RiskFactorMisconfiguration, NodeID: node.ID, Description: "Storage encryption is disabled", Severity: SeverityCritical},
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: fmt.Sprintf("Reachable by %d identities", accessors.TotalCount), Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Disable public accessibility and restrict to private subnets", Resource: node.ID, Effort: "medium", Automated: true},
					{Priority: 2, Action: "Enable storage encryption (KMS) and snapshot encryption", Resource: node.ID, Effort: "medium"},
					{Priority: 3, Action: "Reduce IAM/database principals with access", Resource: node.ID, Effort: "high"},
				},
				AffectedAssets: dedupeStrings(affected),
				Tags:           []string{"aws", "rds", "public", "unencrypted"},
			}
		},
	}
}

func (e *ToxicCombinationEngine) ruleCrossAccountTransitiveTrustChain() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-006",
		Name:        "Transitive Cross-Account Trust Chain to Sensitive Resource",
		Description: "Assume-role chain spans multiple accounts and reaches sensitive assets",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "cross-account", "transitive-trust", "iam"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsIdentity() || node.Provider != "aws" {
				return nil
			}

			startAccount := node.Account
			type chainState struct {
				nodeID         string
				path           []string
				foreignAccount map[string]bool
			}

			queue := []chainState{{
				nodeID:         node.ID,
				path:           []string{node.ID},
				foreignAccount: map[string]bool{},
			}}

			for len(queue) > 0 {
				state := queue[0]
				queue = queue[1:]

				if len(state.path) > 5 {
					continue
				}

				for _, edge := range g.GetOutEdges(state.nodeID) {
					if edge.Kind != EdgeKindCanAssume || edge.IsDeny() {
						continue
					}

					target, ok := g.GetNode(edge.Target)
					if !ok || !target.IsIdentity() {
						continue
					}
					if target.Provider != "" && target.Provider != "aws" {
						continue
					}
					if containsString(state.path, target.ID) {
						continue
					}

					nextForeignAccounts := cloneStringBoolMap(state.foreignAccount)
					targetAccount := target.Account
					if targetAccount == "" {
						targetAccount = readString(edge.Properties, "target_account")
					}
					if targetAccount != "" && targetAccount != startAccount {
						nextForeignAccounts[targetAccount] = true
					}

					nextPath := append(append([]string(nil), state.path...), target.ID)

					for _, resourceEdge := range g.GetOutEdges(target.ID) {
						if resourceEdge.IsDeny() {
							continue
						}
						if resourceEdge.Kind != EdgeKindCanAdmin &&
							resourceEdge.Kind != EdgeKindCanWrite &&
							resourceEdge.Kind != EdgeKindCanRead {
							continue
						}

						resource, ok := g.GetNode(resourceEdge.Target)
						if !ok || !resource.IsResource() {
							continue
						}
						if resource.Risk != RiskCritical && resource.Risk != RiskHigh {
							continue
						}
						if len(nextForeignAccounts) < 2 {
							continue
						}

						affected := append([]string(nil), nextPath...)
						affected = append(affected, resource.ID)

						return &ToxicCombination{
							ID:          fmt.Sprintf("TC-AWS-006-%s", node.ID),
							Name:        "Transitive Cross-Account Trust Chain",
							Description: fmt.Sprintf("Identity %s can traverse %d foreign accounts to reach sensitive resource %s", node.Name, len(nextForeignAccounts), resource.Name),
							Severity:    SeverityCritical,
							Score:       94.0,
							Factors: []*RiskFactor{
								{Type: RiskFactorCrossAccount, NodeID: node.ID, Description: "Multi-hop cross-account assume-role path detected", Severity: SeverityCritical},
								{Type: RiskFactorOverPrivilege, NodeID: target.ID, Description: "Terminal role can access sensitive resource", Severity: SeverityHigh},
								{Type: RiskFactorSensitiveData, NodeID: resource.ID, Description: "Sensitive target reachable through trust chain", Severity: SeverityCritical},
							},
							Remediation: []*RemediationStep{
								{Priority: 1, Action: "Break transitive assume-role links across accounts", Resource: target.ID, Effort: "high"},
								{Priority: 2, Action: "Add external ID and principal conditions to trust policies", Resource: target.ID, Effort: "medium"},
								{Priority: 3, Action: "Scope sensitive resource permissions to local-account roles only", Resource: resource.ID, Effort: "medium"},
							},
							AffectedAssets: dedupeStrings(affected),
							Tags:           []string{"aws", "cross-account", "trust-chain"},
						}
					}

					queue = append(queue, chainState{
						nodeID:         target.ID,
						path:           nextPath,
						foreignAccount: nextForeignAccounts,
					})
				}
			}

			return nil
		},
	}
}

func (e *ToxicCombinationEngine) ruleExposedComputeWithKeyedAdminIdentity() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC-AWS-007",
		Name:        "Exposed Compute with Keyed Admin Identity",
		Description: "Internet-exposed compute can assume key-bearing administrative identity",
		Severity:    SeverityCritical,
		Tags:        []string{"aws", "identity", "access-keys", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindInstance || node.Provider != "aws" {
				return nil
			}
			if !isExposedToInternet(g, node.ID) {
				return nil
			}

			var riskyIdentity *Node
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind != EdgeKindCanAssume || edge.IsDeny() {
					continue
				}
				identity, ok := g.GetNode(edge.Target)
				if !ok || !identity.IsIdentity() {
					continue
				}
				if identity.Provider != "" && identity.Provider != "aws" {
					continue
				}
				if !hasAccessKeys(identity) {
					continue
				}
				if !hasAdministrativeAccess(g, identity) {
					continue
				}
				riskyIdentity = identity
				break
			}

			if riskyIdentity == nil {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC-AWS-007-%s", node.ID),
				Name:        "Exposed Compute with Keyed Admin Identity",
				Description: fmt.Sprintf("Instance %s can assume %s which has long-lived keys and admin-level access", node.Name, riskyIdentity.Name),
				Severity:    SeverityCritical,
				Score:       91.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Compute workload is internet exposed", Severity: SeverityCritical},
					{Type: RiskFactorWeakAuth, NodeID: riskyIdentity.ID, Description: "Identity has long-lived access keys", Severity: SeverityHigh},
					{Type: RiskFactorOverPrivilege, NodeID: riskyIdentity.ID, Description: "Identity has administrative permissions", Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove public exposure path from compute workload", Resource: node.ID, Effort: "medium"},
					{Priority: 2, Action: "Eliminate long-lived access keys and enforce temporary credentials", Resource: riskyIdentity.ID, Effort: "high"},
					{Priority: 3, Action: "Scope down administrative permissions on assumed identity", Resource: riskyIdentity.ID, Effort: "medium"},
				},
				AffectedAssets: []string{node.ID, riskyIdentity.ID},
				Tags:           []string{"aws", "keys", "admin", "exposure"},
			}
		},
	}
}

func isDynamoDBNode(node *Node) bool {
	if node == nil || node.Kind != NodeKindDatabase {
		return false
	}

	engine := strings.ToLower(readString(node.Properties, "engine", "service", "type"))
	if strings.Contains(engine, "dynamodb") {
		return true
	}

	name := strings.ToLower(node.Name + " " + node.ID)
	return strings.Contains(name, "dynamodb")
}

func hasDynamoDBWriteAccess(g *Graph, node *Node) bool {
	if node == nil || !node.IsIdentity() {
		return false
	}

	for _, edge := range g.GetOutEdges(node.ID) {
		if edge.Kind != EdgeKindCanWrite && edge.Kind != EdgeKindCanAdmin {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if ok && isDynamoDBNode(target) {
			return true
		}
	}

	for _, permission := range getNodePermissions(node) {
		p := strings.ToLower(permission)
		if p == "*" || p == "dynamodb:*" {
			return true
		}
		if p == "dynamodb:putitem" || p == "dynamodb:updateitem" || p == "dynamodb:batchwriteitem" {
			return true
		}
	}

	return false
}

func hasAccessKeys(node *Node) bool {
	if node == nil {
		return false
	}
	if readBool(node.Properties, "has_access_keys", "access_keys_enabled") {
		return true
	}
	if readInt(node.Properties, "access_key_count", "key_count") > 0 {
		return true
	}
	if keys, ok := node.Properties["access_keys"].([]any); ok && len(keys) > 0 {
		return true
	}
	return false
}

func hasAdministrativeAccess(g *Graph, node *Node) bool {
	if node == nil || !node.IsIdentity() {
		return false
	}

	for _, edge := range g.GetOutEdges(node.ID) {
		if edge.Kind == EdgeKindCanAdmin {
			return true
		}
	}

	for _, permission := range getNodePermissions(node) {
		p := strings.ToLower(permission)
		if p == "*" || strings.HasSuffix(p, ":*") {
			return true
		}
		if strings.HasPrefix(p, "iam:") || strings.Contains(p, "admin") {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneStringBoolMap(source map[string]bool) map[string]bool {
	cloned := make(map[string]bool, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
