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

			// Check IMDS version - IMDSv2 requires HttpTokens=required
			imdsV2Required, _ := node.Properties["imdsv2_required"].(bool)
			httpTokens, _ := node.Properties["http_tokens"].(string)
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
			dataClassification, _ := node.Properties["data_classification"].(string)
			containsPII, _ := node.Properties["contains_pii"].(bool)
			containsSecrets, _ := node.Properties["contains_secrets"].(bool)

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
