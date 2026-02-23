package graph

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ToxicCombination represents a dangerous combination of risk factors
type ToxicCombination struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	Severity       Severity           `json:"severity"`
	Score          float64            `json:"score"` // 0-100
	Factors        []*RiskFactor      `json:"factors"`
	AttackPath     *AttackPath        `json:"attack_path"`
	Remediation    []*RemediationStep `json:"remediation"`
	AffectedAssets []string           `json:"affected_assets"`
	Tags           []string           `json:"tags"`
}

// Severity levels for toxic combinations
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// RiskFactor represents a single risk component
type RiskFactor struct {
	Type        RiskFactorType `json:"type"`
	NodeID      string         `json:"node_id"`
	Description string         `json:"description"`
	Evidence    string         `json:"evidence,omitempty"`
	Severity    Severity       `json:"severity"`
}

// RiskFactorType categorizes risk factors
type RiskFactorType string

const (
	RiskFactorExposure         RiskFactorType = "network_exposure"
	RiskFactorVulnerability    RiskFactorType = "vulnerability"
	RiskFactorMisconfiguration RiskFactorType = "misconfiguration"
	RiskFactorOverPrivilege    RiskFactorType = "over_privilege"
	RiskFactorSensitiveData    RiskFactorType = "sensitive_data"
	RiskFactorWeakAuth         RiskFactorType = "weak_authentication"
	RiskFactorCrossAccount     RiskFactorType = "cross_account_access"
	RiskFactorPrivEscalation   RiskFactorType = "privilege_escalation"
	RiskFactorLateralMove      RiskFactorType = "lateral_movement"
)

// sensitiveDataPatterns are common patterns indicating sensitive data in resource names
var sensitiveDataPatterns = []string{
	"backup", "log", "audit", "secret", "credential", "key",
	"password", "config", "private", "internal", "pii", "phi",
	"confidential", "restricted", "sensitive",
}

// RemediationStep describes how to fix part of a toxic combination
type RemediationStep struct {
	Priority  int    `json:"priority"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Impact    string `json:"impact"`
	Effort    string `json:"effort"` // low, medium, high
	Automated bool   `json:"automated"`
}

// AttackPath represents a validated path an attacker could take
type AttackPath struct {
	ID             string        `json:"id"`
	EntryPoint     *Node         `json:"entry_point"`
	Target         *Node         `json:"target"`
	Steps          []*AttackStep `json:"steps"`
	TotalRisk      float64       `json:"total_risk"`
	Exploitability float64       `json:"exploitability"` // 0-1, how easy to exploit
	Impact         float64       `json:"impact"`         // 0-1, business impact
	Likelihood     float64       `json:"likelihood"`     // 0-1, probability
}

// AttackStep represents one hop in an attack path
type AttackStep struct {
	Order             int      `json:"order"`
	FromNode          string   `json:"from_node"`
	ToNode            string   `json:"to_node"`
	Technique         string   `json:"technique"`
	Description       string   `json:"description"`
	EdgeKind          EdgeKind `json:"edge_kind"`
	RequiredPrivilege string   `json:"required_privilege,omitempty"`
	MITREAttackID     string   `json:"mitre_attack_id,omitempty"`
}

// ToxicCombinationRule defines a pattern to detect
type ToxicCombinationRule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Tags        []string
	Detector    func(g *Graph, node *Node) *ToxicCombination
}

// ToxicCombinationEngine detects dangerous security patterns
type ToxicCombinationEngine struct {
	rules []*ToxicCombinationRule
}

// NewToxicCombinationEngine creates an engine with default rules.
// It uses the global rule registry for automatic registration and validation.
func NewToxicCombinationEngine() *ToxicCombinationEngine {
	// Use registry-based initialization which validates all rules
	RegisterAllRules()
	engine := &ToxicCombinationEngine{
		rules: GlobalRegistry().GetEnabledRules(),
	}
	if len(engine.rules) == 0 {
		engine.registerDefaultRules()
	}
	return engine
}

// Analyze scans the graph for all toxic combinations
func (e *ToxicCombinationEngine) Analyze(g *Graph) []*ToxicCombination {
	var results []*ToxicCombination
	var mu sync.Mutex
	var wg sync.WaitGroup

	nodes := g.GetAllNodes()
	sem := make(chan struct{}, 32)

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go func(n *Node) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, rule := range e.rules {
				if tc := rule.Detector(g, n); tc != nil {
					mu.Lock()
					results = append(results, tc)
					mu.Unlock()
				}
			}
		}(node)
	}

	wg.Wait()

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	// Deduplicate by ID
	seen := make(map[string]bool)
	deduped := make([]*ToxicCombination, 0, len(results))
	for _, tc := range results {
		if !seen[tc.ID] {
			seen[tc.ID] = true
			deduped = append(deduped, tc)
		}
	}

	return deduped
}

func (e *ToxicCombinationEngine) registerDefaultRules() {
	e.rules = []*ToxicCombinationRule{
		// Core cloud rules
		e.rulePublicExposedWithVuln(),
		e.rulePublicExposedWithSensitiveData(),
		e.ruleOverprivilegedWithCrownJewels(),
		e.ruleCrossAccountWithAdmin(),
		e.rulePrivilegeEscalationPath(),
		e.ruleLateralMovementToData(),
		e.ruleSecretsExposure(),
		e.ruleAdminWithNoMFA(),
		e.rulePublicDatabaseAccess(),
		e.ruleServiceAccountKeyExposure(),
		// AWS-specific rules
		e.ruleIMDSv1WithSensitiveRole(),
		e.ruleS3PublicBucketWithSensitiveData(),
		e.ruleLambdaVPCSecretsAccess(),
		// GCP-specific rules
		e.ruleGCPServiceAccountKeyExposed(),
		e.ruleGCPPublicGCSBucket(),
		e.ruleGCPComputeDefaultSA(),
		// Azure-specific rules
		e.ruleAzureManagedIdentityOverprivileged(),
		e.ruleAzurePublicStorageBlob(),
		// Kubernetes rules
		e.rulePrivilegedPodWithHostPath(),
		e.ruleRBACWildcardSecrets(),
		e.ruleServiceAccountClusterAdmin(),
		e.rulePodServiceAccountTokenMount(),
		// CI/CD supply chain rules
		e.ruleGitHubActionsOIDCOverprivileged(),
		e.ruleEKSNodeRoleECRPush(),
	}
}

// Rule: Public-facing resource with known vulnerability
func (e *ToxicCombinationEngine) rulePublicExposedWithVuln() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC001",
		Name:        "Public Exposure + Vulnerability",
		Description: "Internet-exposed resource with critical vulnerability",
		Severity:    SeverityCritical,
		Tags:        []string{"exposure", "vulnerability", "rce"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsResource() {
				return nil
			}

			// Check if exposed to internet
			isExposed := false
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind == EdgeKindExposedTo {
					sourceNode, _ := g.GetNode(edge.Source)
					if sourceNode != nil && sourceNode.Kind == NodeKindInternet {
						isExposed = true
						break
					}
				}
			}
			if !isExposed {
				return nil
			}

			// Check for vulnerabilities
			hasVuln := false
			var vulnEvidence string
			if findings, ok := node.Properties["vulnerabilities"].([]any); ok && len(findings) > 0 {
				hasVuln = true
				vulnEvidence = fmt.Sprintf("%d vulnerabilities found", len(findings))
			}
			if node.Risk == RiskCritical || node.Risk == RiskHigh {
				hasVuln = true
				if vulnEvidence == "" {
					vulnEvidence = fmt.Sprintf("Risk level: %s", node.Risk)
				}
			}

			if !hasVuln {
				return nil
			}

			// Build attack path
			path := &AttackPath{
				ID:             fmt.Sprintf("AP-%s-internet", node.ID),
				Target:         node,
				Exploitability: 0.9,
				Impact:         calculateNodeImpact(node),
			}
			path.Steps = []*AttackStep{
				{
					Order:         1,
					FromNode:      "internet",
					ToNode:        node.ID,
					Technique:     "Initial Access",
					Description:   "Exploit public-facing vulnerability",
					MITREAttackID: "T1190",
				},
			}
			path.TotalRisk = path.Exploitability * path.Impact
			path.Likelihood = 0.8

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC001-%s", node.ID),
				Name:        "Public Exposure + Vulnerability",
				Description: fmt.Sprintf("%s is exposed to the internet and has vulnerabilities that could be exploited", node.Name),
				Severity:    SeverityCritical,
				Score:       95.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Exposed to internet", Severity: SeverityHigh},
					{Type: RiskFactorVulnerability, NodeID: node.ID, Description: vulnEvidence, Severity: SeverityCritical},
				},
				AttackPath: path,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Patch vulnerabilities", Resource: node.ID, Impact: "Eliminates exploitation vector", Effort: "medium"},
					{Priority: 2, Action: "Restrict network access", Resource: node.ID, Impact: "Reduces attack surface", Effort: "low"},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"public", "vulnerability", "critical"},
			}
		},
	}
}

// Rule: Public-facing resource with path to sensitive data
func (e *ToxicCombinationEngine) rulePublicExposedWithSensitiveData() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC002",
		Name:        "Public Exposure + Sensitive Data Access",
		Description: "Internet-exposed resource can reach sensitive data",
		Severity:    SeverityCritical,
		Tags:        []string{"exposure", "data", "breach"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsResource() || node.Kind == NodeKindBucket {
				return nil
			}

			// Check if exposed
			isExposed := false
			for _, edge := range g.GetInEdges(node.ID) {
				if edge.Kind == EdgeKindExposedTo {
					isExposed = true
					break
				}
			}
			if !isExposed {
				return nil
			}

			// Check if can reach sensitive data
			sensitiveTargets := findSensitiveDataReachable(g, node.ID, 4)
			if len(sensitiveTargets) == 0 {
				return nil
			}

			// Build attack path
			path := buildAttackPath(g, "internet", sensitiveTargets[0].Node.ID, node.ID)
			if path == nil {
				return nil
			}

			affected := []string{node.ID}
			for _, t := range sensitiveTargets {
				affected = append(affected, t.Node.ID)
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC002-%s", node.ID),
				Name:        "Public Exposure to Sensitive Data",
				Description: fmt.Sprintf("Compromising %s could lead to access to %d sensitive data stores", node.Name, len(sensitiveTargets)),
				Severity:    SeverityCritical,
				Score:       90.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Internet-exposed entry point", Severity: SeverityHigh},
					{Type: RiskFactorSensitiveData, NodeID: sensitiveTargets[0].Node.ID, Description: fmt.Sprintf("Can reach %s", sensitiveTargets[0].Node.Name), Severity: SeverityCritical},
				},
				AttackPath:     path,
				AffectedAssets: affected,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Segment network to isolate sensitive data", Resource: sensitiveTargets[0].Node.ID, Impact: "Breaks attack path", Effort: "medium"},
					{Priority: 2, Action: "Add authentication/authorization", Resource: node.ID, Impact: "Prevents unauthorized access", Effort: "medium"},
				},
				Tags: []string{"exposure", "data-breach", "lateral-movement"},
			}
		},
	}
}

// Rule: Overprivileged identity with access to crown jewels
func (e *ToxicCombinationEngine) ruleOverprivilegedWithCrownJewels() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC003",
		Name:        "Overprivileged Identity + Crown Jewel Access",
		Description: "Identity with excessive permissions can access critical assets",
		Severity:    SeverityHigh,
		Tags:        []string{"iam", "privilege", "crown-jewels"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsIdentity() {
				return nil
			}

			// Check for admin permissions
			hasAdmin := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin {
					hasAdmin = true
					break
				}
			}

			// Check for wildcard permissions
			hasWildcard := false
			if policies, ok := node.Properties["policies"].([]any); ok {
				for _, p := range policies {
					if pstr, ok := p.(string); ok && strings.Contains(pstr, "*") {
						hasWildcard = true
						break
					}
				}
			}

			if !hasAdmin && !hasWildcard {
				return nil
			}

			// Check if can reach crown jewels
			crownJewels := findCrownJewels(g, node.ID, 3)
			if len(crownJewels) == 0 {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC003-%s", node.ID),
				Name:        "Overprivileged Identity",
				Description: fmt.Sprintf("%s has excessive permissions and can access %d critical assets", node.Name, len(crownJewels)),
				Severity:    SeverityHigh,
				Score:       75.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has admin or wildcard permissions", Severity: SeverityHigh},
					{Type: RiskFactorSensitiveData, NodeID: crownJewels[0].Node.ID, Description: fmt.Sprintf("Can access %s", crownJewels[0].Node.Name), Severity: SeverityHigh},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Apply least privilege", Resource: node.ID, Impact: "Reduces blast radius", Effort: "medium"},
					{Priority: 2, Action: "Remove wildcard permissions", Resource: node.ID, Impact: "Limits access scope", Effort: "low"},
				},
				Tags: []string{"iam", "least-privilege", "crown-jewels"},
			}
		},
	}
}

// Rule: Cross-account access with admin permissions
func (e *ToxicCombinationEngine) ruleCrossAccountWithAdmin() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC004",
		Name:        "Cross-Account Admin Access",
		Description: "External account has admin access to resources",
		Severity:    SeverityCritical,
		Tags:        []string{"cross-account", "iam", "trust"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsIdentity() {
				return nil
			}

			// Find cross-account admin edges
			var crossAccountAdminEdges []*Edge
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.IsCrossAccount() && edge.Kind == EdgeKindCanAdmin {
					crossAccountAdminEdges = append(crossAccountAdminEdges, edge)
				}
			}

			if len(crossAccountAdminEdges) == 0 {
				return nil
			}

			affected := []string{node.ID}
			for _, e := range crossAccountAdminEdges {
				affected = append(affected, e.Target)
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC004-%s", node.ID),
				Name:        "Cross-Account Admin Access",
				Description: fmt.Sprintf("%s from external account has admin access to %d resources", node.Name, len(crossAccountAdminEdges)),
				Severity:    SeverityCritical,
				Score:       85.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorCrossAccount, NodeID: node.ID, Description: "External account identity", Severity: SeverityHigh},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has admin permissions", Severity: SeverityCritical},
				},
				AffectedAssets: affected,
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Review and restrict trust policy", Resource: node.ID, Impact: "Limits external access", Effort: "medium"},
					{Priority: 2, Action: "Add external ID condition", Resource: node.ID, Impact: "Prevents confused deputy", Effort: "low"},
				},
				Tags: []string{"cross-account", "trust", "admin"},
			}
		},
	}
}

// Rule: Privilege escalation path exists
func (e *ToxicCombinationEngine) rulePrivilegeEscalationPath() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC005",
		Name:        "Privilege Escalation Path",
		Description: "Identity can escalate to higher privileges",
		Severity:    SeverityCritical,
		Tags:        []string{"privilege-escalation", "iam"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if !node.IsIdentity() {
				return nil
			}

			// Check for privilege escalation patterns
			escalationPaths := detectPrivilegeEscalation(g, node)
			if len(escalationPaths) == 0 {
				return nil
			}

			path := escalationPaths[0]
			return &ToxicCombination{
				ID:          fmt.Sprintf("TC005-%s", node.ID),
				Name:        "Privilege Escalation Path",
				Description: fmt.Sprintf("%s can escalate privileges via %s", node.Name, path.Technique),
				Severity:    SeverityCritical,
				Score:       88.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorPrivEscalation, NodeID: node.ID, Description: path.Description, Severity: SeverityCritical},
				},
				AttackPath: &AttackPath{
					ID:             fmt.Sprintf("AP-privesc-%s", node.ID),
					Steps:          escalationPaths,
					Exploitability: 0.7,
					Impact:         0.9,
					TotalRisk:      0.63,
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove dangerous permission combination", Resource: node.ID, Impact: "Eliminates escalation path", Effort: "medium"},
				},
				Tags: []string{"privilege-escalation", "iam", "mitre-t1078"},
			}
		},
	}
}

// Rule: Lateral movement path to sensitive data
func (e *ToxicCombinationEngine) ruleLateralMovementToData() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC006",
		Name:        "Lateral Movement to Sensitive Data",
		Description: "Compromised resource can move laterally to sensitive data",
		Severity:    SeverityHigh,
		Tags:        []string{"lateral-movement", "data"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindInstance && node.Kind != NodeKindFunction {
				return nil
			}

			// Check for attached role with data access
			lateralPaths := detectLateralMovement(g, node)
			if len(lateralPaths) == 0 {
				return nil
			}

			path := lateralPaths[0]
			return &ToxicCombination{
				ID:          fmt.Sprintf("TC006-%s", node.ID),
				Name:        "Lateral Movement Risk",
				Description: fmt.Sprintf("Compromising %s enables lateral movement to %d sensitive targets", node.Name, len(lateralPaths)),
				Severity:    SeverityHigh,
				Score:       70.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorLateralMove, NodeID: node.ID, Description: "Can assume role or access credentials", Severity: SeverityHigh},
					{Type: RiskFactorSensitiveData, NodeID: path.ToNode, Description: "Path to sensitive data", Severity: SeverityHigh},
				},
				AttackPath: &AttackPath{
					ID:             fmt.Sprintf("AP-lateral-%s", node.ID),
					Steps:          lateralPaths,
					Exploitability: 0.6,
					Impact:         0.8,
					TotalRisk:      0.48,
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Restrict instance/function role permissions", Resource: node.ID, Impact: "Limits lateral movement", Effort: "medium"},
					{Priority: 2, Action: "Enable IMDSv2", Resource: node.ID, Impact: "Prevents credential theft", Effort: "low"},
				},
				Tags: []string{"lateral-movement", "instance-role", "mitre-t1550"},
			}
		},
	}
}

// Rule: Secrets exposure
func (e *ToxicCombinationEngine) ruleSecretsExposure() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC007",
		Name:        "Secrets Exposure Risk",
		Description: "Secrets are accessible from internet-facing resources",
		Severity:    SeverityCritical,
		Tags:        []string{"secrets", "exposure"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindSecret {
				return nil
			}

			// Check who can access this secret
			accessors := ReverseAccess(g, node.ID, 4)

			// Find if any accessor is exposed
			for _, acc := range accessors.AccessibleBy {
				if isExposedToInternet(g, acc.Node.ID) {
					return &ToxicCombination{
						ID:          fmt.Sprintf("TC007-%s", node.ID),
						Name:        "Secrets Exposure",
						Description: fmt.Sprintf("Secret %s is accessible from internet-exposed %s", node.Name, acc.Node.Name),
						Severity:    SeverityCritical,
						Score:       92.0,
						Factors: []*RiskFactor{
							{Type: RiskFactorExposure, NodeID: acc.Node.ID, Description: "Internet-exposed resource", Severity: SeverityHigh},
							{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Contains secrets/credentials", Severity: SeverityCritical},
						},
						AffectedAssets: []string{node.ID, acc.Node.ID},
						Remediation: []*RemediationStep{
							{Priority: 1, Action: "Rotate exposed secrets immediately", Resource: node.ID, Impact: "Invalidates compromised credentials", Effort: "high"},
							{Priority: 2, Action: "Restrict secret access", Resource: node.ID, Impact: "Reduces exposure surface", Effort: "medium"},
						},
						Tags: []string{"secrets", "credentials", "exposure"},
					}
				}
			}

			return nil
		},
	}
}

// Rule: Admin without MFA
func (e *ToxicCombinationEngine) ruleAdminWithNoMFA() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC008",
		Name:        "Admin Without MFA",
		Description: "Administrative user without multi-factor authentication",
		Severity:    SeverityHigh,
		Tags:        []string{"iam", "mfa", "authentication"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindUser {
				return nil
			}

			// Check for admin access
			hasAdmin := false
			for _, edge := range g.GetOutEdges(node.ID) {
				if edge.Kind == EdgeKindCanAdmin || edge.Kind == EdgeKindCanAssume {
					if target, ok := g.GetNode(edge.Target); ok && target.Kind == NodeKindRole {
						hasAdmin = true
						break
					}
				}
			}
			if !hasAdmin {
				return nil
			}

			// Check MFA status
			mfaEnabled := false
			if mfa, ok := node.Properties["mfa_enabled"].(bool); ok {
				mfaEnabled = mfa
			}

			if mfaEnabled {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC008-%s", node.ID),
				Name:        "Admin Without MFA",
				Description: fmt.Sprintf("Admin user %s does not have MFA enabled", node.Name),
				Severity:    SeverityHigh,
				Score:       72.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: "No MFA configured", Severity: SeverityHigh},
					{Type: RiskFactorOverPrivilege, NodeID: node.ID, Description: "Has administrative access", Severity: SeverityMedium},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Enable MFA", Resource: node.ID, Impact: "Prevents credential theft attacks", Effort: "low", Automated: true},
				},
				AffectedAssets: []string{node.ID},
				Tags:           []string{"mfa", "authentication", "admin"},
			}
		},
	}
}

// Rule: Public database access
func (e *ToxicCombinationEngine) rulePublicDatabaseAccess() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC009",
		Name:        "Public Database Access",
		Description: "Database is accessible from the internet",
		Severity:    SeverityCritical,
		Tags:        []string{"database", "exposure", "data"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindDatabase {
				return nil
			}

			if !isExposedToInternet(g, node.ID) {
				return nil
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC009-%s", node.ID),
				Name:        "Public Database",
				Description: fmt.Sprintf("Database %s is directly accessible from the internet", node.Name),
				Severity:    SeverityCritical,
				Score:       98.0,
				Factors: []*RiskFactor{
					{Type: RiskFactorExposure, NodeID: node.ID, Description: "Internet-accessible database", Severity: SeverityCritical},
					{Type: RiskFactorSensitiveData, NodeID: node.ID, Description: "Contains data", Severity: SeverityHigh},
				},
				AffectedAssets: []string{node.ID},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Remove public access immediately", Resource: node.ID, Impact: "Critical - eliminates direct attack vector", Effort: "low", Automated: true},
					{Priority: 2, Action: "Place behind VPC/private subnet", Resource: node.ID, Impact: "Adds network isolation", Effort: "medium"},
				},
				Tags: []string{"database", "public", "critical"},
			}
		},
	}
}

// Rule: Service account key exposure
func (e *ToxicCombinationEngine) ruleServiceAccountKeyExposure() *ToxicCombinationRule {
	return &ToxicCombinationRule{
		ID:          "TC010",
		Name:        "Service Account Key Exposure",
		Description: "Service account with long-lived keys",
		Severity:    SeverityHigh,
		Tags:        []string{"service-account", "keys", "credentials"},
		Detector: func(g *Graph, node *Node) *ToxicCombination {
			if node.Kind != NodeKindServiceAccount {
				return nil
			}

			// Check for access keys
			hasKeys := false
			keyAge := 0
			if keys, ok := node.Properties["access_keys"].([]any); ok && len(keys) > 0 {
				hasKeys = true
				if age, ok := node.Properties["oldest_key_age_days"].(int); ok {
					keyAge = age
				}
			}

			if !hasKeys {
				return nil
			}

			severity := SeverityMedium
			score := 55.0
			if keyAge > 90 {
				severity = SeverityHigh
				score = 70.0
			}
			if keyAge > 365 {
				severity = SeverityCritical
				score = 85.0
			}

			return &ToxicCombination{
				ID:          fmt.Sprintf("TC010-%s", node.ID),
				Name:        "Service Account Key Risk",
				Description: fmt.Sprintf("Service account %s has long-lived access keys (%d days old)", node.Name, keyAge),
				Severity:    severity,
				Score:       score,
				Factors: []*RiskFactor{
					{Type: RiskFactorWeakAuth, NodeID: node.ID, Description: fmt.Sprintf("Access keys %d days old", keyAge), Severity: severity},
				},
				Remediation: []*RemediationStep{
					{Priority: 1, Action: "Rotate access keys", Resource: node.ID, Impact: "Reduces credential exposure window", Effort: "medium"},
					{Priority: 2, Action: "Use short-lived credentials (OIDC/AssumeRole)", Resource: node.ID, Impact: "Eliminates long-lived credentials", Effort: "high"},
				},
				Tags: []string{"service-account", "keys", "rotation"},
			}
		},
	}
}

// Helper functions

func findSensitiveDataReachable(g *Graph, nodeID string, maxDepth int) []*ReachableNode {
	result := BlastRadius(g, nodeID, maxDepth)
	var sensitive []*ReachableNode

	for _, rn := range result.ReachableNodes {
		if rn.Node.Kind == NodeKindDatabase || rn.Node.Kind == NodeKindSecret || rn.Node.Kind == NodeKindBucket {
			if rn.Node.Risk == RiskCritical || rn.Node.Risk == RiskHigh {
				sensitive = append(sensitive, rn)
			}
			// Check for sensitive data tags
			if tags := rn.Node.Tags; tags != nil {
				if tags["contains_pii"] == "true" || tags["classification"] == "confidential" {
					sensitive = append(sensitive, rn)
				}
			}
		}
	}

	return sensitive
}

func findCrownJewels(g *Graph, nodeID string, maxDepth int) []*ReachableNode {
	result := BlastRadius(g, nodeID, maxDepth)
	var jewels []*ReachableNode

	for _, rn := range result.ReachableNodes {
		if rn.Node.Risk == RiskCritical {
			jewels = append(jewels, rn)
		}
	}

	return jewels
}

func isExposedToInternet(g *Graph, nodeID string) bool {
	for _, edge := range g.GetInEdges(nodeID) {
		if edge.Kind == EdgeKindExposedTo {
			source, _ := g.GetNode(edge.Source)
			if source != nil && source.Kind == NodeKindInternet {
				return true
			}
		}
	}
	return false
}

func calculateNodeImpact(node *Node) float64 {
	switch node.Risk {
	case RiskCritical:
		return 1.0
	case RiskHigh:
		return 0.8
	case RiskMedium:
		return 0.5
	case RiskLow:
		return 0.2
	default:
		return 0.1
	}
}

func buildAttackPath(g *Graph, entryPoint, target, via string) *AttackPath {
	// Find path from entry to target via intermediate node
	paths := findAllPaths(g, via, target, 4)
	if len(paths) == 0 {
		return nil
	}

	steps := []*AttackStep{
		{
			Order:         1,
			FromNode:      entryPoint,
			ToNode:        via,
			Technique:     "Initial Access",
			Description:   "Compromise public-facing resource",
			MITREAttackID: "T1190",
		},
	}

	for i, edge := range paths[0] {
		steps = append(steps, &AttackStep{
			Order:         i + 2,
			FromNode:      edge.Source,
			ToNode:        edge.Target,
			Technique:     edgeToTechnique(edge.Kind),
			EdgeKind:      edge.Kind,
			MITREAttackID: edgeToMITRE(edge.Kind),
		})
	}

	return &AttackPath{
		ID:             fmt.Sprintf("AP-%s-%s", entryPoint, target),
		Steps:          steps,
		Exploitability: 0.7,
		Impact:         0.9,
		TotalRisk:      0.63,
		Likelihood:     0.6,
	}
}

func edgeToTechnique(kind EdgeKind) string {
	switch kind {
	case EdgeKindCanAssume:
		return "Privilege Escalation"
	case EdgeKindCanRead:
		return "Data Access"
	case EdgeKindCanWrite:
		return "Data Modification"
	case EdgeKindCanAdmin:
		return "Full Control"
	case EdgeKindConnectsTo:
		return "Lateral Movement"
	default:
		return "Access"
	}
}

func edgeToMITRE(kind EdgeKind) string {
	switch kind {
	case EdgeKindCanAssume:
		return "T1078"
	case EdgeKindCanRead:
		return "T1530"
	case EdgeKindCanWrite:
		return "T1565"
	case EdgeKindConnectsTo:
		return "T1021"
	default:
		return ""
	}
}

func detectPrivilegeEscalation(_ *Graph, node *Node) []*AttackStep {
	var paths []*AttackStep

	// Check for iam:PassRole + lambda/ec2 create
	permissions := getNodePermissions(node)

	hasPassRole := containsPermission(permissions, "iam:PassRole")
	hasCreateLambda := containsPermission(permissions, "lambda:CreateFunction")
	hasCreateEC2 := containsPermission(permissions, "ec2:RunInstances")
	hasCreateRole := containsPermission(permissions, "iam:CreateRole")
	hasAttachPolicy := containsPermission(permissions, "iam:AttachRolePolicy")

	if hasPassRole && hasCreateLambda {
		paths = append(paths, &AttackStep{
			Order:         1,
			FromNode:      node.ID,
			ToNode:        "elevated-role",
			Technique:     "PassRole + Lambda",
			Description:   "Create Lambda with privileged role to escalate",
			MITREAttackID: "T1078.004",
		})
	}

	if hasPassRole && hasCreateEC2 {
		paths = append(paths, &AttackStep{
			Order:         1,
			FromNode:      node.ID,
			ToNode:        "elevated-role",
			Technique:     "PassRole + EC2",
			Description:   "Launch EC2 with privileged instance profile",
			MITREAttackID: "T1078.004",
		})
	}

	if hasCreateRole && hasAttachPolicy {
		paths = append(paths, &AttackStep{
			Order:         1,
			FromNode:      node.ID,
			ToNode:        "new-admin-role",
			Technique:     "CreateRole + AttachPolicy",
			Description:   "Create new role with admin policy",
			MITREAttackID: "T1098",
		})
	}

	return paths
}

func detectLateralMovement(g *Graph, node *Node) []*AttackStep {
	var paths []*AttackStep

	// Check for assumed role with data access
	for _, edge := range g.GetOutEdges(node.ID) {
		if edge.Kind == EdgeKindCanAssume {
			roleNode, ok := g.GetNode(edge.Target)
			if !ok {
				continue
			}

			// Check what this role can access
			roleBlast := BlastRadius(g, roleNode.ID, 2)
			for _, rn := range roleBlast.ReachableNodes {
				if rn.Node.Kind == NodeKindDatabase || rn.Node.Kind == NodeKindSecret {
					paths = append(paths, &AttackStep{
						Order:         1,
						FromNode:      node.ID,
						ToNode:        rn.Node.ID,
						Technique:     "Role Assumption",
						Description:   fmt.Sprintf("Assume %s to access %s", roleNode.Name, rn.Node.Name),
						EdgeKind:      EdgeKindCanAssume,
						MITREAttackID: "T1550",
					})
				}
			}
		}
	}

	return paths
}

func getNodePermissions(node *Node) []string {
	var perms []string
	if p, ok := node.Properties["permissions"].([]any); ok {
		for _, perm := range p {
			if s, ok := perm.(string); ok {
				perms = append(perms, s)
			}
		}
	}
	if p, ok := node.Properties["actions"].([]any); ok {
		for _, perm := range p {
			if s, ok := perm.(string); ok {
				perms = append(perms, s)
			}
		}
	}
	return perms
}

func containsPermission(perms []string, target string) bool {
	for _, p := range perms {
		if p == target || p == "*" {
			return true
		}
		// Check wildcard matches
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(target, prefix) {
				return true
			}
		}
	}
	return false
}

// Kubernetes Rules

// Rule: Privileged pod with host path mount - container escape risk
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

// Rule: RBAC wildcard verbs on secrets
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

// Rule: Service account with cluster-admin bound to exposed workload
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

// Rule: Pod with automountServiceAccountToken and secrets access
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

// CI/CD Supply Chain Rules

// Rule: GitHub Actions OIDC with overprivileged AWS role
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

// Rule: EKS node role with ECR push permissions (supply chain risk)
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

// AWS-Specific Rules

// Rule: IMDSv1 enabled with sensitive IAM role - SSRF credential theft risk
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

// Rule: S3 bucket publicly accessible with sensitive data
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

// Rule: Lambda in VPC with secrets access and no VPC endpoints
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

// GCP-Specific Rules

// Rule: GCP Service Account key exposed or downloadable
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

// Rule: GCP GCS bucket publicly accessible
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
			dataClassification, _ := node.Properties["data_classification"].(string)
			containsPII, _ := node.Properties["contains_pii"].(bool)

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

// Rule: GCP Compute instance using default service account
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

// Azure-Specific Rules

// Rule: Azure managed identity with overprivileged role assignments
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
			identityType, _ := node.Properties["identity_type"].(string)
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

// Rule: Azure storage blob container with public access
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
			dataClassification, _ := node.Properties["data_classification"].(string)
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
