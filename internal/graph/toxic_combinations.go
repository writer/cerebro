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
	index := buildToxicCombinationNodeIndex(nodes)
	sem := make(chan struct{}, 32)

	for _, rule := range e.rules {
		candidateNodes := index.candidatesForRule(rule.ID)
		for _, node := range candidateNodes {
			wg.Add(1)
			sem <- struct{}{}
			go func(r *ToxicCombinationRule, n *Node) {
				defer wg.Done()
				defer func() { <-sem }()

				if tc := r.Detector(g, n); tc != nil {
					mu.Lock()
					results = append(results, tc)
					mu.Unlock()
				}
			}(rule, node)
		}
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

type toxicCombinationNodeIndex struct {
	all            []*Node
	resources      []*Node
	identities     []*Node
	byKind         map[NodeKind][]*Node
	byProvider     map[string][]*Node
	byKindProvider map[NodeKind]map[string][]*Node
}

func buildToxicCombinationNodeIndex(nodes []*Node) toxicCombinationNodeIndex {
	index := toxicCombinationNodeIndex{
		all:            nodes,
		byKind:         make(map[NodeKind][]*Node),
		byProvider:     make(map[string][]*Node),
		byKindProvider: make(map[NodeKind]map[string][]*Node),
	}

	for _, node := range nodes {
		if node == nil {
			continue
		}

		if node.IsResource() {
			index.resources = append(index.resources, node)
		}
		if node.IsIdentity() {
			index.identities = append(index.identities, node)
		}

		index.byKind[node.Kind] = append(index.byKind[node.Kind], node)

		provider := strings.TrimSpace(node.Provider)
		if provider != "" {
			index.byProvider[provider] = append(index.byProvider[provider], node)
			if index.byKindProvider[node.Kind] == nil {
				index.byKindProvider[node.Kind] = make(map[string][]*Node)
			}
			index.byKindProvider[node.Kind][provider] = append(index.byKindProvider[node.Kind][provider], node)
		}
	}

	return index
}

func (i toxicCombinationNodeIndex) candidatesForRule(ruleID string) []*Node {
	switch ruleID {
	case "TC001", "TC002":
		return i.resources
	case "TC003", "TC004", "TC005":
		return i.identities
	case "TC006":
		return appendNodeSlices(i.byKind[NodeKindInstance], i.byKind[NodeKindFunction])
	case "TC007":
		return i.byKind[NodeKindSecret]
	case "TC008":
		return i.byKind[NodeKindUser]
	case "TC009":
		return i.byKind[NodeKindDatabase]
	case "TC010":
		return i.byKind[NodeKindServiceAccount]
	case "TC-AWS-001":
		return i.byKindProvider[NodeKindInstance]["aws"]
	case "TC-AWS-002":
		return i.byKindProvider[NodeKindBucket]["aws"]
	case "TC-AWS-003":
		return i.byKindProvider[NodeKindFunction]["aws"]
	case "TC-AWS-004":
		return i.byKindProvider[NodeKindFunction]["aws"]
	case "TC-AWS-005":
		return i.byKindProvider[NodeKindDatabase]["aws"]
	case "TC-AWS-006":
		return appendNodeSlices(
			i.byKindProvider[NodeKindRole]["aws"],
			i.byKindProvider[NodeKindUser]["aws"],
			i.byKindProvider[NodeKindServiceAccount]["aws"],
		)
	case "TC-AWS-007":
		return i.byKindProvider[NodeKindInstance]["aws"]
	case "TC-GCP-001":
		return i.byKindProvider[NodeKindServiceAccount]["gcp"]
	case "TC-GCP-002":
		return i.byKindProvider[NodeKindBucket]["gcp"]
	case "TC-GCP-003":
		return i.byKindProvider[NodeKindInstance]["gcp"]
	case "TC-GCP-004":
		return i.byKindProvider[NodeKindServiceAccount]["gcp"]
	case "TC-AZURE-001":
		return i.byKindProvider[NodeKindServiceAccount]["azure"]
	case "TC-AZURE-002":
		return i.byKindProvider[NodeKindBucket]["azure"]
	case "TC-K8S-001", "TC-K8S-004":
		return i.byKind[NodeKindPod]
	case "TC-K8S-002":
		return i.byKind[NodeKindClusterRole]
	case "TC-K8S-003":
		return i.byKind[NodeKindServiceAccount]
	case "TC-CICD-001", "TC-CICD-002":
		return i.byKindProvider[NodeKindRole]["aws"]
	case "TC-BIZ-001", "TC-BIZ-003", "TC-BIZ-006":
		return appendNodeSlices(i.byKind[NodeKindCustomer], i.byKind[NodeKindCompany])
	case "TC-BIZ-002":
		return appendNodeSlices(i.byKind[NodeKindDeal], i.byKind[NodeKindOpportunity])
	case "TC-BIZ-004":
		return appendNodeSlices(i.byKind[NodeKindApplication], i.byKind[NodeKindInstance], i.byKind[NodeKindFunction])
	case "TC-BIZ-005":
		return appendNodeSlices(i.byKind[NodeKindInvoice], i.byKind[NodeKindSubscription], i.byKind[NodeKindCustomer])
	default:
		return i.all
	}
}

func appendNodeSlices(slices ...[]*Node) []*Node {
	total := 0
	for _, items := range slices {
		total += len(items)
	}
	if total == 0 {
		return nil
	}
	out := make([]*Node, 0, total)
	for _, items := range slices {
		out = append(out, items...)
	}
	return out
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
		e.ruleLambdaPublicInlinePolicyDynamoTrigger(),
		e.rulePublicRDSUnencryptedHighBlastRadius(),
		e.ruleCrossAccountTransitiveTrustChain(),
		e.ruleExposedComputeWithKeyedAdminIdentity(),
		// GCP-specific rules
		e.ruleGCPServiceAccountKeyExposed(),
		e.ruleGCPPublicGCSBucket(),
		e.ruleGCPComputeDefaultSA(),
		e.ruleGCPDefaultSAProjectWidePermissions(),
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
		// Business + cross-system rules
		e.ruleChurnCompoundSignal(),
		e.ruleTrajectoryDeterioration(),
		e.ruleRevenueAtRisk(),
		e.ruleSecurityMeetsBusiness(),
		e.ruleOperationalBlastRadius(),
		e.ruleFinancialGuardrail(),
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
			if nodePropertyBool(node, "mfa_enabled") {
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
				continue
			}
			if detectSensitiveDataExplicit(rn.Node) != nil {
				sensitive = append(sensitive, rn)
				continue
			}
			// Retain legacy tag-based signals for graphs that have not been enriched yet.
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
	case EdgeKindHasCredentialFor:
		return "Credential Pivot"
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
	case EdgeKindHasCredentialFor:
		return "T1552"
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
	seen := make(map[string]struct{})

	appendPath := func(targetID, technique, description string, kind EdgeKind, mitre string) {
		key := targetID + "|" + string(kind)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		paths = append(paths, &AttackStep{
			Order:         1,
			FromNode:      node.ID,
			ToNode:        targetID,
			Technique:     technique,
			Description:   description,
			EdgeKind:      kind,
			MITREAttackID: mitre,
		})
	}

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
					appendPath(
						rn.Node.ID,
						"Role Assumption",
						fmt.Sprintf("Assume %s to access %s", roleNode.Name, rn.Node.Name),
						EdgeKindCanAssume,
						"T1550",
					)
				}
			}
		}
		if edge.Kind == EdgeKindHasCredentialFor {
			targetNode, ok := g.GetNode(edge.Target)
			if !ok {
				continue
			}
			if targetNode.Kind == NodeKindDatabase || targetNode.Kind == NodeKindSecret || targetNode.Kind == NodeKindBucket {
				appendPath(
					targetNode.ID,
					"Credential Pivot",
					fmt.Sprintf("Use discovered credential to access %s", targetNode.Name),
					EdgeKindHasCredentialFor,
					"T1552",
				)
				continue
			}
			if !targetNode.IsIdentity() {
				continue
			}
			blast := BlastRadius(g, targetNode.ID, 2)
			for _, reachable := range blast.ReachableNodes {
				if reachable == nil || reachable.Node == nil {
					continue
				}
				if reachable.Node.Kind != NodeKindDatabase && reachable.Node.Kind != NodeKindSecret && reachable.Node.Kind != NodeKindBucket {
					continue
				}
				appendPath(
					reachable.Node.ID,
					"Credential Pivot",
					fmt.Sprintf("Use discovered credential for %s to access %s", targetNode.Name, reachable.Node.Name),
					EdgeKindHasCredentialFor,
					"T1552",
				)
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
// Rule: RBAC wildcard verbs on secrets
// Rule: Service account with cluster-admin bound to exposed workload
// Rule: Pod with automountServiceAccountToken and secrets access
// CI/CD Supply Chain Rules

// Rule: GitHub Actions OIDC with overprivileged AWS role
// Rule: EKS node role with ECR push permissions (supply chain risk)
// AWS-Specific Rules

// Rule: IMDSv1 enabled with sensitive IAM role - SSRF credential theft risk
// Rule: S3 bucket publicly accessible with sensitive data
// Rule: Lambda in VPC with secrets access and no VPC endpoints
// GCP-Specific Rules

// Rule: GCP Service Account key exposed or downloadable
// Rule: GCP GCS bucket publicly accessible
// Rule: GCP Compute instance using default service account
// Azure-Specific Rules

// Rule: Azure managed identity with overprivileged role assignments
// Rule: Azure storage blob container with public access
