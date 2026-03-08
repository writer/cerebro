package graph

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// RiskEngine is the unified security intelligence layer
type RiskEngine struct {
	graph           *Graph
	toxicEngine     *ToxicCombinationEngine
	attackSimulator *AttackPathSimulator
	permissionsCalc *EffectivePermissionsCalculator
	lastAnalysis    time.Time
	cachedReport    *SecurityReport
	riskProfile     RiskProfile
	entityScores    map[string]float64
	onScoreChange   func(RiskScoreChangedEvent)
	mu              sync.RWMutex
}

// NewRiskEngine creates a new risk engine
func NewRiskEngine(g *Graph) *RiskEngine {
	return &RiskEngine{
		graph:           g,
		toxicEngine:     NewToxicCombinationEngine(),
		permissionsCalc: NewEffectivePermissionsCalculator(g),
		riskProfile:     DefaultRiskProfile("default"),
		entityScores:    make(map[string]float64),
	}
}

// PostureReport is the comprehensive security + business posture analysis.
type PostureReport struct {
	GeneratedAt       time.Time               `json:"generated_at"`
	GraphStats        *GraphStats             `json:"graph_stats"`
	RiskScore         float64                 `json:"risk_score"` // 0-100, overall security posture
	RiskLevel         RiskLevel               `json:"risk_level"`
	OrgHealth         *OrgHealthScore         `json:"org_health,omitempty"`
	ToxicCombinations []*ToxicCombination     `json:"toxic_combinations"`
	AttackPaths       *SimulationResult       `json:"attack_paths"`
	Chokepoints       []*Chokepoint           `json:"chokepoints"`
	TopRisks          []*RankedRisk           `json:"top_risks"`
	RemediationPlan   *RemediationPlan        `json:"remediation_plan"`
	TrendAnalysis     *TrendAnalysis          `json:"trend_analysis,omitempty"`
	ComplianceGaps    []*ComplianceGap        `json:"compliance_gaps,omitempty"`
	RiskProfile       string                  `json:"risk_profile,omitempty"`
	EntityRisks       map[string]EntityRisk   `json:"entity_risks,omitempty"`
	RiskScoreChanges  []RiskScoreChangedEvent `json:"risk_score_changes,omitempty"`
}

// SecurityReport is kept as an alias for backward compatibility.
type SecurityReport = PostureReport

// GraphStats provides overview statistics
type GraphStats struct {
	TotalNodes        int            `json:"total_nodes"`
	TotalEdges        int            `json:"total_edges"`
	IdentityCount     int            `json:"identity_count"`
	ResourceCount     int            `json:"resource_count"`
	CrossAccountEdges int            `json:"cross_account_edges"`
	PublicExposures   int            `json:"public_exposures"`
	CriticalResources int            `json:"critical_resources"`
	NodesByKind       map[string]int `json:"nodes_by_kind"`
	EdgesByKind       map[string]int `json:"edges_by_kind"`
	AccountCount      int            `json:"account_count"`
	ProviderBreakdown map[string]int `json:"provider_breakdown"`
}

// RankedRisk is a prioritized risk item
type RankedRisk struct {
	Rank            int      `json:"rank"`
	Type            string   `json:"type"` // toxic_combination, attack_path, permission_risk
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Score           float64  `json:"score"`
	Severity        Severity `json:"severity"`
	AffectedAssets  []string `json:"affected_assets"`
	MITRE           []string `json:"mitre,omitempty"`
	Remediation     string   `json:"remediation"`
	EstimatedEffort string   `json:"estimated_effort"`
}

// RemediationPlan provides prioritized remediation steps
type RemediationPlan struct {
	TotalIssues       int                  `json:"total_issues"`
	CriticalCount     int                  `json:"critical_count"`
	HighCount         int                  `json:"high_count"`
	EstimatedEffort   string               `json:"estimated_effort"`
	Steps             []*RemediationAction `json:"steps"`
	QuickWins         []*RemediationAction `json:"quick_wins"`         // Low effort, high impact
	StrategicFixes    []*RemediationAction `json:"strategic_fixes"`    // High effort, high impact
	ExpectedReduction float64              `json:"expected_reduction"` // % risk reduction if all completed
}

// RemediationAction is a specific action to take
type RemediationAction struct {
	Priority        int      `json:"priority"`
	Action          string   `json:"action"`
	Target          string   `json:"target"`
	TargetType      string   `json:"target_type"`
	Impact          string   `json:"impact"`
	Effort          string   `json:"effort"` // quick, moderate, significant
	BlockedPaths    int      `json:"blocked_paths"`
	RiskReduction   float64  `json:"risk_reduction"` // 0-1
	Automated       bool     `json:"automated"`
	RelatedFindings []string `json:"related_findings"`
}

// TrendAnalysis shows how risk has changed over time
type TrendAnalysis struct {
	CurrentScore   float64 `json:"current_score"`
	PreviousScore  float64 `json:"previous_score"`
	ScoreChange    float64 `json:"score_change"`
	Trend          string  `json:"trend"` // improving, stable, degrading
	NewIssues      int     `json:"new_issues"`
	ResolvedIssues int     `json:"resolved_issues"`
	TrendPeriod    string  `json:"trend_period"`
}

// ComplianceGap represents a compliance violation
type ComplianceGap struct {
	Framework         string   `json:"framework"` // SOC2, PCI-DSS, HIPAA, etc.
	Control           string   `json:"control"`
	Description       string   `json:"description"`
	Severity          Severity `json:"severity"`
	AffectedResources []string `json:"affected_resources"`
	Remediation       string   `json:"remediation"`
}

// Analyze performs comprehensive security analysis
func (r *RiskEngine) Analyze() *SecurityReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()
	previous := r.cachedReport
	previousEntityScores := make(map[string]float64, len(r.entityScores))
	for id, score := range r.entityScores {
		previousEntityScores[id] = score
	}

	report := &SecurityReport{
		GeneratedAt: start,
		RiskProfile: r.riskProfile.Name,
	}

	// Graph statistics
	report.GraphStats = r.calculateGraphStats()
	orgHealth := ComputeOrgHealthScore(r.graph)
	report.OrgHealth = &orgHealth

	// Toxic combinations
	report.ToxicCombinations = r.toxicEngine.Analyze(r.graph)

	// Attack path simulation
	r.attackSimulator = NewAttackPathSimulator(r.graph)
	report.AttackPaths = r.attackSimulator.Simulate(6)
	report.Chokepoints = report.AttackPaths.Chokepoints
	report.EntityRisks = r.collectEntityRisks(previousEntityScores)

	// Rank all risks
	report.TopRisks = r.rankAllRisks(report)

	// Calculate overall risk score
	report.RiskScore = r.calculateOverallRiskScore(report)
	report.RiskLevel = scoreToRiskLevel(report.RiskScore)
	report.TrendAnalysis = r.calculateTrendAnalysis(previous, report)
	report.RiskScoreChanges = r.calculateRiskScoreChanges(previous, report, start)

	// Generate remediation plan
	report.RemediationPlan = r.generateRemediationPlan(report)

	// Check compliance (basic)
	report.ComplianceGaps = r.checkCompliance(report)

	for entityID, entityRisk := range report.EntityRisks {
		r.entityScores[entityID] = entityRisk.Score
	}
	r.cachedReport = report
	r.lastAnalysis = start
	if r.onScoreChange != nil {
		for _, event := range report.RiskScoreChanges {
			r.onScoreChange(event)
		}
	}

	return report
}

func (r *RiskEngine) calculateGraphStats() *GraphStats {
	stats := &GraphStats{
		TotalNodes:        r.graph.NodeCount(),
		TotalEdges:        r.graph.EdgeCount(),
		NodesByKind:       make(map[string]int),
		EdgesByKind:       make(map[string]int),
		ProviderBreakdown: make(map[string]int),
	}

	accounts := make(map[string]bool)

	for _, node := range r.graph.GetAllNodes() {
		stats.NodesByKind[string(node.Kind)]++

		if node.IsIdentity() {
			stats.IdentityCount++
		}
		if node.IsResource() {
			stats.ResourceCount++
		}
		if node.Risk == RiskCritical {
			stats.CriticalResources++
		}
		if node.Account != "" {
			accounts[node.Account] = true
		}
		if node.Provider != "" {
			stats.ProviderBreakdown[node.Provider]++
		}
	}

	stats.AccountCount = len(accounts)

	for _, edges := range r.graph.GetAllEdges() {
		for _, edge := range edges {
			stats.EdgesByKind[string(edge.Kind)]++
			if edge.IsCrossAccount() {
				stats.CrossAccountEdges++
			}
		}
	}

	// Count public exposures
	for _, node := range r.graph.GetAllNodes() {
		if isExposedToInternet(r.graph, node.ID) {
			stats.PublicExposures++
		}
	}

	return stats
}

func (r *RiskEngine) rankAllRisks(report *SecurityReport) []*RankedRisk {
	risks := make([]*RankedRisk, 0, len(report.ToxicCombinations)+len(report.AttackPaths.Paths))

	// Add toxic combinations
	for _, tc := range report.ToxicCombinations {
		risks = append(risks, &RankedRisk{
			Type:            "toxic_combination",
			ID:              tc.ID,
			Title:           tc.Name,
			Description:     tc.Description,
			Score:           tc.Score,
			Severity:        tc.Severity,
			AffectedAssets:  tc.AffectedAssets,
			MITRE:           extractMITRE(tc),
			Remediation:     formatRemediation(tc.Remediation),
			EstimatedEffort: estimateEffort(tc.Remediation),
		})
	}

	// Add critical attack paths
	for _, path := range report.AttackPaths.Paths {
		if path.TotalScore >= 60 {
			risks = append(risks, &RankedRisk{
				Type:            "attack_path",
				ID:              path.ID,
				Title:           fmt.Sprintf("Attack path: %s -> %s", path.EntryPoint.Name, path.Target.Name),
				Description:     fmt.Sprintf("%d-step path from %s to %s (skill: %s)", path.Length, path.EntryPoint.Kind, path.Target.Kind, path.RequiredSkill),
				Score:           path.TotalScore,
				Severity:        scoreToSeverity(path.TotalScore),
				AffectedAssets:  pathToAssets(path),
				MITRE:           pathToMITRE(path),
				Remediation:     "Break attack path by securing intermediate nodes",
				EstimatedEffort: path.EstimatedTime,
			})
		}
	}
	risks = append(risks, r.rankEntityRisks(report.EntityRisks)...)

	// Sort by score descending
	sort.Slice(risks, func(i, j int) bool {
		return risks[i].Score > risks[j].Score
	})

	// Assign ranks
	for i := range risks {
		risks[i].Rank = i + 1
	}

	// Limit to top 100
	if len(risks) > 100 {
		risks = risks[:100]
	}

	return risks
}

func (r *RiskEngine) calculateOverallRiskScore(report *SecurityReport) float64 {
	securityScore := 0.0

	// Toxic combinations contribute most (up to 40 points)
	toxicScore := 0.0
	for _, tc := range report.ToxicCombinations {
		toxicScore += tc.Score * 0.1
	}
	if toxicScore > 40 {
		toxicScore = 40
	}
	securityScore += toxicScore

	// Attack paths (up to 30 points)
	pathScore := 0.0
	for _, path := range report.AttackPaths.Paths {
		pathScore += path.TotalScore * 0.05
	}
	if pathScore > 30 {
		pathScore = 30
	}
	securityScore += pathScore

	// Public exposures (up to 15 points)
	exposureScore := float64(report.GraphStats.PublicExposures) * 2
	if exposureScore > 15 {
		exposureScore = 15
	}
	securityScore += exposureScore

	// Cross-account access (up to 10 points)
	crossAccountScore := float64(report.GraphStats.CrossAccountEdges) * 0.5
	if crossAccountScore > 10 {
		crossAccountScore = 10
	}
	securityScore += crossAccountScore

	// Critical resources without protection (up to 5 points)
	criticalScore := float64(report.GraphStats.CriticalResources) * 0.5
	if criticalScore > 5 {
		criticalScore = 5
	}
	securityScore += criticalScore

	if securityScore > 100 {
		securityScore = 100
	}

	businessScore := r.calculateBusinessRiskScore(report.EntityRisks)
	if businessScore <= 0 {
		return securityScore
	}

	securityWeight := r.riskProfile.Weight("security")
	if securityWeight <= 0 {
		securityWeight = 1
	}
	businessWeight := r.riskProfile.Weight("business")
	if businessWeight <= 0 {
		businessWeight = 1
	}
	totalWeight := securityWeight + businessWeight
	score := (securityScore*securityWeight + businessScore*businessWeight) / totalWeight
	if score > 100 {
		score = 100
	}

	return score
}

func (r *RiskEngine) generateRemediationPlan(report *SecurityReport) *RemediationPlan {
	plan := &RemediationPlan{
		Steps:          make([]*RemediationAction, 0),
		QuickWins:      make([]*RemediationAction, 0),
		StrategicFixes: make([]*RemediationAction, 0),
	}

	actionMap := make(map[string]*RemediationAction)

	// Add actions from toxic combinations
	for _, tc := range report.ToxicCombinations {
		for _, rem := range tc.Remediation {
			key := fmt.Sprintf("%s-%s", rem.Action, rem.Resource)
			if _, exists := actionMap[key]; !exists {
				action := &RemediationAction{
					Action:          rem.Action,
					Target:          rem.Resource,
					TargetType:      "resource",
					Impact:          rem.Impact,
					Effort:          rem.Effort,
					Automated:       rem.Automated,
					RelatedFindings: []string{tc.ID},
				}
				actionMap[key] = action
			} else {
				actionMap[key].RelatedFindings = append(actionMap[key].RelatedFindings, tc.ID)
			}
		}

		switch tc.Severity {
		case SeverityCritical:
			plan.CriticalCount++
		case SeverityHigh:
			plan.HighCount++
		}
	}

	// Add actions from chokepoints
	for _, cp := range report.Chokepoints {
		key := fmt.Sprintf("secure-%s", cp.Node.ID)
		if _, exists := actionMap[key]; !exists {
			action := &RemediationAction{
				Action:        fmt.Sprintf("Secure chokepoint: %s", cp.Node.Name),
				Target:        cp.Node.ID,
				TargetType:    string(cp.Node.Kind),
				Impact:        fmt.Sprintf("Blocks %d attack paths", cp.BlockedPaths),
				Effort:        "moderate",
				BlockedPaths:  cp.BlockedPaths,
				RiskReduction: cp.RemediationImpact,
			}
			actionMap[key] = action
		}
	}

	// Convert map to slice and sort
	for _, action := range actionMap {
		plan.Steps = append(plan.Steps, action)
	}

	// Sort by risk reduction descending
	sort.Slice(plan.Steps, func(i, j int) bool {
		return plan.Steps[i].RiskReduction > plan.Steps[j].RiskReduction
	})

	// Assign priorities
	for i := range plan.Steps {
		plan.Steps[i].Priority = i + 1
	}

	// Categorize quick wins vs strategic fixes
	for _, step := range plan.Steps {
		if step.Effort == "low" || step.Effort == "quick" {
			plan.QuickWins = append(plan.QuickWins, step)
		} else if step.RiskReduction > 0.3 {
			plan.StrategicFixes = append(plan.StrategicFixes, step)
		}
	}

	plan.TotalIssues = len(plan.Steps)

	// Estimate total effort
	quickCount := len(plan.QuickWins)
	strategicCount := len(plan.StrategicFixes)
	if strategicCount > 5 {
		plan.EstimatedEffort = "weeks"
	} else if strategicCount > 0 || quickCount > 10 {
		plan.EstimatedEffort = "days"
	} else {
		plan.EstimatedEffort = "hours"
	}

	// Calculate expected reduction
	totalReduction := 0.0
	for _, step := range plan.Steps {
		totalReduction += step.RiskReduction
	}
	plan.ExpectedReduction = totalReduction
	if plan.ExpectedReduction > 1 {
		plan.ExpectedReduction = 0.95 // Cap at 95%
	}

	return plan
}

func (r *RiskEngine) checkCompliance(report *SecurityReport) []*ComplianceGap {
	var gaps []*ComplianceGap

	// Basic compliance checks

	// SOC2 - Public exposure
	if report.GraphStats.PublicExposures > 0 {
		var exposed []string
		for _, node := range r.graph.GetAllNodes() {
			if isExposedToInternet(r.graph, node.ID) && node.Kind == NodeKindDatabase {
				exposed = append(exposed, node.ID)
			}
		}
		if len(exposed) > 0 {
			gaps = append(gaps, &ComplianceGap{
				Framework:         "SOC2",
				Control:           "CC6.6",
				Description:       "Databases exposed to internet violate logical access controls",
				Severity:          SeverityCritical,
				AffectedResources: exposed,
				Remediation:       "Place databases in private subnets with no public access",
			})
		}
	}

	// PCI-DSS - Encryption
	for _, node := range r.graph.GetAllNodes() {
		if node.Kind == NodeKindDatabase || node.Kind == NodeKindBucket {
			if enc, ok := node.Properties["encrypted"].(bool); !ok || !enc {
				gaps = append(gaps, &ComplianceGap{
					Framework:         "PCI-DSS",
					Control:           "3.4",
					Description:       "Sensitive data not encrypted at rest",
					Severity:          SeverityHigh,
					AffectedResources: []string{node.ID},
					Remediation:       "Enable encryption at rest",
				})
			}
		}
	}

	// Generic - MFA for admins
	for _, node := range r.graph.GetAllNodes() {
		if node.Kind == NodeKindUser {
			mfaEnabled := false
			if mfa, ok := node.Properties["mfa_enabled"].(bool); ok {
				mfaEnabled = mfa
			}
			if !mfaEnabled {
				// Check if user has admin access
				for _, edge := range r.graph.GetOutEdges(node.ID) {
					if edge.Kind == EdgeKindCanAdmin {
						gaps = append(gaps, &ComplianceGap{
							Framework:         "CIS",
							Control:           "1.10",
							Description:       "Admin user without MFA enabled",
							Severity:          SeverityHigh,
							AffectedResources: []string{node.ID},
							Remediation:       "Enable MFA for all administrative users",
						})
						break
					}
				}
			}
		}
	}

	return gaps
}

// GetCachedReport returns the last analysis if still valid
func (r *RiskEngine) GetCachedReport(maxAge time.Duration) *SecurityReport {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cachedReport == nil {
		return nil
	}

	if time.Since(r.lastAnalysis) > maxAge {
		return nil
	}

	return r.cachedReport
}

// SimulateRemediation shows impact of fixing specific issues
func (r *RiskEngine) SimulateRemediation(nodeID string) *RemediationImpact {
	if r.attackSimulator == nil || r.cachedReport == nil {
		return nil
	}

	fixSim := r.attackSimulator.SimulateFix(r.cachedReport.AttackPaths, nodeID)

	// Find related toxic combinations
	var relatedTC []*ToxicCombination
	for _, tc := range r.cachedReport.ToxicCombinations {
		for _, asset := range tc.AffectedAssets {
			if asset == nodeID {
				relatedTC = append(relatedTC, tc)
				break
			}
		}
	}

	// Calculate new risk score
	newScore := r.cachedReport.RiskScore * (1 - fixSim.RiskReduction)

	return &RemediationImpact{
		NodeID:             nodeID,
		BlockedAttackPaths: fixSim.BlockedCount,
		RemainingPaths:     fixSim.RemainingCount,
		RelatedToxicCombos: len(relatedTC),
		CurrentRiskScore:   r.cachedReport.RiskScore,
		ProjectedRiskScore: newScore,
		RiskReduction:      r.cachedReport.RiskScore - newScore,
		ReductionPercent:   (r.cachedReport.RiskScore - newScore) / r.cachedReport.RiskScore * 100,
	}
}

// RemediationImpact shows the impact of remediating a node
type RemediationImpact struct {
	NodeID             string  `json:"node_id"`
	BlockedAttackPaths int     `json:"blocked_attack_paths"`
	RemainingPaths     int     `json:"remaining_paths"`
	RelatedToxicCombos int     `json:"related_toxic_combos"`
	CurrentRiskScore   float64 `json:"current_risk_score"`
	ProjectedRiskScore float64 `json:"projected_risk_score"`
	RiskReduction      float64 `json:"risk_reduction"`
	ReductionPercent   float64 `json:"reduction_percent"`
}

// Helper functions

func scoreToRiskLevel(score float64) RiskLevel {
	if score >= 70 {
		return RiskCritical
	} else if score >= 50 {
		return RiskHigh
	} else if score >= 25 {
		return RiskMedium
	}
	return RiskLow
}

func scoreToSeverity(score float64) Severity {
	if score >= 70 {
		return SeverityCritical
	} else if score >= 50 {
		return SeverityHigh
	} else if score >= 25 {
		return SeverityMedium
	}
	return SeverityLow
}

func extractMITRE(tc *ToxicCombination) []string {
	var ids []string
	if tc.AttackPath != nil {
		for _, step := range tc.AttackPath.Steps {
			if step.MITREAttackID != "" {
				ids = append(ids, step.MITREAttackID)
			}
		}
	}
	return ids
}

func formatRemediation(steps []*RemediationStep) string {
	if len(steps) == 0 {
		return "Review and secure affected resources"
	}
	return steps[0].Action
}

func estimateEffort(steps []*RemediationStep) string {
	if len(steps) == 0 {
		return "moderate"
	}
	return steps[0].Effort
}

func pathToAssets(path *ScoredAttackPath) []string {
	assets := make([]string, 0, 2+len(path.Steps))
	assets = append(assets, path.EntryPoint.ID, path.Target.ID)
	for _, step := range path.Steps {
		assets = append(assets, step.ToNode)
	}
	return assets
}

func pathToMITRE(path *ScoredAttackPath) []string {
	var ids []string
	for _, step := range path.Steps {
		if step.MITREAttackID != "" {
			ids = append(ids, step.MITREAttackID)
		}
	}
	return ids
}
