// Package findings provides unified context-aware risk scoring for vulnerability prioritization.
package findings

// UnifiedRiskScore represents a composite risk score combining multiple risk signals
type UnifiedRiskScore struct {
	Score       float64         `json:"score"`      // 0-100 normalized
	Priority    string          `json:"priority"`   // critical, high, medium, low
	Factors     *RiskFactors    `json:"factors"`    // Individual factor scores
	Breakdown   *ScoreBreakdown `json:"breakdown"`  // Score contribution breakdown
	Reasoning   []string        `json:"reasoning"`  // Human-readable explanations
	Confidence  float64         `json:"confidence"` // Score confidence (0-1)
	LastUpdated string          `json:"last_updated"`
}

// RiskFactors holds individual risk signals for scoring
type RiskFactors struct {
	CVSSScore          float64  `json:"cvss_score"`          // Base CVSS score (0-10)
	EPSSScore          float64  `json:"epss_score"`          // EPSS probability (0-1)
	EPSSPercentile     float64  `json:"epss_percentile"`     // EPSS relative ranking (0-1)
	IsKEV              bool     `json:"is_kev"`              // In CISA KEV list
	HasPublicExploit   bool     `json:"has_public_exploit"`  // Exploit-DB, Metasploit, etc.
	InternetExposed    bool     `json:"internet_exposed"`    // Reachable from internet
	HasSensitiveData   bool     `json:"has_sensitive_data"`  // Contains PII/secrets
	DataClassification string   `json:"data_classification"` // public, internal, confidential, restricted
	BlastRadius        int      `json:"blast_radius"`        // Number of resources reachable
	IdentityRiskScore  float64  `json:"identity_risk_score"` // Over-privileged identity score
	AttackPathDepth    int      `json:"attack_path_depth"`   // Hops to crown jewels
	ComplianceImpact   []string `json:"compliance_impact"`   // Affected frameworks
	AssetCriticality   string   `json:"asset_criticality"`   // critical, high, medium, low
}

// ScoreBreakdown shows how each factor contributes to the total score
type ScoreBreakdown struct {
	VulnerabilityScore  float64 `json:"vulnerability_score"`  // From CVSS
	ExploitabilityScore float64 `json:"exploitability_score"` // From EPSS + KEV + public exploit
	ExposureScore       float64 `json:"exposure_score"`       // From internet exposure + blast radius
	DataSensitivity     float64 `json:"data_sensitivity"`     // From data classification
	ContextMultiplier   float64 `json:"context_multiplier"`   // Asset criticality adjustment
}

// RiskCalculator computes unified risk scores
type RiskCalculator struct {
	weights *ScoreWeights
}

// ScoreWeights configures the relative importance of each factor
type ScoreWeights struct {
	Vulnerability  float64 `json:"vulnerability"`  // CVSS weight (default: 0.25)
	Exploitability float64 `json:"exploitability"` // EPSS/KEV weight (default: 0.35)
	Exposure       float64 `json:"exposure"`       // Network exposure weight (default: 0.20)
	DataRisk       float64 `json:"data_risk"`      // Data sensitivity weight (default: 0.20)
}

// DefaultWeights returns balanced scoring weights
func DefaultWeights() *ScoreWeights {
	return &ScoreWeights{
		Vulnerability:  0.25,
		Exploitability: 0.35,
		Exposure:       0.20,
		DataRisk:       0.20,
	}
}

// NewRiskCalculator creates a calculator with default weights
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		weights: DefaultWeights(),
	}
}

// NewRiskCalculatorWithWeights creates a calculator with custom weights
func NewRiskCalculatorWithWeights(w *ScoreWeights) *RiskCalculator {
	return &RiskCalculator{weights: w}
}

// Calculate computes a unified risk score from risk factors
func (c *RiskCalculator) Calculate(factors *RiskFactors) *UnifiedRiskScore {
	if factors == nil {
		return &UnifiedRiskScore{
			Score:      0,
			Priority:   "low",
			Factors:    &RiskFactors{},
			Breakdown:  &ScoreBreakdown{},
			Reasoning:  []string{"No risk factors provided"},
			Confidence: 0,
		}
	}

	result := &UnifiedRiskScore{
		Factors:   factors,
		Breakdown: &ScoreBreakdown{},
		Reasoning: []string{},
	}

	// 1. Vulnerability Score (from CVSS, normalized to 0-100)
	vulnScore := (factors.CVSSScore / 10.0) * 100.0
	result.Breakdown.VulnerabilityScore = vulnScore

	// 2. Exploitability Score (EPSS + KEV + public exploit)
	exploitScore := c.calculateExploitability(factors, result)
	result.Breakdown.ExploitabilityScore = exploitScore

	// 3. Exposure Score (internet exposure + blast radius)
	exposureScore := c.calculateExposure(factors, result)
	result.Breakdown.ExposureScore = exposureScore

	// 4. Data Sensitivity Score
	dataScore := c.calculateDataSensitivity(factors, result)
	result.Breakdown.DataSensitivity = dataScore

	// 5. Context Multiplier (asset criticality)
	contextMultiplier := c.getContextMultiplier(factors)
	result.Breakdown.ContextMultiplier = contextMultiplier

	// Compute weighted total
	baseScore := (vulnScore * c.weights.Vulnerability) +
		(exploitScore * c.weights.Exploitability) +
		(exposureScore * c.weights.Exposure) +
		(dataScore * c.weights.DataRisk)

	// Apply context multiplier
	finalScore := baseScore * contextMultiplier
	if finalScore > 100 {
		finalScore = 100
	}

	result.Score = finalScore
	result.Priority = c.getPriority(finalScore, factors)
	result.Confidence = c.calculateConfidence(factors)

	return result
}

func (c *RiskCalculator) calculateExploitability(factors *RiskFactors, result *UnifiedRiskScore) float64 {
	score := 0.0

	// EPSS percentile is the primary signal (0-1 to 0-60)
	if factors.EPSSPercentile > 0 {
		score += factors.EPSSPercentile * 60.0
		if factors.EPSSPercentile > 0.9 {
			result.Reasoning = append(result.Reasoning, "Top 10% EPSS score - very high exploitation likelihood")
		} else if factors.EPSSPercentile > 0.7 {
			result.Reasoning = append(result.Reasoning, "High EPSS percentile - elevated exploitation risk")
		}
	}

	// KEV is a critical signal - adds 30 points
	if factors.IsKEV {
		score += 30.0
		result.Reasoning = append(result.Reasoning, "In CISA KEV - actively exploited in the wild")
	}

	// Public exploit adds 10 points
	if factors.HasPublicExploit {
		score += 10.0
		result.Reasoning = append(result.Reasoning, "Public exploit code available")
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (c *RiskCalculator) calculateExposure(factors *RiskFactors, result *UnifiedRiskScore) float64 {
	score := 0.0

	// Internet exposure is critical
	if factors.InternetExposed {
		score += 50.0
		result.Reasoning = append(result.Reasoning, "Internet-exposed - directly attackable")
	}

	// Blast radius adds risk
	switch {
	case factors.BlastRadius > 100:
		score += 30.0
		result.Reasoning = append(result.Reasoning, "Large blast radius (100+ resources reachable)")
	case factors.BlastRadius > 50:
		score += 20.0
		result.Reasoning = append(result.Reasoning, "Moderate blast radius (50+ resources reachable)")
	case factors.BlastRadius > 10:
		score += 10.0
	}

	// Short attack path to crown jewels
	if factors.AttackPathDepth > 0 && factors.AttackPathDepth <= 2 {
		score += 20.0
		result.Reasoning = append(result.Reasoning, "Short attack path to critical assets")
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (c *RiskCalculator) calculateDataSensitivity(factors *RiskFactors, result *UnifiedRiskScore) float64 {
	score := 0.0

	if factors.HasSensitiveData {
		switch factors.DataClassification {
		case "restricted":
			score = 100.0
			result.Reasoning = append(result.Reasoning, "Contains restricted/highly sensitive data")
		case "confidential":
			score = 75.0
			result.Reasoning = append(result.Reasoning, "Contains confidential data")
		case "internal":
			score = 40.0
		case "public":
			score = 10.0
		default:
			score = 50.0 // Unknown classification is treated as moderate risk
		}
	}

	// Compliance impact adds risk
	if len(factors.ComplianceImpact) > 0 {
		complianceBonus := float64(len(factors.ComplianceImpact)) * 10.0
		if complianceBonus > 30 {
			complianceBonus = 30
		}
		score += complianceBonus
		if len(factors.ComplianceImpact) >= 2 {
			result.Reasoning = append(result.Reasoning, "Multiple compliance frameworks affected")
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

func (c *RiskCalculator) getContextMultiplier(factors *RiskFactors) float64 {
	switch factors.AssetCriticality {
	case "critical":
		return 1.3 // 30% boost for critical assets
	case "high":
		return 1.15
	case "medium":
		return 1.0
	case "low":
		return 0.85
	default:
		return 1.0
	}
}

func (c *RiskCalculator) getPriority(score float64, factors *RiskFactors) string {
	// KEV always escalates to critical
	if factors.IsKEV {
		return "critical"
	}

	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func (c *RiskCalculator) calculateConfidence(factors *RiskFactors) float64 {
	// Start with base confidence
	confidence := 0.5

	// EPSS data increases confidence
	if factors.EPSSScore > 0 {
		confidence += 0.2
	}

	// CVSS score increases confidence
	if factors.CVSSScore > 0 {
		confidence += 0.15
	}

	// Known KEV status increases confidence
	if factors.IsKEV {
		confidence += 0.1
	}

	// Data classification adds confidence
	if factors.DataClassification != "" {
		confidence += 0.05
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

// BatchCalculate computes risk scores for multiple findings
func (c *RiskCalculator) BatchCalculate(factorsList []*RiskFactors) []*UnifiedRiskScore {
	results := make([]*UnifiedRiskScore, len(factorsList))
	for i, factors := range factorsList {
		results[i] = c.Calculate(factors)
	}
	return results
}
