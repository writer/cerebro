package findings

import (
	"testing"
)

func TestNewRiskCalculator(t *testing.T) {
	calc := NewRiskCalculator()
	if calc == nil {
		t.Fatal("expected non-nil calculator")
	}
	if calc.weights == nil {
		t.Error("expected weights to be initialized")
	}
}

func TestDefaultWeights(t *testing.T) {
	w := DefaultWeights()

	// Weights should sum to approximately 1.0
	total := w.Vulnerability + w.Exploitability + w.Exposure + w.DataRisk
	if total < 0.99 || total > 1.01 {
		t.Errorf("weights should sum to ~1.0, got %f", total)
	}
}

func TestRiskCalculator_Calculate_Critical(t *testing.T) {
	calc := NewRiskCalculator()

	factors := &RiskFactors{
		CVSSScore:          10.0,
		EPSSScore:          0.95,
		EPSSPercentile:     0.99,
		IsKEV:              true,
		HasPublicExploit:   true,
		InternetExposed:    true,
		HasSensitiveData:   true,
		DataClassification: "restricted",
		BlastRadius:        150,
		AssetCriticality:   "critical",
	}

	result := calc.Calculate(factors)

	if result.Priority != "critical" {
		t.Errorf("expected critical priority, got %s", result.Priority)
	}
	if result.Score < 80 {
		t.Errorf("expected high score for critical factors, got %f", result.Score)
	}
	if len(result.Reasoning) == 0 {
		t.Error("expected reasoning to be populated")
	}
}

func TestRiskCalculator_Calculate_Low(t *testing.T) {
	calc := NewRiskCalculator()

	factors := &RiskFactors{
		CVSSScore:          2.0,
		EPSSScore:          0.001,
		EPSSPercentile:     0.05,
		IsKEV:              false,
		HasPublicExploit:   false,
		InternetExposed:    false,
		HasSensitiveData:   false,
		DataClassification: "public",
		BlastRadius:        1,
		AssetCriticality:   "low",
	}

	result := calc.Calculate(factors)

	if result.Priority == "critical" {
		t.Errorf("low risk factors should not be critical, got %s", result.Priority)
	}
	if result.Score > 40 {
		t.Errorf("expected low score, got %f", result.Score)
	}
}

func TestRiskCalculator_Calculate_KEVOverride(t *testing.T) {
	calc := NewRiskCalculator()

	// Even with low scores, KEV should escalate to critical
	factors := &RiskFactors{
		CVSSScore:        4.0,
		EPSSScore:        0.1,
		EPSSPercentile:   0.3,
		IsKEV:            true,
		InternetExposed:  false,
		AssetCriticality: "low",
	}

	result := calc.Calculate(factors)

	if result.Priority != "critical" {
		t.Errorf("KEV should always be critical, got %s", result.Priority)
	}
}

func TestRiskCalculator_Calculate_InternetExposure(t *testing.T) {
	calc := NewRiskCalculator()

	exposed := &RiskFactors{
		CVSSScore:       7.0,
		EPSSPercentile:  0.5,
		InternetExposed: true,
	}

	notExposed := &RiskFactors{
		CVSSScore:       7.0,
		EPSSPercentile:  0.5,
		InternetExposed: false,
	}

	exposedResult := calc.Calculate(exposed)
	notExposedResult := calc.Calculate(notExposed)

	if exposedResult.Score <= notExposedResult.Score {
		t.Error("internet exposure should increase score")
	}
}

func TestRiskCalculator_Calculate_BlastRadius(t *testing.T) {
	calc := NewRiskCalculator()

	largeBlast := &RiskFactors{
		CVSSScore:      7.0,
		EPSSPercentile: 0.5,
		BlastRadius:    150,
	}

	smallBlast := &RiskFactors{
		CVSSScore:      7.0,
		EPSSPercentile: 0.5,
		BlastRadius:    5,
	}

	largeResult := calc.Calculate(largeBlast)
	smallResult := calc.Calculate(smallBlast)

	if largeResult.Score <= smallResult.Score {
		t.Error("large blast radius should increase score")
	}
}

func TestRiskCalculator_Calculate_DataClassification(t *testing.T) {
	calc := NewRiskCalculator()

	restricted := &RiskFactors{
		CVSSScore:          7.0,
		HasSensitiveData:   true,
		DataClassification: "restricted",
	}

	public := &RiskFactors{
		CVSSScore:          7.0,
		HasSensitiveData:   true,
		DataClassification: "public",
	}

	restrictedResult := calc.Calculate(restricted)
	publicResult := calc.Calculate(public)

	if restrictedResult.Score <= publicResult.Score {
		t.Error("restricted data should increase score over public")
	}
}

func TestRiskCalculator_Calculate_AssetCriticality(t *testing.T) {
	calc := NewRiskCalculator()

	critical := &RiskFactors{
		CVSSScore:        7.0,
		EPSSPercentile:   0.5,
		AssetCriticality: "critical",
	}

	low := &RiskFactors{
		CVSSScore:        7.0,
		EPSSPercentile:   0.5,
		AssetCriticality: "low",
	}

	criticalResult := calc.Calculate(critical)
	lowResult := calc.Calculate(low)

	if criticalResult.Score <= lowResult.Score {
		t.Error("critical asset should have higher score than low")
	}
}

func TestRiskCalculator_Calculate_Confidence(t *testing.T) {
	calc := NewRiskCalculator()

	// Full data should have higher confidence
	full := &RiskFactors{
		CVSSScore:          8.0,
		EPSSScore:          0.5,
		IsKEV:              true,
		DataClassification: "confidential",
	}

	// Minimal data should have lower confidence
	minimal := &RiskFactors{
		CVSSScore: 8.0,
	}

	fullResult := calc.Calculate(full)
	minimalResult := calc.Calculate(minimal)

	if fullResult.Confidence <= minimalResult.Confidence {
		t.Error("more data should increase confidence")
	}
}

func TestRiskCalculator_Calculate_ComplianceImpact(t *testing.T) {
	calc := NewRiskCalculator()

	withCompliance := &RiskFactors{
		CVSSScore:        7.0,
		HasSensitiveData: true,
		ComplianceImpact: []string{"PCI-DSS", "HIPAA", "SOC2"},
	}

	withoutCompliance := &RiskFactors{
		CVSSScore:        7.0,
		HasSensitiveData: true,
	}

	withResult := calc.Calculate(withCompliance)
	withoutResult := calc.Calculate(withoutCompliance)

	if withResult.Score <= withoutResult.Score {
		t.Error("compliance impact should increase score")
	}
}

func TestRiskCalculator_BatchCalculate(t *testing.T) {
	calc := NewRiskCalculator()

	factorsList := []*RiskFactors{
		{CVSSScore: 9.0, IsKEV: true},
		{CVSSScore: 5.0, InternetExposed: true},
		{CVSSScore: 3.0},
	}

	results := calc.BatchCalculate(factorsList)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// First should be highest priority
	if results[0].Priority != "critical" {
		t.Errorf("first result should be critical, got %s", results[0].Priority)
	}

	// Results should have valid scores
	for i, r := range results {
		if r.Score < 0 || r.Score > 100 {
			t.Errorf("result %d has invalid score: %f", i, r.Score)
		}
	}
}

func TestScoreBreakdown_Fields(t *testing.T) {
	calc := NewRiskCalculator()

	factors := &RiskFactors{
		CVSSScore:          8.0,
		EPSSPercentile:     0.8,
		InternetExposed:    true,
		HasSensitiveData:   true,
		DataClassification: "confidential",
		AssetCriticality:   "high",
	}

	result := calc.Calculate(factors)

	if result.Breakdown == nil {
		t.Fatal("breakdown should not be nil")
	}
	if result.Breakdown.VulnerabilityScore <= 0 {
		t.Error("vulnerability score should be positive")
	}
	if result.Breakdown.ExploitabilityScore <= 0 {
		t.Error("exploitability score should be positive")
	}
	if result.Breakdown.ExposureScore <= 0 {
		t.Error("exposure score should be positive with internet exposure")
	}
	if result.Breakdown.DataSensitivity <= 0 {
		t.Error("data sensitivity should be positive")
	}
	if result.Breakdown.ContextMultiplier <= 0 {
		t.Error("context multiplier should be positive")
	}
}

func TestRiskCalculator_Calculate_NilFactors(t *testing.T) {
	calc := NewRiskCalculator()

	result := calc.Calculate(nil)

	if result == nil {
		t.Fatal("expected non-nil result even with nil factors")
	}
	if result.Score != 0 {
		t.Errorf("expected zero score for nil factors, got %f", result.Score)
	}
	if result.Priority != "low" {
		t.Errorf("expected low priority for nil factors, got %s", result.Priority)
	}
	if result.Confidence != 0 {
		t.Errorf("expected zero confidence for nil factors, got %f", result.Confidence)
	}
	if result.Factors == nil {
		t.Error("expected non-nil factors struct")
	}
	if result.Breakdown == nil {
		t.Error("expected non-nil breakdown struct")
	}
	if len(result.Reasoning) == 0 {
		t.Error("expected reasoning to explain nil factors")
	}
}
