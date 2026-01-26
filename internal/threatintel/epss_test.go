package threatintel

import (
	"testing"
)

func TestNewEPSSClient(t *testing.T) {
	client := NewEPSSClient()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.baseURL == "" {
		t.Error("expected baseURL to be set")
	}
	if client.cache == nil {
		t.Error("expected cache to be initialized")
	}
}

func TestEPSSClient_CacheStats(t *testing.T) {
	client := NewEPSSClient()

	size, _ := client.CacheStats()
	if size != 0 {
		t.Errorf("expected empty cache, got size %d", size)
	}

	// Manually populate cache
	client.cache["CVE-2021-44228"] = &EPSSScore{
		CVE:        "CVE-2021-44228",
		EPSS:       0.97,
		Percentile: 0.99,
	}

	size, _ = client.CacheStats()
	if size != 1 {
		t.Errorf("expected cache size 1, got %d", size)
	}
}

func TestEPSSClient_ClearCache(t *testing.T) {
	client := NewEPSSClient()
	client.cache["CVE-2021-44228"] = &EPSSScore{CVE: "CVE-2021-44228"}

	client.ClearCache()

	size, _ := client.CacheStats()
	if size != 0 {
		t.Errorf("expected empty cache after clear, got size %d", size)
	}
}

func TestCalculateVulnerabilityRisk_KEV(t *testing.T) {
	epss := &EPSSScore{
		CVE:        "CVE-2021-44228",
		EPSS:       0.97,
		Percentile: 0.99,
	}

	result := CalculateVulnerabilityRisk(10.0, epss, true, true)

	if result.Priority != "critical" {
		t.Errorf("KEV vulnerability should be critical, got %s", result.Priority)
	}
	if result.CompositeScore < 80 {
		t.Errorf("expected high composite score for KEV+high EPSS, got %f", result.CompositeScore)
	}
	if !result.IsKEV {
		t.Error("expected IsKEV to be true")
	}
}

func TestCalculateVulnerabilityRisk_LowRisk(t *testing.T) {
	epss := &EPSSScore{
		CVE:        "CVE-2023-12345",
		EPSS:       0.001,
		Percentile: 0.05,
	}

	result := CalculateVulnerabilityRisk(3.0, epss, false, false)

	if result.Priority == "critical" {
		t.Errorf("low risk vulnerability should not be critical, got %s", result.Priority)
	}
	if result.CompositeScore > 50 {
		t.Errorf("expected low composite score, got %f", result.CompositeScore)
	}
}

func TestCalculateVulnerabilityRisk_NoEPSS(t *testing.T) {
	result := CalculateVulnerabilityRisk(9.0, nil, false, false)

	// Should still calculate based on CVSS alone
	if result.CompositeScore < 30 {
		t.Errorf("expected reasonable score from CVSS alone, got %f", result.CompositeScore)
	}
	if result.EPSSScore != 0 {
		t.Errorf("expected zero EPSS score when nil, got %f", result.EPSSScore)
	}
}

func TestCalculateVulnerabilityRisk_HighEPSS(t *testing.T) {
	epss := &EPSSScore{
		CVE:        "CVE-2023-54321",
		EPSS:       0.85,
		Percentile: 0.95,
	}

	result := CalculateVulnerabilityRisk(7.5, epss, false, false)

	if result.Priority == "low" {
		t.Errorf("high EPSS should not be low priority, got %s", result.Priority)
	}
	// High EPSS should contribute significantly
	if result.CompositeScore < 50 {
		t.Errorf("expected moderate-high score from high EPSS, got %f", result.CompositeScore)
	}
}

func TestCalculateVulnerabilityRisk_PublicExploit(t *testing.T) {
	epss := &EPSSScore{
		CVE:        "CVE-2023-99999",
		EPSS:       0.5,
		Percentile: 0.75,
	}

	withExploit := CalculateVulnerabilityRisk(8.0, epss, false, true)
	withoutExploit := CalculateVulnerabilityRisk(8.0, epss, false, false)

	if withExploit.CompositeScore <= withoutExploit.CompositeScore {
		t.Error("public exploit should increase score")
	}
	if !withExploit.HasPublicExploit {
		t.Error("expected HasPublicExploit to be true")
	}
}
