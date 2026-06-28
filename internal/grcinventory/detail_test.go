package grcinventory

import (
	"testing"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcfindings"
)

func TestVulnerabilitiesReturnsEmptySlice(t *testing.T) {
	got := Vulnerabilities([]grcfindings.FindingItem{{ID: "finding-1", Title: "Owner missing", Status: "OPEN"}})
	if got == nil {
		t.Fatal("Vulnerabilities() = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Vulnerabilities() len = %d, want 0", len(got))
	}
}

func TestApplyFindingRiskCombinesInventorySignals(t *testing.T) {
	asset := graphquery.InventoryAsset{RiskScore: 20, RiskReasons: []string{"existing"}}
	got := ApplyFindingRisk(asset,
		[]grcfindings.FindingItem{{ID: "finding-1", Status: "OPEN", GRCFindingRisk: grcfindings.GRCFindingRisk{RiskScore: 80}}},
		[]TestItem{{Status: "failing"}},
		[]Vulnerability{{Severity: "HIGH"}},
	)
	if got.RiskScore != 100 {
		t.Fatalf("RiskScore = %d, want 100", got.RiskScore)
	}
	if got.RiskLevel != "critical" {
		t.Fatalf("RiskLevel = %q, want critical", got.RiskLevel)
	}
	wantReasons := map[string]bool{
		"existing":                         true,
		"open finding":                     true,
		"failing compliance tests":         true,
		"critical or high vulnerabilities": true,
	}
	for _, reason := range got.RiskReasons {
		delete(wantReasons, reason)
	}
	if len(wantReasons) != 0 {
		t.Fatalf("RiskReasons missing %v from %#v", wantReasons, got.RiskReasons)
	}
}
