package securitytooling

import (
	"strings"
	"testing"
)

func TestCoverageStatus(t *testing.T) {
	for _, tt := range []struct {
		coverage string
		want     string
	}{
		{coverage: "", want: ""},
		{coverage: "full", want: "covered"},
		{coverage: "Operating", want: "covered"},
		{coverage: "partial", want: "gap"},
		{coverage: "not_covered", want: "gap"},
		{coverage: "unknown", want: ""},
	} {
		t.Run(tt.coverage, func(t *testing.T) {
			if got := CoverageStatus(tt.coverage); got != tt.want {
				t.Fatalf("CoverageStatus(%q) = %q, want %q", tt.coverage, got, tt.want)
			}
		})
	}
}

func TestControlCoverageURNEscapesDelimiterTokens(t *testing.T) {
	legitimate := ControlCoverageURN("writer", "agent-gateway", "ISO 27001:2022", "CC6.1")
	crafted := ControlCoverageURN("writer", "agent-gateway", "ISO 27001", "2022:CC6.1")
	if legitimate == "" || crafted == "" {
		t.Fatalf("ControlCoverageURN returned empty: legitimate=%q crafted=%q", legitimate, crafted)
	}
	if legitimate == crafted {
		t.Fatalf("ControlCoverageURN alias: legitimate=%q crafted=%q", legitimate, crafted)
	}
	if strings.Contains(legitimate, "ISO 27001:2022") || strings.Contains(crafted, "2022:CC6.1") {
		t.Fatalf("ControlCoverageURN left raw delimiter tokens: legitimate=%q crafted=%q", legitimate, crafted)
	}
}
