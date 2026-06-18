package securitytooling

import "testing"

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
