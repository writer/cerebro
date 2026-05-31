package securityevents

import "testing"

func TestIsCanonicalKind(t *testing.T) {
	tests := []struct {
		kind string
		want bool
	}{
		{kind: "sec.findings.v1.recorded", want: true},
		{kind: " sec.audit.v1.api_access ", want: true},
		{kind: "github.audit", want: false},
		{kind: "section.audit", want: false},
		{kind: "sec", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			if got := IsCanonicalKind(tt.kind); got != tt.want {
				t.Fatalf("IsCanonicalKind(%q) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}
