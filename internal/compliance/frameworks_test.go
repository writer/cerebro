package compliance

import "testing"

func TestGetFrameworks(t *testing.T) {
	frameworks := GetFrameworks()

	if len(frameworks) != 6 {
		t.Errorf("expected 6 frameworks, got %d", len(frameworks))
	}

	ids := make(map[string]bool)
	for _, f := range frameworks {
		ids[f.ID] = true
	}

	expected := []string{"cis-aws-1.5", "pci-dss-4.0", "hipaa-security", "soc2-type2", "cis-gcp-1.3", "cis-azure-1.5"}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("missing framework: %s", id)
		}
	}
}

func TestGetFramework(t *testing.T) {
	tests := []struct {
		id       string
		wantNil  bool
		wantName string
	}{
		{"cis-aws-1.5", false, "CIS AWS Foundations Benchmark"},
		{"pci-dss-4.0", false, "PCI DSS"},
		{"hipaa-security", false, "HIPAA Security Rule"},
		{"soc2-type2", false, "SOC 2 Type II"},
		{"cis-gcp-1.3", false, "CIS Google Cloud Platform Benchmark"},
		{"cis-azure-1.5", false, "CIS Microsoft Azure Foundations Benchmark"},
		{"nonexistent", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			f := GetFramework(tt.id)
			if tt.wantNil && f != nil {
				t.Errorf("expected nil, got %v", f)
			}
			if !tt.wantNil && f == nil {
				t.Error("expected framework, got nil")
			}
			if !tt.wantNil && f != nil && f.Name != tt.wantName {
				t.Errorf("expected name '%s', got '%s'", tt.wantName, f.Name)
			}
		})
	}
}

func TestCISAWSControls(t *testing.T) {
	f := GetFramework("cis-aws-1.5")
	if f == nil {
		t.Fatal("CIS AWS framework not found")
	}

	// Should have many controls now
	if len(f.Controls) < 20 {
		t.Errorf("expected at least 20 controls, got %d", len(f.Controls))
	}

	// Check that controls have policy mappings
	for _, c := range f.Controls {
		if len(c.PolicyIDs) == 0 {
			t.Errorf("control %s has no policy mappings", c.ID)
		}
	}
}

func TestPCIDSSControls(t *testing.T) {
	f := GetFramework("pci-dss-4.0")
	if f == nil {
		t.Fatal("PCI DSS framework not found")
	}

	if len(f.Controls) < 10 {
		t.Errorf("expected at least 10 PCI DSS controls, got %d", len(f.Controls))
	}

	// Check that encryption requirements exist
	var hasEncryption bool
	for _, c := range f.Controls {
		if c.ID == "3.5.1" || c.ID == "4.2.1" {
			hasEncryption = true
			break
		}
	}
	if !hasEncryption {
		t.Error("PCI DSS should have encryption controls")
	}
}

func TestHIPAAControls(t *testing.T) {
	f := GetFramework("hipaa-security")
	if f == nil {
		t.Fatal("HIPAA framework not found")
	}

	if len(f.Controls) < 8 {
		t.Errorf("expected at least 8 HIPAA controls, got %d", len(f.Controls))
	}

	// Check for audit controls
	var hasAudit bool
	for _, c := range f.Controls {
		if c.ID == "164.312(b)" {
			hasAudit = true
			break
		}
	}
	if !hasAudit {
		t.Error("HIPAA should have audit controls")
	}
}

func TestSOC2Controls(t *testing.T) {
	f := GetFramework("soc2-type2")
	if f == nil {
		t.Fatal("SOC 2 framework not found")
	}

	if len(f.Controls) < 8 {
		t.Errorf("expected at least 8 SOC 2 controls, got %d", len(f.Controls))
	}

	// CC6.1 should have multiple policy mappings
	var cc61 *Control
	for _, c := range f.Controls {
		if c.ID == "CC6.1" {
			cc61 = &c
			break
		}
	}

	if cc61 == nil {
		t.Fatal("CC6.1 control not found")
	}

	if len(cc61.PolicyIDs) < 2 {
		t.Errorf("expected CC6.1 to have multiple policy mappings, got %d", len(cc61.PolicyIDs))
	}
}

func TestGetFrameworkIDs(t *testing.T) {
	ids := GetFrameworkIDs()
	if len(ids) != 6 {
		t.Errorf("expected 6 framework IDs, got %d", len(ids))
	}
}

func TestGetControlsForPolicy(t *testing.T) {
	// aws-iam-user-mfa-enabled should be referenced by multiple frameworks
	controls := GetControlsForPolicy("aws-iam-user-mfa-enabled")

	if len(controls) < 3 {
		t.Errorf("expected aws-iam-user-mfa-enabled to be in at least 3 frameworks, got %d", len(controls))
	}

	// Verify the frameworks include CIS, PCI-DSS, and HIPAA
	frameworks := make(map[string]bool)
	for _, c := range controls {
		frameworks[c.Framework.ID] = true
	}

	if !frameworks["cis-aws-1.5"] {
		t.Error("expected aws-iam-user-mfa-enabled to be in CIS AWS")
	}
	if !frameworks["pci-dss-4.0"] {
		t.Error("expected aws-iam-user-mfa-enabled to be in PCI DSS")
	}
}

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		severity ControlSeverity
		want     int
	}{
		{SeverityCritical, 10},
		{SeverityHigh, 5},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{"", 2}, // Default to medium
	}

	for _, tt := range tests {
		if got := tt.severity.Weight(); got != tt.want {
			t.Errorf("Severity(%q).Weight() = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestCalculateWeightedScore(t *testing.T) {
	controls := []Control{
		{ID: "1", Severity: SeverityCritical}, // weight 10
		{ID: "2", Severity: SeverityHigh},     // weight 5
		{ID: "3", Severity: SeverityMedium},   // weight 2
		{ID: "4", Severity: SeverityLow},      // weight 1
	}
	// Total weight: 18

	// All passing
	failing := map[string]bool{}
	score, total, passing := CalculateWeightedScore(controls, failing)
	if score != 100 {
		t.Errorf("all passing score = %.1f, want 100", score)
	}
	if total != 18 || passing != 18 {
		t.Errorf("weights = %d/%d, want 18/18", passing, total)
	}

	// Critical control failing
	failing = map[string]bool{"1": true}
	score, _, _ = CalculateWeightedScore(controls, failing)
	// Passing weight: 5+2+1=8, Total: 18, Score: 8/18*100 = 44.4%
	if score < 44 || score > 45 {
		t.Errorf("critical failing score = %.1f, want ~44.4", score)
	}

	// Low control failing
	failing = map[string]bool{"4": true}
	score, _, _ = CalculateWeightedScore(controls, failing)
	// Passing weight: 10+5+2=17, Total: 18, Score: 17/18*100 = 94.4%
	if score < 94 || score > 95 {
		t.Errorf("low failing score = %.1f, want ~94.4", score)
	}
}
