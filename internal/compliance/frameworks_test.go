package compliance

import "testing"

func TestGetFrameworks(t *testing.T) {
	frameworks := GetFrameworks()

	if len(frameworks) != 4 {
		t.Errorf("expected 4 frameworks, got %d", len(frameworks))
	}

	ids := make(map[string]bool)
	for _, f := range frameworks {
		ids[f.ID] = true
	}

	expected := []string{"cis-aws-1.4", "cis-gcp-1.2", "cis-azure-1.4", "soc2-type2"}
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
		{"cis-aws-1.4", false, "CIS AWS Foundations Benchmark"},
		{"soc2-type2", false, "SOC 2 Type II"},
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
			if !tt.wantNil && f.Name != tt.wantName {
				t.Errorf("expected name '%s', got '%s'", tt.wantName, f.Name)
			}
		})
	}
}

func TestCISAWSControls(t *testing.T) {
	f := GetFramework("cis-aws-1.4")
	if f == nil {
		t.Fatal("CIS AWS framework not found")
	}

	if len(f.Controls) != 5 {
		t.Errorf("expected 5 controls, got %d", len(f.Controls))
	}

	// Check that controls have policy mappings
	for _, c := range f.Controls {
		if len(c.PolicyIDs) == 0 {
			t.Errorf("control %s has no policy mappings", c.ID)
		}
	}
}

func TestSOC2Controls(t *testing.T) {
	f := GetFramework("soc2-type2")
	if f == nil {
		t.Fatal("SOC 2 framework not found")
	}

	if len(f.Controls) != 3 {
		t.Errorf("expected 3 controls, got %d", len(f.Controls))
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
