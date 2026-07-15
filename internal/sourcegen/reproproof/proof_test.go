package reproproof

import "testing"

func TestSourcegenReproducibilityProof(t *testing.T) {
	report, err := Prove(t.TempDir())
	if err != nil {
		t.Fatalf("Prove() error = %v", err)
	}
	if len(report.Cases) != 7 {
		t.Fatalf("proof cases = %d, want 7", len(report.Cases))
	}
	if report.Failed != 0 || report.Passed != len(report.Cases) {
		for _, proof := range report.Cases {
			if proof.Status == ProofStatusFailed {
				t.Logf("%s: %s", proof.ID, proof.Error)
			}
		}
		t.Fatalf("reproducibility proof = %d passed, %d failed", report.Passed, report.Failed)
	}
}

func TestProveRequiresOutputRoot(t *testing.T) {
	if _, err := Prove(""); err == nil {
		t.Fatal("Prove() error = nil, want output-root error")
	}
}
