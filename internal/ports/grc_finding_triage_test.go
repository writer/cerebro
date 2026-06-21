package ports

import "testing"

func TestIsGRCFindingDisposition(t *testing.T) {
	valid := []string{
		GRCFindingDispositionOpen,
		GRCFindingDispositionInTriage,
		GRCFindingDispositionRiskAccepted,
		GRCFindingDispositionFalsePositive,
		GRCFindingDispositionResolved,
	}
	for _, value := range valid {
		if !IsGRCFindingDisposition(value) {
			t.Fatalf("IsGRCFindingDisposition(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "accepted", "OPEN", "snoozed", " open"} {
		if IsGRCFindingDisposition(value) {
			t.Fatalf("IsGRCFindingDisposition(%q) = true, want false", value)
		}
	}
}
