package bootstrap

import "testing"

func TestGRCInventoryVulnerabilitiesReturnsEmptySlice(t *testing.T) {
	got := grcInventoryVulnerabilities([]grcFindingItem{{ID: "finding-1", Title: "Owner missing", Status: "OPEN"}})
	if got == nil {
		t.Fatal("grcInventoryVulnerabilities() = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("grcInventoryVulnerabilities() len = %d, want 0", len(got))
	}
}
