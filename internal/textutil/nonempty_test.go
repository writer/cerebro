package textutil

import "testing"

func TestFirstNonEmptyTrimmed(t *testing.T) {
	if got := FirstNonEmptyTrimmed("   ", "", " alpha ", "beta"); got != "alpha" {
		t.Fatalf("FirstNonEmptyTrimmed() = %q, want alpha", got)
	}
	if got := FirstNonEmptyTrimmed(" ", "\t"); got != "" {
		t.Fatalf("FirstNonEmptyTrimmed() = %q, want empty", got)
	}
}
