package textutil

import "testing"

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty(" ", "\t", " value ", "later"); got != "value" {
		t.Fatalf("FirstNonEmpty() = %q, want value", got)
	}
	if got := FirstNonEmpty("", " "); got != "" {
		t.Fatalf("FirstNonEmpty(empty) = %q, want empty", got)
	}
}
