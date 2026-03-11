package app

import "testing"

func TestParseAPIKeysUsesStableDerivedUserID(t *testing.T) {
	keys := parseAPIKeys("alpha,beta=user-b")

	if got := keys["beta"]; got != "user-b" {
		t.Fatalf("expected explicit mapping for beta, got %q", got)
	}
	if got := keys["alpha"]; got == "" {
		t.Fatal("expected derived user id for alpha")
	} else if got == "alpha" {
		t.Fatal("expected derived user id to avoid leaking API key")
	}
}

func TestDefaultAPIUserIDIsStable(t *testing.T) {
	first := defaultAPIUserID("sample-key")
	second := defaultAPIUserID("sample-key")
	if first == "" {
		t.Fatal("expected non-empty derived user id")
	}
	if first != second {
		t.Fatalf("expected stable derived user id, got %q and %q", first, second)
	}
}
