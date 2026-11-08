package sourcecdk

import (
	"errors"
	"fmt"
	"testing"
)

func TestStableIDJoinsNonEmptyTrimmedParts(t *testing.T) {
	if got := StableID(" a ", "", "b", "  "); got != "a:b" {
		t.Fatalf("StableID() = %q, want a:b", got)
	}
	if got := StableID(); got != "" {
		t.Fatalf("StableID() = %q, want empty", got)
	}
}

func TestNormalizeIDReplacesUnsafeCharacters(t *testing.T) {
	if got := NormalizeID("role/a b:c\nd\te"); got != "role-a-b-c-d-e" {
		t.Fatalf("NormalizeID() = %q, want role-a-b-c-d-e", got)
	}
	if got := NormalizeID("   "); got != "unknown" {
		t.Fatalf("NormalizeID(blank) = %q, want unknown", got)
	}
}

func TestFirstNonEmptyReturnsFirstTrimmedNonEmptyValue(t *testing.T) {
	if got := FirstNonEmpty("", "  ", "b", "c"); got != "b" {
		t.Fatalf("FirstNonEmpty() = %q, want b", got)
	}
	if got := FirstNonEmpty("", ""); got != "" {
		t.Fatalf("FirstNonEmpty() = %q, want empty", got)
	}
}

func TestTrimEmptyAttributesDeletesBlankAndTrimsRemaining(t *testing.T) {
	attrs := map[string]string{"a": " x ", "b": "", "c": "  "}
	TrimEmptyAttributes(attrs)
	if got, want := attrs["a"], "x"; got != want {
		t.Fatalf("attrs[a] = %q, want %q", got, want)
	}
	if _, ok := attrs["b"]; ok {
		t.Fatal("attrs[b] present, want deleted")
	}
	if _, ok := attrs["c"]; ok {
		t.Fatal("attrs[c] present, want deleted")
	}
	if len(attrs) != 1 {
		t.Fatalf("len(attrs) = %d, want 1", len(attrs))
	}
}

func TestCloneRawMessageDoesNotAliasBackingArray(t *testing.T) {
	original := []byte(`{"a":1}`)
	cloned := CloneRawMessage(original)
	cloned[0] = 'X'
	if original[0] == 'X' {
		t.Fatal("CloneRawMessage() aliases the original backing array")
	}
}

func TestScopeHashIsStableAndTwelveHexChars(t *testing.T) {
	a := ScopeHash("https://example.test", "client-1", "scope-1")
	b := ScopeHash("https://example.test", "client-1", "scope-1")
	if a != b {
		t.Fatalf("ScopeHash() = %q, %q, want identical digests for identical parts", a, b)
	}
	if len(a) != 12 {
		t.Fatalf("len(ScopeHash()) = %d, want 12", len(a))
	}
	if c := ScopeHash("https://example.test", "client-2", "scope-1"); c == a {
		t.Fatalf("ScopeHash() = %q, want distinct digest for a different client ID", c)
	}
}

func TestWrapFamilyErrPassesNilThroughAndWrapsNonNil(t *testing.T) {
	if got := WrapFamilyErr("acme", "widgets", nil); got != nil {
		t.Fatalf("WrapFamilyErr(nil) = %v, want nil", got)
	}
	inner := fmt.Errorf("boom")
	wrapped := WrapFamilyErr("acme", "widgets", inner)
	if wrapped == nil || !errors.Is(wrapped, inner) {
		t.Fatalf("WrapFamilyErr() = %v, want wrapping %v", wrapped, inner)
	}
	if got, want := wrapped.Error(), "acme widgets: boom"; got != want {
		t.Fatalf("WrapFamilyErr().Error() = %q, want %q", got, want)
	}
}
