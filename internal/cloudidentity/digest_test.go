package cloudidentity

import "testing"

func TestDigestDeterministic(t *testing.T) {
	v := Grant{ID: "a", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"*"}}
	d1 := Digest(v)
	d2 := Digest(v)
	if d1 != d2 {
		t.Fatalf("Digest not deterministic: %q != %q", d1, d2)
	}
	if d1 == "" {
		t.Fatal("Digest returned empty string")
	}
}

func TestDigestDiffersForDifferentValues(t *testing.T) {
	a := Grant{ID: "a", Effect: "Allow"}
	b := Grant{ID: "b", Effect: "Allow"}
	if Digest(a) == Digest(b) {
		t.Fatal("expected different digests for different values")
	}
}

func TestDigestStableAcrossMapKeyOrder(t *testing.T) {
	m1 := map[string]int{"a": 1, "b": 2, "c": 3}
	m2 := map[string]int{"c": 3, "b": 2, "a": 1}
	if Digest(m1) != Digest(m2) {
		t.Fatal("expected identical digests regardless of map construction order")
	}
}

func TestDigestHasStablePrefix(t *testing.T) {
	d := Digest("hello")
	if len(d) < 7 || d[:7] != "sha256:" {
		t.Errorf("Digest = %q, want sha256: prefix", d)
	}
}
