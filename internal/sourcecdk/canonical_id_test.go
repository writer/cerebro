package sourcecdk

import "testing"

func TestCanonicalRecordIDDistinctForSeparatorOnlyDifference(t *testing.T) {
	a := CanonicalRecordID("assessment", "scan-1", "run-1", "check-1", "aws", "role/a-b")
	b := CanonicalRecordID("assessment", "scan-1", "run-1", "check-1", "aws", "role/a/b")
	if a == b {
		t.Fatalf("CanonicalRecordID(%q) == CanonicalRecordID(%q) = %q, want distinct digests", "role/a-b", "role/a/b", a)
	}
}

func TestCanonicalRecordIDStableForSameParts(t *testing.T) {
	a := CanonicalRecordID("run", "scan-1", "run-1")
	b := CanonicalRecordID("run", "scan-1", "run-1")
	if a != b {
		t.Fatalf("CanonicalRecordID() = %q, %q, want identical digests for identical parts", a, b)
	}
}

func TestCanonicalRecordIDDistinctForConcatenationCollision(t *testing.T) {
	// Without length-prefixing, ("ab", "c") and ("a", "bc") would hash to the
	// same concatenated byte stream.
	a := CanonicalRecordID("ab", "c")
	b := CanonicalRecordID("a", "bc")
	if a == b {
		t.Fatalf("CanonicalRecordID(%q,%q) == CanonicalRecordID(%q,%q) = %q, want distinct digests", "ab", "c", "a", "bc", a)
	}
}
