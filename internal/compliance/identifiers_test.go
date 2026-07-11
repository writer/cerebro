package compliance

import (
	"errors"
	"strings"
	"testing"
)

func TestOpaqueLogicalAndRevisionIdentifiersValidateSeparately(t *testing.T) {
	logical, err := NewIdentifier(IdentifierProgram)
	if err != nil {
		t.Fatalf("NewIdentifier() error = %v", err)
	}
	revision, err := NewRevisionIdentifier(IdentifierProgram)
	if err != nil {
		t.Fatalf("NewRevisionIdentifier() error = %v", err)
	}
	if err := ValidateIdentifier(IdentifierProgram, logical); err != nil {
		t.Fatalf("ValidateIdentifier() error = %v", err)
	}
	if err := ValidateRevisionIdentifier(IdentifierProgram, revision); err != nil {
		t.Fatalf("ValidateRevisionIdentifier() error = %v", err)
	}
	if logical == revision || strings.Contains(logical, "revision") {
		t.Fatalf("logical=%q revision=%q are not distinct", logical, revision)
	}
	if err := ValidateIdentifier(IdentifierProgram, revision); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ValidateIdentifier(revision) error = %v, want ErrInvalidIdentifier", err)
	}
	if err := ValidateRevisionIdentifier(IdentifierProgram, logical); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ValidateRevisionIdentifier(logical) error = %v, want ErrInvalidIdentifier", err)
	}
}

func TestValidateIdentifierRejectsLossyAndNonOpaqueValues(t *testing.T) {
	for _, value := range []string{
		"program-customer/name",
		"program-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-",
		"program-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"program-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-extra",
		" program-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		if err := ValidateIdentifier(IdentifierProgram, value); !errors.Is(err, ErrInvalidIdentifier) {
			t.Fatalf("ValidateIdentifier(%q) error = %v, want ErrInvalidIdentifier", value, err)
		}
	}
}

func TestValidateContentDigestRequiresCanonicalSHA256(t *testing.T) {
	valid := ContentDigest("sha256:" + strings.Repeat("a", 64))
	if err := ValidateContentDigest(valid); err != nil {
		t.Fatalf("ValidateContentDigest() error = %v", err)
	}
	for _, value := range []ContentDigest{"", "sha256:abc", ContentDigest("SHA256:" + strings.Repeat("a", 64)), ContentDigest("sha256:" + strings.Repeat("A", 64))} {
		if err := ValidateContentDigest(value); !errors.Is(err, ErrInvalidRevision) {
			t.Fatalf("ValidateContentDigest(%q) error = %v, want ErrInvalidRevision", value, err)
		}
	}
}
