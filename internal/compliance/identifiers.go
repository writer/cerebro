package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidIdentifier = errors.New("invalid compliance identifier")

// IdentifierKind names the stable public prefix for one compliance resource.
type IdentifierKind string

const (
	IdentifierProgram        IdentifierKind = "program"
	IdentifierScope          IdentifierKind = "scope"
	IdentifierImplementation IdentifierKind = "implementation"
	IdentifierPlan           IdentifierKind = "assessment-plan"
	IdentifierTest           IdentifierKind = "assessment-test"
	IdentifierEvidence       IdentifierKind = "evidence"
	IdentifierClaim          IdentifierKind = "evidence-claim"
	IdentifierRun            IdentifierKind = "assessment-run"
	IdentifierResult         IdentifierKind = "assessment-result"
	IdentifierReview         IdentifierKind = "assessment-review"
	IdentifierArtifact       IdentifierKind = "artifact"
	IdentifierMapping        IdentifierKind = "control-mapping"
)

const identifierEntropyBytes = 16

// NewIdentifier returns an opaque identifier with a resource-specific prefix.
func NewIdentifier(kind IdentifierKind) (string, error) {
	if err := ValidateIdentifierKind(kind); err != nil {
		return "", err
	}
	random := make([]byte, identifierEntropyBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate compliance identifier: %w", err)
	}
	return string(kind) + "-" + hex.EncodeToString(random), nil
}

// NewRevisionIdentifier returns an opaque identity for an immutable revision.
func NewRevisionIdentifier(kind IdentifierKind) (string, error) {
	if err := ValidateIdentifierKind(kind); err != nil {
		return "", err
	}
	random := make([]byte, identifierEntropyBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate compliance revision identifier: %w", err)
	}
	return string(kind) + "-revision-" + hex.EncodeToString(random), nil
}

func ValidateIdentifierKind(kind IdentifierKind) error {
	value := string(kind)
	if value == "" || len(value) > 40 || !identifierToken(value) {
		return fmt.Errorf("%w: kind %q", ErrInvalidIdentifier, value)
	}
	return nil
}

// ValidateIdentifier rejects display names, whitespace, path separators, and
// tenant data in public identifiers. IDs remain opaque and tenant scoping is
// enforced separately by every store lookup.
func ValidateIdentifier(kind IdentifierKind, value string) error {
	if err := ValidateIdentifierKind(kind); err != nil {
		return err
	}
	raw := value
	value = strings.TrimSpace(value)
	if value != raw {
		return fmt.Errorf("%w: identifier contains surrounding whitespace", ErrInvalidIdentifier)
	}
	prefix := string(kind) + "-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+(identifierEntropyBytes*2) {
		return fmt.Errorf("%w: expected %s prefix", ErrInvalidIdentifier, prefix)
	}
	if !lowerHex(value[len(prefix):]) {
		return fmt.Errorf("%w: %q", ErrInvalidIdentifier, value)
	}
	return nil
}

// ValidateRevisionIdentifier checks an immutable revision identity separately
// from the logical record identity.
func ValidateRevisionIdentifier(kind IdentifierKind, value string) error {
	if err := ValidateIdentifierKind(kind); err != nil {
		return err
	}
	raw := value
	value = strings.TrimSpace(value)
	if value != raw {
		return fmt.Errorf("%w: revision identifier contains surrounding whitespace", ErrInvalidIdentifier)
	}
	prefix := string(kind) + "-revision-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+(identifierEntropyBytes*2) {
		return fmt.Errorf("%w: expected %s prefix", ErrInvalidIdentifier, prefix)
	}
	if !lowerHex(value[len(prefix):]) {
		return fmt.Errorf("%w: %q", ErrInvalidIdentifier, value)
	}
	return nil
}

func identifierToken(value string) bool {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func lowerHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'f') || (character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func ValidateContentDigest(digest ContentDigest) error {
	value := string(digest)
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 || !lowerHex(value[len(prefix):]) {
		return fmt.Errorf("%w: invalid content digest", ErrInvalidRevision)
	}
	return nil
}
