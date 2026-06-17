package claims

import (
	"testing"

	"github.com/writer/cerebro/sdk/go/cerebroapi"
)

func TestRefEncodesExternalIDLikeCerebroURNPathSegment(t *testing.T) {
	ref := Ref(
		"tenant-a",
		"runtime-main",
		"finding",
		"finding:id with spaces!*'()~:/?#[]@é",
		"Encoded finding",
	)
	want := "urn:cerebro:tenant-a:runtime:runtime-main:finding:finding%3Aid%20with%20spaces!*'()~%3A%2F%3F%23%5B%5D%40%C3%A9"
	if ref.URN != want {
		t.Fatalf("URN = %q, want %q", ref.URN, want)
	}
}

func TestRefEncodesAllVariableURNSegments(t *testing.T) {
	ref := Ref("tenant:a", "runtime:main", "finding:type", "external id", "Finding")
	want := "urn:cerebro:tenant%3Aa:runtime:runtime%3Amain:finding%3Atype:external%20id"
	if ref.URN != want {
		t.Fatalf("URN = %q, want %q", ref.URN, want)
	}
	if ref.EntityType != "finding:type" {
		t.Fatalf("EntityType = %q", ref.EntityType)
	}
}

func TestEncodeExternalIDAvoidsSpaceHyphenCollision(t *testing.T) {
	withSpace := EncodeExternalID("external id")
	withHyphen := EncodeExternalID("external-id")
	if withSpace == withHyphen {
		t.Fatalf("space and hyphen encodings collided: %q", withSpace)
	}
	if withSpace != "external%20id" || withHyphen != "external-id" {
		t.Fatalf("encodings = %q, %q", withSpace, withHyphen)
	}
}

func TestClaimConstructorsUseCanonicalClaimShapes(t *testing.T) {
	finding := Ref("tenant-a", "runtime-main", "finding", "finding-1", "Finding 1")
	asset := Ref("tenant-a", "runtime-main", "asset", "asset-1", "Asset 1")
	source := Source{
		SourceEventID: "evt-1",
		ObservedAt:    "2026-06-16T12:00:00Z",
		Attributes: map[string]string{
			" provider ": " github ",
			"empty":      "",
			" ":          "ignored",
		},
	}

	cases := []struct {
		name      string
		predicate string
		claimType string
		claim     cerebroapi.Claim
	}{
		{name: "exists", predicate: PredicateExists, claimType: TypeExistence, claim: Exists(finding, source)},
		{name: "attribute", predicate: "severity", claimType: TypeAttribute, claim: Attribute(finding, "severity", "HIGH", source)},
		{name: "relation", predicate: "affects", claimType: TypeRelation, claim: Relation(finding, "affects", asset, source)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.claim.Predicate != tc.predicate || tc.claim.ClaimType != tc.claimType {
				t.Fatalf("claim = %#v", tc.claim)
			}
			if tc.claim.SubjectURN != finding.URN || tc.claim.Status != StatusAsserted || tc.claim.SourceEventID != "evt-1" {
				t.Fatalf("claim source fields = %#v", tc.claim)
			}
			if _, ok := tc.claim.Attributes["empty"]; ok {
				t.Fatalf("empty attribute was retained: %#v", tc.claim.Attributes)
			}
			if tc.claim.Attributes["provider"] != "github" {
				t.Fatalf("provider attribute = %#v", tc.claim.Attributes)
			}
			if _, ok := tc.claim.Attributes[" provider "]; ok {
				t.Fatalf("untrimmed attribute key was retained: %#v", tc.claim.Attributes)
			}
		})
	}
}

func TestCopyAttributesReturnsNilWhenAllEntriesFiltered(t *testing.T) {
	attributes := copyAttributes(map[string]string{
		"empty": "",
		" ":     "ignored",
	})
	if attributes != nil {
		t.Fatalf("attributes = %#v, want nil", attributes)
	}
}
