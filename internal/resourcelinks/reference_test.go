package resourcelinks

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/fabriccontract"
)

func TestResourceRefRoundTripsIDThroughPathsAndJSON(t *testing.T) {
	reference, err := NewID(fabriccontract.ResourceKindFinding, "finding/50% ready?")
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	if reference.APIPath != "/platform/resources/finding/finding%2F50%25%20ready%3F" {
		t.Fatalf("APIPath = %q", reference.APIPath)
	}
	if reference.MCPURI != "cerebro://resource/finding/finding%2F50%25%20ready%3F" {
		t.Fatalf("MCPURI = %q", reference.MCPURI)
	}

	fromPath, err := ParseAPIPath(reference.APIPath)
	if err != nil {
		t.Fatalf("ParseAPIPath() error = %v", err)
	}
	fromURI, err := ParseMCPURI(reference.MCPURI)
	if err != nil {
		t.Fatalf("ParseMCPURI() error = %v", err)
	}
	if fromPath.Identifier() != reference.ID || fromURI.Identifier() != reference.ID {
		t.Fatalf("round trip identifiers = %q, %q", fromPath.Identifier(), fromURI.Identifier())
	}

	encoded, err := reference.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	want := `{"kind":"finding","id":"finding/50% ready?","state":"current","api_path":"/platform/resources/finding/finding%2F50%25%20ready%3F","mcp_uri":"cerebro://resource/finding/finding%2F50%25%20ready%3F"}`
	if string(encoded) != want {
		t.Fatalf("CanonicalJSON() = %s", encoded)
	}
	var decoded ResourceRef
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded != reference {
		t.Fatalf("decoded = %#v, want %#v", decoded, reference)
	}
}

func TestResourceRefRoundTripsURNWithOneEscapingPass(t *testing.T) {
	resourceURN := "urn:cerebro:writer:aws.role:team/admin%2Fprimary"
	reference, err := NewURN(fabriccontract.ResourceKindGraphEntity, resourceURN)
	if err != nil {
		t.Fatalf("NewURN() error = %v", err)
	}
	parsed, err := ParseMCPURI(reference.MCPURI)
	if err != nil {
		t.Fatalf("ParseMCPURI() error = %v", err)
	}
	if parsed.URN != resourceURN {
		t.Fatalf("URN = %q, want %q", parsed.URN, resourceURN)
	}
	if strings.Count(reference.MCPURI, "%252F") != 1 {
		t.Fatalf("MCPURI should preserve literal percent escape exactly once: %q", reference.MCPURI)
	}
}

func TestResourceRefUnmarshalPreservesJSONDecodeError(t *testing.T) {
	var reference ResourceRef
	err := reference.UnmarshalJSON([]byte(`{"kind":`))
	if !errors.Is(err, ErrInvalidResourceRef) {
		t.Fatalf("UnmarshalJSON() error = %v, want ErrInvalidResourceRef", err)
	}
	var syntaxError *json.SyntaxError
	if !errors.As(err, &syntaxError) {
		t.Fatalf("UnmarshalJSON() error = %v, want json.SyntaxError", err)
	}
}

func TestNormalizeResourceRefHistoricalState(t *testing.T) {
	reference, err := Normalize(ResourceRef{
		Kind:     fabriccontract.ResourceKindEvidencePacket,
		ID:       "packet-1",
		Revision: "revision-7",
		Digest:   "sha256:abc",
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if reference.State != ResourceStateImmutable {
		t.Fatalf("State = %q", reference.State)
	}
}

func TestNormalizeResourceRefRejectsInvalidContracts(t *testing.T) {
	tests := []ResourceRef{
		{Kind: "unknown", ID: "id-1"},
		{Kind: fabriccontract.ResourceKindFinding, URN: "urn:cerebro:writer:finding:id-1"},
		{Kind: fabriccontract.ResourceKindGraphEntity, ID: "id-1"},
		{Kind: fabriccontract.ResourceKindGraphEntity, URN: "not-a-urn"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "../secret"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "parent\\child"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "line\nbreak"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "id-1", State: ResourceStateImmutable},
		{Kind: fabriccontract.ResourceKindFinding, ID: "id-1", State: ResourceStateCurrent, Revision: "revision-1"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "id-1", APIPath: "/findings/id-1"},
		{Kind: fabriccontract.ResourceKindFinding, ID: "id-1", MCPURI: "cerebro://finding/id-1"},
	}
	for _, test := range tests {
		if _, err := Normalize(test); !errors.Is(err, ErrInvalidResourceRef) {
			t.Fatalf("Normalize(%#v) error = %v", test, err)
		}
	}
}

func TestResourcePathParsersRejectAlternateOrUnsafeForms(t *testing.T) {
	apiPaths := []string{
		"https://cerebro.example/platform/resources/finding/id-1",
		"/platform/resources/finding/id-1?tenant_id=other",
		"/platform/resources/finding/id-1/extra",
		"/platform/resources/finding/id%2f1",
		"/platform/resources/finding/%2E%2E",
	}
	for _, path := range apiPaths {
		if _, err := ParseAPIPath(path); !errors.Is(err, ErrInvalidResourceRef) {
			t.Fatalf("ParseAPIPath(%q) error = %v", path, err)
		}
	}

	resourceURIs := []string{
		"https://resource/finding/id-1",
		"cerebro://user@resource/finding/id-1",
		"cerebro://resource:443/finding/id-1",
		"cerebro://resource/finding/id-1?tenant_id=other",
		"cerebro://resource/finding/id-1#fragment",
		"cerebro://resource/finding/id-1/extra",
		"cerebro://resource/finding/id%2f1",
	}
	for _, uri := range resourceURIs {
		if _, err := ParseMCPURI(uri); !errors.Is(err, ErrInvalidResourceRef) {
			t.Fatalf("ParseMCPURI(%q) error = %v", uri, err)
		}
	}
}

func TestFindingLinksUseCanonicalReferencesAndStableOrder(t *testing.T) {
	input := FindingInput{
		ID:        "finding/a%2Fb ?#",
		TenantID:  "tenant-a",
		RuntimeID: "runtime/a%2Fb ?#",
		ResourceURNs: []string{
			"urn:cerebro:tenant-a:aws:resource/with space",
			"urn:cerebro:tenant-a:aws:resource/with space",
			"urn:cerebro:tenant-a:github:repo?name=a/b",
		},
	}
	first, err := FindingLinks(input)
	if err != nil {
		t.Fatalf("FindingLinks() error = %v", err)
	}
	input.ResourceURNs[0], input.ResourceURNs[2] = input.ResourceURNs[2], input.ResourceURNs[0]
	second, err := FindingLinks(input)
	if err != nil {
		t.Fatalf("FindingLinks(shuffled) error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("FindingLinks() changed across input order\nfirst: %#v\nsecond: %#v", first, second)
	}
	if len(first) != 6 {
		t.Fatalf("len(FindingLinks()) = %d, want 6", len(first))
	}

	self := findLink(t, first, fabriccontract.RelationSelf, fabriccontract.ResourceKindFinding)
	if self.Target.Identifier() != "finding/a%2Fb ?#" {
		t.Fatalf("self identifier = %q", self.Target.Identifier())
	}
	for _, link := range first {
		fromPath, pathErr := ParseAPIPath(link.Target.APIPath)
		if pathErr != nil {
			t.Fatalf("ParseAPIPath(%q) error = %v", link.Target.APIPath, pathErr)
		}
		fromURI, uriErr := ParseMCPURI(link.Target.MCPURI)
		if uriErr != nil {
			t.Fatalf("ParseMCPURI(%q) error = %v", link.Target.MCPURI, uriErr)
		}
		if fromPath.Identifier() != link.Target.Identifier() || fromURI.Identifier() != link.Target.Identifier() {
			t.Fatalf("link %q did not round trip: %#v", link.Relation, link.Target)
		}
		if link.Target.Kind == fabriccontract.ResourceKindGraphEntity && link.Target.URN == "" {
			t.Fatalf("graph link did not preserve URN: %#v", link.Target)
		}
	}
}

func TestFindingLinksRejectCrossTenantAffectedResource(t *testing.T) {
	_, err := FindingLinks(FindingInput{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		RuntimeID:    "runtime-1",
		ResourceURNs: []string{"urn:cerebro:tenant-b:asset:resource-1"},
	})
	if !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("FindingLinks() error = %v, want %v", err, ErrInvalidLink)
	}
}

func TestCanonicalReferenceBytesAreStable(t *testing.T) {
	reference, err := NewID(fabriccontract.ResourceKindFinding, "finding-1")
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	first, err := CanonicalReferenceBytes(reference)
	if err != nil {
		t.Fatalf("CanonicalReferenceBytes() error = %v", err)
	}
	second, err := CanonicalReferenceBytes(reference)
	if err != nil {
		t.Fatalf("CanonicalReferenceBytes(second) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical bytes differ: %q != %q", first, second)
	}
}

func TestNewLinkEnforcesCanonicalRelationEndpoints(t *testing.T) {
	target, err := NewID(fabriccontract.ResourceKindSourceRuntime, "runtime-1")
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	if _, err := NewLink(fabriccontract.ResourceKindFinding, fabriccontract.RelationObservedOn, target, AuthorityDerivedRecord, CompletenessComplete); err != nil {
		t.Fatalf("NewLink(valid) error = %v", err)
	}
	if _, err := NewLink(fabriccontract.ResourceKindControl, fabriccontract.RelationObservedOn, target, AuthorityDerivedRecord, CompletenessComplete); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("NewLink(invalid source) error = %v, want ErrInvalidLink", err)
	}
}

func findLink(t *testing.T, links []ResourceLink, relation string, kind fabriccontract.ResourceKind) ResourceLink {
	t.Helper()
	for _, link := range links {
		if link.Relation == relation && link.Target.Kind == kind {
			return link
		}
	}
	t.Fatalf("link %s -> %s not found", relation, kind)
	return ResourceLink{}
}
