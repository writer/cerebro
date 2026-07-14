package resourcelinks

import (
	"bytes"
	"net/url"
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/fabriccontract"
)

func TestFindingLinksAreDeterministicAndRoundTripEscaping(t *testing.T) {
	input := FindingInput{
		ID:        "finding/a%2Fb ?#",
		RuntimeID: "runtime/a%2Fb ?#",
		ResourceURNs: []string{
			"urn:cerebro:aws:resource/with space",
			"urn:cerebro:aws:resource/with space",
			"urn:cerebro:github:repo?name=a/b",
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

	self := findLink(t, first, fabriccontract.RelationSelf, KindFinding)
	assertMCPPathRoundTrip(t, self.Target.MCPURI, input.ID)
	parsedAPI, err := url.Parse(self.Target.APIPath)
	if err != nil {
		t.Fatalf("url.Parse(self api path): %v", err)
	}
	decodedID, err := url.PathUnescape(parsedAPI.EscapedPath()[len("/findings/"):])
	if err != nil || decodedID != input.ID {
		t.Fatalf("self api id = %q, err = %v, want %q", decodedID, err, input.ID)
	}

	runtime := findLink(t, first, fabriccontract.RelationObservedOn, KindSourceRuntime)
	assertMCPPathRoundTrip(t, runtime.Target.MCPURI, input.RuntimeID)

	for _, link := range first {
		if link.Target.Kind != KindGraphEntity {
			continue
		}
		assertMCPPathRoundTrip(t, link.Target.MCPURI, link.Target.ID)
		parsed, err := url.Parse(link.Target.APIPath)
		if err != nil {
			t.Fatalf("url.Parse(graph api path): %v", err)
		}
		if got := parsed.Query().Get("root_urn"); got != link.Target.ID {
			t.Fatalf("graph root_urn = %q, want %q", got, link.Target.ID)
		}
	}
}

func TestCanonicalReferenceBytesAreStable(t *testing.T) {
	reference := ResourceRef{
		Kind:    KindFinding,
		ID:      "finding-1",
		APIPath: "/findings/finding-1",
		MCPURI:  "cerebro://finding/finding-1",
		State:   StateCurrent,
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

func TestNewReferenceRejectsAbsoluteAndMalformedLocations(t *testing.T) {
	tests := []ResourceRef{
		{Kind: KindFinding, ID: "finding-1", APIPath: "https://example.invalid/findings/finding-1", State: StateCurrent},
		{Kind: KindFinding, ID: "finding-1", MCPURI: "https://example.invalid/finding/finding-1", State: StateCurrent},
		{Kind: KindFinding, ID: "finding-1", APIPath: "/findings/finding-1", State: StateImmutable},
		{Kind: Kind("unknown"), ID: "finding-1", APIPath: "/findings/finding-1", State: StateCurrent},
	}
	for _, test := range tests {
		if _, err := NewReference(test); err == nil {
			t.Fatalf("NewReference(%#v) succeeded", test)
		}
	}
}

func TestNewLinkEnforcesRelationEndpoints(t *testing.T) {
	target := ResourceRef{
		Kind:    KindSourceRuntime,
		ID:      "runtime-1",
		APIPath: "/source-runtimes/runtime-1",
		State:   StateCurrent,
	}
	if _, err := NewLink(KindFinding, fabriccontract.RelationObservedOn, target, AuthorityDerivedRecord, CompletenessComplete); err != nil {
		t.Fatalf("NewLink(valid) error = %v", err)
	}
	if _, err := NewLink(KindGraphEntity, fabriccontract.RelationObservedOn, target, AuthorityDerivedRecord, CompletenessComplete); err == nil {
		t.Fatal("NewLink accepted invalid source kind")
	}
}

func findLink(t *testing.T, links []ResourceLink, relation string, kind Kind) ResourceLink {
	t.Helper()
	for _, link := range links {
		if link.Relation == relation && link.Target.Kind == kind {
			return link
		}
	}
	t.Fatalf("link %s -> %s not found", relation, kind)
	return ResourceLink{}
}

func assertMCPPathRoundTrip(t *testing.T, rawURI, want string) {
	t.Helper()
	parsed, err := url.Parse(rawURI)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURI, err)
	}
	got, err := url.PathUnescape(parsed.EscapedPath()[1:])
	if err != nil {
		t.Fatalf("url.PathUnescape(%q): %v", rawURI, err)
	}
	if got != want {
		t.Fatalf("MCP path round trip = %q, want %q", got, want)
	}
}
