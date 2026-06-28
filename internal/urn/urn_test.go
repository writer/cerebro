package urn

import "testing"

func TestMintAndParse(t *testing.T) {
	raw, err := Mint("writer", "github_code_repository", "writer/cerebro")
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if raw != "urn:cerebro:writer:github_code_repository:writer/cerebro" {
		t.Fatalf("Mint() = %q", raw)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.TenantID != "writer" || parsed.Kind != "github_code_repository" || len(parsed.Parts) != 1 || parsed.Parts[0] != "writer/cerebro" {
		t.Fatalf("Parse() = %#v", parsed)
	}
}

func TestParseAllowsColonDelimitedIDs(t *testing.T) {
	raw := "urn:cerebro:writer:aws_role:arn:aws:iam::123456789012:role/AdminRole"
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Raw != raw || parsed.TenantID != "writer" || parsed.Kind != "aws_role" {
		t.Fatalf("Parse() = %#v", parsed)
	}
}

func TestMintAllowsKindOnlyProjectionURNs(t *testing.T) {
	raw, err := Mint("writer", "data_classification")
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if raw != "urn:cerebro:writer:data_classification" {
		t.Fatalf("Mint() = %q", raw)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.TenantID != "writer" || parsed.Kind != "data_classification" || len(parsed.Parts) != 0 {
		t.Fatalf("Parse() = %#v", parsed)
	}
}

func TestEncodeSegment(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty", value: "", want: ""},
		{name: "whitespace", value: "   ", want: ""},
		{name: "colon and slash", value: " ISO:27001/2022 ", want: "ISO%3A27001%2F2022"},
		{name: "space", value: "Access Policy:v2", want: "Access%20Policy%3Av2"},
		{name: "literal plus", value: "role/Admin+Owner", want: "role%2FAdmin+Owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EncodeSegment(tc.value); got != tc.want {
				t.Fatalf("EncodeSegment(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestMintWithEncodedSegmentKeepsProviderIDInOnePart(t *testing.T) {
	raw, err := Mint("writer", "policy", "provider", EncodeSegment("ISO:27001/2022"))
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.Parts) != 2 || parsed.Parts[0] != "provider" || parsed.Parts[1] != "ISO%3A27001%2F2022" {
		t.Fatalf("Parse().Parts = %#v", parsed.Parts)
	}
}

func TestParseRejectsInvalidValue(t *testing.T) {
	for _, raw := range []string{
		"",
		"user:123",
		"urn:other:tenant:user:123",
		"urn:cerebro::user:123",
		"urn:cerebro:tenant::123",
		"urn:cerebro:tenant:user::123",
		"urn:cerebro:tenant:runtime:runtime-id::entity-id",
		"urn:cerebro:tenant:user:",
		"urn:cerebro: tenant:user:123",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("Parse() error = nil, want non-nil")
			}
		})
	}
}

func TestStableExternalID(t *testing.T) {
	first := StableExternalID("owner/name\x00repo:1", "fallback")
	second := StableExternalID("owner/name\x00repo:1", "fallback")
	if first == "" || first != second {
		t.Fatalf("StableExternalID() unstable: %q vs %q", first, second)
	}
	if got := StableExternalID("", "fallback"); got != "fallback" {
		t.Fatalf("StableExternalID(empty) = %q", got)
	}
}
