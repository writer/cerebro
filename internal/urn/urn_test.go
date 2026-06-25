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
