package main

import (
	"strings"
	"testing"
)

func TestCheckProjectableKindAcceptsSourceAndFamily(t *testing.T) {
	for _, kind := range []string{"github.audit", "gcp.cloud_function", "asset.data_sensitivity"} {
		if issues := checkProjectableKind("sources/x/catalog.yaml", "github", kind); len(issues) != 0 {
			t.Fatalf("checkProjectableKind(%q) = %v, want no issues", kind, issues)
		}
	}
}

// A shared namespace is projectable regardless of which catalog emits it: the
// source comes from the kind, not from the emitting catalog's id.
func TestCheckProjectableKindAllowsSharedNamespaces(t *testing.T) {
	for _, sourceID := range []string{"aws", "azure", "gcp"} {
		if issues := checkProjectableKind("sources/x/catalog.yaml", sourceID, "asset.data_sensitivity"); len(issues) != 0 {
			t.Fatalf("checkProjectableKind(%q) = %v, want no issues", sourceID, issues)
		}
	}
}

func TestCheckProjectableKindRejectsKindsWithoutTwoSegments(t *testing.T) {
	for _, kind := range []string{"github", "github.", ".audit", "."} {
		t.Run(kind, func(t *testing.T) {
			issues := checkProjectableKind("sources/github/catalog.yaml", "github", kind)
			if len(issues) != 1 {
				t.Fatalf("checkProjectableKind(%q) = %v, want exactly one issue", kind, issues)
			}
			if !strings.Contains(issues[0].message, "not projectable") {
				t.Fatalf("issue message = %q", issues[0].message)
			}
		})
	}
}
