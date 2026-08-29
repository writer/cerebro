package main

import (
	"strings"
	"testing"
)

func TestCheckProjectableKindAcceptsSourceAndFamily(t *testing.T) {
	for _, kind := range []string{"github.audit", "gcp.cloud_function", "asset.data_sensitivity"} {
		if issues := checkProjectableKind("sources/x/catalog.yaml", kind); len(issues) != 0 {
			t.Fatalf("checkProjectableKind(%q) = %v, want no issues", kind, issues)
		}
	}
}

// A shared namespace is projectable whichever catalog emits it. aws, azure, and
// gcp all emit asset.data_sensitivity, and the source comes from the kind, so
// the emitting catalog's id is not an input at all.
func TestCheckProjectableKindAllowsSharedNamespaces(t *testing.T) {
	if issues := checkProjectableKind("sources/x/catalog.yaml", "asset.data_sensitivity"); len(issues) != 0 {
		t.Fatalf("checkProjectableKind() = %v, want no issues", issues)
	}
}

func TestCheckProjectableKindRejectsKindsWithoutTwoSegments(t *testing.T) {
	for _, kind := range []string{"github", "github.", ".audit", "."} {
		t.Run(kind, func(t *testing.T) {
			issues := checkProjectableKind("sources/github/catalog.yaml", kind)
			if len(issues) != 1 {
				t.Fatalf("checkProjectableKind(%q) = %v, want exactly one issue", kind, issues)
			}
			if !strings.Contains(issues[0].message, "not projectable") {
				t.Fatalf("issue message = %q", issues[0].message)
			}
		})
	}
}
