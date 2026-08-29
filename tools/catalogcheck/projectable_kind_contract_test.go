package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCheckProjectableKindAcceptsSourcePrefixedKinds(t *testing.T) {
	if issues := checkProjectableKind("sources/github/catalog.yaml", "github", "github.audit"); len(issues) != 0 {
		t.Fatalf("checkProjectableKind() = %v, want no issues", issues)
	}
}

func TestCheckProjectableKindRejectsForeignPrefixes(t *testing.T) {
	for _, kind := range []string{"asset.crown_jewel", "github", "github.", "octocat.audit"} {
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

func TestCheckProjectableKindAllowsOnlyTheRecordedCloudAssetKinds(t *testing.T) {
	for _, sourceID := range []string{"aws", "azure", "gcp"} {
		if issues := checkProjectableKind("sources/x/catalog.yaml", sourceID, "asset.data_sensitivity"); len(issues) != 0 {
			t.Fatalf("checkProjectableKind(%q) = %v, want the recorded exception to pass", sourceID, issues)
		}
	}
	// The exception is scoped to the three cloud sources it was recorded for.
	if issues := checkProjectableKind("sources/okta/catalog.yaml", "okta", "asset.data_sensitivity"); len(issues) != 1 {
		t.Fatalf("checkProjectableKind(okta) = %v, want one issue", issues)
	}
}

// The exception list is a record of known defects and must only shrink. If a
// catalog stops emitting one of these, delete the entry rather than leaving a
// stale allowance behind that would silently readmit the kind later.
func TestUnprojectableEmittedKindsMatchTheCatalogs(t *testing.T) {
	root := repositoryRoot(t)
	emitted := map[string]map[string]bool{}
	sourceID := regexp.MustCompile(`(?m)^id:\s*(\S+)`)
	kinds := regexp.MustCompile(`(?ms)^emitted_kinds:\n((?:  - \S+\n)+)`)
	entry := regexp.MustCompile(`(?m)^  - (\S+)`)

	matches, err := filepath.Glob(filepath.Join(root, "sources", "*", "catalog.yaml"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) == 0 {
		t.Skip("source catalogs are not present in this checkout")
	}
	for _, path := range matches {
		content, err := os.ReadFile(path) // #nosec G304 -- repository catalog path from a fixed glob.
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		id := sourceID.FindSubmatch(content)
		block := kinds.FindSubmatch(content)
		if id == nil || block == nil {
			continue
		}
		for _, kind := range entry.FindAllSubmatch(block[1], -1) {
			k, s := string(kind[1]), string(id[1])
			if strings.HasPrefix(k, s+".") && len(k) > len(s)+1 {
				continue
			}
			if emitted[k] == nil {
				emitted[k] = map[string]bool{}
			}
			emitted[k][s] = true
		}
	}

	for kind, sources := range unprojectableEmittedKinds {
		for source := range sources {
			if !emitted[kind][source] {
				t.Errorf("unprojectableEmittedKinds records %q for source %q, but no catalog emits it; remove the entry", kind, source)
			}
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	for range 6 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repository root not found")
	return ""
}
