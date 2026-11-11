package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalProjectionLocatorMatchesClosedCatalogGrammar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		baseURL string
		path    string
		want    string
		ok      bool
	}{
		{path: "/organization/groups/{group_id}/users", want: "/organization/groups/{}/users", ok: true},
		{baseURL: "https://api.example.com/v1", path: "/groups/${config.group_id}", want: "https://api.example.com/v1/groups/{}", ok: true},
		{baseURL: "http://api.example.com", path: "/users", want: "/users", ok: true},
		{path: "users", ok: false},
		{path: "/users/{bad.value}", ok: false},
		{path: "/users?cursor={cursor}", ok: false},
	}
	for _, test := range tests {
		got, ok := canonicalFamilyLocator(test.baseURL, test.path)
		if got != test.want || ok != test.ok {
			t.Errorf("canonicalFamilyLocator(%q, %q) = %q, %v; want %q, %v", test.baseURL, test.path, got, ok, test.want, test.ok)
		}
	}
}

func TestProjectionSourceLineCount(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]int{"": 0, "one": 1, "one\n": 1, "one\ntwo": 2, "one\ntwo\n": 2} {
		if got := sourceLineCount([]byte(input)); got != want {
			t.Errorf("sourceLineCount(%q) = %d, want %d", input, got, want)
		}
	}
}

// TestClassifyImplementationFilesExcludesOwnershipPathsFromCandidates proves
// the two safety properties the batch/candidate pipeline must hold,
// independent of the live connector catalog's migration state: (1) a path
// listed in the ownership exclusions manifest can never flow into a batch's
// ImplementationFiles/TestFiles (and therefore can never reach
// buildProjectionCandidates), even when it is the sole owner of its
// implementation file, and (2) every candidate that does surface is bound to
// the actual on-disk content and the real source(s) that reference it, not
// to incidental zero-value metadata. It uses a small temp-directory fixture
// instead of whole-repository counts or a byte-for-byte golden file, since
// those drift on every unrelated catalog change and say nothing about
// whether the exclusion/ownership logic itself is correct.
func TestClassifyImplementationFilesExcludesOwnershipPathsFromCandidates(t *testing.T) {
	root := t.TempDir()
	write := func(relative, contents string) {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("owned/kept.go", "package owned\n\nfunc Kept() {}\n")
	write("owned/kept_test.go", "package owned\n\nfunc TestKept() {}\n")
	write("owned/retired.go", "package owned\n\nfunc Retired() {}\n")
	write("owned/retired_test.go", "package owned\n\nfunc TestRetired() {}\n")
	write("exclusions.json", `{
  "schema_version": "cerebro.rustcarve.path-exclusions/v1",
  "owner": "guard-test",
  "revision": "1",
  "paths": ["owned/retired.go", "owned/retired_test.go"]
}`)

	exclusions, exclusionRecord, err := loadProjectionExclusions(root, "exclusions.json")
	if err != nil {
		t.Fatal(err)
	}

	fileSourceIDs := map[string]map[string]struct{}{
		"owned/kept.go":    {"sourcea": {}},
		"owned/retired.go": {"sourcea": {}},
	}
	implementationSet := map[string]struct{}{"owned/kept.go": {}, "owned/retired.go": {}}

	implFiles, testFiles, excludedPaths, blockers := classifyImplementationFiles(root, implementationSet, exclusions, fileSourceIDs)

	// Property 1: the excluded implementation file and its paired test file
	// never reach ImplementationFiles/TestFiles, even though it has exactly
	// one owning source (i.e. would otherwise be a clean candidate), and the
	// classifier records both paths as excluded instead of blocked.
	for _, path := range implFiles {
		if path == "owned/retired.go" {
			t.Fatalf("excluded path owned/retired.go leaked into implementation files: %v", implFiles)
		}
	}
	for _, path := range testFiles {
		if path == "owned/retired_test.go" {
			t.Fatalf("excluded path owned/retired_test.go leaked into test files: %v", testFiles)
		}
	}
	if len(blockers) != 0 {
		t.Fatalf("excluded path should not also be reported as blocked: %v", blockers)
	}
	wantExcluded := map[string]bool{"owned/retired.go": false, "owned/retired_test.go": false}
	for _, path := range excludedPaths {
		if _, ok := wantExcluded[path]; !ok {
			t.Fatalf("unexpected excluded path %s", path)
		}
		wantExcluded[path] = true
	}
	for path, seen := range wantExcluded {
		if !seen {
			t.Fatalf("expected %s to be recorded as excluded, got %v", path, excludedPaths)
		}
	}
	if len(exclusionRecord.Paths) != 2 {
		t.Fatalf("exclusion record paths = %v, want the 2 manifest entries", exclusionRecord.Paths)
	}

	// The kept file is unaffected: it is still an eligible candidate.
	if len(implFiles) != 1 || implFiles[0] != "owned/kept.go" {
		t.Fatalf("implementation files = %v, want only owned/kept.go", implFiles)
	}
	if len(testFiles) != 1 || testFiles[0] != "owned/kept_test.go" {
		t.Fatalf("test files = %v, want only owned/kept_test.go", testFiles)
	}

	batch := projectionBatch{SourceID: "sourcea", ImplementationFiles: implFiles, TestFiles: testFiles}
	candidates, err := buildProjectionCandidates(root, []projectionBatch{batch})
	if err != nil {
		t.Fatal(err)
	}

	// The excluded files never surface as deletion candidates.
	for _, candidate := range candidates {
		if candidate.Path == "owned/retired.go" || candidate.Path == "owned/retired_test.go" {
			t.Fatalf("excluded path %s escaped into deletion candidates", candidate.Path)
		}
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %#v, want exactly the 2 non-excluded files", candidates)
	}

	// Property 2: every surviving candidate is bound to the real file
	// content and to the sources that actually reference it.
	byPath := make(map[string]projectionFileCandidate, len(candidates))
	for _, candidate := range candidates {
		byPath[candidate.Path] = candidate
	}
	kept, ok := byPath["owned/kept.go"]
	if !ok {
		t.Fatalf("missing candidate for owned/kept.go in %#v", candidates)
	}
	payload, err := os.ReadFile(filepath.Join(root, "owned/kept.go")) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if kept.DigestSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("candidate digest %s does not match owned/kept.go on-disk content", kept.DigestSHA256)
	}
	if kept.Class != "production" || kept.Lines != sourceLineCount(payload) {
		t.Fatalf("candidate %#v is not bound to the real content of owned/kept.go", kept)
	}
	if len(kept.SourceIDs) != 1 || kept.SourceIDs[0] != "sourcea" {
		t.Fatalf("candidate source IDs = %v, want [sourcea]", kept.SourceIDs)
	}
	keptTest, ok := byPath["owned/kept_test.go"]
	if !ok || keptTest.Class != "test" {
		t.Fatalf("missing or misclassified candidate for owned/kept_test.go in %#v", candidates)
	}

	// A plausible regression: if the digest were computed from a different
	// (mutated) copy of the file, the digest bound to the candidate would
	// stop matching the content actually on disk.
	if err := os.WriteFile(filepath.Join(root, "owned/kept.go"), []byte("package owned\n\nfunc Kept() { /* mutated */ }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutatedPayload, err := os.ReadFile(filepath.Join(root, "owned/kept.go")) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	mutatedSum := sha256.Sum256(mutatedPayload)
	if kept.DigestSHA256 == hex.EncodeToString(mutatedSum[:]) {
		t.Fatalf("stale candidate digest unexpectedly matches mutated content")
	}
}
