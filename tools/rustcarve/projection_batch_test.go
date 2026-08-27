package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type projectionBatchGolden struct {
	SchemaVersion          string   `json:"schema_version"`
	ToolRevision           string   `json:"tool_revision"`
	InputDigestSHA256      string   `json:"input_digest_sha256"`
	EligibleSources        int      `json:"eligible_sources"`
	EligibleFamilies       int      `json:"eligible_families"`
	CandidateSources       int      `json:"candidate_sources"`
	CandidateProductionLOC int      `json:"candidate_production_lines"`
	CandidateTestLOC       int      `json:"candidate_test_lines"`
	DeletionCandidates     int      `json:"deletion_candidates"`
	ExcludedSourceIDs      []string `json:"excluded_source_ids"`
	BlockedSourceIDs       []string `json:"blocked_source_ids"`
}

func TestProjectionBatchPlanMatchesRepositoryGolden(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", ".."))
	exclusions := "tools/rustcarve/testdata/projection-batch-pr-2827-exclusions.json"
	plan, err := discoverProjectionBatchPlan(root, exclusions)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload, err := os.ReadFile("testdata/golden/projection-batch-summary.json")
	if err != nil {
		t.Fatal(err)
	}
	var want projectionBatchGolden
	if err := json.Unmarshal(wantPayload, &want); err != nil {
		t.Fatal(err)
	}
	got := projectionBatchGolden{
		SchemaVersion:          plan.SchemaVersion,
		ToolRevision:           plan.ToolRevision,
		InputDigestSHA256:      plan.InputDigestSHA256,
		EligibleSources:        plan.EligibleSources,
		EligibleFamilies:       plan.EligibleFamilies,
		CandidateSources:       plan.CandidateSources,
		CandidateProductionLOC: plan.CandidateProductionLOC,
		CandidateTestLOC:       plan.CandidateTestLOC,
		DeletionCandidates:     len(plan.DeletionCandidates),
	}
	for _, batch := range plan.Batches {
		if len(batch.ExcludedPaths) != 0 {
			got.ExcludedSourceIDs = append(got.ExcludedSourceIDs, batch.SourceID)
		}
		if len(batch.Blockers) != 0 {
			got.BlockedSourceIDs = append(got.BlockedSourceIDs, batch.SourceID)
		}
	}
	if !reflect.DeepEqual(got, want) {
		gotPayload, marshalErr := marshalJSON(got)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		t.Fatalf("projection batch golden drifted\nwant:\n%s\ngot:\n%s", wantPayload, gotPayload)
	}

	excluded := make(map[string]struct{}, len(plan.OwnershipExclusions.Paths))
	for _, path := range plan.OwnershipExclusions.Paths {
		excluded[path] = struct{}{}
	}
	for _, candidate := range plan.DeletionCandidates {
		if _, collision := excluded[candidate.Path]; collision {
			t.Fatalf("PR-owned path escaped into deletion candidates: %s", candidate.Path)
		}
		if candidate.DigestSHA256 == "" || candidate.Lines <= 0 || len(candidate.SourceIDs) == 0 {
			t.Fatalf("candidate is not exactly digest and ownership bound: %#v", candidate)
		}
	}
}

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
