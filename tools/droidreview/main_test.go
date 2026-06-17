package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSuspiciousCypherTokenIgnoresGuardrailGuidance(t *testing.T) {
	const guardrail = `Rules:
- Generate read-only Cypher only.
- Do not use CREATE, MERGE, DELETE, REMOVE, SET, DROP, FOREACH, LOAD CSV, USING PERIODIC, apoc.trigger, or apoc.periodic.
- Always include a numeric LIMIT <= 100.`

	if got := suspiciousCypherToken(guardrail); got != "" {
		t.Fatalf("suspiciousCypherToken() = %q, want no finding for guardrail prose", got)
	}
}

func TestSuspiciousCypherTokenFlagsWriteQueryLiterals(t *testing.T) {
	query := "MATCH (n) LOAD CSV FROM 'file:///tmp.csv' AS row RETURN row LIMIT 1"

	if got := suspiciousCypherToken(query); got != "LOAD CSV" {
		t.Fatalf("suspiciousCypherToken() = %q, want LOAD CSV", got)
	}
}

func TestClassifyReviewSkipsDocsOnly(t *testing.T) {
	result := classifyReview([]string{"docs/notes.md", ".factory/templates/example.md"})

	if result.RunDroidReview {
		t.Fatalf("RunDroidReview = true, want false for docs-only changes")
	}
	if result.ReviewModel != sonnetBugReviewModel {
		t.Fatalf("ReviewModel = %q, want %q", result.ReviewModel, sonnetBugReviewModel)
	}
}

func TestReviewProbePlanIncludesPathSpecificPasses(t *testing.T) {
	passes := reviewProbePlan([]string{
		"internal/graphagent/ask.go",
		"scripts/droid_ci_context.py",
		"sources/github/source.go",
	})
	names := map[string]bool{}
	for _, pass := range passes {
		names[pass.Name] = true
		if len(pass.Commands) == 0 {
			t.Fatalf("pass %q has no commands", pass.Name)
		}
	}
	for _, name := range []string{"changed-invariants", "ask-trajectory", "security-context", "focused-go-tests"} {
		if !names[name] {
			t.Fatalf("probe plan missing pass %q: %#v", name, passes)
		}
	}
}

func TestWriteJSONFilePersistsPreflightShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preflight.json")
	result := preflightResult{
		ChangedFiles:   []string{"internal/graphagent/ask.go"},
		RunDroidReview: true,
		ReviewModel:    sonnetBugReviewModel,
		ReviewReason:   "code changed",
		Checks:         []string{"cypher-safety"},
		Findings:       []checkFinding{{Rule: "cypher-safety", File: "internal/graphagent/ask.go", Line: 12, Message: "bad cypher"}},
		ProbePlan:      []reviewProbePass{{Name: "ask-trajectory", Why: "Ask changed", Commands: []string{"go test ./internal/graphagent"}}},
	}

	if err := writeJSONFile(path, result); err != nil {
		t.Fatalf("writeJSONFile() error = %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read preflight json: %v", err)
	}
	var decoded preflightResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode preflight json: %v", err)
	}
	if !decoded.RunDroidReview || len(decoded.ProbePlan) != 1 || decoded.Findings[0].Rule != "cypher-safety" {
		t.Fatalf("decoded preflight = %#v", decoded)
	}
}

func TestPreflightSampleFixtureCoversAskAndSecurityPasses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "preflight_sample.json"))
	if err != nil {
		t.Fatalf("read sample fixture: %v", err)
	}
	var sample preflightResult
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatalf("decode sample fixture: %v", err)
	}
	names := map[string]bool{}
	for _, pass := range sample.ProbePlan {
		names[pass.Name] = true
	}
	for _, name := range []string{"changed-invariants", "ask-trajectory", "security-context"} {
		if !names[name] {
			t.Fatalf("fixture missing pass %q: %#v", name, sample.ProbePlan)
		}
	}
}

func TestPreflightFixtureProbePlanIsStable(t *testing.T) {
	raw, err := os.ReadFile("testdata/preflight_sample.json")
	if err != nil {
		t.Fatalf("read preflight fixture: %v", err)
	}
	var fixture preflightResult
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode preflight fixture: %v", err)
	}
	if !fixture.RunDroidReview {
		t.Fatalf("fixture run_droid_review = false, want true")
	}
	var passNames []string
	for _, pass := range fixture.ProbePlan {
		passNames = append(passNames, pass.Name)
	}
	for _, want := range []string{"changed-invariants", "ask-trajectory", "security-context"} {
		if !slices.Contains(passNames, want) {
			t.Fatalf("fixture pass plan missing %q: %v", want, passNames)
		}
	}
}
