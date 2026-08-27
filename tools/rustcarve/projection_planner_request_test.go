package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type projectionPlannerGolden struct {
	Units            int      `json:"units"`
	CandidateUnits   int      `json:"candidate_units"`
	BlockedUnits     int      `json:"blocked_units"`
	ProductionLines  int      `json:"production_lines"`
	TestLines        int      `json:"test_lines"`
	DeletionTargets  int      `json:"deletion_targets"`
	BlockedSourceIDs []string `json:"blocked_source_ids"`
}

func TestProjectionPlanRequestMatchesRustPlannerContract(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", ".."))
	plan, err := discoverProjectionBatchPlan(root, "tools/rustcarve/testdata/projection-batch-pr-2827-exclusions.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := buildProjectionPlanRequest(plan)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := marshalJSON(request)
	if err != nil {
		t.Fatal(err)
	}

	validateProjectionPlanRequestSchema(t, payload)
	validateProjectionPlanRequestGolden(t, request)
	validateWithRustPlannerWhenAvailable(t, payload)

	second, err := buildProjectionPlanRequest(plan)
	if err != nil {
		t.Fatal(err)
	}
	secondPayload, err := marshalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, secondPayload) {
		t.Fatal("projection planner request is not deterministic")
	}
}

func TestProjectionPlanRequestFailsClosed(t *testing.T) {
	t.Parallel()
	batch := projectionBatch{
		SourceID:        "provider",
		FamilyIDs:       []string{"records"},
		EventKinds:      []string{"provider.record"},
		ExcludedPaths:   []string{"internal/sourceprojection/provider.go"},
		ProductionLines: 10,
	}
	unit, err := buildProjectionUnit("d73291696ef32079c1bfa2ff110d12539f89a640", batch)
	if err != nil {
		t.Fatal(err)
	}
	if unit.Status != projectionBlockedStatus {
		t.Fatalf("excluded projection status = %q, want blocked", unit.Status)
	}
	if len(unit.DeletionTargets) != 0 || !reflect.DeepEqual(unit.Blockers, []string{
		"no_exact_deletion_targets",
		"ownership_exclusion:internal/sourceprojection/provider.go",
	}) {
		t.Fatalf("excluded projection did not fail closed: %#v", unit)
	}
	if _, err := buildProjectionPlanRequest(projectionBatchPlan{RepositoryRevision: "HEAD"}); err == nil {
		t.Fatal("projection planner request accepted an unbound base revision")
	}
}

func validateProjectionPlanRequestSchema(t *testing.T, payload []byte) {
	t.Helper()
	schemaPayload, err := os.ReadFile("testdata/schema/cerebro-migrator-plan-request-v1.schema.json")
	if err != nil {
		t.Fatalf("read planner schema: %v", err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaPayload, &schemaDocument); err != nil {
		t.Fatalf("decode planner schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("cerebro-migrator-plan-request-v1.schema.json", schemaDocument); err != nil {
		t.Fatalf("add planner schema: %v", err)
	}
	compiled, err := compiler.Compile("cerebro-migrator-plan-request-v1.schema.json")
	if err != nil {
		t.Fatalf("compile planner schema: %v", err)
	}
	var instance any
	if err := json.Unmarshal(payload, &instance); err != nil {
		t.Fatalf("decode planner request: %v", err)
	}
	if err := compiled.Validate(instance); err != nil {
		t.Fatalf("planner request violates closed Rust contract: %v", err)
	}
}

func validateProjectionPlanRequestGolden(t *testing.T, request projectionPlanRequest) {
	t.Helper()
	wantPayload, err := os.ReadFile("testdata/golden/projection-plan-request-summary.json")
	if err != nil {
		t.Fatalf("read planner golden: %v", err)
	}
	var want projectionPlannerGolden
	if err := json.Unmarshal(wantPayload, &want); err != nil {
		t.Fatalf("decode planner golden: %v", err)
	}
	got := projectionPlannerGolden{Units: len(request.Units)}
	for _, unit := range request.Units {
		got.ProductionLines += unit.Benefit.ProductionLines
		got.TestLines += unit.Benefit.TestLines
		got.DeletionTargets += len(unit.DeletionTargets)
		switch unit.Status {
		case projectionCandidateStatus:
			got.CandidateUnits++
		case projectionBlockedStatus:
			got.BlockedUnits++
			got.BlockedSourceIDs = append(got.BlockedSourceIDs, unit.ID)
		default:
			t.Fatalf("projection unit %s emitted disallowed status %q", unit.ID, unit.Status)
		}
	}
	if !reflect.DeepEqual(got, want) {
		gotPayload, marshalErr := marshalJSON(got)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		t.Fatalf("projection planner golden drifted\nwant:\n%s\ngot:\n%s", wantPayload, gotPayload)
	}
}

func validateWithRustPlannerWhenAvailable(t *testing.T, payload []byte) {
	t.Helper()
	binary, err := exec.LookPath("cerebro-migrator")
	if err != nil {
		return
	}
	command := exec.Command(binary, "plan", "--input", "-") // #nosec G204 -- resolved executable has no shell interpolation.
	command.Stdin = bytes.NewReader(payload)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Rust planner rejected projection request: %v\n%s", err, output)
	}
}
