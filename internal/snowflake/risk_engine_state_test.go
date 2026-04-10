package snowflake

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestRiskEngineStateRepository_Validation(t *testing.T) {
	repo := &RiskEngineStateRepository{}
	if err := repo.SaveSnapshot(context.Background(), "graph-id", []byte("{}")); err == nil {
		t.Fatal("expected save to fail when repository is uninitialized")
		return
	}
	if _, err := repo.LoadSnapshot(context.Background(), "graph-id"); err == nil {
		t.Fatal("expected load to fail when repository is uninitialized")
		return
	}

	repo = &RiskEngineStateRepository{
		client: &Client{},
		schema: "CEREBRO.CEREBRO",
	}
	if err := repo.SaveSnapshot(context.Background(), "", []byte("{}")); err == nil {
		t.Fatal("expected save validation error for missing graph id")
		return
	}
	if _, err := repo.LoadSnapshot(context.Background(), ""); err == nil {
		t.Fatal("expected load validation error for missing graph id")
		return
	}
}

func TestRiskEngineStateRepositoryTableRef(t *testing.T) {
	repo := &RiskEngineStateRepository{schema: "cerebro.app"}
	ref, err := repo.tableRef()
	if err != nil {
		t.Fatalf("tableRef failed: %v", err)
	}
	if ref != "CEREBRO.APP.RISK_ENGINE_STATE" {
		t.Fatalf("unexpected table ref %q", ref)
	}

	repo.schema = "bad schema"
	if _, err := repo.tableRef(); err == nil {
		t.Fatal("expected invalid schema ref to fail")
		return
	}
}

func TestNormalizeVariantJSONForState(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want string
	}{
		{name: "nil", raw: nil, want: ""},
		{name: "empty bytes", raw: []byte("   "), want: ""},
		{name: "bytes", raw: []byte(" {\"ok\":true} "), want: "{\"ok\":true}"},
		{name: "string", raw: "  [1,2,3]  ", want: "[1,2,3]"},
		{name: "map", raw: map[string]any{"count": 2}, want: "{\"count\":2}"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeVariantJSONForState(tc.raw)
			if string(got) != tc.want {
				t.Fatalf("normalizeVariantJSONForState(%v) = %q, want %q", tc.raw, string(got), tc.want)
			}
			if tc.want != "" && !json.Valid(got) {
				t.Fatalf("expected valid JSON for %s, got %q", tc.name, string(got))
			}
		})
	}
}

func TestIsMissingRiskEngineStateTableErrRejectsAuthorizationErrors(t *testing.T) {
	testCases := []string{
		"SQL access control error: Insufficient privileges to operate on table",
		"permission denied while reading risk_engine_state",
		"not authorized to access schema",
	}

	for _, message := range testCases {
		t.Run(message, func(t *testing.T) {
			if isMissingRiskEngineStateTableErr(errors.New(message)) {
				t.Fatalf("expected auth error %q to not be treated as a missing-table error", message)
			}
		})
	}
}

func TestIsMissingRiskEngineStateTableErrAcceptsMissingTableErrors(t *testing.T) {
	testCases := []string{
		"object does not exist",
		"no such table: risk_engine_state",
		"unknown table risk_engine_state",
	}

	for _, message := range testCases {
		t.Run(message, func(t *testing.T) {
			if !isMissingRiskEngineStateTableErr(errors.New(message)) {
				t.Fatalf("expected missing-table error %q to be accepted", message)
			}
		})
	}
}
