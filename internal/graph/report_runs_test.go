package graph

import (
	"testing"
	"time"
)

func TestValidateReportParameterValues(t *testing.T) {
	definition := ReportDefinition{
		ID: "quality",
		Parameters: []ReportParameter{
			{Name: "stale_after_hours", ValueType: "integer", Required: true},
			{Name: "include_counterfactual", ValueType: "boolean"},
		},
	}
	staleAfter := int64(24)
	includeCounterfactual := true

	if err := ValidateReportParameterValues(definition, []ReportParameterValue{
		{Name: "stale_after_hours", IntegerValue: &staleAfter},
		{Name: "include_counterfactual", BooleanValue: &includeCounterfactual},
	}); err != nil {
		t.Fatalf("expected parameter validation success, got %v", err)
	}

	if err := ValidateReportParameterValues(definition, []ReportParameterValue{{Name: "stale_after_hours"}}); err == nil {
		t.Fatal("expected missing typed value to fail")
	}
	if err := ValidateReportParameterValues(definition, []ReportParameterValue{{Name: "stale_after_hours", StringValue: "24"}}); err == nil {
		t.Fatal("expected mismatched value type to fail")
	}
	if err := ValidateReportParameterValues(definition, []ReportParameterValue{{Name: "unknown", StringValue: "x"}}); err == nil {
		t.Fatal("expected unknown parameter to fail")
	}
	if err := ValidateReportParameterValues(definition, []ReportParameterValue{{Name: "include_counterfactual", BooleanValue: &includeCounterfactual}}); err == nil {
		t.Fatal("expected missing required parameter to fail")
	}
}

func TestBuildReportSnapshotAndSections(t *testing.T) {
	definition := ReportDefinition{
		ID:           "quality",
		ResultSchema: "graph.GraphQualityReport",
		Sections: []ReportSection{
			{Key: "summary", Title: "Summary", Kind: "scorecard", Measures: []string{"maturity_score"}},
			{Key: "recommendations", Title: "Recommendations", Kind: "action_list"},
		},
	}
	result := map[string]any{
		"summary":         map[string]any{"maturity_score": 91.2, "nodes": 5},
		"recommendations": []any{"normalize metadata", "close decision loops"},
	}
	now := time.Date(2026, 3, 9, 19, 15, 0, 0, time.UTC)

	sections := BuildReportSectionResults(definition, result)
	if len(sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(sections))
	}
	if !sections[0].Present || sections[0].ContentType != "object" || sections[0].FieldCount != 2 {
		t.Fatalf("unexpected summary section metadata: %+v", sections[0])
	}
	if !sections[1].Present || sections[1].ContentType != "array" || sections[1].ItemCount != 2 {
		t.Fatalf("unexpected recommendations section metadata: %+v", sections[1])
	}

	snapshot, err := BuildReportSnapshot("report_run:test", definition, result, true, now)
	if err != nil {
		t.Fatalf("build report snapshot failed: %v", err)
	}
	if snapshot.ResultSchema != definition.ResultSchema {
		t.Fatalf("expected snapshot result schema %q, got %q", definition.ResultSchema, snapshot.ResultSchema)
	}
	if snapshot.ContentHash == "" || snapshot.ByteSize == 0 {
		t.Fatalf("expected non-empty snapshot materialization metadata, got %+v", snapshot)
	}
	if !snapshot.Retained || snapshot.ExpiresAt == nil {
		t.Fatalf("expected retained snapshot with expiry, got %+v", snapshot)
	}

	staleAfter := int64(24)
	cacheKeyA, err := BuildReportRunCacheKey(definition.ID, []ReportParameterValue{{Name: "stale_after_hours", IntegerValue: &staleAfter}})
	if err != nil {
		t.Fatalf("cache key build failed: %v", err)
	}
	cacheKeyB, err := BuildReportRunCacheKey(definition.ID, []ReportParameterValue{{Name: "stale_after_hours", IntegerValue: &staleAfter}})
	if err != nil {
		t.Fatalf("cache key rebuild failed: %v", err)
	}
	if cacheKeyA == "" || cacheKeyA != cacheKeyB {
		t.Fatalf("expected stable cache key, got %q and %q", cacheKeyA, cacheKeyB)
	}
}
