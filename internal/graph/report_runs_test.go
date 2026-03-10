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

	sections := BuildReportSectionResults(definition, result, nil)
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

func TestBuildReportLineageAndStoragePolicy(t *testing.T) {
	g := New()
	builtAt := time.Date(2026, 3, 10, 4, 30, 0, 0, time.UTC)
	g.SetMetadata(Metadata{
		BuiltAt:   builtAt,
		NodeCount: 12,
		EdgeCount: 7,
		Providers: []string{"github", "okta"},
		Accounts:  []string{"acct-a"},
	})

	lineage := BuildReportLineage(g, ReportDefinition{ID: "quality", Version: "2.1.0"})
	if lineage.GraphSnapshotID == "" {
		t.Fatal("expected graph snapshot id")
	}
	if lineage.GraphBuiltAt == nil || !lineage.GraphBuiltAt.Equal(builtAt) {
		t.Fatalf("expected graph built at %s, got %+v", builtAt, lineage.GraphBuiltAt)
	}
	if lineage.GraphSchemaVersion == 0 {
		t.Fatal("expected graph schema version")
	}
	if lineage.OntologyContractVersion == "" {
		t.Fatal("expected ontology contract version")
	}
	if lineage.ReportDefinitionVersion != "2.1.0" {
		t.Fatalf("expected report definition version 2.1.0, got %q", lineage.ReportDefinitionVersion)
	}

	storage := BuildReportStoragePolicy(true, false)
	if storage.StorageClass != "local_durable" {
		t.Fatalf("expected local_durable storage class, got %q", storage.StorageClass)
	}
	if storage.RetentionTier != "short_term" {
		t.Fatalf("expected short_term retention tier, got %q", storage.RetentionTier)
	}
	if !storage.MaterializedResultAvailable {
		t.Fatal("expected materialized result availability")
	}

	metadataOnly := BuildReportStoragePolicy(false, false)
	if metadataOnly.StorageClass != "metadata_only" {
		t.Fatalf("expected metadata_only storage class, got %q", metadataOnly.StorageClass)
	}
	if metadataOnly.MaterializedResultAvailable {
		t.Fatal("expected metadata-only policy to disable materialized result")
	}
}

func TestBuildReportSectionResultsIncludesLineageAndTruncationSignals(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "claim:payments:tier", Kind: NodeKindClaim, Name: "Payments tier claim"})
	g.AddNode(&Node{ID: "evidence:runbook", Kind: NodeKindEvidence, Name: "Runbook"})
	g.AddNode(&Node{ID: "source:github", Kind: NodeKindSource, Name: "GitHub"})
	g.AddEdge(&Edge{ID: "claim-based-on", Source: "claim:payments:tier", Target: "evidence:runbook", Kind: EdgeKindBasedOn})
	g.AddEdge(&Edge{ID: "claim-asserted-by", Source: "claim:payments:tier", Target: "source:github", Kind: EdgeKindAssertedBy})

	definition := ReportDefinition{
		ID: "claim-conflicts",
		Sections: []ReportSection{
			{Key: "conflicts", Title: "Conflicts", Kind: "table"},
		},
	}
	result := map[string]any{
		"conflicts": []any{
			map[string]any{
				"claim_ids":             []any{"claim:payments:tier"},
				"returned_conflicts":    1,
				"conflicts_truncated":   true,
				"partial_results":       true,
				"supporting_evidence":   []any{"evidence:runbook"},
				"asserting_source_ids":  []any{"source:github"},
				"non_graph_identifier":  "not-a-node",
				"irrelevant_plain_text": "payments",
			},
		},
	}

	sections := BuildReportSectionResults(definition, result, g)
	if len(sections) != 1 {
		t.Fatalf("expected one section, got %d", len(sections))
	}
	lineage := sections[0].Lineage
	if lineage == nil {
		t.Fatalf("expected lineage metadata, got %+v", sections[0])
	}
	if lineage.ReferencedNodeCount != 3 {
		t.Fatalf("expected referenced_node_count=3, got %+v", lineage)
	}
	if lineage.ClaimCount != 1 || len(lineage.ClaimIDs) != 1 || lineage.ClaimIDs[0] != "claim:payments:tier" {
		t.Fatalf("expected one claim lineage ref, got %+v", lineage)
	}
	if lineage.EvidenceCount != 1 || len(lineage.EvidenceIDs) != 1 || lineage.EvidenceIDs[0] != "evidence:runbook" {
		t.Fatalf("expected one evidence lineage ref, got %+v", lineage)
	}
	if lineage.SourceCount != 1 || len(lineage.SourceIDs) != 1 || lineage.SourceIDs[0] != "source:github" {
		t.Fatalf("expected one source lineage ref, got %+v", lineage)
	}
	materialization := sections[0].Materialization
	if materialization == nil || !materialization.Truncated {
		t.Fatalf("expected truncation materialization metadata, got %+v", sections[0].Materialization)
	}
	if len(materialization.TruncationSignals) != 2 {
		t.Fatalf("expected truncation signals, got %+v", materialization)
	}
}

func TestBuildReportSectionLineageExpandsTransitiveClaimRefs(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "claim:root", Kind: NodeKindClaim, Name: "Root claim"})
	g.AddNode(&Node{ID: "claim:prior", Kind: NodeKindClaim, Name: "Prior claim"})
	g.AddNode(&Node{ID: "claim:support", Kind: NodeKindClaim, Name: "Supporting claim"})
	g.AddNode(&Node{ID: "evidence:root", Kind: NodeKindEvidence, Name: "Root evidence"})
	g.AddNode(&Node{ID: "evidence:prior", Kind: NodeKindEvidence, Name: "Prior evidence"})
	g.AddNode(&Node{ID: "evidence:support", Kind: NodeKindEvidence, Name: "Supporting evidence"})
	g.AddNode(&Node{ID: "source:root", Kind: NodeKindSource, Name: "Root source"})
	g.AddNode(&Node{ID: "source:prior", Kind: NodeKindSource, Name: "Prior source"})
	g.AddNode(&Node{ID: "source:support", Kind: NodeKindSource, Name: "Supporting source"})
	g.AddEdge(&Edge{ID: "root-based-on", Source: "claim:root", Target: "evidence:root", Kind: EdgeKindBasedOn})
	g.AddEdge(&Edge{ID: "root-asserted-by", Source: "claim:root", Target: "source:root", Kind: EdgeKindAssertedBy})
	g.AddEdge(&Edge{ID: "root-supersedes", Source: "claim:root", Target: "claim:prior", Kind: EdgeKindSupersedes})
	g.AddEdge(&Edge{ID: "prior-based-on", Source: "claim:prior", Target: "evidence:prior", Kind: EdgeKindBasedOn})
	g.AddEdge(&Edge{ID: "prior-asserted-by", Source: "claim:prior", Target: "source:prior", Kind: EdgeKindAssertedBy})
	g.AddEdge(&Edge{ID: "support-refutes", Source: "claim:support", Target: "claim:prior", Kind: EdgeKindRefutes})
	g.AddEdge(&Edge{ID: "support-based-on", Source: "claim:support", Target: "evidence:support", Kind: EdgeKindBasedOn})
	g.AddEdge(&Edge{ID: "support-asserted-by", Source: "claim:support", Target: "source:support", Kind: EdgeKindAssertedBy})

	lineage := BuildReportSectionLineage(g, map[string]any{
		"claim_ids": []any{"claim:root"},
	})
	if lineage == nil {
		t.Fatal("expected lineage metadata")
	}
	if lineage.ClaimCount != 3 {
		t.Fatalf("expected claim_count=3, got %+v", lineage)
	}
	if lineage.EvidenceCount != 3 {
		t.Fatalf("expected evidence_count=3, got %+v", lineage)
	}
	if lineage.SourceCount != 3 {
		t.Fatalf("expected source_count=3, got %+v", lineage)
	}
}

func TestReportRunAttemptAndEventCollections(t *testing.T) {
	run := &ReportRun{
		ID:            "report_run:test",
		ReportID:      "quality",
		Status:        ReportRunStatusQueued,
		ExecutionMode: ReportExecutionModeSync,
		SubmittedAt:   time.Date(2026, 3, 10, 5, 0, 0, 0, time.UTC),
	}
	run.Attempts = append(run.Attempts, NewReportRunAttempt(run.ID, 1, run.Status, "api.request", "platform.inline", "host-a", "alice", "", run.SubmittedAt))
	run.LatestAttemptID = run.Attempts[0].ID
	AppendReportRunEvent(run, "platform.report_run.queued", run.Status, "api.request", "alice", run.SubmittedAt, map[string]any{"report_id": run.ReportID})
	StartLatestReportRunAttempt(run, run.SubmittedAt.Add(10*time.Millisecond))
	CompleteLatestReportRunAttempt(run, ReportRunStatusSucceeded, run.SubmittedAt.Add(20*time.Millisecond), "", "")
	AppendReportRunEvent(run, "platform.report_run.completed", ReportRunStatusSucceeded, "api.request", "alice", run.SubmittedAt.Add(20*time.Millisecond), map[string]any{"report_id": run.ReportID})

	attempts := ReportRunAttemptCollectionSnapshot(run.ReportID, run.ID, run.Attempts)
	if attempts.Count != 1 || len(attempts.Attempts) != 1 {
		t.Fatalf("expected one attempt, got %+v", attempts)
	}
	if attempts.Attempts[0].Status != ReportRunStatusSucceeded {
		t.Fatalf("expected succeeded attempt, got %+v", attempts.Attempts[0])
	}

	events := ReportRunEventCollectionSnapshot(run.ReportID, run.ID, run.Events)
	if events.Count != 2 || len(events.Events) != 2 {
		t.Fatalf("expected two events, got %+v", events)
	}
	if events.Events[0].Type != "platform.report_run.queued" || events.Events[1].Type != "platform.report_run.completed" {
		t.Fatalf("unexpected event ordering: %+v", events.Events)
	}
}

func TestReportRetryPolicyNormalizationAndBackoff(t *testing.T) {
	policy := NormalizeReportRetryPolicy(ReportRetryPolicy{})
	if policy.MaxAttempts != DefaultReportRetryMaxAttempts {
		t.Fatalf("expected default max attempts %d, got %d", DefaultReportRetryMaxAttempts, policy.MaxAttempts)
	}
	if policy.BaseBackoffMS != DefaultReportRetryBaseBackoffMS {
		t.Fatalf("expected default base backoff %d, got %d", DefaultReportRetryBaseBackoffMS, policy.BaseBackoffMS)
	}
	if policy.MaxBackoffMS != DefaultReportRetryMaxBackoffMS {
		t.Fatalf("expected default max backoff %d, got %d", DefaultReportRetryMaxBackoffMS, policy.MaxBackoffMS)
	}

	custom := NormalizeReportRetryPolicy(ReportRetryPolicy{
		MaxAttempts:   5,
		BaseBackoffMS: 1000,
		MaxBackoffMS:  2500,
	})
	if backoff := ReportRetryBackoff(custom, 1); backoff != 0 {
		t.Fatalf("expected first attempt backoff 0, got %s", backoff)
	}
	if backoff := ReportRetryBackoff(custom, 2); backoff != 1*time.Second {
		t.Fatalf("expected second attempt backoff 1s, got %s", backoff)
	}
	if backoff := ReportRetryBackoff(custom, 3); backoff != 2*time.Second {
		t.Fatalf("expected third attempt backoff 2s, got %s", backoff)
	}
	if backoff := ReportRetryBackoff(custom, 4); backoff != 2500*time.Millisecond {
		t.Fatalf("expected capped fourth attempt backoff 2.5s, got %s", backoff)
	}
}

func TestCloneReportRunAttemptsClonesRetrySchedulingMetadata(t *testing.T) {
	scheduledFor := time.Date(2026, 3, 10, 7, 0, 0, 0, time.UTC)
	startedAt := scheduledFor.Add(2 * time.Second)
	completedAt := startedAt.Add(3 * time.Second)
	attempts := []ReportRunAttempt{{
		ID:               "report_run:test:attempt:2",
		RunID:            "report_run:test",
		AttemptNumber:    2,
		Status:           ReportRunStatusFailed,
		Classification:   ReportAttemptClassTransient,
		RetryOfAttemptID: "report_run:test:attempt:1",
		RetryReason:      "manual_retry",
		RetryBackoffMS:   5000,
		ScheduledFor:     &scheduledFor,
		SubmittedAt:      scheduledFor.Add(-1 * time.Second),
		StartedAt:        &startedAt,
		CompletedAt:      &completedAt,
	}}

	cloned := CloneReportRunAttempts(attempts)
	if len(cloned) != 1 {
		t.Fatalf("expected one cloned attempt, got %d", len(cloned))
	}
	if cloned[0].ScheduledFor == attempts[0].ScheduledFor || cloned[0].StartedAt == attempts[0].StartedAt || cloned[0].CompletedAt == attempts[0].CompletedAt {
		t.Fatal("expected retry scheduling timestamps to be deep-cloned")
	}
	if cloned[0].Classification != ReportAttemptClassTransient || cloned[0].RetryBackoffMS != 5000 {
		t.Fatalf("expected retry metadata to survive clone, got %+v", cloned[0])
	}
}
