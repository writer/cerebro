package reports

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
		ResultSchema: "reports.GraphQualityReport",
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

func TestBuildReportLineageFromMetadata(t *testing.T) {
	meta := Metadata{
		BuiltAt:   time.Date(2026, 3, 10, 4, 30, 0, 0, time.UTC),
		NodeCount: 12,
		EdgeCount: 7,
		Providers: []string{"github", "okta"},
		Accounts:  []string{"acct-a"},
	}

	lineage := BuildReportLineageFromMetadata(meta, ReportDefinition{ID: "quality", Version: "2.1.0"})
	if lineage.GraphSnapshotID == "" {
		t.Fatal("expected graph snapshot id")
	}
	if lineage.GraphBuiltAt == nil || !lineage.GraphBuiltAt.Equal(meta.BuiltAt) {
		t.Fatalf("expected graph built at %s, got %+v", meta.BuiltAt, lineage.GraphBuiltAt)
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

func TestBuildReportSectionResultsWithOptionsIncludesTelemetryAndBitemporalSupportingEdges(t *testing.T) {
	g := New()
	validAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	recordedAt := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	futureValidAt := validAt.Add(2 * time.Hour)
	futureRecordedAt := recordedAt.Add(2 * time.Hour)

	g.AddNode(&Node{
		ID:   "claim:root",
		Kind: NodeKindClaim,
		Name: "Root claim",
		Properties: map[string]any{
			"valid_from":  validAt.Format(time.RFC3339),
			"recorded_at": recordedAt.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "evidence:visible",
		Kind: NodeKindEvidence,
		Name: "Visible evidence",
		Properties: map[string]any{
			"valid_from":  validAt.Format(time.RFC3339),
			"recorded_at": recordedAt.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "source:visible",
		Kind: NodeKindSource,
		Name: "Visible source",
		Properties: map[string]any{
			"valid_from":  validAt.Format(time.RFC3339),
			"recorded_at": recordedAt.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "claim:future",
		Kind: NodeKindClaim,
		Name: "Future claim",
		Properties: map[string]any{
			"valid_from":  futureValidAt.Format(time.RFC3339),
			"recorded_at": futureRecordedAt.Format(time.RFC3339),
		},
	})
	g.AddEdge(&Edge{
		ID:     "claim-based-on-visible",
		Source: "claim:root",
		Target: "evidence:visible",
		Kind:   EdgeKindBasedOn,
		Properties: map[string]any{
			"valid_from":  validAt.Format(time.RFC3339),
			"recorded_at": recordedAt.Format(time.RFC3339),
		},
	})
	g.AddEdge(&Edge{
		ID:     "claim-asserted-by-visible",
		Source: "claim:root",
		Target: "source:visible",
		Kind:   EdgeKindAssertedBy,
		Properties: map[string]any{
			"valid_from":  validAt.Format(time.RFC3339),
			"recorded_at": recordedAt.Format(time.RFC3339),
		},
	})
	g.AddEdge(&Edge{
		ID:     "claim-supports-future",
		Source: "claim:root",
		Target: "claim:future",
		Kind:   EdgeKindSupports,
		Properties: map[string]any{
			"valid_from":  futureValidAt.Format(time.RFC3339),
			"recorded_at": futureRecordedAt.Format(time.RFC3339),
		},
	})

	definition := ReportDefinition{
		ID: "claim-conflicts",
		Sections: []ReportSection{
			{Key: "conflicts", Title: "Conflicts", Kind: "table"},
		},
	}
	result := map[string]any{
		"conflicts": []any{map[string]any{"claim_ids": []any{"claim:root"}}},
	}

	sections := BuildReportSectionResultsWithOptions(definition, result, &ReportSectionBuildOptions{
		Graph:            g,
		TimeSlice:        ReportTimeSlice{ValidAt: &validAt, RecordedAt: &recordedAt},
		CacheStatus:      ReportCacheStatusMiss,
		RetryBackoffMS:   250,
		CacheSourceRunID: "report_run:cached",
	})
	if len(sections) != 1 {
		t.Fatalf("expected one section, got %d", len(sections))
	}
	lineage := sections[0].Lineage
	if lineage == nil {
		t.Fatalf("expected lineage metadata, got %+v", sections[0])
	}
	if lineage.SupportingEdgeCount != 2 {
		t.Fatalf("expected two visible supporting edges, got %+v", lineage)
	}
	if len(lineage.SupportingEdgeIDs) != 2 || lineage.SupportingEdgeIDs[0] != "claim-asserted-by-visible" || lineage.SupportingEdgeIDs[1] != "claim-based-on-visible" {
		t.Fatalf("expected only visible supporting edge ids, got %+v", lineage.SupportingEdgeIDs)
	}
	if lineage.ValidAt == nil || !lineage.ValidAt.Equal(validAt) {
		t.Fatalf("expected valid_at=%s, got %+v", validAt, lineage.ValidAt)
	}
	if lineage.RecordedAt == nil || !lineage.RecordedAt.Equal(recordedAt) {
		t.Fatalf("expected recorded_at=%s, got %+v", recordedAt, lineage.RecordedAt)
	}
	telemetry := sections[0].Telemetry
	if telemetry == nil {
		t.Fatalf("expected telemetry metadata, got %+v", sections[0])
	}
	if telemetry.CacheStatus != ReportCacheStatusMiss {
		t.Fatalf("expected cache_status=miss, got %+v", telemetry)
	}
	if telemetry.CacheSourceRunID != "report_run:cached" {
		t.Fatalf("expected cache_source_run_id report_run:cached, got %+v", telemetry)
	}
	if telemetry.RetryBackoffMS != 250 {
		t.Fatalf("expected retry_backoff_ms=250, got %+v", telemetry)
	}
}

func TestBuildReportSectionResultsTracksActualPayloadContract(t *testing.T) {
	definition := ReportDefinition{
		ID: "quality",
		Sections: []ReportSection{
			{
				Key:            "summary",
				Title:          "Summary",
				Kind:           "scorecard",
				EnvelopeKind:   "summary",
				EnvelopeSchema: "PlatformSummaryEnvelope",
			},
			{
				Key:            "raw_scope",
				Title:          "Raw Scope",
				Kind:           "context",
				EnvelopeKind:   "summary",
				EnvelopeSchema: "PlatformSummaryEnvelope",
			},
			{
				Key:            "timeseries",
				Title:          "Timeseries",
				Kind:           "timeseries_summary",
				EnvelopeKind:   "timeseries",
				EnvelopeSchema: "PlatformTimeseriesEnvelope",
			},
		},
	}
	result := map[string]any{
		"summary": map[string]any{
			"headline": "Healthy graph",
			"measures": []map[string]any{{
				"id":         "coverage",
				"label":      "Coverage",
				"value_type": "number",
				"value":      98.2,
			}},
		},
		"raw_scope": map[string]any{
			"entity_id": "service:payments",
		},
		"timeseries": map[string]any{
			"points": []map[string]any{{
				"timestamp": "not-a-time",
				"values": []map[string]any{{
					"id":         "coverage",
					"label":      "Coverage",
					"value_type": "number",
					"value":      98.2,
				}},
			}},
		},
	}

	sections := BuildReportSectionResults(definition, result, nil)
	if len(sections) != 3 {
		t.Fatalf("expected three sections, got %d", len(sections))
	}
	if got := sections[0].PayloadSchema; got != "PlatformSummaryEnvelope" {
		t.Fatalf("expected typed summary payload schema, got %q", got)
	}
	if !sections[0].PayloadStrict {
		t.Fatalf("expected typed summary payload to be strict, got %+v", sections[0])
	}
	if got := sections[1].PayloadSchema; got != "PlatformFlexibleObjectValue" {
		t.Fatalf("expected raw scope payload to fall back to flexible object contract, got %q", got)
	}
	if sections[1].PayloadStrict {
		t.Fatalf("expected raw scope payload to remain non-strict, got %+v", sections[1])
	}
	if got := sections[2].PayloadSchema; got != "PlatformFlexibleObjectValue" {
		t.Fatalf("expected invalid nested timeseries payload to fall back to flexible object contract, got %q", got)
	}
	if sections[2].PayloadStrict {
		t.Fatalf("expected invalid nested timeseries payload to remain non-strict, got %+v", sections[2])
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

func TestReportRunControlAndRetryPolicySnapshots(t *testing.T) {
	now := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	run := &ReportRun{
		ID:                "report_run:test",
		ReportID:          "quality",
		Status:            ReportRunStatusRunning,
		ExecutionMode:     ReportExecutionModeAsync,
		SubmittedAt:       now.Add(-time.Minute),
		RetryPolicy:       ReportRetryPolicy{MaxAttempts: 4, BaseBackoffMS: 1000, MaxBackoffMS: 2000},
		CancelRequestedAt: &now,
		CancelRequestedBy: "alice@example.com",
		CancelReason:      "operator requested cancellation",
	}
	run.Attempts = []ReportRunAttempt{
		NewReportRunAttempt(run.ID, 1, ReportAttemptStatusFailed, "api.request", "platform.job", "host-a", "alice@example.com", "", now.Add(-2*time.Minute)),
		NewReportRunAttempt(run.ID, 2, ReportAttemptStatusScheduled, "api.retry", "platform.job", "host-a", "alice@example.com", "", now.Add(-30*time.Second)),
	}
	run.Attempts[1].RetryBackoffMS = 1000
	scheduledFor := now.Add(30 * time.Second)
	run.Attempts[1].ScheduledFor = &scheduledFor
	run.LatestAttemptID = run.Attempts[1].ID

	retryState := ReportRunRetryPolicyStateSnapshot(run.ReportID, run)
	if retryState.RemainingAttempts != 2 {
		t.Fatalf("expected remaining_attempts=2, got %+v", retryState)
	}
	if retryState.LatestAttemptStatus != ReportAttemptStatusScheduled {
		t.Fatalf("expected latest_attempt_status=scheduled, got %+v", retryState)
	}

	control := ReportRunControlSnapshot(run.ReportID, run)
	if control.Cancelable {
		t.Fatalf("expected run with outstanding cancel request to stop exposing cancel action, got %+v", control)
	}
	if control.Retryable {
		t.Fatalf("expected running run to not be retryable, got %+v", control)
	}
	if control.CancelRequestedAt == nil || !control.CancelRequestedAt.Equal(now) {
		t.Fatalf("expected cancel_requested_at=%s, got %+v", now, control.CancelRequestedAt)
	}
	if control.LatestAttemptStatus != ReportAttemptStatusScheduled {
		t.Fatalf("expected control latest_attempt_status=scheduled, got %+v", control)
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

func TestGraphSnapshotCollectionSnapshotIncludesCurrentAndObservedRuns(t *testing.T) {
	g := New()
	builtAt := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	g.SetMetadata(Metadata{
		BuiltAt:       builtAt,
		NodeCount:     12,
		EdgeCount:     7,
		Providers:     []string{"github"},
		Accounts:      []string{"acct-a"},
		BuildDuration: 3 * time.Second,
	})
	lineage := BuildReportLineage(g, ReportDefinition{ID: "quality", Version: "1.2.0"})
	run := &ReportRun{
		ID:          "report_run:test",
		ReportID:    "quality",
		SubmittedAt: builtAt.Add(5 * time.Minute),
		Lineage:     lineage,
		Snapshot: &ReportSnapshot{
			ID:          "report_snapshot:test",
			GeneratedAt: builtAt.Add(6 * time.Minute),
			Lineage:     lineage,
		},
	}
	collection := GraphSnapshotCollectionSnapshot(g, map[string]*ReportRun{run.ID: run}, builtAt.Add(10*time.Minute))
	if collection.Count != 1 {
		t.Fatalf("expected one snapshot record, got %+v", collection)
	}
	record := collection.Snapshots[0]
	if !record.Current {
		t.Fatalf("expected current snapshot flag, got %+v", record)
	}
	if record.ObservedRunCount != 2 {
		t.Fatalf("expected observed_run_count=2 from run lineage + snapshot lineage, got %+v", record)
	}
	if record.ObservedMaterializations != 1 {
		t.Fatalf("expected observed_materializations=1, got %+v", record)
	}
	if len(record.ObservedReportIDs) != 1 || record.ObservedReportIDs[0] != "quality" {
		t.Fatalf("expected observed report ids to include quality, got %+v", record)
	}
}
