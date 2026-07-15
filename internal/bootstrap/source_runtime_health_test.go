package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/nhicoverage"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/sourcehealthview"
	"github.com/writer/cerebro/internal/sourcehttp/responseview"
	"github.com/writer/cerebro/internal/sourceruntime"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSourceRuntimeHealthRecordIncludesScheduleReceipt(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		Id:           "runtime-1",
		SourceId:     "generated",
		TenantId:     "tenant",
		LastSyncedAt: timestamppb.New(now.Add(-time.Hour)),
		Config: map[string]string{
			"expected_cadence_seconds": "3600",
			"stale_after_seconds":      "7200",
		},
	}

	record := sourcehealthview.FromRuntime(runtime, now, nil, nil)
	if record.ExpectedCadenceSeconds == nil || *record.ExpectedCadenceSeconds != 3600 {
		t.Fatalf("ExpectedCadenceSeconds = %v, want 3600", record.ExpectedCadenceSeconds)
	}
	if record.StaleAfterSeconds == nil || *record.StaleAfterSeconds != 7200 {
		t.Fatalf("StaleAfterSeconds = %v, want 7200", record.StaleAfterSeconds)
	}
	if !record.ScheduleContextConfigured {
		t.Fatal("ScheduleContextConfigured = false, want true")
	}
	if record.Status != "healthy" {
		t.Fatalf("Status = %q, want healthy", record.Status)
	}
}

func TestSourceRuntimeHealthRecordIgnoresMalformedStoredScopePolicy(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		Id:       "runtime-1",
		SourceId: "generated",
		TenantId: "tenant",
		Config: map[string]string{
			resourcescope.ConfigKey: "{not-json",
		},
	}

	record := sourcehealthview.FromRuntime(runtime, now, nil, nil)
	if record.ScopePolicy != nil {
		t.Fatalf("ScopePolicy = %#v, want nil for malformed stored policy", record.ScopePolicy)
	}
}

func TestRuntimeHealthStatusHonorsStaleAfter(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	runtime := &cerebrov1.SourceRuntime{
		LastSyncedAt: timestamppb.New(now.Add(-2 * time.Hour)),
		Config: map[string]string{
			"stale_after_seconds": "3600",
		},
	}

	if got := runtimeHealthStatus(runtime, now); got != "stale" {
		t.Fatalf("runtimeHealthStatus() = %q, want stale", got)
	}
}

func TestSourceRuntimeHealthRecordHandlesPartialAndInvalidScheduleReceipt(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		config         map[string]string
		wantCadence    *int64
		wantStale      *int64
		wantConfigured bool
	}{
		{
			name: "cadence only",
			config: map[string]string{
				"expected_cadence_seconds": " 1800 ",
			},
			wantCadence:    int64Ptr(1800),
			wantConfigured: true,
		},
		{
			name: "stale only",
			config: map[string]string{
				"stale_after_seconds": "3600",
			},
			wantStale:      int64Ptr(3600),
			wantConfigured: true,
		},
		{
			name: "invalid values ignored",
			config: map[string]string{
				"expected_cadence_seconds": "invalid",
				"stale_after_seconds":      "-1",
			},
		},
		{
			name: "zero values ignored",
			config: map[string]string{
				"expected_cadence_seconds": "0",
				"stale_after_seconds":      "0",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := sourcehealthview.FromRuntime(&cerebrov1.SourceRuntime{
				Id:           "runtime-1",
				SourceId:     "generated",
				TenantId:     "tenant",
				LastSyncedAt: timestamppb.New(now),
				Config:       test.config,
			}, now, nil, nil)
			assertOptionalInt64(t, "ExpectedCadenceSeconds", record.ExpectedCadenceSeconds, test.wantCadence)
			assertOptionalInt64(t, "StaleAfterSeconds", record.StaleAfterSeconds, test.wantStale)
			if record.ScheduleContextConfigured != test.wantConfigured {
				t.Fatalf("ScheduleContextConfigured = %v, want %v", record.ScheduleContextConfigured, test.wantConfigured)
			}
		})
	}
}

func TestSourceRuntimeHealthRecordsPreserveOrderAndSkipNil(t *testing.T) {
	now := time.Date(2026, 6, 16, 9, 30, 0, 0, time.UTC)
	runtimes := []*cerebrov1.SourceRuntime{
		{
			Id:       "runtime-c",
			SourceId: "slack",
			TenantId: "writer",
			Config:   map[string]string{"family": "conversation"},
		},
		nil,
		{
			Id:       "runtime-a",
			SourceId: "okta",
			TenantId: "writer",
			Config:   map[string]string{"family": "user"},
		},
		{
			Id:           "runtime-b",
			SourceId:     "aws",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.New(now.Add(-time.Minute)),
			Config:       map[string]string{"family": "account"},
		},
	}

	records, err := (&App{}).sourceRuntimeHealthRecords(context.Background(), runtimes, now)
	if err != nil {
		t.Fatalf("sourceRuntimeHealthRecords() error = %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d, want 3", len(records))
	}
	for index, wantRuntimeID := range []string{"runtime-c", "runtime-a", "runtime-b"} {
		if records[index].RuntimeID != wantRuntimeID {
			t.Fatalf("records[%d].RuntimeID = %q, want %q; records=%#v", index, records[index].RuntimeID, wantRuntimeID, records)
		}
	}
	if records[0].Family != "conversation" || records[2].Family != "account" {
		t.Fatalf("records did not retain runtime metadata: %#v", records)
	}
}

func TestRuntimeHealthStatusStaleBoundaryAndFailurePrecedence(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		lastSynced time.Time
		config     map[string]string
		want       string
	}{
		{
			name:       "exact threshold is healthy",
			lastSynced: now.Add(-time.Hour),
			config:     map[string]string{"stale_after_seconds": "3600"},
			want:       "healthy",
		},
		{
			name:       "over threshold is stale",
			lastSynced: now.Add(-time.Hour - time.Second),
			config:     map[string]string{"stale_after_seconds": "3600"},
			want:       "stale",
		},
		{
			name:       "failure beats stale",
			lastSynced: now.Add(-2 * time.Hour),
			config: map[string]string{
				"stale_after_seconds":               "3600",
				runtimeLastFailureCategoryConfigKey: "auth_error",
			},
			want: "failing",
		},
		{
			name:       "large int64 stale window",
			lastSynced: now.Add(-2 * time.Hour),
			config:     map[string]string{"stale_after_seconds": "4294967296"},
			want:       "healthy",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &cerebrov1.SourceRuntime{
				LastSyncedAt: timestamppb.New(test.lastSynced),
				Config:       test.config,
			}
			if got := runtimeHealthStatus(runtime, now); got != test.want {
				t.Fatalf("runtimeHealthStatus() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSourceRuntimeHealthSummariesAggregateBySource(t *testing.T) {
	graphLag := int64(7200)
	staleAfter := int64(3600)
	records := []sourceRuntimeHealthRecord{
		{
			RuntimeID:          "runtime-a",
			SourceID:           "okta",
			Status:             "healthy",
			ContractProbeState: "passing",
			LatestGraphRun:     sourcehealthview.GraphRunFromStore(graphstore.IngestRun{Status: "completed"}),
			GraphLagSeconds:    &graphLag,
			StaleAfterSeconds:  &staleAfter,
		},
		{
			RuntimeID:          "runtime-b",
			SourceID:           "okta",
			Status:             "failing",
			CursorPending:      true,
			ContractProbeState: "failure",
			LatestGraphRun:     sourcehealthview.GraphRunFromStore(graphstore.IngestRun{Status: "failed"}),
			StaleAfterSeconds:  &staleAfter,
		},
		{
			RuntimeID:          "runtime-c",
			SourceID:           "panopticon",
			Status:             "unknown",
			ContractProbeState: "not_configured",
		},
	}

	summaries := sourceRuntimeHealthSummaries(records)

	if len(summaries) != 2 {
		t.Fatalf("len(sourceRuntimeHealthSummaries()) = %d, want 2", len(summaries))
	}
	okta := summaries[0]
	if okta.SourceID != "okta" || okta.Total != 2 || okta.Healthy != 1 || okta.Failing != 1 {
		t.Fatalf("okta summary = %+v", okta)
	}
	if okta.CursorPending != 1 || okta.GraphBehind != 1 || okta.GraphFailed != 1 {
		t.Fatalf("okta graph/cursor summary = %+v", okta)
	}
	if okta.ContractProbePassing != 1 || okta.ContractProbeFailure != 1 {
		t.Fatalf("okta contract summary = %+v", okta)
	}
	panopticon := summaries[1]
	if panopticon.SourceID != "panopticon" || panopticon.Total != 1 || panopticon.Unknown != 1 || panopticon.GraphNotObserved != 1 || panopticon.ContractProbeNotConfigured != 1 {
		t.Fatalf("panopticon summary = %+v", panopticon)
	}
}

func TestRuntimeFreshnessFromHealthClassifiesBackfillWorklist(t *testing.T) {
	graphLag := int64(7200)
	staleAfter := int64(3600)
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-06-12T00:00:00Z",
		Runtimes: []sourceRuntimeHealthRecord{
			{
				RuntimeID:         "runtime-current",
				SourceID:          "okta",
				EnabledState:      "enabled",
				Status:            "healthy",
				LatestGraphRun:    sourcehealthview.GraphRunFromStore(graphstore.IngestRun{Status: "completed"}),
				GraphLagSeconds:   int64Ptr(60),
				StaleAfterSeconds: &staleAfter,
			},
			{
				RuntimeID:         "runtime-missing-graph",
				SourceID:          "okta",
				EnabledState:      "enabled",
				Status:            "healthy",
				GraphLagSeconds:   &graphLag,
				StaleAfterSeconds: &staleAfter,
			},
			{
				RuntimeID:           "runtime-source-failed",
				SourceID:            "gcp",
				EnabledState:        "enabled",
				Status:              "failing",
				LastFailureCategory: "auth_error",
				LatestGraphRun:      sourcehealthview.GraphRunFromStore(graphstore.IngestRun{Status: "completed"}),
				StaleAfterSeconds:   &staleAfter,
			},
			{
				RuntimeID:    "runtime-disabled",
				SourceID:     "cosmo",
				EnabledState: "disabled",
				Status:       "unknown",
			},
		},
	}

	response := runtimeFreshnessFromHealth(health)

	if response.Status != "degraded" {
		t.Fatalf("Status = %q, want degraded", response.Status)
	}
	byRuntime := map[string]runtimeFreshnessRecord{}
	for _, record := range response.Runtimes {
		byRuntime[record.RuntimeID] = record
	}
	if got := byRuntime["runtime-current"]; got.FreshnessState != "healthy" || got.BackfillEligible {
		t.Fatalf("runtime-current freshness = %+v", got)
	}
	if got := byRuntime["runtime-missing-graph"]; got.FreshnessState != "graph_missing" || !got.BackfillEligible || got.RecommendedWorkflow != "source-runtime-backfill" {
		t.Fatalf("runtime-missing-graph freshness = %+v", got)
	}
	if got := byRuntime["runtime-source-failed"]; got.FreshnessState != "source_failed" || got.FailureClass != "auth_error" || got.BackfillEligible {
		t.Fatalf("runtime-source-failed freshness = %+v", got)
	}
	if got := byRuntime["runtime-disabled"]; got.FreshnessState != "disabled" || got.LifecycleState != "disabled" || got.BackfillEligible {
		t.Fatalf("runtime-disabled freshness = %+v", got)
	}
	if len(response.Summaries) != 3 {
		t.Fatalf("len(Summaries) = %d, want 3", len(response.Summaries))
	}
	if response.Summaries[0].SourceID != "okta" || response.Summaries[0].BackfillEligible != 1 || response.Summaries[0].GraphMissing != 1 {
		t.Fatalf("okta summary = %+v", response.Summaries[0])
	}
}

func TestRuntimeFreshnessFromHealthTreatsRunningGraphAsHealthy(t *testing.T) {
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-06-12T00:00:00Z",
		Runtimes: []sourceRuntimeHealthRecord{
			{
				RuntimeID:      "runtime-graph-running",
				SourceID:       "okta",
				EnabledState:   "enabled",
				Status:         "healthy",
				LatestGraphRun: sourcehealthview.GraphRunFromStore(graphstore.IngestRun{Status: "running"}),
			},
		},
	}

	response := runtimeFreshnessFromHealth(health)

	if response.Status != "healthy" {
		t.Fatalf("Status = %q, want healthy", response.Status)
	}
	record := response.Runtimes[0]
	if record.GraphIngestState != "running" || record.FreshnessState != "healthy" || record.BackfillEligible || record.NextAction != "monitor" {
		t.Fatalf("running graph freshness = %+v", record)
	}
	if response.Summaries[0].Healthy != 1 || response.Summaries[0].NeedsAttention != 0 {
		t.Fatalf("summary = %+v", response.Summaries[0])
	}
}

func TestRuntimeFreshnessFromHealthSchedulesBackfillForPartialGraphCheckpoint(t *testing.T) {
	latestGraphRun := sourcehealthview.GraphRunFromStore(graphstore.IngestRun{
		ID:                      "graph-run-partial",
		Status:                  graphstore.IngestRunStatusCompleted,
		CheckpointCursor:        "page-2",
		CheckpointComplete:      false,
		CheckpointCompleteKnown: true,
	})
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-07-14T12:00:00Z",
		Runtimes: []sourceRuntimeHealthRecord{{
			RuntimeID:      "runtime-partial",
			SourceID:       "okta",
			EnabledState:   "enabled",
			Status:         "healthy",
			LatestGraphRun: latestGraphRun,
		}},
	}

	response := runtimeFreshnessFromHealth(health)

	if latestGraphRun.CheckpointComplete == nil || *latestGraphRun.CheckpointComplete || latestGraphRun.CheckpointCursor != "page-2" {
		t.Fatalf("latest graph run = %+v, want explicit partial checkpoint", latestGraphRun)
	}
	record := response.Runtimes[0]
	if record.GraphIngestState != "behind" || record.FreshnessState != "graph_behind" || !record.BackfillEligible || record.RecommendedWorkflow != "source-runtime-backfill" {
		t.Fatalf("partial graph freshness = %+v, want graph backfill work", record)
	}
}

func TestRuntimeFreshnessFromHealthSchedulesBackfillForExplicitIncompleteGraphCheckpoint(t *testing.T) {
	latestGraphRun := sourcehealthview.GraphRunFromStore(graphstore.IngestRun{
		ID:                      "graph-run-incomplete",
		Status:                  graphstore.IngestRunStatusCompleted,
		CheckpointComplete:      false,
		CheckpointCompleteKnown: true,
	})
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-07-14T12:00:00Z",
		Runtimes: []sourceRuntimeHealthRecord{{
			RuntimeID:      "runtime-incomplete",
			SourceID:       "okta",
			EnabledState:   "enabled",
			Status:         "healthy",
			LatestGraphRun: latestGraphRun,
		}},
	}

	response := runtimeFreshnessFromHealth(health)

	if latestGraphRun.CheckpointComplete == nil || *latestGraphRun.CheckpointComplete {
		t.Fatalf("latest graph run = %+v, want explicit incomplete checkpoint", latestGraphRun)
	}
	record := response.Runtimes[0]
	if record.GraphIngestState != "behind" || record.FreshnessState != "graph_behind" || !record.BackfillEligible || record.RecommendedWorkflow != "source-runtime-backfill" {
		t.Fatalf("incomplete graph freshness = %+v, want graph backfill work", record)
	}
}

func TestRuntimeFreshnessFromHealthTreatsLegacyGraphCheckpointStateAsUnknown(t *testing.T) {
	latestGraphRun := sourcehealthview.GraphRunFromStore(graphstore.IngestRun{
		ID:     "graph-run-legacy",
		Status: graphstore.IngestRunStatusCompleted,
	})
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-07-14T12:00:00Z",
		Runtimes: []sourceRuntimeHealthRecord{{
			RuntimeID:      "runtime-legacy",
			SourceID:       "okta",
			EnabledState:   "enabled",
			Status:         "healthy",
			LatestGraphRun: latestGraphRun,
		}},
	}

	response := runtimeFreshnessFromHealth(health)

	if latestGraphRun.CheckpointComplete != nil {
		t.Fatalf("latest graph run = %+v, want legacy checkpoint state absent", latestGraphRun)
	}
	record := response.Runtimes[0]
	if record.GraphIngestState != "current" || record.FreshnessState != "healthy" || record.BackfillEligible {
		t.Fatalf("legacy graph freshness = %+v, want current without forced backfill", record)
	}
}

func TestSourceCoverageRecordsSurfacesBlindSpots(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	app := &App{sources: registry}

	records := app.sourceCoverageRecords([]*cerebrov1.SourceRuntime{{
		Id:           "okta-user",
		SourceId:     "okta",
		TenantId:     "writer",
		LastSyncedAt: timestamppb.New(now),
		Config:       map[string]string{"family": "user"},
	}}, ports.SourceRuntimeFilter{TenantID: "writer", SourceID: "okta"}, now)

	byDimension := map[string]sourcecoverage.Record{}
	for _, record := range records {
		byDimension[record.DimensionID] = record
	}
	if got := byDimension["users"].State; got != sourcecoverage.StateHealthy {
		t.Fatalf("users state = %q, want healthy; records=%#v", got, records)
	}
	if got := byDimension["applications"].State; got != sourcecoverage.StateUnconfigured {
		t.Fatalf("applications state = %q, want unconfigured; records=%#v", got, records)
	}
	if got := byDimension["remediation"].State; got != sourcecoverage.StateUnsupported {
		t.Fatalf("remediation state = %q, want unsupported; records=%#v", got, records)
	}
	blindSpots := sourcecoverage.BlindSpots(records)
	if len(blindSpots) != 2 {
		t.Fatalf("len(BlindSpots()) = %d, want 2: %#v", len(blindSpots), blindSpots)
	}
}

func TestListSourceRuntimeHealthFiltersCoverageByAllowedTenant(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-user": {
			Id:           "writer-okta-user",
			SourceId:     "okta",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "user"},
		},
		"other-okta-application": {
			Id:           "other-okta-application",
			SourceId:     "okta",
			TenantId:     "other",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "application"},
		},
	}}
	app := &App{deps: Dependencies{StateStore: store}, sources: registry}
	req := httptest.NewRequest("GET", "/source-runtime-health?runtime_ids=writer-okta-user,other-okta-application", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, authContext{
		principal: authPrincipal{AllowedTenants: []string{"writer"}},
	}))

	response, err := app.listSourceRuntimeHealth(req)
	if err != nil {
		t.Fatalf("listSourceRuntimeHealth() error = %v", err)
	}
	if len(response.Runtimes) != 1 || response.Runtimes[0].RuntimeID != "writer-okta-user" {
		t.Fatalf("Runtimes = %#v, want only writer-okta-user", response.Runtimes)
	}
	byDimension := map[string]sourcecoverage.Record{}
	for _, record := range response.Coverage {
		if record.RuntimeID == "other-okta-application" || record.TenantID == "other" {
			t.Fatalf("coverage leaked forbidden tenant runtime: %#v", record)
		}
		byDimension[record.DimensionID] = record
	}
	if got := byDimension["users"].RuntimeID; got != "writer-okta-user" {
		t.Fatalf("users coverage runtime_id = %q, want writer-okta-user", got)
	}
	if got := byDimension["applications"].State; got != sourcecoverage.StateUnconfigured {
		t.Fatalf("applications state = %q, want unconfigured; coverage=%#v", got, response.Coverage)
	}
	if got := byDimension["applications"].RuntimeID; got != "" {
		t.Fatalf("applications runtime_id = %q, want empty", got)
	}
}

func TestListSourceRuntimeHealthSummaryKeepsAggregatesAndOmitsRecords(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-user": {
			Id:           "writer-okta-user",
			SourceId:     "okta",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.Now(),
			Config:       map[string]string{"family": "user"},
		},
	}}
	app := &App{deps: Dependencies{StateStore: store}, sources: registry}
	request := httptest.NewRequest(http.MethodGet, "/source-runtimes/health?view=summary", nil)

	response, err := app.listSourceRuntimeHealth(request)
	if err != nil {
		t.Fatalf("listSourceRuntimeHealth() error = %v", err)
	}
	if len(response.Coverage) != 0 {
		t.Fatalf("Coverage length = %d, want 0", len(response.Coverage))
	}
	if len(response.coverageRecords) != 3 || len(response.CoverageSummary) != 1 {
		t.Fatalf("summary coverage records/summaries = %d/%d, want 3/1", len(response.coverageRecords), len(response.CoverageSummary))
	}
	if response.view != responseview.Summary {
		t.Fatalf("view = %q, want summary", response.view)
	}

	freshness := runtimeFreshnessFromHealth(response)
	if len(freshness.CoverageBlindSpots) != 0 {
		t.Fatalf("freshness raw blind spots length = %d, want 0", len(freshness.CoverageBlindSpots))
	}
	if len(freshness.CoverageBlindSummary) != 1 || freshness.CoverageBlindSummary[0].BlindSpots != 2 {
		t.Fatalf("freshness blind spot summary = %#v, want two blind spots", freshness.CoverageBlindSummary)
	}
}

func TestSourceCoverageConfiguredScopeExcludesUnconfiguredSources(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{}, secondaryCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := &App{sources: registry}
	runtimes := []*cerebrov1.SourceRuntime{{Id: "writer-okta", SourceId: "okta", TenantId: "writer"}}

	records := app.sourceCoverageRecordsScoped(runtimes, ports.SourceRuntimeFilter{TenantID: "writer"}, time.Now().UTC(), responseview.CoverageConfigured)

	for _, record := range records {
		if record.SourceID == "secondary" {
			t.Fatalf("configured coverage included unconfigured source: %#v", record)
		}
	}
	if len(records) != 3 {
		t.Fatalf("configured coverage length = %d, want 3", len(records))
	}
}

func TestSourceRuntimeHealthRecordsBatchLatestRunQueries(t *testing.T) {
	stateStore := &stubRuntimeStore{findingEvaluationRuns: map[string]*cerebrov1.FindingEvaluationRun{}}
	graphStore := &stubGraphStore{ingestRuns: map[string]graphstore.IngestRun{}}
	app := &App{deps: Dependencies{StateStore: stateStore, GraphStore: graphStore}}
	runtimes := []*cerebrov1.SourceRuntime{
		{Id: "runtime-b", SourceId: "aws", TenantId: "writer"},
		{Id: "runtime-a", SourceId: "okta", TenantId: "writer"},
	}

	if _, err := app.sourceRuntimeHealthRecords(context.Background(), runtimes, time.Now().UTC()); err != nil {
		t.Fatalf("sourceRuntimeHealthRecords() error = %v", err)
	}
	if !graphStore.ingestRunListFilter.LatestByRuntime || len(graphStore.ingestRunListFilter.RuntimeIDs) != 2 {
		t.Fatalf("graph run filter = %#v, want one latest run for two runtimes", graphStore.ingestRunListFilter)
	}
	if !stateStore.findingEvaluationRunListRequest.LatestByRuntime || len(stateStore.findingEvaluationRunListRequest.RuntimeIDs) != 2 {
		t.Fatalf("finding run request = %#v, want one latest run for two runtimes", stateStore.findingEvaluationRunListRequest)
	}
}

func TestConnectorCoverageReportUsesAuthenticatedTenantAndBlindSpotTotals(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"writer-okta-user": {
			Id:           "writer-okta-user",
			SourceId:     "okta",
			TenantId:     "writer",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "user"},
		},
		"other-okta-application": {
			Id:           "other-okta-application",
			SourceId:     "okta",
			TenantId:     "other",
			LastSyncedAt: timestamppb.New(now),
			Config:       map[string]string{"family": "application"},
		},
	}}
	app := &App{deps: Dependencies{StateStore: store}, sources: registry}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/connectors/coverage?source_id=okta", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "writer"},
	}))

	app.handleGetConnectorCoverage(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var report nhicoverage.SourceCoverageResponse
	if err := json.NewDecoder(recorder.Body).Decode(&report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.TenantID != "writer" || report.SourceID != "okta" {
		t.Fatalf("report scope = tenant:%q source:%q", report.TenantID, report.SourceID)
	}
	if report.Totals.Dimensions != 3 || report.Totals.BlindSpots != 2 {
		t.Fatalf("report totals = %#v", report.Totals)
	}
	if report.Gate.Status != "fail" || report.Gate.BlockingReason != "blind_spot" {
		t.Fatalf("report gate = %#v, want blind_spot failure", report.Gate)
	}
	if report.NHICoverage.Version != nhicoverage.Version {
		t.Fatalf("NHI coverage version = %q, want %q", report.NHICoverage.Version, nhicoverage.Version)
	}
	if report.NHICoverage.Totals.Dimensions != 1 || report.NHICoverage.Totals.BlindSpots != 1 {
		t.Fatalf("NHI coverage totals = %#v", report.NHICoverage.Totals)
	}
	if len(report.NHICoverage.Records) != 1 {
		t.Fatalf("NHI coverage records = %#v, want one application identity record", report.NHICoverage.Records)
	}
	if got := report.NHICoverage.Records[0]; got.DimensionID != "applications" || got.Lane != nhicoverage.LaneInventory || got.SubjectKind != "application" {
		t.Fatalf("NHI coverage record = %#v, want application inventory", got)
	}
	for _, record := range report.Records {
		if record.TenantID == "other" || record.RuntimeID == "other-okta-application" {
			t.Fatalf("report leaked other tenant record: %#v", record)
		}
	}
}

func TestEmitSourceCoverageGateTelemetry(t *testing.T) {
	report := sourcecoverage.Report{
		Totals: sourcecoverage.Totals{
			Dimensions:          4,
			HighValueDimensions: 3,
			Healthy:             1,
			Failed:              1,
			Unconfigured:        1,
			BlindSpots:          2,
		},
	}
	report.Gate = sourcecoverage.GateForTotals(report.Totals)

	stderr := captureBootstrapStderr(t, func() {
		emitSourceCoverageGateTelemetry(context.Background(), report)
	})
	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"name":                                        "source_coverage.release_gate",
		"source_coverage.gate.status":                 "fail",
		"source_coverage.gate.blocking_reason":        "failed",
		"source_coverage.dimensions.total":            float64(4),
		"source_coverage.high_value_dimensions.total": float64(3),
		"source_coverage.healthy_count":               float64(1),
		"source_coverage.failed_count":                float64(1),
		"source_coverage.unconfigured_count":          float64(1),
		"source_coverage.blind_spot_count":            float64(2),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestListSourceRuntimeHealthFailsClosedWithoutRuntimeStore(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest("GET", "/source-runtimes/health?source_id=aws", nil)

	if _, err := app.listSourceRuntimeHealth(req); !errors.Is(err, sourceruntime.ErrRuntimeUnavailable) {
		t.Fatalf("listSourceRuntimeHealth() error = %v, want runtime unavailable", err)
	}
}

func TestRuntimeFreshnessIncludesCoverageBlindSpots(t *testing.T) {
	health := sourceRuntimeHealthResponse{
		GeneratedAt: "2026-06-15T00:00:00Z",
		Coverage: []sourcecoverage.Record{{
			SourceID:      "okta",
			DimensionID:   "applications",
			DimensionType: "entity_family",
			Title:         "Applications",
			State:         sourcecoverage.StateUnconfigured,
			SupportLevel:  sourcecdk.CoverageSupportSupported,
			HighValue:     true,
			BlindSpot:     true,
		}},
	}

	response := runtimeFreshnessFromHealth(health)

	if response.Status != "healthy" {
		t.Fatalf("Status = %q, want healthy", response.Status)
	}
	if len(response.CoverageBlindSpots) != 1 || response.CoverageBlindSpots[0].DimensionID != "applications" {
		t.Fatalf("CoverageBlindSpots = %#v", response.CoverageBlindSpots)
	}
	if len(response.CoverageBlindSummary) != 1 || response.CoverageBlindSummary[0].BlindSpots != 1 {
		t.Fatalf("CoverageBlindSummary = %#v", response.CoverageBlindSummary)
	}
}

func BenchmarkSourceRuntimeHealthSerialization(b *testing.B) {
	coverage := make([]sourcecoverage.Record, 5143)
	for index := range coverage {
		coverage[index] = sourcecoverage.Record{
			SourceID:      "connector",
			DimensionID:   "dimension-" + strconv.Itoa(index),
			DimensionType: "entity_family",
			Title:         "Coverage dimension",
			State:         sourcecoverage.StateUnconfigured,
			SupportLevel:  sourcecdk.CoverageSupportSupported,
			BlindSpot:     true,
		}
	}
	cases := map[string]sourceRuntimeHealthResponse{
		"expanded": {
			GeneratedAt:     "2026-07-14T00:00:00Z",
			Coverage:        coverage,
			CoverageSummary: sourcecoverage.Summaries(coverage),
		},
		"summary": {
			GeneratedAt:     "2026-07-14T00:00:00Z",
			CoverageSummary: sourcecoverage.Summaries(coverage),
		},
	}
	for name, response := range cases {
		b.Run(name, func(b *testing.B) {
			payload, err := json.Marshal(response)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := json.Marshal(response); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(payload)), "response-bytes")
		})
	}
}

func FuzzRuntimeHealthConfigParsing(f *testing.F) {
	f.Add("", "", "")
	f.Add("3600", "7200", "passing")
	f.Add("-1", "0", " failure ")
	f.Add("999999999999999999999999", "nan", "unknown")
	f.Fuzz(func(t *testing.T, cadence string, stale string, probe string) {
		runtime := &cerebrov1.SourceRuntime{
			SourceId:     "evidence_cas",
			LastSyncedAt: timestamppb.New(time.Now().UTC()),
			Config: map[string]string{
				"expected_cadence_seconds":         cadence,
				"stale_after_seconds":              stale,
				runtimeContractProbeStateConfigKey: probe,
			},
		}
		if got := runtimeConfigInt64(runtime, "expected_cadence_seconds"); got < 0 {
			t.Fatalf("runtimeConfigInt64() = %d, want non-negative", got)
		}
		if got := runtimeConfigUint32(runtime, runtimeRecordsScannedConfigKey); got != 0 {
			t.Fatalf("runtimeConfigUint32(absent) = %d, want 0", got)
		}
		if got := runtimeEnabledState(runtime); got != "enabled" && got != "disabled" && got != "unknown" {
			t.Fatalf("runtimeEnabledState() = %q", got)
		}
		if got := runtimeContractProbeState(runtime); strings.TrimSpace(probe) != "" && got != strings.TrimSpace(probe) {
			t.Fatalf("runtimeContractProbeState() = %q, want trimmed probe", got)
		}
	})
}

type sourceCoverageHealthSource struct{}

type secondaryCoverageHealthSource struct{}

func (sourceCoverageHealthSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "okta", Name: "Okta"}
}

func (sourceCoverageHealthSource) CoverageContract() sourcecdk.CoverageContract {
	return sourcecdk.CoverageContract{
		SourceID:        "okta",
		OwnerDomain:     "identity",
		AuthorityDomain: "okta",
		Dimensions: []sourcecdk.CoverageDimension{
			{ID: "users", Type: "entity_family", Title: "Users", Families: []string{"user"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "applications", Type: "entity_family", Title: "Applications", Families: []string{"application"}, Support: sourcecdk.CoverageSupportSupported, HighValue: true},
			{ID: "remediation", Type: "remediation_state", Title: "Remediation lifecycle", Support: sourcecdk.CoverageSupportUnsupported, HighValue: true},
		},
	}
}

func (sourceCoverageHealthSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (sourceCoverageHealthSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (sourceCoverageHealthSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}

func (secondaryCoverageHealthSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "secondary", Name: "Secondary"}
}

func (secondaryCoverageHealthSource) CoverageContract() sourcecdk.CoverageContract {
	return sourcecdk.CoverageContract{
		SourceID:        "secondary",
		OwnerDomain:     "inventory",
		AuthorityDomain: "secondary",
		Dimensions: []sourcecdk.CoverageDimension{
			{ID: "assets", Type: "entity_family", Title: "Assets", Families: []string{"asset"}, Support: sourcecdk.CoverageSupportSupported},
		},
	}
}

func (secondaryCoverageHealthSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (secondaryCoverageHealthSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (secondaryCoverageHealthSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return sourcecdk.Pull{}, nil
}

func FuzzSourceRuntimeHealthSummaries(f *testing.F) {
	f.Add("okta", "healthy", "passing", "completed", false)
	f.Add("", "failing", "failure", "failed", true)
	f.Add("aws", "stale", "unknown", "running", false)
	f.Fuzz(func(t *testing.T, sourceID string, status string, probe string, graphStatus string, cursorPending bool) {
		graphLag := int64(7200)
		staleAfter := int64(3600)
		records := []sourceRuntimeHealthRecord{{
			SourceID:           sourceID,
			Status:             status,
			ContractProbeState: probe,
			CursorPending:      cursorPending,
			LatestGraphRun:     &sourceRuntimeHealthGraphRun{Status: graphStatus},
			GraphLagSeconds:    &graphLag,
			StaleAfterSeconds:  &staleAfter,
		}}
		summaries := sourceRuntimeHealthSummaries(records)
		if len(summaries) != 1 {
			t.Fatalf("summary count = %d, want 1", len(summaries))
		}
		summary := summaries[0]
		if summary.Total != 1 {
			t.Fatalf("summary total = %d, want 1", summary.Total)
		}
		if summary.Healthy+summary.Stale+summary.Failing+summary.Unknown != summary.Total {
			t.Fatalf("status buckets do not partition total: %+v", summary)
		}
		if summary.ContractProbePassing+summary.ContractProbeFailure+summary.ContractProbeUnknown+summary.ContractProbeNotConfigured != summary.Total {
			t.Fatalf("contract buckets do not partition total: %+v", summary)
		}
		if summary.GraphCurrent+summary.GraphBehind+summary.GraphRunning+summary.GraphFailed+summary.GraphNotObserved != summary.Total {
			t.Fatalf("graph buckets do not partition total: %+v", summary)
		}
		if strings.TrimSpace(sourceID) == "" && summary.SourceID != "unknown" {
			t.Fatalf("empty source summary source_id = %q, want unknown", summary.SourceID)
		}
	})
}

func int64Ptr(value int64) *int64 {
	return &value
}

func assertOptionalInt64(t *testing.T, label string, got *int64, want *int64) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("%s = %v, want nil", label, *got)
		}
		return
	}
	if got == nil || *got != *want {
		t.Fatalf("%s = %v, want %v", label, got, *want)
	}
}
