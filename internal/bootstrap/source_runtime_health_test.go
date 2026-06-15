package bootstrap

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcecoverage"
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

	record, err := (&App{}).sourceRuntimeHealthRecord(context.Background(), runtime, now)
	if err != nil {
		t.Fatalf("sourceRuntimeHealthRecord() error = %v", err)
	}
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
			record, err := (&App{}).sourceRuntimeHealthRecord(context.Background(), &cerebrov1.SourceRuntime{
				Id:           "runtime-1",
				SourceId:     "generated",
				TenantId:     "tenant",
				LastSyncedAt: timestamppb.New(now),
				Config:       test.config,
			}, now)
			if err != nil {
				t.Fatalf("sourceRuntimeHealthRecord() error = %v", err)
			}
			assertOptionalInt64(t, "ExpectedCadenceSeconds", record.ExpectedCadenceSeconds, test.wantCadence)
			assertOptionalInt64(t, "StaleAfterSeconds", record.StaleAfterSeconds, test.wantStale)
			if record.ScheduleContextConfigured != test.wantConfigured {
				t.Fatalf("ScheduleContextConfigured = %v, want %v", record.ScheduleContextConfigured, test.wantConfigured)
			}
		})
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
			LatestGraphRun:     sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "completed"}),
			GraphLagSeconds:    &graphLag,
			StaleAfterSeconds:  &staleAfter,
		},
		{
			RuntimeID:          "runtime-b",
			SourceID:           "okta",
			Status:             "failing",
			CursorPending:      true,
			ContractProbeState: "failure",
			LatestGraphRun:     sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "failed"}),
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
				LatestGraphRun:    sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "completed"}),
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
				LatestGraphRun:      sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "completed"}),
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
				LatestGraphRun: sourceRuntimeGraphRunHealth(graphstore.IngestRun{Status: "running"}),
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

func TestListSourceRuntimeHealthToleratesUnavailableStore(t *testing.T) {
	app := &App{}
	req := httptest.NewRequest("GET", "/source-runtimes/health?source_id=aws", nil)

	response, err := app.listSourceRuntimeHealth(req)
	if err != nil {
		t.Fatalf("listSourceRuntimeHealth() error = %v", err)
	}
	if strings.TrimSpace(response.GeneratedAt) == "" {
		t.Fatalf("GeneratedAt is empty")
	}
	if len(response.Runtimes) != 0 {
		t.Fatalf("Runtimes = %#v, want empty", response.Runtimes)
	}
	if len(response.SourceSummaries) != 0 {
		t.Fatalf("SourceSummaries = %#v, want empty", response.SourceSummaries)
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
