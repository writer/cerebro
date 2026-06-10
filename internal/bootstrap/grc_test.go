package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRCDashboardAggregatesOperatorView(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:           "writer-okta-audit",
				SourceId:     "okta",
				TenantId:     "writer",
				LastSyncedAt: timestamppb.New(now.Add(-30 * time.Minute)),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-30 * time.Minute))},
			},
			"writer-github": {
				Id:           "writer-github",
				SourceId:     "github",
				TenantId:     "writer",
				LastSyncedAt: timestamppb.New(now.Add(-30 * time.Minute)),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-48 * time.Hour))},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-high": {
				ID:           "finding-high",
				TenantID:     "writer",
				RuntimeID:    "writer-okta-audit",
				RuleID:       "identity-api-token-or-oauth-app-created",
				Title:        "Identity API token created",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:writer:okta_user:00u1"},
				ControlRefs: []ports.FindingControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.1",
				}},
				FindingWorkflow: ports.FindingWorkflow{DueAt: now.Add(-24 * time.Hour)},
				LastObservedAt:  now,
			},
			"finding-critical": {
				ID:             "finding-critical",
				TenantID:       "writer",
				RuntimeID:      "writer-github",
				RuleID:         "github-dependabot-critical",
				Title:          "Critical dependency exposure",
				Severity:       "CRITICAL",
				Status:         "open",
				ResourceURNs:   []string{"urn:cerebro:writer:github_repository:writer/app"},
				LastObservedAt: now.Add(-time.Hour),
			},
			"finding-resolved": {
				ID:             "finding-resolved",
				TenantID:       "writer",
				RuntimeID:      "writer-okta-audit",
				Title:          "Resolved finding",
				Severity:       "LOW",
				Status:         "resolved",
				LastObservedAt: now.Add(-2 * time.Hour),
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {
				Id:            "evidence-1",
				RuntimeId:     "writer-okta-audit",
				RuleId:        "identity-api-token-or-oauth-app-created",
				FindingId:     "finding-high",
				RunId:         "run-1",
				EventIds:      []string{"event-1"},
				GraphRootUrns: []string{"urn:cerebro:writer:okta_user:00u1"},
				CreatedAt:     timestamppb.New(now),
			},
			"evidence-resolved": {
				Id:        "evidence-resolved",
				RuntimeId: "writer-" + "okta-audit",
				FindingId: "finding-resolved",
				RunId:     "run-1",
				CreatedAt: timestamppb.New(now.Add(time.Hour)),
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcDashboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/dashboard: %v", err)
	}
	if payload.Summary.OpenFindings != 2 {
		t.Fatalf("open findings = %d, want 2", payload.Summary.OpenFindings)
	}
	if payload.Summary.CriticalFindings != 1 || payload.Summary.HighFindings != 1 {
		t.Fatalf("severity counts = critical %d high %d, want 1/1", payload.Summary.CriticalFindings, payload.Summary.HighFindings)
	}
	if payload.Summary.OverdueFindings != 1 {
		t.Fatalf("overdue findings = %d, want 1", payload.Summary.OverdueFindings)
	}
	if payload.Summary.ControlsFailing != 2 {
		t.Fatalf("failing controls = %d, want 2", payload.Summary.ControlsFailing)
	}
	if len(payload.Findings) != 2 {
		t.Fatalf("findings len = %d, want 2", len(payload.Findings))
	}
	if payload.Findings[0].Severity != "CRITICAL" {
		t.Fatalf("first finding severity = %q, want CRITICAL", payload.Findings[0].Severity)
	}
	if payload.Findings[1].EvidenceCount != 1 {
		t.Fatalf("evidence count = %d, want 1", payload.Findings[1].EvidenceCount)
	}
	if len(payload.Evidence) != 1 || payload.Evidence[0].FindingID != "finding-high" {
		t.Fatalf("dashboard evidence = %#v, want only evidence for visible findings", payload.Evidence)
	}
	if len(payload.Connectors) != 2 {
		t.Fatalf("connectors len = %d, want 2", len(payload.Connectors))
	}
	connectors := map[string]grcConnector{}
	for _, connector := range payload.Connectors {
		connectors[connector.RuntimeID] = connector
	}
	githubConnector := connectors["writer-github"]
	if githubConnector.Status != "healthy" || githubConnector.Freshness == "stale" {
		t.Fatalf("github connector sync health = %q/%q, want healthy non-stale despite old checkpoint", githubConnector.Status, githubConnector.Freshness)
	}
	if githubConnector.WatermarkFreshness != "stale" || githubConnector.WatermarkLagSeconds == nil {
		t.Fatalf("github connector watermark = %q/%v, want stale lag surfaced separately", githubConnector.WatermarkFreshness, githubConnector.WatermarkLagSeconds)
	}
	if got := len(store.findingListRequest.RuntimeIDs); got != 2 {
		t.Fatalf("batched finding runtime count = %d, want 2", got)
	}
	if !store.findingListRequest.PriorityOrder {
		t.Fatalf("GRC dashboard did not request priority finding ordering")
	}
	if got := len(store.findingEvidenceListRequest.RuntimeIDs); got != 2 {
		t.Fatalf("batched evidence runtime count = %d, want 2", got)
	}
	if got := store.findingEvidenceListRequest.FindingIDs; len(got) != 2 || got[0] != "finding-critical" || got[1] != "finding-high" {
		t.Fatalf("batched evidence finding ids = %#v, want visible finding ids", got)
	}
	if !store.findingEvidenceListRequest.CreatedOrder {
		t.Fatalf("GRC dashboard did not request created-at evidence ordering")
	}
	if payload.Summary.StaleConnectors != 0 {
		t.Fatalf("stale connectors = %d, want 0", payload.Summary.StaleConnectors)
	}
	if payload.Connectors[0].CheckpointWatermark == nil && payload.Connectors[1].CheckpointWatermark == nil {
		t.Fatalf("connector checkpoint watermarks were not surfaced")
	}
}

func TestGRCDashboardEmitsLatencyTelemetry(t *testing.T) {
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-grc": {
				Id:       "writer-grc",
				SourceId: "grc",
				TenantId: "writer",
			},
		},
		findings:        map[string]*ports.FindingRecord{},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=writer&limit=1")
		if err != nil {
			t.Fatalf("GET /grc/dashboard error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})

	payload := decodeBootstrapTelemetryPayload(t, stderr)
	for key, want := range map[string]any{
		"kind":           "span_end",
		"name":           "grc.dashboard",
		"status":         "completed",
		"route":          "/grc/dashboard",
		"dashboard":      "grc",
		"status_code":    float64(http.StatusOK),
		"limit":          float64(1),
		"preview_limit":  float64(1),
		"runtime_count":  float64(1),
		"finding_count":  float64(0),
		"evidence_count": float64(0),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
}

func TestGRCDashboardTelemetryRecordsHTTPErrorStatus(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: &stubRuntimeStore{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	stderr := captureBootstrapStderr(t, func() {
		resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=writer&limit=501")
		if err != nil {
			t.Fatalf("GET /grc/dashboard error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
	})

	payload := decodeBootstrapTelemetryPayload(t, stderr)
	if got := payload["status"]; got != "failed" {
		t.Fatalf("telemetry status = %#v, want failed; payload=%#v", got, payload)
	}
	if got := payload["status_code"]; got != float64(http.StatusBadRequest) {
		t.Fatalf("telemetry status_code = %#v, want %d; payload=%#v", got, http.StatusBadRequest, payload)
	}
	if got := payload["error_kind"]; got != "invalid_request" {
		t.Fatalf("telemetry error_kind = %#v, want invalid_request; payload=%#v", got, payload)
	}
	if strings.Contains(stderr, "limit must be <= 500") {
		t.Fatalf("GRC dashboard telemetry leaked raw error: %s", stderr)
	}
}

func TestGRCConnectorHealthUsesLastSyncedAtSeparatelyFromWatermark(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimes := []*cerebrov1.SourceRuntime{
		{
			Id:           "historical-backfill",
			SourceId:     "okta",
			TenantId:     "tenant",
			LastSyncedAt: timestamppb.New(now.Add(-10 * time.Minute)),
			Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-90 * 24 * time.Hour))},
		},
		{
			Id:           "stalled-sync",
			SourceId:     "github",
			TenantId:     "tenant",
			LastSyncedAt: timestamppb.New(now.Add(-48 * time.Hour)),
			Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-10 * time.Minute))},
		},
	}

	connectors := grcConnectorItems(runtimes)
	byID := map[string]grcConnector{}
	for _, connector := range connectors {
		byID[connector.RuntimeID] = connector
	}

	historical := byID["historical-backfill"]
	if historical.Status != "healthy" || historical.Freshness != "fresh" {
		t.Fatalf("historical sync health = %q/%q, want healthy/fresh", historical.Status, historical.Freshness)
	}
	if historical.WatermarkFreshness != "stale" || historical.WatermarkLagSeconds == nil {
		t.Fatalf("historical watermark health = %q/%v, want stale lag surfaced", historical.WatermarkFreshness, historical.WatermarkLagSeconds)
	}

	stalled := byID["stalled-sync"]
	if stalled.Status != "stale" || stalled.Freshness != "stale" {
		t.Fatalf("stalled sync health = %q/%q, want stale/stale", stalled.Status, stalled.Freshness)
	}
	if stalled.WatermarkFreshness != "fresh" {
		t.Fatalf("stalled watermark freshness = %q, want fresh", stalled.WatermarkFreshness)
	}

	summary := grcBuildSummary(nil, nil, nil, runtimes, nil, nil)
	if summary.StaleConnectors != 1 {
		t.Fatalf("summary stale connectors = %d, want 1", summary.StaleConnectors)
	}
}

func TestGRCDashboardSummaryUsesUnpaginatedAggregates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "tenant-okta-audit"
	secondRuntimeID := "tenant-github-audit"
	tenantID := "tenant"
	controlRefs := []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
			secondRuntimeID: {
				Id:           secondRuntimeID,
				SourceId:     "github",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    controlRefs,
				LastObservedAt: now.Add(-time.Minute),
			},
			"finding-2": {
				ID:             "finding-2",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 2",
				Severity:       "CRITICAL",
				Status:         "open",
				ControlRefs:    controlRefs,
				LastObservedAt: now.Add(-2 * time.Minute),
			},
			"finding-3": {
				ID:             "finding-3",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 3",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    controlRefs,
				LastObservedAt: now.Add(-3 * time.Minute),
			},
			"finding-4": {
				ID:             "finding-4",
				TenantID:       tenantID,
				RuntimeID:      secondRuntimeID,
				Title:          "Finding 4",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    controlRefs,
				LastObservedAt: now.Add(-4 * time.Minute),
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-2", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: secondRuntimeID, FindingId: "finding-4", CreatedAt: timestamppb.New(now)},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=" + tenantID + "&limit=1")
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcDashboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/dashboard: %v", err)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("findings len = %d, want paginated row count 1", len(payload.Findings))
	}
	if payload.Summary.OpenFindings != 4 {
		t.Fatalf("summary open findings = %d, want unpaginated total 4", payload.Summary.OpenFindings)
	}
	if payload.Summary.CriticalFindings != 1 || payload.Summary.HighFindings != 3 {
		t.Fatalf("summary severities = critical %d high %d, want 1/3", payload.Summary.CriticalFindings, payload.Summary.HighFindings)
	}
	if payload.Summary.ControlsFailing != 1 {
		t.Fatalf("summary failing controls = %d, want deduplicated total 1", payload.Summary.ControlsFailing)
	}
	if payload.Summary.EvidenceItems != 1 {
		t.Fatalf("summary evidence items = %d, want visible finding evidence total 1", payload.Summary.EvidenceItems)
	}
}

func TestGRCDashboardCapsPreviewWorkToRenderedLimit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "tenant-okta-audit"
	tenantID := "tenant"
	store := &stubGRCAggregateStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings:        map[string]*ports.FindingRecord{},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{},
	}}
	for i := range 40 {
		id := fmt.Sprintf("finding-%02d", i)
		store.findings[id] = &ports.FindingRecord{
			ID:             id,
			TenantID:       tenantID,
			RuntimeID:      runtimeID,
			Title:          fmt.Sprintf("Finding %02d", i),
			Severity:       "HIGH",
			Status:         "open",
			ControlRefs:    []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			LastObservedAt: now.Add(-time.Duration(i) * time.Minute),
		}
		store.findingEvidence["evidence-"+id] = &cerebrov1.FindingEvidence{
			Id:        "evidence-" + id,
			RuntimeId: runtimeID,
			FindingId: id,
			CreatedAt: timestamppb.New(now.Add(-time.Duration(i) * time.Minute)),
		}
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=" + tenantID + "&limit=500")
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcDashboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/dashboard: %v", err)
	}
	if len(payload.Findings) != 25 {
		t.Fatalf("findings len = %d, want capped preview 25", len(payload.Findings))
	}
	if len(payload.Evidence) != 25 {
		t.Fatalf("evidence len = %d, want capped preview 25", len(payload.Evidence))
	}
	if store.findingListRequest.Limit != grcDashboardPreviewLimit {
		t.Fatalf("finding list limit = %d, want dashboard preview limit %d", store.findingListRequest.Limit, grcDashboardPreviewLimit)
	}
	if store.findingEvidenceListRequest.Limit != grcDashboardPreviewLimit {
		t.Fatalf("evidence list limit = %d, want dashboard preview limit %d", store.findingEvidenceListRequest.Limit, grcDashboardPreviewLimit)
	}
	if got := len(store.findingEvidenceListRequest.FindingIDs); got != int(grcDashboardPreviewLimit) {
		t.Fatalf("evidence finding id count = %d, want dashboard preview limit %d", got, grcDashboardPreviewLimit)
	}
	if payload.Summary.OpenFindings != 40 {
		t.Fatalf("summary open findings = %d, want unpaginated total 40", payload.Summary.OpenFindings)
	}
	if store.aggregateCalls != 1 {
		t.Fatalf("aggregate calls = %d, want 1", store.aggregateCalls)
	}
}

func TestGRCDashboardUsesHeaderOnlyEvidenceLister(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "tenant-okta-audit"
	tenantID := "tenant"
	store := &stubGRCEvidenceHeaderStore{stubGRCAggregateStore: &stubGRCAggregateStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
		},
	}}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=" + tenantID)
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if store.headerEvidenceCalls != 1 {
		t.Fatalf("header evidence calls = %d, want 1", store.headerEvidenceCalls)
	}
	if store.fullEvidenceCalls != 0 {
		t.Fatalf("full evidence calls = %d, want 0", store.fullEvidenceCalls)
	}
}

func TestGRCDashboardUsesHeaderOnlyFindingLister(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "runtime-alpha"
	tenantID := "tenant"
	store := &stubGRCFindingHeaderStore{stubGRCAggregateStore: &stubGRCAggregateStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
		},
	}}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=" + tenantID)
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if store.headerFindingCalls != 1 {
		t.Fatalf("header finding calls = %d, want 1", store.headerFindingCalls)
	}
	if store.fullFindingCalls != 0 {
		t.Fatalf("full finding calls = %d, want 0", store.fullFindingCalls)
	}
}

func TestGRCFindingsUsesGroupedEvidenceCounts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "runtime-alpha"
	tenantID := "tenant"
	store := &stubGRCEvidenceCountStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now.Add(-time.Minute))},
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/findings?tenant_id=" + tenantID + "&limit=1")
	if err != nil {
		t.Fatalf("GET /grc/findings error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/findings status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Findings []grcFindingItem `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/findings: %v", err)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].EvidenceCount != 2 {
		t.Fatalf("findings = %+v, want grouped evidence count 2", payload.Findings)
	}
	if store.groupedCountCalls != 1 {
		t.Fatalf("grouped count calls = %d, want 1", store.groupedCountCalls)
	}
	if store.fullEvidenceCalls != 0 {
		t.Fatalf("full evidence calls = %d, want 0", store.fullEvidenceCalls)
	}
	if store.groupedCountRequest.Limit != 0 {
		t.Fatalf("grouped count limit = %d, want unpaginated 0", store.groupedCountRequest.Limit)
	}
	if len(store.groupedCountRequest.FindingIDs) != 1 || store.groupedCountRequest.FindingIDs[0] != "finding-1" {
		t.Fatalf("grouped count finding ids = %#v, want finding-1", store.groupedCountRequest.FindingIDs)
	}
}

func TestGRCControlsUsesGroupedEvidenceCounts(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "runtime-alpha"
	tenantID := "tenant"
	store := &stubGRCEvidenceCountStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now.Add(-time.Minute))},
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/controls?tenant_id=" + tenantID + "&limit=1")
	if err != nil {
		t.Fatalf("GET /grc/controls error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/controls status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Controls []grcControlItem `json:"controls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/controls: %v", err)
	}
	if len(payload.Controls) != 1 || payload.Controls[0].EvidenceItems != 2 {
		t.Fatalf("controls = %+v, want grouped evidence count 2", payload.Controls)
	}
	if store.groupedCountCalls != 1 {
		t.Fatalf("grouped count calls = %d, want 1", store.groupedCountCalls)
	}
	if store.fullEvidenceCalls != 0 {
		t.Fatalf("full evidence calls = %d, want 0", store.fullEvidenceCalls)
	}
	if store.groupedCountRequest.Limit != 0 {
		t.Fatalf("grouped count limit = %d, want unpaginated 0", store.groupedCountRequest.Limit)
	}
	if len(store.groupedCountRequest.FindingIDs) != 1 || store.groupedCountRequest.FindingIDs[0] != "finding-1" {
		t.Fatalf("grouped count finding ids = %#v, want finding-1", store.groupedCountRequest.FindingIDs)
	}
}

func TestGRCDashboardUsesPurposeBuiltAggregateStore(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "tenant-okta-audit"
	tenantID := "tenant"
	store := &stubGRCAggregateStore{stubRuntimeStore: &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:           runtimeID,
				SourceId:     "okta",
				TenantId:     tenantID,
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now.Add(-time.Minute))},
		},
	}}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=" + tenantID + "&limit=1")
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcDashboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/dashboard: %v", err)
	}
	if store.aggregateCalls != 1 {
		t.Fatalf("aggregate calls = %d, want 1", store.aggregateCalls)
	}
	if payload.Summary.OpenFindings != 1 || payload.Summary.EvidenceItems != 2 {
		t.Fatalf("summary = %+v, want aggregate finding/evidence counts", payload.Summary)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].EvidenceCount != 2 {
		t.Fatalf("findings = %+v, want aggregate evidence count 2", payload.Findings)
	}
	if len(payload.Controls) != 1 || payload.Controls[0].EvidenceItems != 2 {
		t.Fatalf("controls = %+v, want aggregate evidence count 2", payload.Controls)
	}
}

func TestGRCEntityImpactAndAuditPacket(t *testing.T) {
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	rootURN := "urn:cerebro:writer:okta_user:00u1"
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-high": {
				ID:             "finding-high",
				TenantID:       "writer",
				RuntimeID:      "writer-okta-audit",
				Title:          "Identity API token created",
				Severity:       "HIGH",
				Status:         "open",
				ResourceURNs:   []string{rootURN},
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {
				Id:            "evidence-1",
				RuntimeId:     "writer-okta-audit",
				FindingId:     "finding-high",
				EventIds:      []string{"event-1"},
				GraphRootUrns: []string{rootURN},
				CreatedAt:     timestamppb.New(now),
			},
		},
	}
	graphStore := &stubGraphStore{
		neighborhood: &ports.EntityNeighborhood{
			Root: &ports.NeighborhoodNode{
				URN:        rootURN,
				EntityType: "okta.user",
				Label:      "user@example.com",
			},
			Neighbors: []*ports.NeighborhoodNode{{
				URN:        "urn:cerebro:writer:finding:finding-high",
				EntityType: "finding",
				Label:      "Identity API token created",
			}},
			Relations: []*ports.NeighborhoodRelation{{
				FromURN:  rootURN,
				Relation: "has_finding",
				ToURN:    "urn:cerebro:writer:finding:finding-high",
			}},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, GraphStore: graphStore}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	impactResp, err := server.Client().Get(server.URL + "/grc/entities/" + url.PathEscape(rootURN) + "/impact?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /grc/entities impact error = %v", err)
	}
	defer func() { _ = impactResp.Body.Close() }()
	if impactResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/entities impact status = %d, want %d", impactResp.StatusCode, http.StatusOK)
	}
	var impact grcEntityImpactResponse
	if err := json.NewDecoder(impactResp.Body).Decode(&impact); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	if impact.Graph == nil || impact.Graph.Root == nil || impact.Graph.Root.URN != rootURN {
		t.Fatalf("impact graph root = %#v, want %q", impact.Graph, rootURN)
	}
	if len(impact.Findings) != 1 || impact.Findings[0].ID != "finding-high" {
		t.Fatalf("impact findings = %#v, want finding-high", impact.Findings)
	}

	packetResp, err := server.Client().Get(server.URL + "/grc/audit-packets/finding-high")
	if err != nil {
		t.Fatalf("GET /grc/audit-packets error = %v", err)
	}
	defer func() { _ = packetResp.Body.Close() }()
	if packetResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/audit-packets status = %d, want %d", packetResp.StatusCode, http.StatusOK)
	}
	var packet grcAuditPacketResponse
	if err := json.NewDecoder(packetResp.Body).Decode(&packet); err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	if packet.Finding.ID != "finding-high" {
		t.Fatalf("packet finding = %q, want finding-high", packet.Finding.ID)
	}
	if len(packet.Evidence) != 1 {
		t.Fatalf("packet evidence len = %d, want 1", len(packet.Evidence))
	}
	if packet.Graph == nil || packet.Graph.Root == nil {
		t.Fatalf("packet graph missing")
	}
	if packet.RecommendedAction == "" {
		t.Fatalf("packet recommended action is empty")
	}

	briefResp, err := server.Client().Get(server.URL + "/findings/finding-high/investigation-brief?limit=10")
	if err != nil {
		t.Fatalf("GET /findings investigation-brief error = %v", err)
	}
	defer func() { _ = briefResp.Body.Close() }()
	if briefResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /findings investigation-brief status = %d, want %d", briefResp.StatusCode, http.StatusOK)
	}
	var brief investigationBriefResponse
	if err := json.NewDecoder(briefResp.Body).Decode(&brief); err != nil {
		t.Fatalf("decode investigation brief: %v", err)
	}
	if brief.ID != "finding-high" || brief.Kind != "finding" {
		t.Fatalf("brief identity = %#v, want finding-high finding", brief)
	}
	if brief.Trust.GraphStatus != "available" || brief.Trust.EvidenceCount != 1 {
		t.Fatalf("brief trust = %#v", brief.Trust)
	}
	if !strings.Contains(brief.Markdown, "Investigation Brief") {
		t.Fatalf("brief markdown = %q", brief.Markdown)
	}
	if len(brief.NextPivots) < 3 {
		t.Fatalf("brief pivots = %#v, want operator pivots", brief.NextPivots)
	}
}

type stubGRCAggregateStore struct {
	*stubRuntimeStore
	aggregateCalls int
}

func (s *stubGRCAggregateStore) SummarizeGRCDashboard(ctx context.Context, request ports.GRCDashboardAggregateRequest) (ports.GRCDashboardAggregate, error) {
	s.aggregateCalls++
	summary, err := s.SummarizeFindings(ctx, request.FindingRequest)
	if err != nil {
		return ports.GRCDashboardAggregate{}, err
	}
	count, err := s.CountFindingEvidence(ctx, request.EvidenceRequest)
	if err != nil {
		return ports.GRCDashboardAggregate{}, err
	}
	countsByFindingID := map[string]int{}
	for _, evidence := range s.findingEvidence {
		if evidence == nil {
			continue
		}
		for _, findingID := range request.EvidenceRequest.FindingIDs {
			if evidence.GetFindingId() == findingID {
				countsByFindingID[findingID]++
			}
		}
	}
	return ports.GRCDashboardAggregate{FindingSummary: summary, EvidenceCount: count, EvidenceCountsByFindingID: countsByFindingID}, nil
}

type stubGRCEvidenceHeaderStore struct {
	*stubGRCAggregateStore
	headerEvidenceCalls int
	fullEvidenceCalls   int
}

func (s *stubGRCEvidenceHeaderStore) ListGRCFindingEvidence(ctx context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	s.headerEvidenceCalls++
	return s.stubRuntimeStore.ListFindingEvidence(ctx, request)
}

func (s *stubGRCEvidenceHeaderStore) ListFindingEvidence(ctx context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	s.fullEvidenceCalls++
	return s.stubRuntimeStore.ListFindingEvidence(ctx, request)
}

type stubGRCFindingHeaderStore struct {
	*stubGRCAggregateStore
	headerFindingCalls int
	fullFindingCalls   int
}

func (s *stubGRCFindingHeaderStore) ListGRCFindings(ctx context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.headerFindingCalls++
	return s.stubRuntimeStore.ListFindings(ctx, request)
}

func (s *stubGRCFindingHeaderStore) ListFindings(ctx context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.fullFindingCalls++
	return s.stubRuntimeStore.ListFindings(ctx, request)
}

type stubGRCEvidenceCountStore struct {
	*stubRuntimeStore
	groupedCountCalls   int
	groupedCountRequest ports.ListFindingEvidenceRequest
	fullEvidenceCalls   int
}

func (s *stubGRCEvidenceCountStore) CountGRCFindingEvidenceByFindingID(_ context.Context, request ports.ListFindingEvidenceRequest) (map[string]int, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.groupedCountCalls++
	s.groupedCountRequest = request
	counts := map[string]int{}
	for _, record := range s.findingEvidence {
		if record != nil && findingEvidenceMatches(request, record) {
			counts[record.GetFindingId()]++
		}
	}
	return counts, nil
}

func (s *stubGRCEvidenceCountStore) ListFindingEvidence(ctx context.Context, request ports.ListFindingEvidenceRequest) ([]*cerebrov1.FindingEvidence, error) {
	s.fullEvidenceCalls++
	return s.stubRuntimeStore.ListFindingEvidence(ctx, request)
}
