package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcaudit"
	"github.com/writer/cerebro/internal/grcauditpacket"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcecoverage"
	grcuploadhttp "github.com/writer/cerebro/internal/sourcehttp/grcupload"
	questionnairehttp "github.com/writer/cerebro/internal/sourcehttp/questionnaire"
	"github.com/writer/cerebro/internal/workflowevents"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestJoinGRCErrorsPreservesAllFailures(t *testing.T) {
	errA := fmt.Errorf("%w: evidence", graphquery.ErrRuntimeUnavailable)
	errB := fmt.Errorf("%w: aggregate", ports.ErrFindingNotFound)
	errs := make(chan error, 2)
	errs <- errA
	errs <- errB
	close(errs)

	err := joinGRCErrors(errs)
	if !errors.Is(err, graphquery.ErrRuntimeUnavailable) {
		t.Fatalf("joined error = %v, want runtime unavailable", err)
	}
	if !errors.Is(err, ports.ErrFindingNotFound) {
		t.Fatalf("joined error = %v, want finding not found", err)
	}
}

func TestGRCQuestionnaireRuntimeUnavailableMapsToServiceUnavailable(t *testing.T) {
	if got := grcHTTPStatusCode(questionnairehttp.ErrRuntimeUnavailable); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

func TestGRCSourceCoverageEvaluatorUnavailableMapsToServiceUnavailable(t *testing.T) {
	if got := grcHTTPStatusCode(sourcecoverage.ErrEvaluatorUnavailable); got != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", got, http.StatusServiceUnavailable)
	}
}

func TestGRCScopeDoesNotReadQuestionnaireVendorURN(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/grc/control-packets?tenant_id=writer&vendor_urn=urn:cerebro:writer:vendor:okta", nil)
	scope, err := grcScopeFromRequest(req)
	if err != nil {
		t.Fatalf("grcScopeFromRequest error = %v", err)
	}
	if scope.VendorURN != "" {
		t.Fatalf("scope vendor = %q, want empty shared GRC scope", scope.VendorURN)
	}

	questionnaireScope, err := grcQuestionnaireScopeFromRequest(req)
	if err != nil {
		t.Fatalf("grcQuestionnaireScopeFromRequest error = %v", err)
	}
	if questionnaireScope.VendorURN != "urn:cerebro:writer:vendor:okta" {
		t.Fatalf("questionnaire vendor = %q, want vendor urn", questionnaireScope.VendorURN)
	}
}

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
				NextCursor:   &cerebrov1.SourceCursor{Opaque: "next-page"},
				Config: map[string]string{
					"stale_after_seconds": "60",
				},
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
				ResourceURNs:   []string{"urn:cerebro:writer:github_code_repository:writer/app"},
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
	if len(payload.SourceSummaries) != 2 {
		t.Fatalf("source summaries len = %d, want 2", len(payload.SourceSummaries))
	}
	if len(payload.ProductAreas) == 0 {
		t.Fatalf("product areas = 0, want backend product area taxonomy")
	}
	if payload.ProductAreas[0].ID != "compliance" || payload.ProductAreas[0].Status == "" {
		t.Fatalf("first product area = %+v, want compliance area with status", payload.ProductAreas[0])
	}
	summaries := map[string]sourceRuntimeHealthSummary{}
	for _, summary := range payload.SourceSummaries {
		summaries[summary.SourceID] = summary
	}
	githubSummary := summaries["github"]
	if githubSummary.Total != 1 || githubSummary.Stale != 1 || githubSummary.CursorPending != 1 || githubSummary.ContractProbeNotConfigured != 1 || githubSummary.GraphNotObserved != 1 {
		t.Fatalf("github source summary = %+v, want stale cursor-pending contract-not-configured graph-not-observed rollup", githubSummary)
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

func TestGRCUploadReplayProjectsUploadEvents(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	appendLog := &recordingAppendLog{replayEvents: []*cerebrov1.EventEnvelope{{
		Id:         "event-policy",
		SourceId:   "grc",
		TenantId:   "writer",
		Kind:       "grc.policy",
		OccurredAt: timestamppb.New(now),
		Attributes: map[string]string{
			"upload_id":     "upload-1",
			"provider":      "cerebro_upload",
			"source_system": "cerebro_upload",
			"policy_id":     "access-policy",
			"name":          "Access Policy",
			"policy_name":   "Access Policy",
			"status":        "uploaded",
		},
	}}}
	state := &stubRuntimeStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{
		AppendLog:  appendLog,
		StateStore: state,
	}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/grc/policy-lifecycle/uploads/upload-1/replay?tenant_id=writer", nil)
	if err != nil {
		t.Fatalf("new replay request: %v", err)
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST upload replay error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST upload replay status = %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	var payload grcuploadhttp.ReplayResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if payload.Status != "projected" || payload.EventsFound != 1 || payload.EventsProjected != 1 {
		t.Fatalf("replay response = %+v, want one projected event", payload)
	}
	if len(appendLog.replayRequests) != 1 {
		t.Fatalf("replay requests = %d, want 1", len(appendLog.replayRequests))
	}
	replayRequest := appendLog.replayRequests[0]
	if replayRequest.TenantID != "writer" || replayRequest.AttributeEquals["upload_id"] != "upload-1" {
		t.Fatalf("replay request = %+v, want tenant writer upload filter", replayRequest)
	}
	if len(state.entities) == 0 {
		t.Fatalf("projected entities = 0, want policy entity")
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

	stderr := captureBootstrapStderr(t, func() {
		defer server.Close()
		resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=writer&limit=1")
		if err != nil {
			t.Fatalf("GET /grc/dashboard error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("read /grc/dashboard body: %v", err)
		}
	})

	payload := decodeBootstrapTelemetryPayload(t, stderr, "grc.dashboard")
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

	stderr := captureBootstrapStderr(t, func() {
		defer server.Close()
		resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=writer&limit=501")
		if err != nil {
			t.Fatalf("GET /grc/dashboard error = %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("read /grc/dashboard body: %v", err)
		}
	})

	payload := decodeBootstrapTelemetryPayload(t, stderr, "grc.dashboard")
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
				Config:       map[string]string{"family": "user"},
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
	registry, err := sourcecdk.NewRegistry(sourceCoverageHealthSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, registry)
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
	if payload.Summary.EvidenceItems != 40 {
		t.Fatalf("summary evidence items = %d, want unpaginated total 40 (not the %d-row preview)", payload.Summary.EvidenceItems, grcDashboardPreviewLimit)
	}
	if store.aggregateCalls != 1 {
		t.Fatalf("aggregate calls = %d, want 1", store.aggregateCalls)
	}
	if got := len(payload.CoverageBlindSpots); got != 2 {
		t.Fatalf("coverage blind spots = %d, want 2: %#v", got, payload.CoverageBlindSpots)
	}
	if got := len(payload.CoverageSummaries); got != 1 {
		t.Fatalf("coverage summaries = %d, want 1: %#v", got, payload.CoverageSummaries)
	}
	summary := payload.CoverageSummaries[0]
	if summary.Total != 3 || summary.Healthy != 1 || summary.BlindSpots != 2 {
		t.Fatalf("coverage summary = %+v, want total=3 healthy=1 blind_spots=2", summary)
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
			"finding-2": {
				ID:             "finding-2",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Finding 2",
				Severity:       "LOW",
				Status:         "open",
				LastObservedAt: now.Add(-time.Hour),
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
		Meta     struct {
			Limit     uint32 `json:"limit"`
			Returned  int    `json:"returned"`
			Truncated bool   `json:"truncated"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/findings: %v", err)
	}
	if len(payload.Findings) != 1 || payload.Findings[0].EvidenceCount != 2 {
		t.Fatalf("findings = %+v, want grouped evidence count 2", payload.Findings)
	}
	if payload.Meta.Limit != 1 || payload.Meta.Returned != 1 || !payload.Meta.Truncated {
		t.Fatalf("meta = %+v, want one truncated row", payload.Meta)
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

func TestGRCEvidenceIncludesListMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	runtimeID := "runtime-alpha"
	tenantID := "tenant"
	store := &stubRuntimeStore{
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
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/evidence?tenant_id=" + tenantID + "&limit=1")
	if err != nil {
		t.Fatalf("GET /grc/evidence error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/evidence status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Evidence []grcEvidenceItem `json:"evidence"`
		Meta     struct {
			Limit     uint32 `json:"limit"`
			Returned  int    `json:"returned"`
			Truncated bool   `json:"truncated"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /grc/evidence: %v", err)
	}
	if len(payload.Evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(payload.Evidence))
	}
	if payload.Meta.Limit != 1 || payload.Meta.Returned != 1 || !payload.Meta.Truncated {
		t.Fatalf("meta = %+v, want one truncated row", payload.Meta)
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
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer", LastSyncedAt: timestamppb.New(now), Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)}},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-high": {
				ID:              "finding-high",
				Fingerprint:     "fingerprint-high",
				TenantID:        "writer",
				RuntimeID:       "writer-okta-audit",
				Title:           "Identity API token created",
				Severity:        "HIGH",
				Status:          "open",
				ResourceURNs:    []string{rootURN},
				LastObservedAt:  now,
				ControlRefs:     []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
				FindingWorkflow: ports.FindingWorkflow{StatusUpdatedAt: now},
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {
				Id:            "evidence-1",
				RuntimeId:     "writer-okta-audit",
				FindingId:     "finding-high",
				RunId:         "evaluation-run-1",
				RunIds:        []string{"evaluation-run-1"},
				EventIds:      []string{"event-1"},
				GraphRootUrns: []string{rootURN},
				GraphPathUrns: []string{"urn:cerebro:writer:graph-path:path-1"},
				GraphRows:     []*cerebrov1.GraphEvidenceRow{{Attributes: map[string]string{"fact_id": "fact-1"}}},
				Observations: []*cerebrov1.FindingEvidenceObservation{{
					RunId: "observation-run-1", ObservedAt: timestamppb.New(now),
				}},
				CreatedAt: timestamppb.New(now),
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
	appendLog := &recordingAppendLog{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, GraphStore: graphStore, AppendLog: appendLog}, nil)
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

	previewResp, err := server.Client().Get(server.URL + "/grc/findings/finding-high/audit-preview")
	if err != nil {
		t.Fatalf("GET audit preview error = %v", err)
	}
	defer func() { _ = previewResp.Body.Close() }()
	if previewResp.StatusCode != http.StatusOK {
		t.Fatalf("GET audit preview status = %d, want %d", previewResp.StatusCode, http.StatusOK)
	}
	var preview grcAuditPacketResponse
	if err := json.NewDecoder(previewResp.Body).Decode(&preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.ResourceState != "live_preview" || preview.Graph == nil || preview.Graph.Root == nil {
		t.Fatalf("preview = %#v, want live graph context", preview)
	}

	createResp, err := server.Client().Post(server.URL+"/grc/audit-packets", "application/json", bytes.NewBufferString(`{"finding_id":"finding-high"}`))
	if err != nil {
		t.Fatalf("POST /grc/audit-packets error = %v", err)
	}
	defer func() { _ = createResp.Body.Close() }()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /grc/audit-packets status = %d, want %d", createResp.StatusCode, http.StatusCreated)
	}
	var created grcAuditPacketResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created packet: %v", err)
	}
	if created.ID == "finding-high" || !strings.HasPrefix(created.ID, "audit-packet-") {
		t.Fatalf("packet id = %q, want independent audit-packet id", created.ID)
	}
	if created.ResourceState != "immutable" || created.SchemaVersion != grcAuditPacketSchema || !strings.HasPrefix(created.Digest, "sha256:") {
		t.Fatalf("created packet identity = %#v", created)
	}
	if created.Graph != nil || len(created.GraphReferences.RootURNs) != 1 {
		t.Fatalf("created graph state = graph %#v refs %#v, want references only", created.Graph, created.GraphReferences)
	}
	if !containsTrimmed(created.GraphReferences.FactRefs, "fact-1") || len(created.ControlReferences) != 1 {
		t.Fatalf("created exact references = graph %#v controls %#v", created.GraphReferences, created.ControlReferences)
	}
	if len(created.EvidenceReferences) != 1 || !containsTrimmed(created.EvidenceReferences[0].EvaluationRunIDs, "evaluation-run-1") || !containsTrimmed(created.EvidenceReferences[0].ObservationRunIDs, "observation-run-1") {
		t.Fatalf("created evidence references = %#v, want exact evaluation and observation runs", created.EvidenceReferences)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("appended audit packet events = %d, want 1", len(appendLog.events))
	}
	recorded, err := workflowevents.DecodeComplianceAggregate(appendLog.events[0])
	if err != nil {
		t.Fatalf("decode appended audit packet event: %v", err)
	}
	if recorded.AggregateType != grcaudit.AuditAggregatePacketReceipt || recorded.AggregateID != created.ID || recorded.ContentDigest != created.Digest {
		t.Fatalf("appended audit packet event = %#v", recorded)
	}

	// Current finding and graph mutations after creation must not affect the packet.
	store.findings["finding-high"].Status = "resolved"
	store.findingEvidence = map[string]*cerebrov1.FindingEvidence{}
	graphStore.neighborhood = nil

	packetResp, err := server.Client().Get(server.URL + "/grc/audit-packets/" + created.ID)
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
	if packet.Finding.Status == "resolved" || packet.Digest != created.Digest {
		t.Fatalf("packet changed after current-state mutation: %#v", packet)
	}
	if packet.RecommendedAction == "" {
		t.Fatalf("packet recommended action is empty")
	}
	if packet.Metadata.Readiness.Status == "" || packet.Metadata.Provenance.ReportType != "finding" {
		t.Fatalf("packet metadata = %#v, want finding readiness and provenance", packet.Metadata)
	}
	if packet.Metadata.Redaction.DefaultMode != "share_safe" {
		t.Fatalf("redaction metadata = %#v, want share-safe default", packet.Metadata.Redaction)
	}

	exportResp, err := server.Client().Get(server.URL + "/grc/audit-packets/" + created.ID + "/export")
	if err != nil {
		t.Fatalf("GET /grc/audit-packets export error = %v", err)
	}
	defer func() { _ = exportResp.Body.Close() }()
	if exportResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/audit-packets export status = %d, want %d", exportResp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(exportResp.Body)
	if err != nil {
		t.Fatalf("read packet export: %v", err)
	}
	markdown := string(body)
	for _, want := range []string{"# Finding Audit Packet", "Recommended Action", "Readiness", created.ID, created.Digest, "Review state: unreviewed", "Export state: ready"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("finding export missing %q:\n%s", want, markdown)
		}
	}
	jsonExportResp, err := server.Client().Get(server.URL + "/grc/audit-packets/" + created.ID + "/export?format=json")
	if err != nil {
		t.Fatalf("GET JSON packet export error = %v", err)
	}
	defer func() { _ = jsonExportResp.Body.Close() }()
	var exported grcAuditPacketResponse
	if err := json.NewDecoder(jsonExportResp.Body).Decode(&exported); err != nil {
		t.Fatalf("decode JSON packet export: %v", err)
	}
	if exported.Digest != packet.Digest || exported.ID != packet.ID {
		t.Fatalf("JSON export = %q/%q, read = %q/%q", exported.ID, exported.Digest, packet.ID, packet.Digest)
	}
}

func TestGRCAuditPacketDigestIsDeterministic(t *testing.T) {
	packet := grcAuditPacketResponse{
		ID: "audit-packet-1", SchemaVersion: grcAuditPacketSchema, ResourceState: "immutable", TenantID: "writer",
		FindingReference: grcAuditFindingReference{ID: "finding-1", Status: "open", StatusRevision: time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC)},
		Gaps:             []grcAuditPacketGap{}, Supersedes: []string{}, GeneratedAt: time.Date(2026, 7, 14, 8, 1, 0, 0, time.UTC),
	}
	first, err := grcauditpacket.Digest(packet)
	if err != nil {
		t.Fatal(err)
	}
	second, err := grcauditpacket.Digest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("digest mismatch: %q != %q", first, second)
	}
	packet.FindingReference.Status = "resolved"
	changed, err := grcauditpacket.Digest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatalf("digest did not change after finding revision changed")
	}
}

func TestGRCAuditPacketRecordsGraphGapWhenProjectionUnavailable(t *testing.T) {
	now := time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{"runtime-1": {Id: "runtime-1", TenantId: "writer", SourceId: "okta"}},
		findings: map[string]*ports.FindingRecord{"finding-1": {ID: "finding-1", TenantID: "writer", RuntimeID: "runtime-1", Status: "open", LastObservedAt: now}},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, AppendLog: &recordingAppendLog{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/grc/audit-packets", "application/json", bytes.NewBufferString(`{"finding_id":"finding-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	packet := grcAuditPacketResponse{}
	if err := json.NewDecoder(response.Body).Decode(&packet); err != nil {
		t.Fatal(err)
	}
	if !hasGRCAuditPacketGap(packet.Gaps, "graph_context_unavailable") || !hasGRCAuditPacketGap(packet.Gaps, "evidence_unavailable") {
		t.Fatalf("gaps = %#v, want graph and evidence gaps", packet.Gaps)
	}
	if !hasGRCAuditPacketGap(packet.Gaps, "finding_fingerprint_unavailable") || !hasGRCAuditPacketGap(packet.Gaps, "source_checkpoint_unavailable") {
		t.Fatalf("gaps = %#v, want missing finding and runtime references", packet.Gaps)
	}
	if len(packet.SourceRuntimes) != 1 || packet.SourceRuntimes[0].CompletenessState != "unknown" {
		t.Fatalf("runtime references = %#v, want unknown completeness without a checkpoint", packet.SourceRuntimes)
	}
}

func TestGRCAuditPacketRecordsTruncatedEvidenceSnapshot(t *testing.T) {
	now := time.Date(2026, time.July, 14, 8, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{"runtime-1": {Id: "runtime-1", TenantId: "writer", SourceId: "okta"}},
		findings: map[string]*ports.FindingRecord{"finding-1": {
			ID: "finding-1", TenantID: "writer", RuntimeID: "runtime-1", Status: "open", LastObservedAt: now,
			FindingWorkflow: ports.FindingWorkflow{StatusUpdatedAt: now},
		}},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: "runtime-1", FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: "runtime-1", FindingId: "finding-1", CreatedAt: timestamppb.New(now.Add(-time.Minute))},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, AppendLog: &recordingAppendLog{}}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/grc/audit-packets?limit=1", "application/json", bytes.NewBufferString(`{"finding_id":"finding-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	packet := grcAuditPacketResponse{}
	if err := json.NewDecoder(response.Body).Decode(&packet); err != nil {
		t.Fatal(err)
	}
	if len(packet.Evidence) != 1 || len(packet.EvidenceReferences) != 1 {
		t.Fatalf("captured evidence = %d/%d, want one limited record", len(packet.Evidence), len(packet.EvidenceReferences))
	}
	if !hasGRCAuditPacketGap(packet.Gaps, "evidence_snapshot_truncated") {
		t.Fatalf("gaps = %#v, want evidence_snapshot_truncated", packet.Gaps)
	}
}

func TestGRCAuditPacketDoesNotProjectWhenAppendFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{"runtime-1": {Id: "runtime-1", TenantId: "writer", SourceId: "okta"}},
		findings: map[string]*ports.FindingRecord{"finding-1": {ID: "finding-1", TenantID: "writer", RuntimeID: "runtime-1", Status: "open", LastObservedAt: now}},
	}
	appendLog := &recordingAppendLog{err: errors.New("append unavailable")}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, AppendLog: appendLog}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	response, err := server.Client().Post(server.URL+"/grc/audit-packets", "application/json", bytes.NewBufferString(`{"finding_id":"finding-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /grc/audit-packets status = %d, want %d", response.StatusCode, http.StatusServiceUnavailable)
	}
	if len(store.grcAuditPackets) != 0 {
		t.Fatalf("projected audit packets = %d, want 0 after append failure", len(store.grcAuditPackets))
	}
}

func hasGRCAuditPacketGap(gaps []grcAuditPacketGap, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

func TestGRCEntityImpactResolvesLegacyGitHubRepoURN(t *testing.T) {
	legacyURN := "urn:cerebro:writer:github_repo:sohalloran-writer"
	canonicalURN := "urn:cerebro:writer:github_user:sohalloran-writer"
	now := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-github": {Id: "writer-github", SourceId: "github", TenantId: "writer"},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-canonical": {
				ID:             "finding-canonical",
				TenantID:       "writer",
				RuntimeID:      "writer-github",
				Title:          "Canonical identity finding",
				Severity:       "HIGH",
				Status:         "open",
				ResourceURNs:   []string{canonicalURN},
				LastObservedAt: now,
			},
			"finding-legacy": {
				ID:             "finding-legacy",
				TenantID:       "writer",
				RuntimeID:      "writer-github",
				Title:          "Legacy identity finding",
				Severity:       "MEDIUM",
				Status:         "open",
				ResourceURNs:   []string{legacyURN},
				LastObservedAt: now.Add(-time.Minute),
			},
		},
	}
	graphStore := &stubGraphStore{
		entities: map[string]*ports.ProjectedEntity{
			canonicalURN: {
				URN:        canonicalURN,
				TenantID:   "writer",
				SourceID:   "github",
				EntityType: "github.user",
				Label:      "sohalloran-writer",
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store, GraphStore: graphStore}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/entities/" + url.PathEscape(legacyURN) + "/impact?tenant_id=writer")
	if err != nil {
		t.Fatalf("GET /grc/entities legacy github repo impact error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /grc/entities legacy github repo impact status = %d, want %d: %s", resp.StatusCode, http.StatusOK, body)
	}
	var impact grcEntityImpactResponse
	if err := json.NewDecoder(resp.Body).Decode(&impact); err != nil {
		t.Fatalf("decode impact: %v", err)
	}
	if impact.EntityURN != canonicalURN {
		t.Fatalf("impact entity urn = %q, want %q", impact.EntityURN, canonicalURN)
	}
	if impact.Graph == nil || impact.Graph.Root == nil || impact.Graph.Root.URN != canonicalURN {
		t.Fatalf("impact graph root = %#v, want %q", impact.Graph, canonicalURN)
	}
	if graphStore.neighborhoodRootURN != canonicalURN {
		t.Fatalf("queried root urn = %q, want %q", graphStore.neighborhoodRootURN, canonicalURN)
	}
	if got := store.findingListRequest.ResourceURN; got != "" {
		t.Fatalf("finding resource urn = %q, want multi-resource lookup", got)
	}
	for _, want := range []string{canonicalURN, legacyURN} {
		if !containsTrimmed(store.findingListRequest.ResourceURNs, want) {
			t.Fatalf("finding resource urns = %#v, want %q", store.findingListRequest.ResourceURNs, want)
		}
	}
	gotFindings := map[string]struct{}{}
	for _, finding := range impact.Findings {
		gotFindings[finding.ID] = struct{}{}
	}
	for _, want := range []string{"finding-canonical", "finding-legacy"} {
		if _, ok := gotFindings[want]; !ok {
			t.Fatalf("impact findings = %#v, want %q", impact.Findings, want)
		}
	}
}

func TestGRCAuditPacketNormalizesForeignFindingLookup(t *testing.T) {
	store := &stubRuntimeStore{
		findings: map[string]*ports.FindingRecord{
			"foreign-finding": {
				ID:        "foreign-finding",
				TenantID:  "other",
				RuntimeID: "other-runtime",
				Title:     "Foreign finding",
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	request := httptest.NewRequest(http.MethodGet, "/grc/findings/foreign-finding/audit-preview", nil)
	request.SetPathValue("findingID", "foreign-finding")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		cfg:       config.AuthConfig{},
		principal: authPrincipal{TenantID: "writer"},
	}))

	_, err := app.buildGRCAuditPreview(request, "foreign-finding")
	if !errors.Is(err, ports.ErrFindingNotFound) {
		t.Fatalf("buildGRCAuditPreview() error = %v, want finding not found", err)
	}
	if got := grcHTTPStatusCode(err); got != http.StatusNotFound {
		t.Fatalf("grcHTTPStatusCode(buildGRCAuditPreview error) = %d, want %d", got, http.StatusNotFound)
	}
}

func TestGRCAuditPacketNormalizesForeignReceiptLookup(t *testing.T) {
	store := &stubRuntimeStore{grcAuditPackets: map[string]*ports.GRCAuditPacketReceipt{
		"packet-other": {ID: "packet-other", TenantID: "other", FindingID: "finding-other", Digest: "sha256:unused", Payload: []byte(`{}`), CreatedAt: time.Now()},
	}}
	request := httptest.NewRequest(http.MethodGet, "/grc/audit-packets/packet-other", nil)
	request.SetPathValue("packetID", "packet-other")
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{cfg: config.AuthConfig{}, principal: authPrincipal{TenantID: "writer"}}))

	_, err := grcauditpacket.Load(request.Context(), store, "packet-other", func(tenantID string) bool {
		return tenantAllowedByContext(request.Context(), tenantID)
	})
	if !errors.Is(err, ports.ErrGRCAuditPacketNotFound) {
		t.Fatalf("getGRCAuditPacket() error = %v, want packet not found", err)
	}
	if got := grcHTTPStatusCode(err); got != http.StatusNotFound {
		t.Fatalf("grcHTTPStatusCode(getGRCAuditPacket error) = %d, want %d", got, http.StatusNotFound)
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
	// Mirror the real aggregate query: evidence counts follow the open finding
	// scope (every matching finding), not the windowed preview finding-id list.
	countsByFindingID := map[string]int{}
	total := 0
	status := strings.TrimSpace(request.FindingRequest.Status)
	for _, evidence := range s.findingEvidence {
		if evidence == nil || !findingEvidenceMatches(request.EvidenceRequest, evidence) {
			continue
		}
		finding, ok := s.findings[evidence.GetFindingId()]
		if !ok {
			continue
		}
		if status != "" && !strings.EqualFold(strings.TrimSpace(finding.Status), status) {
			continue
		}
		countsByFindingID[evidence.GetFindingId()]++
		total++
	}
	return ports.GRCDashboardAggregate{FindingSummary: summary, EvidenceCount: total, EvidenceCountsByFindingID: countsByFindingID}, nil
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
