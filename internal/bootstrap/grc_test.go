package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
			"tenant-okta-audit": {
				Id:           "tenant-okta-audit",
				SourceId:     "okta",
				TenantId:     "tenant-a",
				LastSyncedAt: timestamppb.New(now.Add(-30 * time.Minute)),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-30 * time.Minute))},
			},
			"tenant-github": {
				Id:           "tenant-github",
				SourceId:     "github",
				TenantId:     "tenant-a",
				LastSyncedAt: timestamppb.New(now.Add(-30 * time.Minute)),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-48 * time.Hour))},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-high": {
				ID:           "finding-high",
				TenantID:     "tenant-a",
				RuntimeID:    "tenant-okta-audit",
				RuleID:       "identity-api-token-or-oauth-app-created",
				Title:        "Identity API token created",
				Severity:     "HIGH",
				Status:       "open",
				ResourceURNs: []string{"urn:cerebro:tenant-a:okta_user:00u1"},
				ControlRefs: []ports.FindingControlRef{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.1",
				}},
				FindingWorkflow: ports.FindingWorkflow{DueAt: now.Add(-24 * time.Hour)},
				LastObservedAt:  now,
			},
			"finding-critical": {
				ID:             "finding-critical",
				TenantID:       "tenant-a",
				RuntimeID:      "tenant-github",
				RuleID:         "github-dependabot-critical",
				Title:          "Critical dependency exposure",
				Severity:       "CRITICAL",
				Status:         "open",
				ResourceURNs:   []string{"urn:cerebro:tenant-a:github_repository:tenant-a/app"},
				LastObservedAt: now.Add(-time.Hour),
			},
			"finding-resolved": {
				ID:             "finding-resolved",
				TenantID:       "tenant-a",
				RuntimeID:      "tenant-okta-audit",
				Title:          "Resolved finding",
				Severity:       "LOW",
				Status:         "resolved",
				LastObservedAt: now.Add(-2 * time.Hour),
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {
				Id:            "evidence-1",
				RuntimeId:     "tenant-okta-audit",
				RuleId:        "identity-api-token-or-oauth-app-created",
				FindingId:     "finding-high",
				RunId:         "run-1",
				EventIds:      []string{"event-1"},
				GraphRootUrns: []string{"urn:cerebro:tenant-a:okta_user:00u1"},
				CreatedAt:     timestamppb.New(now),
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=tenant-a")
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
	if len(payload.Connectors) != 2 {
		t.Fatalf("connectors len = %d, want 2", len(payload.Connectors))
	}
	if payload.Summary.StaleConnectors != 1 {
		t.Fatalf("stale connectors = %d, want 1", payload.Summary.StaleConnectors)
	}
	if payload.Connectors[0].CheckpointWatermark == nil && payload.Connectors[1].CheckpointWatermark == nil {
		t.Fatalf("connector checkpoint watermarks were not surfaced")
	}
}

func TestGRCDashboardSummaryUsesUnpaginatedAggregates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"tenant-okta-audit": {
				Id:           "tenant-okta-audit",
				SourceId:     "okta",
				TenantId:     "tenant-a",
				LastSyncedAt: timestamppb.New(now),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				TenantID:       "tenant-a",
				RuntimeID:      "tenant-okta-audit",
				Title:          "Finding 1",
				Severity:       "HIGH",
				Status:         "open",
				LastObservedAt: now.Add(-time.Minute),
			},
			"finding-2": {
				ID:             "finding-2",
				TenantID:       "tenant-a",
				RuntimeID:      "tenant-okta-audit",
				Title:          "Finding 2",
				Severity:       "CRITICAL",
				Status:         "open",
				LastObservedAt: now.Add(-2 * time.Minute),
			},
			"finding-3": {
				ID:             "finding-3",
				TenantID:       "tenant-a",
				RuntimeID:      "tenant-okta-audit",
				Title:          "Finding 3",
				Severity:       "HIGH",
				Status:         "open",
				LastObservedAt: now.Add(-3 * time.Minute),
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: "tenant-okta-audit", FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: "tenant-okta-audit", FindingId: "finding-2", CreatedAt: timestamppb.New(now)},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=tenant-a&limit=1")
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
	if payload.Summary.OpenFindings != 3 {
		t.Fatalf("summary open findings = %d, want unpaginated total 3", payload.Summary.OpenFindings)
	}
	if payload.Summary.CriticalFindings != 1 || payload.Summary.HighFindings != 2 {
		t.Fatalf("summary severities = critical %d high %d, want 1/2", payload.Summary.CriticalFindings, payload.Summary.HighFindings)
	}
	if payload.Summary.EvidenceItems != 2 {
		t.Fatalf("summary evidence items = %d, want unpaginated total 2", payload.Summary.EvidenceItems)
	}
}

func TestGRCDashboardBatchesRuntimeStoreQueries(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"tenant-github": {
				Id:         "tenant-github",
				SourceId:   "github",
				TenantId:   "tenant-a",
				Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
			"tenant-okta-audit": {
				Id:         "tenant-okta-audit",
				SourceId:   "okta",
				TenantId:   "tenant-a",
				Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
			"tenant-sentinelone": {
				Id:         "tenant-sentinelone",
				SourceId:   "sentinelone",
				TenantId:   "tenant-a",
				Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now)},
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/dashboard?tenant_id=tenant-a&limit=100")
	if err != nil {
		t.Fatalf("GET /grc/dashboard error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/dashboard status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	expectedRuntimeIDs := []string{"tenant-github", "tenant-okta-audit", "tenant-sentinelone"}
	if got := len(store.findingListRequests); got != 1 {
		t.Fatalf("ListFindings calls = %d, want 1", got)
	}
	if !reflect.DeepEqual(store.findingListRequests[0].RuntimeIDs, expectedRuntimeIDs) {
		t.Fatalf("ListFindings runtime ids = %#v, want %#v", store.findingListRequests[0].RuntimeIDs, expectedRuntimeIDs)
	}
	if got := len(store.findingSummaryRequests); got != 1 {
		t.Fatalf("SummarizeFindings calls = %d, want 1", got)
	}
	if got := len(store.findingEvidenceListRequests); got != 1 {
		t.Fatalf("ListFindingEvidence calls = %d, want 1", got)
	}
	if !reflect.DeepEqual(store.findingEvidenceListRequests[0].RuntimeIDs, expectedRuntimeIDs) {
		t.Fatalf("ListFindingEvidence runtime ids = %#v, want %#v", store.findingEvidenceListRequests[0].RuntimeIDs, expectedRuntimeIDs)
	}
	if got := len(store.findingEvidenceCountRequests); got != 1 {
		t.Fatalf("CountFindingEvidence calls = %d, want 1", got)
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
}
