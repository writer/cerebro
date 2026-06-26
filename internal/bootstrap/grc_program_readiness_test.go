package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRCProgramReadinessEndpointReturnsProofBundleWorkQueue(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:           "writer-okta-audit",
				SourceId:     "okta",
				TenantId:     "writer",
				LastSyncedAt: timestamppb.New(now.Add(-20 * time.Minute)),
				Checkpoint:   &cerebrov1.SourceCheckpoint{Watermark: timestamppb.New(now.Add(-20 * time.Minute))},
			},
		},
		findings: map[string]*ports.FindingRecord{
			"finding-cc6": {
				ID:             "finding-cc6",
				TenantID:       "writer",
				RuntimeID:      "writer-okta-audit",
				RuleID:         "identity-api-token-or-oauth-app-created",
				Title:          "Identity API token created",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-cc6": {
				Id:            "evidence-cc6",
				RuntimeId:     "writer-okta-audit",
				RuleId:        "identity-api-token-or-oauth-app-created",
				FindingId:     "finding-cc6",
				GraphRootUrns: []string{"urn:cerebro:writer:okta_user:00u1"},
				CreatedAt:     timestamppb.New(now),
			},
		},
	}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/program-readiness?tenant_id=writer&profile=soc2-security-core&framework=SOC%202")
	if err != nil {
		t.Fatalf("GET /grc/program-readiness error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/program-readiness status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload grcProgramReadinessResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode program readiness: %v", err)
	}
	if payload.Profile.ID != "soc2-security-core" {
		t.Fatalf("profile id = %q, want soc2-security-core", payload.Profile.ID)
	}
	if payload.Summary.Controls == 0 || payload.Summary.OpenFindings == 0 || payload.Summary.EvidenceItems != 1 {
		t.Fatalf("summary = %+v, want controls with mapped findings and one evidence item", payload.Summary)
	}
	if payload.Summary.Score == 0 || strings.TrimSpace(payload.Summary.Status) == "" {
		t.Fatalf("readiness = %q/%d, want populated status and score", payload.Summary.Status, payload.Summary.Score)
	}
	if len(payload.WorkItems) == 0 {
		t.Fatalf("work items = 0, want prioritized audit work")
	}
	if payload.ProofBundle.ID != "proofbundle:soc2-security-core" {
		t.Fatalf("proof bundle id = %q, want deterministic profile bundle", payload.ProofBundle.ID)
	}
	if !strings.HasPrefix(payload.ProofBundle.ExportPath, "/grc/control-packets/export?") {
		t.Fatalf("export path = %q, want control packet export path", payload.ProofBundle.ExportPath)
	}
	if len(payload.Connectors) != 1 || payload.Connectors[0].RuntimeID != "writer-okta-audit" {
		t.Fatalf("connectors = %+v, want scoped runtime", payload.Connectors)
	}
	if len(payload.Frameworks) == 0 || payload.Frameworks[0].FrameworkName == "" {
		t.Fatalf("frameworks = %+v, want readiness rollup", payload.Frameworks)
	}
	if len(payload.ProductAreas) == 0 {
		t.Fatalf("product areas = 0, want backend product area taxonomy")
	}
	if payload.ProductAreas[0].ID != "compliance" || payload.ProductAreas[0].Status == "" {
		t.Fatalf("first product area = %+v, want compliance area with status", payload.ProductAreas[0])
	}
}
