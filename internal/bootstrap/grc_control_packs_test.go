package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRCControlArchetypesEndpointReturnsReusableControls(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/control-archetypes")
	if err != nil {
		t.Fatalf("GET /grc/control-archetypes error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/control-archetypes status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Archetypes []compliance.ControlArchetype `json:"archetypes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode archetypes: %v", err)
	}
	if len(payload.Archetypes) < 6 {
		t.Fatalf("archetype count = %d, want reusable baseline controls", len(payload.Archetypes))
	}
	if payload.Archetypes[0].Control.Title == "" {
		t.Fatalf("first archetype missing auditor-facing control title: %#v", payload.Archetypes[0])
	}
}

func TestGRCFrameworksEndpointReturnsLifecycleMetadata(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/frameworks")
	if err != nil {
		t.Fatalf("GET /grc/frameworks error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/frameworks status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload compliance.FrameworksResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode frameworks: %v", err)
	}
	var foundUpcoming bool
	for _, framework := range payload.Frameworks {
		if framework.Name == "NIST AI RMF 1.0" && framework.Lifecycle == compliance.FrameworkLifecycleUpcoming {
			foundUpcoming = true
		}
	}
	if !foundUpcoming {
		t.Fatalf("frameworks = %#v, want upcoming NIST AI RMF", payload.Frameworks)
	}
}

func TestGRCControlPackPreviewEndpointReturnsYAMLFilesAndCoverage(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := bytes.NewBufferString(`{
		"framework_id":"customer-security",
		"framework_name":"Customer Security Framework",
		"profile_id":"customer-security-audit",
		"profile_name":"Customer Security Audit",
		"archetype_ids":["privileged-mfa","critical-vulnerability-sla"]
	}`)
	resp, err := server.Client().Post(server.URL+"/grc/control-packs/preview", "application/json", body)
	if err != nil {
		t.Fatalf("POST /grc/control-packs/preview error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /grc/control-packs/preview status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Preview compliance.ControlPackPreview `json:"preview"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode control pack preview: %v", err)
	}
	if payload.Preview.Summary.Controls != 2 {
		t.Fatalf("controls = %d, want 2", payload.Preview.Summary.Controls)
	}
	if payload.Preview.Summary.AuditorReadyControls != 2 {
		t.Fatalf("auditor ready = %d, want 2", payload.Preview.Summary.AuditorReadyControls)
	}
	for _, name := range []string{"extension.yaml", "controls.yaml", "profiles.yaml", "coverage.yaml"} {
		if strings.TrimSpace(payload.Preview.Files[name]) == "" {
			t.Fatalf("file %s is empty in preview payload", name)
		}
	}
	if !strings.Contains(payload.Preview.Files["controls.yaml"], "Customer Security Framework") {
		t.Fatalf("controls.yaml missing generated framework:\n%s", payload.Preview.Files["controls.yaml"])
	}
}

func TestGRCControlEvidencePacketEndpointBuildsProfilePosture(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	scopePolicy, err := resourcescope.ConfigValue(resourcescope.Policy{
		ExcludedFamilies:     []string{"okta.audit"},
		ExcludedResourceURNs: []string{"urn:cerebro:writer:okta_user:excluded"},
	})
	if err != nil {
		t.Fatalf("scope policy: %v", err)
	}
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
				Config:   map[string]string{resourcescope.ConfigKey: scopePolicy},
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

	resp, err := server.Client().Get(server.URL + "/grc/control-packets?tenant_id=writer&profile=soc2-security-core&framework=SOC%202")
	if err != nil {
		t.Fatalf("GET /grc/control-packets error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/control-packets status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Profile  grccontrol.Profile               `json:"profile"`
		Packet   compliance.ControlEvidencePacket `json:"packet"`
		Controls []grccontrol.ControlItem         `json:"controls"`
		Metadata grccontrol.ReportMetadata        `json:"metadata"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode control packet: %v", err)
	}
	if payload.Profile.ID != "soc2-security-core" {
		t.Fatalf("profile id = %q, want soc2-security-core", payload.Profile.ID)
	}
	if payload.Packet.Summary.Total < 2 {
		t.Fatalf("packet controls = %d, want filtered CC6 family controls", payload.Packet.Summary.Total)
	}
	byID := map[string]grccontrol.ControlItem{}
	for _, control := range payload.Controls {
		byID[control.ControlID] = control
	}
	if got := byID["CC6.1"]; got.Status != string(compliance.ControlPostureFailing) || got.OpenFindings != 1 || got.EvidenceItems != 1 {
		t.Fatalf("CC6.1 = %+v, want failing with finding and evidence", got)
	}
	var missingControl grccontrol.ControlItem
	for _, control := range payload.Controls {
		if control.Status == string(compliance.ControlPostureMissingEvidence) {
			missingControl = control
			break
		}
	}
	if missingControl.ControlID == "" || missingControl.MissingEvidence == 0 || missingControl.Expectations == 0 {
		t.Fatalf("missing control = %+v, want a selected control with missing required evidence", missingControl)
	}
	if payload.Metadata.Readiness.Status == "" || payload.Metadata.Readiness.Score == 0 {
		t.Fatalf("metadata readiness = %#v, want packet readiness", payload.Metadata.Readiness)
	}
	if payload.Metadata.Scope.Exclusions.Total != 2 {
		t.Fatalf("scope exclusions = %#v, want two configured exclusions", payload.Metadata.Scope.Exclusions)
	}
	if !payload.Metadata.Scope.Exclusions.AppliedToIncrementalFetch || !payload.Metadata.Scope.IncrementalFetch.PolicyAppliedBeforeRead {
		t.Fatalf("scope incremental metadata = %#v, want exclusions carried before incremental fetch", payload.Metadata.Scope)
	}
}

func TestGRCControlEvidencePacketDetailEndpointReturnsOneControl(t *testing.T) {
	server := newGRCControlPacketTestServer(t)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/control-packets/detail?tenant_id=writer&profile=soc2-security-core&framework=SOC%202&control=CC6.1")
	if err != nil {
		t.Fatalf("GET /grc/control-packets/detail error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/control-packets/detail status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Packet compliance.ControlEvidencePacket `json:"packet"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode control packet detail: %v", err)
	}
	if len(payload.Packet.Controls) != 1 {
		t.Fatalf("packet controls = %d, want 1", len(payload.Packet.Controls))
	}
	control := payload.Packet.Controls[0]
	if control.Control.ControlID != "CC6.1" || control.Readiness.Score == 0 || control.Readiness.Rating == "" {
		t.Fatalf("control detail = %#v, want CC6.1 with audit readiness", control)
	}
}

func TestGRCControlEvidencePacketExportEndpointReturnsMarkdown(t *testing.T) {
	server := newGRCControlPacketTestServer(t)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/control-packets/export?tenant_id=writer&profile=soc2-security-core&framework=SOC%202&control=CC6.1")
	if err != nil {
		t.Fatalf("GET /grc/control-packets/export error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /grc/control-packets/export status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.Contains(contentType, "text/markdown") {
		t.Fatalf("Content-Type = %q, want text/markdown", contentType)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read markdown export: %v", err)
	}
	markdown := string(body)
	for _, want := range []string{"# Control Evidence Packet", "SOC 2 CC6.1", "Evidence Expectations", "Evidence score"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown export missing %q:\n%s", want, markdown)
		}
	}
}

func TestWriteGRCMarkdownExportPreservesMarkdownBytes(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := "# Control & Evidence <Packet>\n\n- Link text: [literal](https://example.invalid)\n"

	writeGRCMarkdownExport(recorder, "packet.md", body)

	if got := recorder.Body.String(); got != body {
		t.Fatalf("markdown body = %q, want raw %q", got, body)
	}
	if strings.Contains(recorder.Body.String(), "&amp;") || strings.Contains(recorder.Body.String(), "&lt;") {
		t.Fatalf("markdown export was HTML-escaped: %q", recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestGRCCustomControlEvidencePacketEndpointBuildsGeneratedProfilePacket(t *testing.T) {
	server := newGRCControlPacketTestServer(t)
	defer server.Close()

	body := strings.NewReader(`{
		"framework_id":"customer-security",
		"framework_name":"Customer Security Framework",
		"profile_id":"customer-security-audit",
		"profile_name":"Customer Security Audit",
		"archetype_ids":["privileged-mfa"]
	}`)
	resp, err := server.Client().Post(server.URL+"/grc/control-packets?tenant_id=writer", "application/json", body)
	if err != nil {
		t.Fatalf("POST /grc/control-packets error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /grc/control-packets status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload struct {
		Profile  grccontrol.Profile               `json:"profile"`
		Packet   compliance.ControlEvidencePacket `json:"packet"`
		Controls []grccontrol.ControlItem         `json:"controls"`
		Preview  compliance.ControlPackPreview    `json:"preview"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode custom control packet: %v", err)
	}
	if payload.Profile.ID != "customer-security-audit" || payload.Preview.Summary.Controls != 1 {
		t.Fatalf("custom payload profile/preview = %#v %#v, want generated one-control profile", payload.Profile, payload.Preview.Summary)
	}
	if len(payload.Packet.Controls) != 1 || payload.Packet.Controls[0].Control.FrameworkName != "Customer Security Framework" {
		t.Fatalf("custom packet controls = %#v, want generated framework control", payload.Packet.Controls)
	}
	if len(payload.Controls) != 1 || payload.Controls[0].EvidenceQuality == "" {
		t.Fatalf("custom controls = %#v, want summarized audit quality", payload.Controls)
	}
}

func TestGRCControlPackCreateEndpointReturnsStatelessExport(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := strings.NewReader(`{
		"framework_id":"customer-security",
		"framework_name":"Customer Security Framework",
		"profile_id":"customer-security-audit",
		"profile_name":"Customer Security Audit",
		"archetype_ids":["privileged-mfa"]
	}`)
	resp, err := server.Client().Post(server.URL+"/grc/control-packs", "application/json", body)
	if err != nil {
		t.Fatalf("POST /grc/control-packs error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /grc/control-packs status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if location := resp.Header.Get("Location"); location != "" {
		t.Fatalf("Location header = %q, want none for stateless export", location)
	}
}

func TestGRCControlPackPreviewEndpointReturnsValidationIssues(t *testing.T) {
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Post(server.URL+"/grc/control-packs/preview", "application/json", strings.NewReader(`{"archetype_ids":["missing"]}`))
	if err != nil {
		t.Fatalf("POST /grc/control-packs/preview error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /grc/control-packs/preview status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	var payload struct {
		Issues []compliance.ValidationIssue `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode issues: %v", err)
	}
	if len(payload.Issues) == 0 {
		t.Fatal("issues = 0, want validation issue")
	}
	if payload.Issues[0].Path == "" || payload.Issues[0].Message == "" {
		t.Fatalf("issue = %#v, want JSON-decoded path and message fields", payload.Issues[0])
	}
}

func newGRCControlPacketTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	store := &stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {Id: "writer-okta-audit", SourceId: "okta", TenantId: "writer"},
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
	return httptest.NewServer(app.Handler())
}
