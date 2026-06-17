package bootstrap

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/config"
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
}
