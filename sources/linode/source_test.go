package linode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckAndRead(t *testing.T) {
	fixture, err := os.ReadFile("testdata/read_issue.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	readQuerySeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/managed/issues" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		switch pageSize := r.URL.Query().Get("page_size"); pageSize {
		case "", "1":
		case "100":
			readQuerySeen = true
		default:
			t.Fatalf("page_size = %q, want empty, 1, or 100", pageSize)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	if !readQuerySeen {
		t.Fatal("read request did not include page_size")
	}
	event := pull.Events[0]
	if event.Kind != "linode.issue" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if event.TenantId != "tenant" {
		t.Fatalf("tenant_id = %q, want tenant", event.TenantId)
	}
	scope := sha256.Sum256([]byte(server.URL + "\x00/managed/issues"))
	wantID := "linode-tenant-" + hex.EncodeToString(scope[:])[:12] + "-issue-823"
	if event.Id != wantID {
		t.Fatalf("event id = %q, want %q", event.Id, wantID)
	}
	if event.SchemaRef != "linode/issue/v1" {
		t.Fatalf("schema_ref = %q", event.SchemaRef)
	}
	for key, want := range map[string]string{
		"finding_id":      "823",
		"resource_urn":    "urn:cerebro:tenant:linode_issue:823",
		"severity":        "medium",
		"source_event_id": "823",
		"status":          "open",
		"tenant_id":       "tenant",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("payload decode error = %v", err)
	}
	if payload["id"] != float64(823) {
		t.Fatalf("payload id = %#v", payload["id"])
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}
