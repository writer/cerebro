package vulnview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// readContractFixture loads a synthetic copy of a VulnView
// /exports/findings page from sources/vulnview/testdata, shaped per
// Contract C7's vulnview-finding-export/v1 schema.
func readContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name) //nolint:gosec // test-only read of a fixed vendored testdata file.
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

// fixtureNextCursor extracts the "nextCursor" field a fixture page
// carries, so tests assert against the exact VulnView-issued cursor
// instead of a hardcoded, easily-stale copy of it.
func fixtureNextCursor(t *testing.T, raw []byte) string {
	t.Helper()
	var decoded struct {
		NextCursor string `json:"nextCursor"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode fixture nextCursor: %v", err)
	}
	return decoded.NextCursor
}

// TestFindingsContractFixtureEndToEnd drives Source.Read against
// VulnView's standardized /exports/findings shape (Contract C7) for the
// cloud_identity source and confirms the nested resource/details fields
// (including the consumer summary and evidence hash) reach bounded event
// attributes.
func TestFindingsContractFixtureEndToEnd(t *testing.T) {
	fixture := readContractFixture(t, "exports-findings.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			if got := r.URL.Query().Get("source"); got != "cloud_identity" {
				t.Fatalf("source query = %q, want cloud_identity", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "cloud_identity")
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(pull.Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Attributes["consumers"] != "cluster-a/payments/worker" {
		t.Fatalf("finding consumers = %q, want cluster-a/payments/worker", event.Attributes["consumers"])
	}
	if event.Attributes["consumers_complete"] != "true" {
		t.Fatalf("consumers_complete = %q, want true", event.Attributes["consumers_complete"])
	}
	if event.Attributes["evidence_principal_evidence_sha256"] == "" {
		t.Fatal("missing evidence_principal_evidence_sha256 attribute")
	}
	if event.Attributes["last_scan_id"] != "scan-a" || event.Attributes["last_run_id"] != "run-1" {
		t.Fatalf("provenance attrs = last_scan_id:%q last_run_id:%q", event.Attributes["last_scan_id"], event.Attributes["last_run_id"])
	}
	if got := event.Attributes["provenance_integrations"]; got != "cloud_account:111111111111,cloud_account:222222222222" {
		t.Fatalf("provenance_integrations = %q, want sorted cloud_account:111111111111,cloud_account:222222222222", got)
	}
	if got := event.Attributes["provenance_repository_integrations"]; got != "github:gh-2" {
		t.Fatalf("provenance_repository_integrations = %q, want github:gh-2", got)
	}
	if got := event.Attributes["provenance_integration_attribution"]; got != "run" {
		t.Fatalf("provenance_integration_attribution = %q, want run", got)
	}
	if event.Attributes["resource_account"] != "111111111111" {
		t.Fatalf("resource_account = %q, want 111111111111", event.Attributes["resource_account"])
	}
}

// TestFindingResumesFromTerminalCheckpointAcrossSyncs pins Contract C8's
// resumable checkpoint: a sync that starts with no in-sync cursor but a
// resumable checkpoint persisted from a prior terminal (hasMore=false)
// page must resume from that checkpoint's terminal VulnView cursor, not
// restart at cursor="".
func TestFindingResumesFromTerminalCheckpointAcrossSyncs(t *testing.T) {
	fixture := readContractFixture(t, "exports-findings.json")
	terminalCursor := fixtureNextCursor(t, fixture)
	if terminalCursor == "" {
		t.Fatal("fixture must carry a non-empty terminal nextCursor")
	}

	var sawCursor string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenHandler(w)
		case "/exports/findings":
			sawCursor = r.URL.Query().Get("cursor")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, cfg := findingExportTestSource(t, server, "cloud_identity")
	first, err := source.ReadWithCheckpoint(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if sawCursor != "" {
		t.Fatalf("first request sent cursor %q, want empty (no prior checkpoint)", sawCursor)
	}
	if first.Checkpoint == nil {
		t.Fatal("first.Checkpoint = nil, want a resumable checkpoint even for a terminal page")
	}
	envelope, ok := sourcecdk.DecodeCursorEnvelope(first.Checkpoint.GetCursorOpaque())
	if !ok || !envelope.ResumableCheckpoint || envelope.Token != terminalCursor {
		t.Fatalf("first.Checkpoint envelope = %+v, want a resumable envelope carrying %q", envelope, terminalCursor)
	}

	startCursor := &cerebrov1.SourceCursor{Opaque: first.Checkpoint.GetCursorOpaque()}
	second, err := source.ReadWithCheckpoint(context.Background(), cfg, startCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if sawCursor != terminalCursor {
		t.Fatalf("second sync sent cursor %q, want the persisted terminal cursor %q (resume, not restart)", sawCursor, terminalCursor)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(second.Events) = %d, want 1 (the fixture is replayed, not advanced)", len(second.Events))
	}
}
