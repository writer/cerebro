package bootstrap

import (
	"encoding/csv"
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

func grcExportTestStore(tenantID, runtimeID string, now time.Time) *stubGRCEvidenceCountStore {
	return &stubGRCEvidenceCountStore{stubRuntimeStore: &stubRuntimeStore{
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
				Title:          "Risky, finding",
				Severity:       "HIGH",
				Status:         "open",
				ControlRefs:    []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
				LastObservedAt: now,
			},
			"finding-2": {
				ID:             "finding-2",
				TenantID:       tenantID,
				RuntimeID:      runtimeID,
				Title:          "Second finding",
				Severity:       "CRITICAL",
				Status:         "open",
				LastObservedAt: now,
			},
		},
		findingEvidence: map[string]*cerebrov1.FindingEvidence{
			"evidence-1": {Id: "evidence-1", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now)},
			"evidence-2": {Id: "evidence-2", RuntimeId: runtimeID, FindingId: "finding-1", CreatedAt: timestamppb.New(now.Add(-time.Minute))},
			"evidence-3": {Id: "evidence-3", RuntimeId: runtimeID, FindingId: "finding-2", CreatedAt: timestamppb.New(now)},
		},
	}}
}

func parseCSVResponse(t *testing.T, resp *http.Response) [][]string {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", contentType)
	}
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, "attachment; filename=") {
		t.Fatalf("content-disposition = %q, want attachment filename", disposition)
	}
	records, err := csv.NewReader(resp.Body).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	return records
}

func indexCSVByColumn(records [][]string, column string) map[string]map[string]string {
	header := records[0]
	columnIndex := -1
	for i, name := range header {
		if name == column {
			columnIndex = i
		}
	}
	rows := map[string]map[string]string{}
	for _, record := range records[1:] {
		row := map[string]string{}
		for i, name := range header {
			if i < len(record) {
				row[name] = record[i]
			}
		}
		if columnIndex >= 0 && columnIndex < len(record) {
			rows[record[columnIndex]] = row
		}
	}
	return rows
}

func TestGRCFindingsExportReturnsCSV(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, runtimeID := "tenant", "runtime-alpha"
	store := grcExportTestStore(tenantID, runtimeID, now)
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/findings/export?tenant_id=" + tenantID)
	if err != nil {
		t.Fatalf("GET /grc/findings/export error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, "cerebro-findings-") {
		t.Fatalf("content-disposition = %q, want cerebro-findings filename", disposition)
	}
	records := parseCSVResponse(t, resp)
	if len(records) != 3 {
		t.Fatalf("records = %d, want header + 2 findings", len(records))
	}
	for i, want := range grcFindingExportHeader() {
		if records[0][i] != want {
			t.Fatalf("header[%d] = %q, want %q", i, records[0][i], want)
		}
	}
	rows := indexCSVByColumn(records, "id")
	finding1, ok := rows["finding-1"]
	if !ok {
		t.Fatalf("finding-1 row missing: %#v", rows)
	}
	if finding1["severity"] != "HIGH" {
		t.Fatalf("finding-1 severity = %q, want HIGH", finding1["severity"])
	}
	if finding1["evidence_count"] != "2" {
		t.Fatalf("finding-1 evidence_count = %q, want 2", finding1["evidence_count"])
	}
	if finding1["controls"] != "SOC 2 CC6.1" {
		t.Fatalf("finding-1 controls = %q, want SOC 2 CC6.1", finding1["controls"])
	}
	if finding1["title"] != "Risky, finding" {
		t.Fatalf("finding-1 title = %q, want comma-safe title", finding1["title"])
	}
	if rows["finding-2"]["evidence_count"] != "1" {
		t.Fatalf("finding-2 evidence_count = %q, want 1", rows["finding-2"]["evidence_count"])
	}
}

func TestGRCControlsExportReturnsCSV(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tenantID, runtimeID := "tenant", "runtime-alpha"
	store := grcExportTestStore(tenantID, runtimeID, now)
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/grc/controls/export?tenant_id=" + tenantID)
	if err != nil {
		t.Fatalf("GET /grc/controls/export error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if disposition := resp.Header.Get("Content-Disposition"); !strings.Contains(disposition, "cerebro-controls-") {
		t.Fatalf("content-disposition = %q, want cerebro-controls filename", disposition)
	}
	records := parseCSVResponse(t, resp)
	for i, want := range grcControlExportHeader() {
		if records[0][i] != want {
			t.Fatalf("header[%d] = %q, want %q", i, records[0][i], want)
		}
	}
	rows := indexCSVByColumn(records, "control_id")
	control, ok := rows["CC6.1"]
	if !ok {
		t.Fatalf("CC6.1 control row missing: %#v", rows)
	}
	if control["framework_name"] != "SOC 2" {
		t.Fatalf("control framework = %q, want SOC 2", control["framework_name"])
	}
	if control["open_findings"] != "1" {
		t.Fatalf("control open_findings = %q, want 1", control["open_findings"])
	}
	if control["evidence_items"] != "2" {
		t.Fatalf("control evidence_items = %q, want 2", control["evidence_items"])
	}
}
