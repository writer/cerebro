package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type memoryGRCInventoryAssetReportStore struct {
	reports map[string]*ports.GRCInventoryAssetReportRecord
}

func (s *memoryGRCInventoryAssetReportStore) Ping(context.Context) error { return nil }

func (s *memoryGRCInventoryAssetReportStore) CreateGRCInventoryAssetReport(_ context.Context, record ports.GRCInventoryAssetReportRecord) (*ports.GRCInventoryAssetReportRecord, error) {
	if s.reports == nil {
		s.reports = map[string]*ports.GRCInventoryAssetReportRecord{}
	}
	now := time.Now().UTC().Truncate(time.Second)
	record.CreatedAt = now
	record.UpdatedAt = now
	s.reports[record.ID] = cloneGRCInventoryAssetReport(record)
	return cloneGRCInventoryAssetReport(record), nil
}

func (s *memoryGRCInventoryAssetReportStore) GetGRCInventoryAssetReport(_ context.Context, id string, tenantID string) (*ports.GRCInventoryAssetReportRecord, error) {
	report, ok := s.reports[strings.TrimSpace(id)]
	if !ok || (tenantID != "" && report.TenantID != tenantID) {
		return nil, ports.ErrGRCInventoryAssetReportNotFound
	}
	return cloneGRCInventoryAssetReportValue(report), nil
}

func (s *memoryGRCInventoryAssetReportStore) ListGRCInventoryAssetReports(_ context.Context, filter ports.GRCInventoryAssetReportFilter) ([]*ports.GRCInventoryAssetReportRecord, error) {
	urns := map[string]struct{}{}
	for _, urn := range filter.AssetURNs {
		urn = strings.TrimSpace(urn)
		if urn != "" {
			urns[urn] = struct{}{}
		}
	}
	reports := []*ports.GRCInventoryAssetReportRecord{}
	for _, report := range s.reports {
		if filter.TenantID != "" && report.TenantID != filter.TenantID {
			continue
		}
		if filter.SourceID != "" && report.SourceID != filter.SourceID {
			continue
		}
		if filter.TriageStatus != "" && report.TriageStatus != filter.TriageStatus {
			continue
		}
		if len(urns) > 0 {
			if _, ok := urns[report.AssetURN]; !ok {
				continue
			}
		}
		reports = append(reports, cloneGRCInventoryAssetReportValue(report))
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].UpdatedAt.After(reports[j].UpdatedAt) })
	return reports, nil
}

func (s *memoryGRCInventoryAssetReportStore) UpdateGRCInventoryAssetReportTriage(_ context.Context, update ports.GRCInventoryAssetReportTriageUpdate) (*ports.GRCInventoryAssetReportRecord, error) {
	report, ok := s.reports[strings.TrimSpace(update.ID)]
	if !ok || (update.TenantID != "" && report.TenantID != update.TenantID) {
		return nil, ports.ErrGRCInventoryAssetReportNotFound
	}
	now := time.Now().UTC().Truncate(time.Second)
	report.TriageStatus = update.TriageStatus
	report.TriageReason = update.TriageReason
	report.TriagedBy = update.TriagedBy
	report.TriagedAt = &now
	report.UpdatedAt = now
	return cloneGRCInventoryAssetReportValue(report), nil
}

func TestGRCInventoryAssetReportSubmitAndTriage(t *testing.T) {
	store := &memoryGRCInventoryAssetReportStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	createBody := bytes.NewBufferString(`{"asset_urn":"urn:cerebro:writer:github_code_repository:writer/app","source_id":"github","reason":"Owner metadata is stale"}`)
	createResp, err := server.Client().Post(server.URL+"/grc/inventory/asset-reports", "application/json", createBody)
	if err != nil {
		t.Fatalf("POST /grc/inventory/asset-reports error = %v", err)
	}
	defer func() { _ = createResp.Body.Close() }()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want %d", createResp.StatusCode, http.StatusCreated)
	}
	var created grcInventoryAssetReportResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Report == nil || created.Report.TriageStatus != ports.GRCInventoryAssetReportStatusSubmitted {
		t.Fatalf("created report = %#v, want submitted report", created.Report)
	}

	patchBody := bytes.NewBufferString(`{"triage_status":"accepted","triage_reason":"Confirmed bad owner data"}`)
	patchReq, err := http.NewRequest(http.MethodPatch, server.URL+"/grc/inventory/asset-reports/"+created.Report.ID+"/triage", patchBody)
	if err != nil {
		t.Fatalf("NewRequest error = %v", err)
	}
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, err := server.Client().Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH /grc/inventory/asset-reports/{id}/triage error = %v", err)
	}
	defer func() { _ = patchResp.Body.Close() }()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH status = %d, want %d", patchResp.StatusCode, http.StatusOK)
	}
	var triaged grcInventoryAssetReportResponse
	if err := json.NewDecoder(patchResp.Body).Decode(&triaged); err != nil {
		t.Fatalf("decode triage response: %v", err)
	}
	if triaged.Report == nil || triaged.Report.TriageStatus != ports.GRCInventoryAssetReportStatusAccepted || triaged.Report.TriageReason != "Confirmed bad owner data" {
		t.Fatalf("triaged report = %#v, want accepted with reason", triaged.Report)
	}
}

func TestGRCInventoryAssetReportRejectsInvalidStatus(t *testing.T) {
	store := &memoryGRCInventoryAssetReportStore{}
	app := New(config.Config{HTTPAddr: "127.0.0.1:0", ShutdownTimeout: time.Second}, Dependencies{StateStore: store}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	body := bytes.NewBufferString(`{"asset_urn":"urn:cerebro:writer:github_code_repository:writer/app","reason":"bad","triage_status":"unknown"}`)
	resp, err := server.Client().Post(server.URL+"/grc/inventory/asset-reports", "application/json", body)
	if err != nil {
		t.Fatalf("POST /grc/inventory/asset-reports error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func cloneGRCInventoryAssetReport(record ports.GRCInventoryAssetReportRecord) *ports.GRCInventoryAssetReportRecord {
	cloned := record
	if record.Attributes != nil {
		cloned.Attributes = map[string]string{}
		for key, value := range record.Attributes {
			cloned.Attributes[key] = value
		}
	}
	if record.TriagedAt != nil {
		triagedAt := *record.TriagedAt
		cloned.TriagedAt = &triagedAt
	}
	return &cloned
}

func cloneGRCInventoryAssetReportValue(record *ports.GRCInventoryAssetReportRecord) *ports.GRCInventoryAssetReportRecord {
	if record == nil {
		return nil
	}
	return cloneGRCInventoryAssetReport(*record)
}

var _ ports.GRCInventoryAssetReportStore = (*memoryGRCInventoryAssetReportStore)(nil)
