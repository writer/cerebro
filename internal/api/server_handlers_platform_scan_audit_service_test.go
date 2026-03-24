package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/scanaudit"
)

type stubPlatformScanAuditService struct {
	records         []scanaudit.Record
	unified         []scanaudit.UnifiedFinding
	record          *scanaudit.Record
	exportPackage   *scanaudit.ExportPackage
	err             error
	lastListOpts    scanaudit.ListOptions
	lastUnifiedOpts scanaudit.UnifiedFindingListOptions
	lastNamespace   string
	lastRunID       string
}

func (s *stubPlatformScanAuditService) ListRecords(_ context.Context, opts scanaudit.ListOptions) ([]scanaudit.Record, error) {
	s.lastListOpts = opts
	if s.err != nil {
		return nil, s.err
	}
	return append([]scanaudit.Record(nil), s.records...), nil
}

func (s *stubPlatformScanAuditService) GetRecord(_ context.Context, namespace, runID string) (*scanaudit.Record, bool, error) {
	s.lastNamespace = namespace
	s.lastRunID = runID
	if s.err != nil {
		return nil, false, s.err
	}
	if s.record == nil {
		return nil, false, nil
	}
	record := *s.record
	return &record, true, nil
}

func (s *stubPlatformScanAuditService) ListUnifiedFindings(_ context.Context, opts scanaudit.UnifiedFindingListOptions) ([]scanaudit.UnifiedFinding, error) {
	s.lastUnifiedOpts = opts
	if s.err != nil {
		return nil, s.err
	}
	return append([]scanaudit.UnifiedFinding(nil), s.unified...), nil
}

func (s *stubPlatformScanAuditService) ExportRecord(_ context.Context, namespace, runID string) (*scanaudit.ExportPackage, error) {
	s.lastNamespace = namespace
	s.lastRunID = runID
	if s.err != nil {
		return nil, s.err
	}
	return s.exportPackage, nil
}

func TestPlatformScanAuditHandlersUseServiceInterface(t *testing.T) {
	record := scanaudit.Record{
		Namespace:   "image_scan",
		RunID:       "image_scan:test",
		Kind:        "ecr",
		Status:      "succeeded",
		Stage:       "completed",
		SubmittedAt: time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 12, 1, 0, 0, time.UTC),
		Retention: scanaudit.RetentionPolicy{
			StorageClass:  "execution_store",
			RetentionTier: "audit",
		},
	}
	svc := &stubPlatformScanAuditService{
		records: []scanaudit.Record{record},
		unified: []scanaudit.UnifiedFinding{{
			ID:              "acme/platform|vulnerability|cve-2026-0002|log4j-core",
			AssetKey:        "acme/platform",
			Kind:            "vulnerability",
			Severity:        "high",
			Title:           "CVE-2026-0002",
			Namespaces:      []string{"image_scan", "repo_scan"},
			ScanKinds:       []string{"image", "repo"},
			DetectionKinds:  []string{"filesystem", "image_native"},
			OccurrenceCount: 2,
			FirstSeen:       time.Date(2026, 3, 21, 11, 0, 0, 0, time.UTC),
			LastSeen:        time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		}},
		record: &record,
		exportPackage: &scanaudit.ExportPackage{
			Manifest: scanaudit.ExportManifest{
				Namespace:   "image_scan",
				RunID:       "image_scan:test",
				GeneratedAt: time.Date(2026, 3, 21, 12, 2, 0, 0, time.UTC).Format(time.RFC3339),
				GeneratedBy: "cerebro",
			},
			Record: record,
		},
	}

	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })

	server.platformScanAudit = svc
	server.app.Config = nil
	server.app.ExecutionStore = nil

	listResp := do(t, server, http.MethodGet, "/api/v1/platform/scan-audit?namespace=image_scan,repo_scan&status=running&exclude_status=failed&limit=25&offset=5&order=submitted", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected list 200, got %d: %s", listResp.Code, listResp.Body.String())
	}
	if got := svc.lastListOpts; len(got.Namespaces) != 2 || got.Namespaces[0] != "image_scan" || got.Namespaces[1] != "repo_scan" {
		t.Fatalf("expected namespaces to flow through service, got %#v", got.Namespaces)
	}
	if got := svc.lastListOpts.Statuses; len(got) != 1 || got[0] != "running" {
		t.Fatalf("expected status filter to flow through service, got %#v", got)
	}
	if got := svc.lastListOpts.ExcludeStatuses; len(got) != 1 || got[0] != "failed" {
		t.Fatalf("expected exclude_status filter to flow through service, got %#v", got)
	}
	if svc.lastListOpts.Limit != 25 || svc.lastListOpts.Offset != 5 || !svc.lastListOpts.OrderBySubmittedAt {
		t.Fatalf("unexpected list options %#v", svc.lastListOpts)
	}

	unifiedResp := do(t, server, http.MethodGet, "/api/v1/platform/scan-audit/findings?namespace=image_scan,repo_scan&severity=high&kind=vulnerability&limit=25&offset=5", nil)
	if unifiedResp.Code != http.StatusOK {
		t.Fatalf("expected unified findings 200, got %d: %s", unifiedResp.Code, unifiedResp.Body.String())
	}
	if got := svc.lastUnifiedOpts; len(got.Namespaces) != 2 || got.Namespaces[0] != "image_scan" || got.Namespaces[1] != "repo_scan" {
		t.Fatalf("expected unified namespaces to flow through service, got %#v", got.Namespaces)
	}
	if got := svc.lastUnifiedOpts.Severities; len(got) != 1 || got[0] != "high" {
		t.Fatalf("expected unified severity filter to flow through service, got %#v", got)
	}
	if got := svc.lastUnifiedOpts.Kinds; len(got) != 1 || got[0] != "vulnerability" {
		t.Fatalf("expected unified kind filter to flow through service, got %#v", got)
	}
	if svc.lastUnifiedOpts.Limit != 25 || svc.lastUnifiedOpts.Offset != 5 {
		t.Fatalf("unexpected unified list options %#v", svc.lastUnifiedOpts)
	}

	detailResp := do(t, server, http.MethodGet, "/api/v1/platform/scan-audit/image_scan/image_scan:test", nil)
	if detailResp.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d: %s", detailResp.Code, detailResp.Body.String())
	}
	if svc.lastNamespace != "image_scan" || svc.lastRunID != "image_scan:test" {
		t.Fatalf("unexpected get target namespace/run_id = %q/%q", svc.lastNamespace, svc.lastRunID)
	}

	exportResp := do(t, server, http.MethodGet, "/api/v1/platform/scan-audit/image_scan/image_scan:test/export", nil)
	if exportResp.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d: %s", exportResp.Code, exportResp.Body.String())
	}
	if got := exportResp.Header().Get("Content-Type"); !strings.Contains(got, "application/zip") {
		t.Fatalf("expected zip content-type, got %q", got)
	}
	if got := exportResp.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment;") || !strings.Contains(got, "cerebro-scan-audit-image_scan-") {
		t.Fatalf("unexpected content-disposition %q", got)
	}
}

func TestPlatformScanAuditServiceReportsAvailabilityErrors(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		svc := newPlatformScanAuditService(nil)
		_, err := svc.ListRecords(t.Context(), scanaudit.ListOptions{})
		if !errors.Is(err, errPlatformScanAuditStoreNotConfigured) {
			t.Fatalf("expected not configured error, got %v", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		svc := newPlatformScanAuditService(&serverDependencies{
			Config: &app.Config{ExecutionStoreFile: t.TempDir()},
		})
		_, err := svc.ListRecords(t.Context(), scanaudit.ListOptions{})
		if !errors.Is(err, errPlatformScanAuditStoreUnavailable) {
			t.Fatalf("expected unavailable error, got %v", err)
		}
	})
}

func TestPlatformScanAuditHandlersRejectTenantScopedAccess(t *testing.T) {
	record := scanaudit.Record{
		Namespace:   "image_scan",
		RunID:       "image_scan:test",
		Kind:        "ecr",
		Status:      "succeeded",
		Stage:       "completed",
		SubmittedAt: time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		UpdatedAt:   time.Date(2026, 3, 21, 12, 1, 0, 0, time.UTC),
	}
	svc := &stubPlatformScanAuditService{
		records: []scanaudit.Record{record},
		record:  &record,
		exportPackage: &scanaudit.ExportPackage{
			Manifest: scanaudit.ExportManifest{
				Namespace:   "image_scan",
				RunID:       "image_scan:test",
				GeneratedAt: time.Date(2026, 3, 21, 12, 2, 0, 0, time.UTC).Format(time.RFC3339),
				GeneratedBy: "cerebro",
			},
			Record: record,
		},
	}

	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })
	server.platformScanAudit = svc

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "list records", path: "/api/v1/platform/scan-audit"},
		{name: "list findings", path: "/api/v1/platform/scan-audit/findings"},
		{name: "get record", path: "/api/v1/platform/scan-audit/image_scan/image_scan:test"},
		{name: "export record", path: "/api/v1/platform/scan-audit/image_scan/image_scan:test/export"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doWithTenantContext(t, server, http.MethodGet, tc.path, nil, "tenant-acme")
			if resp.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for tenant-scoped scan audit access, got %d: %s", resp.Code, resp.Body.String())
			}
		})
	}
}
