package scanaudit

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/functionscan"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/repohistoryscan"
	"github.com/writer/cerebro/internal/reposcan"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/workloadscan"
)

func TestServiceListRecordsIncludesAllSupportedScanNamespaces(t *testing.T) {
	store := newTestExecutionStore(t)
	svc := NewService(store, Config{
		RetentionDays: 45,
		Now: func() time.Time {
			return time.Date(2026, 3, 21, 17, 45, 0, 0, time.UTC)
		},
	})

	runs := []struct {
		namespace   string
		runID       string
		submittedAt time.Time
		payload     any
	}{
		{
			namespace:   executionstore.NamespaceImageScan,
			runID:       "image_scan:list-image",
			submittedAt: time.Date(2026, 3, 21, 17, 0, 0, 0, time.UTC),
			payload: imagescan.RunRecord{
				ID:          "image_scan:list-image",
				Registry:    imagescan.RegistryECR,
				Status:      imagescan.RunStatusSucceeded,
				Stage:       imagescan.RunStageCompleted,
				Target:      imagescan.ScanTarget{Registry: imagescan.RegistryECR, RegistryHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "svc/image", Tag: "1.0.0"},
				RequestedBy: "alice",
				SubmittedAt: time.Date(2026, 3, 21, 17, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 3, 21, 17, 1, 0, 0, time.UTC),
			},
		},
		{
			namespace:   executionstore.NamespaceFunctionScan,
			runID:       "function_scan:list-function",
			submittedAt: time.Date(2026, 3, 21, 16, 0, 0, 0, time.UTC),
			payload: functionscan.RunRecord{
				ID:          "function_scan:list-function",
				Provider:    functionscan.ProviderAWS,
				Status:      functionscan.RunStatusSucceeded,
				Stage:       functionscan.RunStageCompleted,
				Target:      functionscan.FunctionTarget{Provider: functionscan.ProviderAWS, Region: "us-east-1", FunctionARN: "arn:aws:lambda:us-east-1:123456789012:function:payments"},
				RequestedBy: "bob",
				SubmittedAt: time.Date(2026, 3, 21, 16, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 3, 21, 16, 1, 0, 0, time.UTC),
			},
		},
		{
			namespace:   executionstore.NamespaceWorkloadScan,
			runID:       "workload_scan:list-workload",
			submittedAt: time.Date(2026, 3, 21, 15, 0, 0, 0, time.UTC),
			payload: workloadscan.RunRecord{
				ID:          "workload_scan:list-workload",
				Provider:    workloadscan.ProviderAWS,
				Status:      workloadscan.RunStatusSucceeded,
				Stage:       workloadscan.RunStageCompleted,
				Target:      workloadscan.VMTarget{Provider: workloadscan.ProviderAWS, Region: "us-east-1", InstanceID: "i-list"},
				ScannerHost: workloadscan.ScannerHost{HostID: "scanner-1", Region: "us-east-1"},
				RequestedBy: "carol",
				SubmittedAt: time.Date(2026, 3, 21, 15, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 3, 21, 15, 1, 0, 0, time.UTC),
			},
		},
		{
			namespace:   executionstore.NamespaceRepoScan,
			runID:       "repo_scan:list-repo",
			submittedAt: time.Date(2026, 3, 21, 14, 0, 0, 0, time.UTC),
			payload: reposcan.RunRecord{
				ID:          "repo_scan:list-repo",
				Status:      reposcan.RunStatusSucceeded,
				Stage:       reposcan.RunStageCompleted,
				Target:      reposcan.ScanTarget{Repository: "github.com/acme/infra", Ref: "main"},
				RequestedBy: "dave",
				SubmittedAt: time.Date(2026, 3, 21, 14, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 3, 21, 14, 1, 0, 0, time.UTC),
			},
		},
		{
			namespace:   executionstore.NamespaceRepoHistoryScan,
			runID:       "repo_history_scan:list-history",
			submittedAt: time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC),
			payload: repohistoryscan.RunRecord{
				ID:          "repo_history_scan:list-history",
				Status:      repohistoryscan.RunStatusSucceeded,
				Stage:       repohistoryscan.RunStageCompleted,
				Target:      repohistoryscan.ScanTarget{Repository: "github.com/acme/app", Ref: "main"},
				RequestedBy: "erin",
				SubmittedAt: time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC),
				UpdatedAt:   time.Date(2026, 3, 21, 13, 1, 0, 0, time.UTC),
			},
		},
		{
			namespace:   executionstore.NamespacePlatformReportRun,
			runID:       "report_run:ignored",
			submittedAt: time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC),
			payload:     map[string]any{"id": "report_run:ignored"},
		},
	}

	for _, run := range runs {
		saveRunEnvelope(t, store, run.namespace, run.runID, "test", "succeeded", "completed", run.submittedAt, run.submittedAt.Add(time.Minute), run.payload)
	}

	records, err := svc.ListRecords(context.Background(), ListOptions{
		Limit:              10,
		OrderBySubmittedAt: true,
	})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	if len(records) != 5 {
		t.Fatalf("expected 5 scan audit records, got %d", len(records))
	}

	got := make([]string, 0, len(records))
	for _, record := range records {
		got = append(got, record.Namespace)
	}
	want := []string{
		executionstore.NamespaceImageScan,
		executionstore.NamespaceFunctionScan,
		executionstore.NamespaceWorkloadScan,
		executionstore.NamespaceRepoScan,
		executionstore.NamespaceRepoHistoryScan,
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected namespaces %v, want %v", got, want)
	}
}

func TestServiceGetRecordProjectsConfigurationResultsExceptionsAndRetention(t *testing.T) {
	store := newTestExecutionStore(t)
	now := time.Date(2026, 3, 21, 17, 45, 0, 0, time.UTC)
	svc := NewService(store, Config{
		RetentionDays: 45,
		Now: func() time.Time {
			return now
		},
	})

	submittedAt := time.Date(2026, 3, 21, 16, 0, 0, 0, time.UTC)
	startedAt := submittedAt.Add(15 * time.Second)
	completedAt := submittedAt.Add(3 * time.Minute)
	run := imagescan.RunRecord{
		ID:             "image_scan:detail",
		Registry:       imagescan.RegistryECR,
		Status:         imagescan.RunStatusFailed,
		Stage:          imagescan.RunStageAnalyze,
		Target:         imagescan.ScanTarget{Registry: imagescan.RegistryECR, RegistryHost: "123456789012.dkr.ecr.us-east-1.amazonaws.com", Repository: "payments/api", Tag: "1.2.3", Digest: "sha256:abc123"},
		RequestedBy:    "analyst:alice",
		DryRun:         true,
		KeepFilesystem: true,
		Metadata:       map[string]string{"ticket": "INC-236"},
		SubmittedAt:    submittedAt,
		StartedAt:      &startedAt,
		CompletedAt:    &completedAt,
		UpdatedAt:      completedAt,
		Error:          "analysis failed while reading /var/lib/cerebro/scans/image_scan:detail/report.json",
		Layers: []imagescan.LayerArtifact{
			{Digest: "sha256:l1"},
			{Digest: "sha256:l2"},
		},
		Filesystem: &imagescan.FilesystemArtifact{
			Path:           "/var/lib/cerebro/scans/image_scan:detail/rootfs",
			MaterializedAt: startedAt,
			FileCount:      42,
			ByteSize:       2048,
			Retained:       true,
		},
		Analysis: &imagescan.AnalysisReport{
			Analyzer:                     "filesystem",
			NativeVulnerabilityCount:     2,
			FilesystemVulnerabilityCount: 3,
			Result: scanner.ContainerScanResult{
				Repository: "payments/api",
				Tag:        "1.2.3",
				Digest:     "sha256:abc123",
				Summary: scanner.VulnerabilitySummary{
					Critical: 1,
					High:     1,
					Total:    2,
					Fixable:  1,
				},
			},
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceImageScan, run.ID, string(run.Registry), string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)
	saveEvent(t, store, executionstore.NamespaceImageScan, run.ID, imagescan.RunEvent{
		Status:     imagescan.RunStatusRunning,
		Stage:      imagescan.RunStageMaterialize,
		Message:    "materializing image filesystem",
		Data:       map[string]any{"filesystem_path": "/var/lib/cerebro/scans/image_scan:detail/rootfs"},
		RecordedAt: submittedAt.Add(30 * time.Second),
	})
	saveEvent(t, store, executionstore.NamespaceImageScan, run.ID, imagescan.RunEvent{
		Status:     imagescan.RunStatusFailed,
		Stage:      imagescan.RunStageAnalyze,
		Message:    "failed to open /tmp/cerebro/image-scan/report.json",
		RecordedAt: completedAt,
	})

	record, ok, err := svc.GetRecord(context.Background(), executionstore.NamespaceImageScan, run.ID)
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if !ok {
		t.Fatal("expected record to be found")
	}

	if record.RequestedBy != "analyst:alice" {
		t.Fatalf("requested_by = %q, want analyst:alice", record.RequestedBy)
	}
	if got, ok := record.Configuration["dry_run"].(bool); !ok || !got {
		t.Fatalf("expected dry_run=true in configuration, got %#v", record.Configuration["dry_run"])
	}
	target, ok := record.Configuration["target"].(imagescan.ScanTarget)
	if !ok {
		t.Fatalf("expected image target in configuration, got %#v", record.Configuration["target"])
	}
	if target.Repository != "payments/api" {
		t.Fatalf("target repository = %q, want payments/api", target.Repository)
	}
	if got, ok := record.Results["layer_count"].(int); !ok || got != 2 {
		t.Fatalf("layer_count = %#v, want 2", record.Results["layer_count"])
	}
	if got, ok := record.Results["filesystem_retained"].(bool); !ok || !got {
		t.Fatalf("filesystem_retained = %#v, want true", record.Results["filesystem_retained"])
	}
	if got, ok := record.Results["filesystem_vulnerability_count"].(int); !ok || got != 3 {
		t.Fatalf("filesystem_vulnerability_count = %#v, want 3", record.Results["filesystem_vulnerability_count"])
	}
	if got, ok := record.Results["native_vulnerability_count"].(int); !ok || got != 2 {
		t.Fatalf("native_vulnerability_count = %#v, want 2", record.Results["native_vulnerability_count"])
	}
	if record.Retention.RetentionDays != 45 {
		t.Fatalf("retention days = %d, want 45", record.Retention.RetentionDays)
	}
	if record.Retention.RetainUntil == nil || !record.Retention.RetainUntil.Equal(submittedAt.Add(45*24*time.Hour)) {
		t.Fatalf("retain_until = %#v, want %s", record.Retention.RetainUntil, submittedAt.Add(45*24*time.Hour))
	}
	if len(record.Retention.Artifacts) != 1 || record.Retention.Artifacts[0].Type != "filesystem" || !record.Retention.Artifacts[0].Retained {
		t.Fatalf("unexpected retention artifacts %#v", record.Retention.Artifacts)
	}
	if len(record.Exceptions) != 2 {
		t.Fatalf("expected 2 exceptions, got %#v", record.Exceptions)
	}
	for _, item := range record.Exceptions {
		if strings.Contains(item.Message, "/tmp/") || strings.Contains(item.Message, "/var/lib/") {
			t.Fatalf("exception message leaked path: %q", item.Message)
		}
	}
	if len(record.Events) != 2 {
		t.Fatalf("expected 2 events, got %#v", record.Events)
	}
	if got, ok := record.Events[0].Data["filesystem_path"].(string); !ok || got != "<redacted-path>" {
		t.Fatalf("expected sanitized event data, got %#v", record.Events[0].Data["filesystem_path"])
	}
}

func TestServiceExportRecordRendersAuditZIP(t *testing.T) {
	store := newTestExecutionStore(t)
	now := time.Date(2026, 3, 21, 17, 45, 0, 0, time.UTC)
	svc := NewService(store, Config{
		RetentionDays: 30,
		Now: func() time.Time {
			return now
		},
	})

	run := reposcan.RunRecord{
		ID:           "repo_scan:export",
		Status:       reposcan.RunStatusFailed,
		Stage:        reposcan.RunStageAnalyze,
		Target:       reposcan.ScanTarget{Repository: "github.com/acme/infra", Ref: "main"},
		RequestedBy:  "developer:bob",
		KeepCheckout: true,
		Metadata:     map[string]string{"ticket": "SEC-236"},
		SubmittedAt:  time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 3, 21, 12, 2, 0, 0, time.UTC),
		Error:        "analysis failed for /tmp/cerebro/checkouts/repo_scan:export",
		Descriptor: &reposcan.RepositoryDescriptor{
			Repository:   "github.com/acme/infra",
			RequestedRef: "main",
			ResolvedRef:  "refs/heads/main",
			CommitSHA:    "deadbeef",
		},
		Checkout: &reposcan.CheckoutArtifact{Retained: true},
		Analysis: &reposcan.AnalysisReport{
			Analyzer:              "filesystem",
			IaCArtifactCount:      4,
			MisconfigurationCount: 2,
		},
	}
	saveRunEnvelope(t, store, executionstore.NamespaceRepoScan, run.ID, "iac", string(run.Status), string(run.Stage), run.SubmittedAt, run.UpdatedAt, run)
	saveEvent(t, store, executionstore.NamespaceRepoScan, run.ID, reposcan.RunEvent{
		Status:     reposcan.RunStatusFailed,
		Stage:      reposcan.RunStageAnalyze,
		Message:    "analyze step failed at /tmp/cerebro/checkouts/repo_scan:export",
		RecordedAt: run.UpdatedAt,
	})

	pkg, err := svc.ExportRecord(context.Background(), executionstore.NamespaceRepoScan, run.ID)
	if err != nil {
		t.Fatalf("ExportRecord: %v", err)
	}
	if pkg.Record.Namespace != executionstore.NamespaceRepoScan || pkg.Record.RunID != run.ID {
		t.Fatalf("unexpected export package record %#v", pkg.Record)
	}

	zipBytes, err := RenderExportPackageZIP(*pkg)
	if err != nil {
		t.Fatalf("RenderExportPackageZIP: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip payload invalid: %v", err)
	}
	entries := make(map[string]*zip.File, len(zr.File))
	for _, file := range zr.File {
		entries[file.Name] = file
	}
	for _, name := range []string{"manifest.json", "record.json", "events.json", "exceptions.json"} {
		if _, ok := entries[name]; !ok {
			t.Fatalf("missing zip entry %q", name)
		}
	}

	manifest := readZipJSONEntry(t, entries["manifest.json"])
	if manifest["namespace"] != executionstore.NamespaceRepoScan {
		t.Fatalf("manifest namespace = %#v, want %q", manifest["namespace"], executionstore.NamespaceRepoScan)
	}
	if manifest["generated_by"] != "cerebro" {
		t.Fatalf("manifest generated_by = %#v, want cerebro", manifest["generated_by"])
	}

	record := readZipJSONEntry(t, entries["record.json"])
	retention, ok := record["retention"].(map[string]any)
	if !ok {
		t.Fatalf("expected retention object in record export, got %#v", record["retention"])
	}
	if retention["retention_days"] != float64(30) {
		t.Fatalf("retention_days = %#v, want 30", retention["retention_days"])
	}
}

func newTestExecutionStore(t *testing.T) executionstore.Store {
	t.Helper()
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "execution.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func saveRunEnvelope(t *testing.T, store executionstore.Store, namespace, runID, kind, status, stage string, submittedAt, updatedAt time.Time, payload any) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal run payload: %v", err)
	}
	if err := store.UpsertRun(context.Background(), executionstore.RunEnvelope{
		Namespace:   namespace,
		RunID:       runID,
		Kind:        kind,
		Status:      status,
		Stage:       stage,
		SubmittedAt: submittedAt,
		UpdatedAt:   updatedAt,
		Payload:     encoded,
	}); err != nil {
		t.Fatalf("UpsertRun(%s/%s): %v", namespace, runID, err)
	}
}

func saveEvent(t *testing.T, store executionstore.Store, namespace, runID string, payload any) {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal event payload: %v", err)
	}
	if _, err := store.SaveEvent(context.Background(), executionstore.EventEnvelope{
		Namespace: namespace,
		RunID:     runID,
		Payload:   encoded,
	}); err != nil {
		t.Fatalf("SaveEvent(%s/%s): %v", namespace, runID, err)
	}
}

func readZipJSONEntry(t *testing.T, file *zip.File) map[string]any {
	t.Helper()
	rc, err := file.Open()
	if err != nil {
		t.Fatalf("Open(%s): %v", file.Name, err)
	}
	defer func() {
		_ = rc.Close()
	}()
	var body map[string]any
	if err := json.NewDecoder(rc).Decode(&body); err != nil {
		t.Fatalf("decode %s: %v", file.Name, err)
	}
	return body
}
