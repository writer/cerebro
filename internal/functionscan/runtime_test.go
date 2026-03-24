package functionscan

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scanpolicy"
	"github.com/writer/cerebro/internal/webhooks"
)

type fakeProvider struct {
	kind        ProviderKind
	descriptor  *FunctionDescriptor
	artifacts   map[string][]byte
	describeErr error
	openErr     error
}

func (p *fakeProvider) Kind() ProviderKind { return p.kind }

func (p *fakeProvider) DescribeFunction(context.Context, FunctionTarget) (*FunctionDescriptor, error) {
	if p.describeErr != nil {
		return nil, p.describeErr
	}
	return p.descriptor, nil
}

func (p *fakeProvider) OpenArtifact(_ context.Context, _ FunctionTarget, artifact ArtifactRef) (io.ReadCloser, error) {
	if p.openErr != nil {
		return nil, p.openErr
	}
	data, ok := p.artifacts[artifact.ID]
	if !ok {
		return nil, fmt.Errorf("artifact %s not found", artifact.ID)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type fakeFilesystemScanner struct {
	result *scanner.ContainerScanResult
	err    error
}

func (s fakeFilesystemScanner) ScanFilesystem(context.Context, string) (*scanner.ContainerScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type captureEmitter struct {
	events []webhooks.EventType
}

func (e *captureEmitter) EmitWithErrors(_ context.Context, eventType webhooks.EventType, _ map[string]interface{}) error {
	e.events = append(e.events, eventType)
	return nil
}

func TestSQLiteRunStoreRoundTripAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "function-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "function_scan:test",
		Provider:    ProviderAWS,
		Status:      RunStatusRunning,
		Stage:       RunStageAnalyze,
		Target:      FunctionTarget{Provider: ProviderAWS, Region: "us-east-1", FunctionName: "demo"},
		SubmittedAt: now,
		UpdatedAt:   now,
	}
	if err := store.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("save run: %v", err)
	}
	event, err := store.AppendEvent(context.Background(), run.ID, RunEvent{
		Status:     run.Status,
		Stage:      run.Stage,
		Message:    "analysis started",
		RecordedAt: now,
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	if event.Sequence != 1 {
		t.Fatalf("expected first event sequence 1, got %d", event.Sequence)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.ID != run.ID {
		t.Fatalf("expected loaded run %q, got %#v", run.ID, loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 || events[0].Message != "analysis started" {
		t.Fatalf("unexpected stored events: %#v", events)
	}
}

func TestLocalMaterializerAppliesLayersBeforeFunctionCode(t *testing.T) {
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	archiveDir, err := materializer.archiveDirPath("function_scan:test")
	if err != nil {
		t.Fatalf("archive dir path: %v", err)
	}
	descriptor := &FunctionDescriptor{
		Artifacts: []ArtifactRef{
			{ID: "layer", Kind: ArtifactLayer, Format: ArchiveFormatZIP},
			{ID: "function_code", Kind: ArtifactFunctionCode, Format: ArchiveFormatZIP},
		},
	}
	artifact, applied, err := materializer.Materialize(context.Background(), "function_scan:test", descriptor, func(_ context.Context, artifact ArtifactRef) (io.ReadCloser, error) {
		switch artifact.ID {
		case "layer":
			return io.NopCloser(bytes.NewReader(zipBytes(t, map[string]string{
				"opt/lib/shared.txt": "layer\n",
				"var/task/app.py":    "from layer import base\n",
			}))), nil
		case "function_code":
			return io.NopCloser(bytes.NewReader(zipBytes(t, map[string]string{
				"var/task/app.py": "print('function')\n",
			}))), nil
		default:
			return nil, fmt.Errorf("unexpected artifact %s", artifact.ID)
		}
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("expected two applied artifacts, got %d", len(applied))
	}
	data, err := os.ReadFile(filepath.Join(artifact.Path, "var", "task", "app.py"))
	if err != nil {
		t.Fatalf("read materialized file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "print('function')" {
		t.Fatalf("expected function code to override layer, got %q", string(data))
	}
	if _, err := os.Stat(archiveDir); !os.IsNotExist(err) {
		t.Fatalf("expected archive staging dir to be removed, got %v", err)
	}
}

func TestRunnerPersistsResultsAndEmitsLifecycleEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "function-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 11, 22, 0, 0, 0, time.UTC)
	emitter := &captureEmitter{}
	provider := &fakeProvider{
		kind: ProviderAWS,
		descriptor: &FunctionDescriptor{
			ID:         "arn:aws:lambda:us-east-1:123:function:demo",
			Name:       "demo",
			Runtime:    "python3.8",
			CodeSHA256: "sha256-demo",
			Environment: map[string]string{
				"DB_PASSWORD":              "supersecret-value",
				"AzureWebJobsStorage":      "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=supersecret",
				"FUNCTIONS_WORKER_RUNTIME": "python",
			},
			Artifacts: []ArtifactRef{
				{ID: "function_code", Kind: ArtifactFunctionCode, Format: ArchiveFormatZIP},
			},
		},
		artifacts: map[string][]byte{
			"function_code": zipBytes(t, map[string]string{
				"handler.py": "API_TOKEN = 'ghp_12345678901234567890'\n",
			}),
		},
	}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Providers:    []Provider{provider},
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs")),
		Analyzer: FilesystemAnalyzer{Scanner: fakeFilesystemScanner{result: &scanner.ContainerScanResult{
			Vulnerabilities: []scanner.ImageVulnerability{{
				ID:           "CVE-2026-0001",
				CVE:          "CVE-2026-0001",
				Severity:     "high",
				FixedVersion: "2.0.0",
			}},
		}}},
		Events: emitter,
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunFunctionScan(context.Background(), ScanRequest{
		Target: FunctionTarget{Provider: ProviderAWS, Region: "us-east-1", FunctionName: "demo"},
	})
	if err != nil {
		t.Fatalf("run function scan: %v", err)
	}
	if run.Status != RunStatusSucceeded || run.Stage != RunStageCompleted {
		t.Fatalf("expected succeeded run, got status=%s stage=%s", run.Status, run.Stage)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report")
	}
	if run.Analysis.EnvironmentSecretCount != 1 {
		t.Fatalf("expected one environment secret, got %d", run.Analysis.EnvironmentSecretCount)
	}
	if got := run.Descriptor.Environment["DB_PASSWORD"]; got != redactedSecretValue {
		t.Fatalf("expected persisted environment secret to be redacted, got %q", got)
	}
	if got := run.Descriptor.Environment["AzureWebJobsStorage"]; got != redactedSecretValue {
		t.Fatalf("expected non-allowlisted environment value to be redacted by default, got %q", got)
	}
	if got := run.Descriptor.Environment["FUNCTIONS_WORKER_RUNTIME"]; got != "python" {
		t.Fatalf("expected allowlisted runtime environment value to remain visible, got %q", got)
	}
	if run.Analysis.CodeSecretCount != 1 {
		t.Fatalf("expected one code secret, got %d", run.Analysis.CodeSecretCount)
	}
	if !run.Analysis.RuntimeDeprecated {
		t.Fatal("expected deprecated runtime finding")
	}
	if len(run.Analysis.Result.Vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability, got %d", len(run.Analysis.Result.Vulnerabilities))
	}
	if len(emitter.events) != 2 || emitter.events[0] != webhooks.EventSecurityFunctionScanStarted || emitter.events[1] != webhooks.EventSecurityFunctionScanCompleted {
		t.Fatalf("unexpected lifecycle events: %#v", emitter.events)
	}
	persisted, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load persisted run: %v", err)
	}
	if persisted == nil || persisted.Analysis == nil {
		t.Fatal("expected persisted run with analysis")
	}
}

func TestRedactSensitiveEnvDefaultsToRedaction(t *testing.T) {
	got := redactSensitiveEnv(map[string]string{
		"AzureWebJobsStorage":      "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=supersecret",
		"FUNCTIONS_WORKER_RUNTIME": "node",
		"EMPTY_VALUE":              "",
	})
	if got["AzureWebJobsStorage"] != redactedSecretValue {
		t.Fatalf("expected AzureWebJobsStorage to be redacted, got %q", got["AzureWebJobsStorage"])
	}
	if got["FUNCTIONS_WORKER_RUNTIME"] != "node" {
		t.Fatalf("expected allowlisted runtime key to remain visible, got %q", got["FUNCTIONS_WORKER_RUNTIME"])
	}
	if got["EMPTY_VALUE"] != "" {
		t.Fatalf("expected empty values to remain empty, got %q", got["EMPTY_VALUE"])
	}
}

func TestOpenHTTPArtifactSanitizesResponseBodyURLs(t *testing.T) {
	originalValidator := artifactURLValidator
	artifactURLValidator = func(string) error { return nil }
	defer func() { artifactURLValidator = originalValidator }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "download failed for https://example.com/object.zip?X-Amz-Signature=supersecret&X-Amz-Credential=abc")
	}))
	defer server.Close()

	_, err := openHTTPArtifact(context.Background(), server.Client(), server.URL)
	if err == nil {
		t.Fatal("expected artifact download error")
	}
	if strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("expected presigned query string to be redacted, got %q", err)
	}
	if !strings.Contains(err.Error(), "https://example.com/object.zip") {
		t.Fatalf("expected sanitized url to remain addressable, got %q", err)
	}
}

func TestOpenHTTPArtifactValidatesDialTarget(t *testing.T) {
	originalValidator := artifactURLValidator
	artifactURLValidator = func(string) error { return nil }
	defer func() { artifactURLValidator = originalValidator }()

	originalDialValidator := artifactDialTargetValidator
	callCount := 0
	artifactDialTargetValidator = func(host string) error {
		callCount++
		return fmt.Errorf("blocked dial target %s", host)
	}
	defer func() { artifactDialTargetValidator = originalDialValidator }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := openHTTPArtifact(context.Background(), server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked dial target") {
		t.Fatalf("expected dial target validation error, got %v", err)
	}
	if callCount == 0 {
		t.Fatal("expected dial target validator to be invoked")
	}
}

func TestLocalMaterializerRejectsOversizedArchiveEntry(t *testing.T) {
	originalEntryBytes := maxArchiveEntryBytes
	maxArchiveEntryBytes = 8
	defer func() { maxArchiveEntryBytes = originalEntryBytes }()

	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	descriptor := &FunctionDescriptor{
		Artifacts: []ArtifactRef{{ID: "function_code", Kind: ArtifactFunctionCode, Format: ArchiveFormatZIP}},
	}
	rootfsPath, err := materializer.rootfsPath("function_scan:oversized-entry")
	if err != nil {
		t.Fatalf("rootfs path: %v", err)
	}
	_, _, err = materializer.Materialize(context.Background(), "function_scan:oversized-entry", descriptor, func(_ context.Context, artifact ArtifactRef) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(zipBytes(t, map[string]string{
			"handler.py": "this payload is too large",
		}))), nil
	})
	if err == nil || !strings.Contains(err.Error(), "max extracted size") {
		t.Fatalf("expected max extracted size error, got %v", err)
	}
	if _, statErr := os.Stat(rootfsPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected rootfs path cleanup after failure, got %v", statErr)
	}
}

func TestLocalMaterializerRejectsOversizedDownload(t *testing.T) {
	originalDownloadBytes := maxArtifactDownloadBytes
	maxArtifactDownloadBytes = 16
	defer func() { maxArtifactDownloadBytes = originalDownloadBytes }()

	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	descriptor := &FunctionDescriptor{
		Artifacts: []ArtifactRef{{ID: "function_code", Kind: ArtifactFunctionCode, Format: ArchiveFormatZIP}},
	}
	rootfsPath, err := materializer.rootfsPath("function_scan:oversized-download")
	if err != nil {
		t.Fatalf("rootfs path: %v", err)
	}
	_, _, err = materializer.Materialize(context.Background(), "function_scan:oversized-download", descriptor, func(_ context.Context, artifact ArtifactRef) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), 32))), nil
	})
	if err == nil || !strings.Contains(err.Error(), "max download size") {
		t.Fatalf("expected max download size error, got %v", err)
	}
	if _, statErr := os.Stat(rootfsPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected rootfs path cleanup after failure, got %v", statErr)
	}
}

func TestRunnerRunFunctionScanRejectsPolicyViolationsBeforePersistence(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "function-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	allowDryRun := false
	policyEngine, err := scanpolicy.NewEngine([]scanpolicy.Policy{{
		ID:          "platform-function-policy",
		ScanKinds:   []scanpolicy.Kind{scanpolicy.KindFunction},
		Teams:       []string{"platform"},
		AllowDryRun: &allowDryRun,
	}})
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:           store,
		PolicyEvaluator: policyEngine,
	})

	_, err = runner.RunFunctionScan(context.Background(), ScanRequest{
		RequestedBy: "user:alice",
		Target: FunctionTarget{
			Provider:     ProviderAWS,
			Region:       "us-east-1",
			FunctionName: "demo",
		},
		DryRun: true,
		Metadata: map[string]string{
			"team": "platform",
		},
	})
	if err == nil {
		t.Fatal("expected policy validation error")
	}

	var validationErr *scanpolicy.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected validation error, got %T", err)
	}

	runs, err := store.ListRuns(context.Background(), RunListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 0 {
		t.Fatalf("expected no persisted runs, got %d", len(runs))
	}
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		writer, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := io.WriteString(writer, content); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}
