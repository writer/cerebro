package imagescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/webhooks"
)

type fakeRegistry struct {
	name     string
	host     string
	manifest *scanner.ImageManifest
	vulns    []scanner.ImageVulnerability
	blobs    map[string][]byte
	blobErr  error
}

func (r *fakeRegistry) Name() string { return r.name }
func (r *fakeRegistry) RegistryHost() string {
	return r.host
}
func (r *fakeRegistry) QualifyImageRef(repo, tag string) string {
	return r.host + "/" + repo + ":" + tag
}
func (r *fakeRegistry) ListRepositories(context.Context) ([]scanner.Repository, error) {
	return nil, nil
}
func (r *fakeRegistry) ListTags(context.Context, string) ([]scanner.ImageTag, error) {
	return nil, nil
}
func (r *fakeRegistry) GetManifest(context.Context, string, string) (*scanner.ImageManifest, error) {
	return r.manifest, nil
}
func (r *fakeRegistry) GetVulnerabilities(context.Context, string, string) ([]scanner.ImageVulnerability, error) {
	return append([]scanner.ImageVulnerability(nil), r.vulns...), nil
}
func (r *fakeRegistry) DownloadBlob(_ context.Context, _ string, digest string) (io.ReadCloser, error) {
	if r.blobErr != nil {
		return nil, r.blobErr
	}
	data, ok := r.blobs[digest]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", digest)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type fakeFilesystemScanner struct {
	result *scanner.ContainerScanResult
	err    error
}

func (s fakeFilesystemScanner) ScanFilesystem(_ context.Context, _ string) (*scanner.ContainerScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type captureEmitter struct {
	events   []webhooks.EventType
	payloads []map[string]any
}

func (e *captureEmitter) EmitWithErrors(_ context.Context, eventType webhooks.EventType, data map[string]interface{}) error {
	e.events = append(e.events, eventType)
	if data == nil {
		e.payloads = append(e.payloads, nil)
	} else {
		payload := make(map[string]any, len(data))
		for key, value := range data {
			payload[key] = value
		}
		e.payloads = append(e.payloads, payload)
	}
	return nil
}

func TestSQLiteRunStoreRoundTripAndEvents(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Now().UTC()
	run := &RunRecord{
		ID:          "image_scan:test",
		Registry:    RegistryECR,
		Status:      RunStatusRunning,
		Stage:       RunStageAnalyze,
		Target:      ScanTarget{Registry: RegistryECR, Repository: "repo", Tag: "latest"},
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

func TestLocalMaterializerAppliesWhiteouts(t *testing.T) {
	layer1 := gzipTarLayer(t, map[string]string{
		"etc/os-release": "NAME=Ubuntu\n",
		"tmp/old.txt":    "old\n",
	}, nil)
	layer2 := gzipTarLayer(t, map[string]string{
		"tmp/new.txt": "new\n",
	}, []string{"tmp/.wh.old.txt"})

	manifest := &scanner.ImageManifest{
		Layers: []scanner.Layer{
			{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			{Digest: "sha256:two", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		},
	}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	artifact, _, err := materializer.Materialize(context.Background(), "image_scan:test", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		switch digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layer1)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layer2)), nil
		default:
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
	})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "etc", "os-release")); err != nil {
		t.Fatalf("expected os-release to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "tmp", "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected old.txt to be removed by whiteout, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifact.Path, "tmp", "new.txt")); err != nil {
		t.Fatalf("expected new.txt to exist: %v", err)
	}
}

func TestLocalMaterializerRejectsWriteThroughSymlinkParent(t *testing.T) {
	outsideDir := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outsideDir, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	layer1 := gzipTarEntries(t, []tarEntry{{
		name:     "linkdir",
		typeflag: tar.TypeSymlink,
		linkname: outsideDir,
	}})
	layer2 := gzipTarLayer(t, map[string]string{
		"linkdir/pwned.txt": "nope\n",
	}, nil)

	manifest := &scanner.ImageManifest{
		Layers: []scanner.Layer{
			{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			{Digest: "sha256:two", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		},
	}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	_, _, err := materializer.Materialize(context.Background(), "image_scan:symlink-write", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		switch digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layer1)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layer2)), nil
		default:
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink traversal error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected outside file to remain absent, got %v", err)
	}
}

func TestLocalMaterializerRejectsWhiteoutThroughSymlinkParent(t *testing.T) {
	outsideDir := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outsideDir, 0o750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	victimPath := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("keep\n"), 0o640); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	layer1 := gzipTarEntries(t, []tarEntry{{
		name:     "linkdir",
		typeflag: tar.TypeSymlink,
		linkname: outsideDir,
	}})
	layer2 := gzipTarEntries(t, []tarEntry{{
		name: ".wh.victim.txt",
		dir:  "linkdir",
	}})

	manifest := &scanner.ImageManifest{
		Layers: []scanner.Layer{
			{Digest: "sha256:one", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			{Digest: "sha256:two", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
		},
	}
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs"))
	_, _, err := materializer.Materialize(context.Background(), "image_scan:symlink-whiteout", manifest, func(_ context.Context, digest string) (io.ReadCloser, error) {
		switch digest {
		case "sha256:one":
			return io.NopCloser(bytes.NewReader(layer1)), nil
		case "sha256:two":
			return io.NopCloser(bytes.NewReader(layer2)), nil
		default:
			return nil, fmt.Errorf("unexpected digest %s", digest)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink traversal error, got %v", err)
	}
	if _, err := os.Stat(victimPath); err != nil {
		t.Fatalf("expected victim to remain after rejected whiteout, got %v", err)
	}
}

func TestRunnerRunImageScanPersistsLifecycleAndCleanup(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	layer := gzipTarLayer(t, map[string]string{
		"etc/os-release": "NAME=Ubuntu\n",
	}, nil)
	registry := &fakeRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		manifest: &scanner.ImageManifest{
			Digest:       "sha256:image",
			ConfigDigest: "sha256:config",
			Config: scanner.ImageConfig{
				OS:           "linux",
				Architecture: "amd64",
			},
			Layers: []scanner.Layer{
				{Digest: "sha256:layer", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			},
		},
		vulns: []scanner.ImageVulnerability{{
			CVE:              "CVE-2024-0001",
			Severity:         "high",
			Package:          "openssl",
			InstalledVersion: "1.0.0",
		}},
		blobs: map[string][]byte{
			"sha256:layer": layer,
		},
	}
	emitter := &captureEmitter{}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Registries:   []scanner.RegistryClient{registry},
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs")),
		Analyzer: FilesystemAnalyzer{
			Scanner: fakeFilesystemScanner{
				result: &scanner.ContainerScanResult{
					Vulnerabilities: []scanner.ImageVulnerability{{
						CVE:              "CVE-2024-0002",
						Severity:         "critical",
						Package:          "glibc",
						InstalledVersion: "2.31",
					}},
				},
			},
		},
		Events: emitter,
	})

	run, err := runner.RunImageScan(context.Background(), ScanRequest{
		ID: "image_scan:success",
		Target: ScanTarget{
			Registry:   RegistryECR,
			Repository: "repo",
			Tag:        "latest",
		},
	})
	if err != nil {
		t.Fatalf("run image scan: %v", err)
	}
	if run.Status != RunStatusSucceeded {
		t.Fatalf("expected succeeded run, got %s", run.Status)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report to be persisted")
	}
	if run.Analysis.Result.Summary.Total != 2 {
		t.Fatalf("expected merged vulnerabilities total 2, got %#v", run.Analysis.Result.Summary)
	}
	if run.Filesystem == nil || run.Filesystem.CleanedUpAt == nil {
		t.Fatalf("expected filesystem artifact to be cleaned up, got %#v", run.Filesystem)
	}
	if len(emitter.events) != 2 || emitter.events[0] != webhooks.EventSecurityImageScanStarted || emitter.events[1] != webhooks.EventSecurityImageScanCompleted {
		t.Fatalf("unexpected emitted events: %#v", emitter.events)
	}
	loaded, err := store.LoadRun(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load run: %v", err)
	}
	if loaded == nil || loaded.Status != RunStatusSucceeded {
		t.Fatalf("expected persisted succeeded run, got %#v", loaded)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("expected multiple lifecycle events, got %#v", events)
	}
}

func TestRunnerRunImageScanPreservesFilesystemVulnerabilityCountAcrossDedup(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	layer := gzipTarLayer(t, map[string]string{
		"etc/os-release": "NAME=Ubuntu\n",
	}, nil)
	duplicate := scanner.ImageVulnerability{
		CVE:              "CVE-2024-0001",
		Severity:         "high",
		Package:          "openssl",
		InstalledVersion: "1.0.0",
	}
	registry := &fakeRegistry{
		name: "gcr",
		host: "gcr.io",
		manifest: &scanner.ImageManifest{
			Digest:       "sha256:image",
			ConfigDigest: "sha256:config",
			Config: scanner.ImageConfig{
				OS:           "linux",
				Architecture: "amd64",
			},
			Layers: []scanner.Layer{
				{Digest: "sha256:layer", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			},
		},
		vulns: []scanner.ImageVulnerability{
			duplicate,
			duplicate,
		},
		blobs: map[string][]byte{
			"sha256:layer": layer,
		},
	}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Registries:   []scanner.RegistryClient{registry},
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs")),
		Analyzer: FilesystemAnalyzer{
			Scanner: fakeFilesystemScanner{
				result: &scanner.ContainerScanResult{
					Vulnerabilities: []scanner.ImageVulnerability{duplicate},
				},
			},
		},
	})

	run, err := runner.RunImageScan(context.Background(), ScanRequest{
		ID: "image_scan:dedup-counts",
		Target: ScanTarget{
			Registry:   RegistryGCR,
			Repository: "repo",
			Tag:        "latest",
		},
	})
	if err != nil {
		t.Fatalf("run image scan: %v", err)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report")
	}
	if run.Analysis.NativeVulnerabilityCount != 2 {
		t.Fatalf("expected native vulnerability count 2, got %d", run.Analysis.NativeVulnerabilityCount)
	}
	if run.Analysis.FilesystemVulnerabilityCount != 1 {
		t.Fatalf("expected filesystem vulnerability count 1, got %d", run.Analysis.FilesystemVulnerabilityCount)
	}
	if run.Analysis.Result.Summary.Total != 1 {
		t.Fatalf("expected one merged vulnerability, got %#v", run.Analysis.Result.Summary)
	}
}

func TestRunnerRunImageScanSanitizesPersistedAndEmittedErrors(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "image-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	registry := &fakeRegistry{
		name: "ecr",
		host: "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		manifest: &scanner.ImageManifest{
			Digest: "sha256:image",
			Layers: []scanner.Layer{
				{Digest: "sha256:layer", MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"},
			},
		},
		blobErr: &url.Error{
			Op:  "Get",
			URL: "https://registry.example.com/layer?X-Amz-Signature=secret&X-Amz-Credential=creds",
			Err: context.DeadlineExceeded,
		},
	}
	emitter := &captureEmitter{}
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Registries:   []scanner.RegistryClient{registry},
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "rootfs")),
		Events:       emitter,
	})

	run, err := runner.RunImageScan(context.Background(), ScanRequest{
		ID: "image_scan:redacted-error",
		Target: ScanTarget{
			Registry:   RegistryECR,
			Repository: "repo",
			Tag:        "latest",
		},
	})
	if err == nil {
		t.Fatal("expected scan failure")
	}
	if run == nil {
		t.Fatal("expected failed run record")
	}
	if strings.Contains(run.Error, "X-Amz-Signature=secret") || strings.Contains(run.Error, "X-Amz-Credential=creds") {
		t.Fatalf("expected run error to redact presigned query params, got %q", run.Error)
	}
	events, err := store.LoadEvents(context.Background(), run.ID)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	foundFailure := false
	for _, event := range events {
		if event.Status != RunStatusFailed {
			continue
		}
		foundFailure = true
		if strings.Contains(event.Message, "X-Amz-Signature=secret") || strings.Contains(event.Message, "X-Amz-Credential=creds") {
			t.Fatalf("expected persisted failure event to redact presigned query params, got %q", event.Message)
		}
	}
	if !foundFailure {
		t.Fatalf("expected failed lifecycle event, got %#v", events)
	}
	if len(emitter.payloads) == 0 {
		t.Fatal("expected emitted lifecycle payloads")
	}
	failedPayload := emitter.payloads[len(emitter.payloads)-1]
	errorValue, _ := failedPayload["error"].(string)
	if strings.Contains(errorValue, "X-Amz-Signature=secret") || strings.Contains(errorValue, "X-Amz-Credential=creds") {
		t.Fatalf("expected emitted failure payload to redact presigned query params, got %q", errorValue)
	}
}

func gzipTarLayer(t *testing.T, files map[string]string, extraEntries []string) []byte {
	t.Helper()
	entries := make([]tarEntry, 0, len(files)+len(extraEntries))
	for name, content := range files {
		entries = append(entries, tarEntry{
			name:     name,
			typeflag: tar.TypeReg,
			body:     []byte(content),
			mode:     0o644,
		})
	}
	for _, name := range extraEntries {
		entries = append(entries, tarEntry{
			name: name,
			mode: 0o000,
		})
	}
	return gzipTarEntries(t, entries)
}

type tarEntry struct {
	dir      string
	name     string
	typeflag byte
	linkname string
	body     []byte
	mode     int64
}

func gzipTarEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		name := entry.name
		if entry.dir != "" {
			name = filepath.Join(entry.dir, entry.name)
		}
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     name,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
			Typeflag: typeflag,
			Linkname: entry.linkname,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %s: %v", name, err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatalf("write tar content %s: %v", name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return archive.Bytes()
}
