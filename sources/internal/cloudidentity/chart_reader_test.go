package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestChartReaderHelmRepositoryIndexFetch(t *testing.T) {
	pkg := buildTarGz(map[string]string{
		"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n",
	})
	digest := sha256Hex(pkg)

	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "entries:\n  sub:\n  - name: sub\n    version: 1.0.0\n    digest: %s\n    urls:\n    - sub-1.0.0.tgz\n", digest)
	})
	mux.HandleFunc("/sub-1.0.0.tgz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pkg)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	reader, err := NewChartReader(ChartReaderOptions{
		AllowedRepositories: []string{server.URL},
		AllowLoopback:       true,
		HTTPClient:          server.Client(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: server.URL, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.Pin.Digest != "sha256:"+digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
	if !repo.Pin.Exact {
		t.Fatalf("expected Exact=true for a digest-verified fetch")
	}
	found := false
	for _, f := range repo.Files {
		if f.Path == "Chart.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the chart's top-level wrapper directory to be stripped, got %+v", repo.Files)
	}
}

func TestChartReaderHelmRepositoryDigestMismatchRejected(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "entries:\n  sub:\n  - name: sub\n    version: 1.0.0\n    digest: 0000000000000000000000000000000000000000000000000000000000000000\n    urls:\n    - sub-1.0.0.tgz\n")
	})
	mux.HandleFunc("/sub-1.0.0.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{server.URL}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: server.URL, Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected a digest mismatch error")
	}
}

func TestChartReaderRejectsUnallowlistedRepository(t *testing.T) {
	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{"https://trusted.example.com"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: "https://untrusted.example.com", Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected an error for a non-allowlisted repository")
	}
}

func TestChartReaderOCIManifestAndBlobFetch(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := "sha256:" + sha256Hex(pkg)

	mux := http.NewServeMux()
	mux.HandleFunc("/v2/charts/sub/manifests/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		manifest := map[string]any{
			"schemaVersion": 2,
			"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": "sha256:deadbeef", "size": 2},
			"layers": []map[string]any{
				{"mediaType": ociChartLayerMediaType, "digest": digest, "size": len(pkg)},
			},
		}
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/v2/charts/sub/blobs/"+digest, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ociRepo := "oci://" + strings.TrimPrefix(server.URL, "https://") + "/charts"
	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{ociRepo}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: ociRepo, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.Pin.Digest != digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
}

func TestChartExtractTarGzRejectsSymlinks(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "sub/evil", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	_ = tw.Close()
	_ = gz.Close()

	_, err := chartExtractTarGz(testContext(), buf.Bytes(), 100, 1<<20, 1<<20)
	if err == nil {
		t.Fatalf("expected symlink entries to be rejected")
	}
}

func TestChartExtractTarGzRejectsPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("malicious")
	_ = tw.WriteHeader(&tar.Header{Name: "sub/../../etc/passwd", Typeflag: tar.TypeReg, Size: int64(len(content))})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()

	_, err := chartExtractTarGz(testContext(), buf.Bytes(), 100, 1<<20, 1<<20)
	if err == nil {
		t.Fatalf("expected a path-traversal tar entry to be rejected")
	}
}

func TestChartExtractTarGzEnforcesEntryByteBound(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/big.txt": strings.Repeat("a", 1024)})
	_, err := chartExtractTarGz(testContext(), pkg, 100, 100, 1<<20)
	if err == nil {
		t.Fatalf("expected an entry exceeding the byte bound to be rejected")
	}
}

func TestChartExtractTarGzEnforcesAggregateByteBound(t *testing.T) {
	// Many individually sub-per-entry-limit files whose combined
	// decompressed size exceeds the aggregate bound: the per-entry bound
	// alone would accept every one of them.
	files := make(map[string]string, 50)
	for i := range 50 {
		files[fmt.Sprintf("sub/file-%02d.txt", i)] = strings.Repeat("a", 1000)
	}
	pkg := buildTarGz(files)
	_, err := chartExtractTarGz(testContext(), pkg, 100, 2000, 10000)
	if err == nil {
		t.Fatalf("expected the aggregate decompressed byte bound to be enforced")
	}
	if !strings.Contains(err.Error(), "aggregate decompressed byte bound") {
		t.Fatalf("expected an aggregate decompressed byte bound error, got %v", err)
	}
}

// TestChartExtractTarGzCountsDirectoryHeadersAgainstEntryBound reproduces
// the R18 static finding: only TypeReg entries incremented the file-count
// budget, so an archive padded with thousands of directory headers (which
// still cost full tar-header parsing and gzip decompression work) could
// sail past maxFiles entirely as long as the number of actual regular
// files stayed low.
func TestChartExtractTarGzCountsDirectoryHeadersAgainstEntryBound(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	const dirCount = 5000
	for i := range dirCount {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("sub/dir%05d/", i), Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatalf("write dir header: %v", err)
		}
	}
	content := []byte("apiVersion: v2\n")
	if err := tw.WriteHeader(&tar.Header{Name: "sub/Chart.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatalf("write reg header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write reg content: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()

	const maxFiles = 100 // far fewer than dirCount+1 total headers
	_, err := chartExtractTarGz(testContext(), buf.Bytes(), maxFiles, 1<<20, 1<<20)
	if err == nil {
		t.Fatalf("expected the %d directory headers plus 1 regular file (%d total) to exceed the %d entry bound", dirCount, dirCount+1, maxFiles)
	}
	if !strings.Contains(err.Error(), "entry bound") {
		t.Fatalf("expected an entry-bound error, got %v", err)
	}
}
