package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	k8syaml "sigs.k8s.io/yaml"
)

const (
	chartDefaultMaxArchiveBytes int64 = 16 << 20
	chartDefaultMaxFiles              = 2048
	chartDefaultMaxEntryBytes   int64 = 8 << 20
	// chartDefaultMaxTotalBytes bounds the aggregate decompressed size
	// across every extracted entry, independent of the per-entry bound: a
	// highly compressible archive within the bounded compressed download
	// size could otherwise still expand toward an unbounded multiple of it
	// via many individually sub-limit entries.
	chartDefaultMaxTotalBytes int64 = 64 << 20
)

// ChartReaderOptions configures NewChartReader. AllowedRepositories is
// required and is matched against ChartReference.Repository by exact scheme
// plus host (and, for OCI, path prefix), never by substring/wildcard. No
// credentials are ever attached to a chart fetch; only public chart
// repositories/registries are supported.
type ChartReaderOptions struct {
	// AllowedRepositories lists exact Helm repository base URLs
	// ("https://charts.example.com") and/or OCI repository prefixes
	// ("oci://registry.example.com/charts") a ChartReference may name.
	AllowedRepositories []string
	// AllowLoopback permits fetches to loopback/private hosts. It exists
	// only for tests against an in-process fixture server and must never be
	// set from runtime configuration.
	AllowLoopback bool
	// HTTPClient is hardened with sourcehttp host-safety settings for every
	// request. A nil client uses the default transport.
	HTTPClient *http.Client
	// MaxArchiveBytes bounds one fetched chart package. Zero uses the
	// package default.
	MaxArchiveBytes int64
	// MaxFiles bounds the number of files extracted from one chart package.
	// Zero uses the package default.
	MaxFiles int
	// MaxEntryBytes bounds the decompressed size of any single archive
	// entry, enforced during the copy (the tar header's declared size is
	// never trusted). Zero uses the package default.
	MaxEntryBytes int64
	// MaxTotalBytes bounds the aggregate decompressed size across every
	// extracted entry in one chart package. Zero uses the package default.
	MaxTotalBytes int64
}

type chartReader struct {
	allowed       []string
	allowLoopback bool
	client        *http.Client
	maxArchive    int64
	maxFiles      int
	maxEntryBytes int64
	maxTotalBytes int64
}

// NewChartReader builds a ci.ChartReader that fetches an allowlisted,
// exact-version Helm chart from either a classic Helm HTTP(S) chart
// repository (index.yaml + packaged .tgz, verified against the index's
// published digest) or an OCI registry (manifest + chart content layer,
// verified against the manifest's declared digest), entirely in memory, with
// bounded, safe tar.gz extraction (no symlink/hardlink entries followed, no
// path traversal, no unbounded decompression).
func NewChartReader(options ChartReaderOptions) (ci.ChartReader, error) {
	if len(options.AllowedRepositories) == 0 {
		return nil, fmt.Errorf("cloudidentitysource: chart reader requires at least one allowed repository")
	}
	client := sourcehttp.HardenClient(options.HTTPClient, sourcehttp.ClientOptions{SourceID: ci.SourceID, Timeout: 30 * time.Second, AllowLoopback: options.AllowLoopback})
	r := &chartReader{
		allowed:       append([]string(nil), options.AllowedRepositories...),
		allowLoopback: options.AllowLoopback,
		client:        client,
		maxArchive:    options.MaxArchiveBytes,
		maxFiles:      options.MaxFiles,
		maxEntryBytes: options.MaxEntryBytes,
		maxTotalBytes: options.MaxTotalBytes,
	}
	if r.maxArchive <= 0 {
		r.maxArchive = chartDefaultMaxArchiveBytes
	}
	if r.maxFiles <= 0 {
		r.maxFiles = chartDefaultMaxFiles
	}
	if r.maxEntryBytes <= 0 {
		r.maxEntryBytes = chartDefaultMaxEntryBytes
	}
	if r.maxTotalBytes <= 0 {
		r.maxTotalBytes = chartDefaultMaxTotalBytes
	}
	return r, nil
}

func (r *chartReader) allow(repository string) bool {
	for _, a := range r.allowed {
		if a == repository {
			return true
		}
	}
	return false
}

func (r *chartReader) ReadChart(ctx context.Context, ref ci.ChartReference) (ci.Repository, error) {
	if ref.Name == "" || ref.Version == "" {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: chart reference requires an exact name and version")
	}
	if !r.allow(ref.Repository) {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: chart repository %q is not allowlisted", ref.Repository)
	}
	if strings.HasPrefix(ref.Repository, "oci://") {
		return r.readOCIChart(ctx, ref)
	}
	return r.readHTTPChart(ctx, ref)
}

// --- classic Helm HTTP(S) chart repository ---

type chartIndex struct {
	Entries map[string][]chartIndexEntry `json:"entries"`
}

type chartIndexEntry struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Digest  string   `json:"digest"`
	URLs    []string `json:"urls"`
}

func (r *chartReader) readHTTPChart(ctx context.Context, ref ci.ChartReference) (ci.Repository, error) {
	base := strings.TrimSuffix(ref.Repository, "/")
	indexBytes, err := r.getBounded(ctx, base+"/index.yaml")
	if err != nil {
		return ci.Repository{}, fmt.Errorf("fetch chart index: %w", err)
	}
	var index chartIndex
	if err := k8syaml.Unmarshal(indexBytes, &index); err != nil {
		return ci.Repository{}, fmt.Errorf("decode chart index: %w", err)
	}
	var match *chartIndexEntry
	for _, e := range index.Entries[ref.Name] {
		if e.Version == ref.Version {
			entry := e
			match = &entry
			break
		}
	}
	if match == nil || len(match.URLs) == 0 {
		return ci.Repository{}, fmt.Errorf("chart %s@%s was not found in repository index", ref.Name, ref.Version)
	}
	chartURL := match.URLs[0]
	if !strings.Contains(chartURL, "://") {
		chartURL = base + "/" + strings.TrimPrefix(chartURL, "/")
	}
	if !strings.HasPrefix(chartURL, base+"/") {
		return ci.Repository{}, fmt.Errorf("chart package URL %q is outside the allowlisted repository", chartURL)
	}
	pkg, err := r.getBounded(ctx, chartURL)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("fetch chart package: %w", err)
	}
	digest := manifestBytesDigest(pkg)
	expected := match.Digest
	if expected != "" {
		expectedNormalized := expected
		if !strings.Contains(expectedNormalized, ":") {
			expectedNormalized = "sha256:" + expectedNormalized
		}
		if expectedNormalized != digest {
			return ci.Repository{}, fmt.Errorf("chart package digest mismatch: index declared %s, fetched %s", expectedNormalized, digest)
		}
	}
	if ref.Digest != "" && ref.Digest != digest {
		return ci.Repository{}, fmt.Errorf("chart package digest mismatch: requested %s, fetched %s", ref.Digest, digest)
	}
	files, err := chartExtractTarGz(ctx, pkg, r.maxFiles, r.maxEntryBytes, r.maxTotalBytes)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("extract chart package: %w", err)
	}
	return ci.Repository{
		Pin:   ci.SourcePin{Repository: ref.Repository, Revision: ref.Version, Digest: digest, Exact: true},
		Files: files,
	}, nil
}

// --- OCI registry chart pull ---

type chartOCIManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Config        chartOCIDescriptor   `json:"config"`
	Layers        []chartOCIDescriptor `json:"layers"`
}

type chartOCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

const ociChartLayerMediaType = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

func (r *chartReader) readOCIChart(ctx context.Context, ref ci.ChartReference) (ci.Repository, error) {
	host, repoPath, err := chartParseOCIRepository(ref.Repository)
	if err != nil {
		return ci.Repository{}, err
	}
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", host, repoPath+"/"+ref.Name, ref.Version)
	manifestBytes, err := r.getBoundedAccept(ctx, manifestURL, "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
	if err != nil {
		return ci.Repository{}, fmt.Errorf("fetch OCI chart manifest: %w", err)
	}
	var manifest chartOCIManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ci.Repository{}, fmt.Errorf("decode OCI chart manifest: %w", err)
	}
	var layer *chartOCIDescriptor
	for _, l := range manifest.Layers {
		if l.MediaType == ociChartLayerMediaType {
			cur := l
			layer = &cur
			break
		}
	}
	if layer == nil && len(manifest.Layers) == 1 {
		layer = &manifest.Layers[0]
	}
	if layer == nil {
		return ci.Repository{}, fmt.Errorf("OCI chart manifest has no recognizable chart content layer")
	}
	blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", host, repoPath+"/"+ref.Name, layer.Digest)
	pkg, err := r.getBounded(ctx, blobURL)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("fetch OCI chart blob: %w", err)
	}
	digest := manifestBytesDigest(pkg)
	if layer.Digest != "" && layer.Digest != digest {
		return ci.Repository{}, fmt.Errorf("OCI chart blob digest mismatch: manifest declared %s, fetched %s", layer.Digest, digest)
	}
	if ref.Digest != "" && ref.Digest != digest {
		return ci.Repository{}, fmt.Errorf("OCI chart blob digest mismatch: requested %s, fetched %s", ref.Digest, digest)
	}
	files, err := chartExtractTarGz(ctx, pkg, r.maxFiles, r.maxEntryBytes, r.maxTotalBytes)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("extract OCI chart blob: %w", err)
	}
	return ci.Repository{
		Pin:   ci.SourcePin{Repository: ref.Repository, Revision: ref.Version, Digest: digest, Exact: true},
		Files: files,
	}, nil
}

func chartParseOCIRepository(repository string) (host, path string, err error) {
	trimmed := strings.TrimPrefix(repository, "oci://")
	u, parseErr := url.Parse("oci://" + trimmed)
	if parseErr != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid OCI repository %q", repository)
	}
	return u.Host, strings.Trim(u.Path, "/"), nil
}

// --- bounded HTTP fetch ---

func (r *chartReader) getBounded(ctx context.Context, rawURL string) ([]byte, error) {
	return r.getBoundedAccept(ctx, rawURL, "")
}

func (r *chartReader) getBoundedAccept(ctx context.Context, rawURL, accept string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-https chart fetch %q", rawURL)
	}
	if !r.allowLoopback && sourcecdk.IsUnsafeHost(u.Hostname()) {
		return nil, fmt.Errorf("refusing chart fetch to unsafe host %q", u.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d fetching %q", resp.StatusCode, rawURL)
	}
	limited := io.LimitReader(resp.Body, r.maxArchive+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > r.maxArchive {
		return nil, fmt.Errorf("response for %q exceeded the %d byte bound", rawURL, r.maxArchive)
	}
	return data, nil
}

// --- bounded, safe tar.gz extraction ---

// chartExtractTarGz extracts a gzip-compressed tar archive entirely in
// memory. Symlink and hardlink entries are rejected outright (never followed
// or written); every entry path is cleaned and must stay within the archive
// root; decompressed size is bounded per entry via io.LimitReader rather
// than trusting the tar header's declared size, and the total file count,
// per-entry byte count, and aggregate decompressed byte count across every
// entry are all bounded -- the per-entry bound alone cannot stop a highly
// compressible archive (many sub-limit entries) from expanding far past the
// bounded compressed download size. maxFiles bounds every tar header read
// from the stream, not just regular files: directories and any other
// non-regular entry still cost full header parsing and gzip decompression
// work and must not be able to bypass the budget by never being a regular
// file. Likewise every entry's declared body -- including directories and
// anything else that is not kept -- is drained through the same aggregate
// maxTotalBytes bound rather than left for the tar reader to silently
// discard an unbounded amount of decompressed data for when advancing past
// it. ctx is checked once per entry so a canceled scan stops promptly.
func chartExtractTarGz(ctx context.Context, data []byte, maxFiles int, maxEntryBytes, maxTotalBytes int64) ([]ci.SourceFile, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()
	tr := tar.NewReader(gzr)
	var files []ci.SourceFile
	count := 0
	var totalBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		count++
		if count > maxFiles {
			return nil, &ErrArchiveEntryBoundExceeded{Limit: maxFiles}
		}

		remaining := maxTotalBytes - totalBytes
		if remaining < 0 {
			remaining = 0
		}

		switch hdr.Typeflag {
		case tar.TypeReg:
			// fall through to extraction below
		case tar.TypeSymlink, tar.TypeLink:
			return nil, fmt.Errorf("refusing tar entry %q: symlink/hardlink entries are not supported", hdr.Name)
		default:
			// Directories and any other non-regular entry: still drain
			// the declared body through the aggregate bound instead of
			// leaving it for the tar reader to discard without limit.
			n, err := io.Copy(io.Discard, io.LimitReader(tr, remaining+1))
			if err != nil {
				return nil, fmt.Errorf("read tar entry %q: %w", hdr.Name, err)
			}
			totalBytes += n
			if totalBytes > maxTotalBytes {
				return nil, &ErrArchiveAggregateBoundExceeded{Limit: maxTotalBytes}
			}
			continue
		}
		rel, ok := chartSafeTarPath(hdr.Name)
		if !ok {
			return nil, fmt.Errorf("refusing tar entry %q: path escapes archive root", hdr.Name)
		}
		if rel == "" {
			continue
		}
		entryLimit := maxEntryBytes
		if remaining < entryLimit {
			entryLimit = remaining
		}
		limited := io.LimitReader(tr, entryLimit+1)
		content, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("read tar entry %q: %w", hdr.Name, err)
		}
		if int64(len(content)) > maxEntryBytes {
			return nil, fmt.Errorf("tar entry %q exceeded the %d byte bound", hdr.Name, maxEntryBytes)
		}
		totalBytes += int64(len(content))
		if totalBytes > maxTotalBytes {
			return nil, &ErrArchiveAggregateBoundExceeded{Limit: maxTotalBytes}
		}
		files = append(files, ci.SourceFile{Path: rel, Content: content, Digest: manifestBytesDigest(content)})
	}
	return files, nil
}

// chartSafeTarPath cleans a tar entry path, strips a single leading
// top-level directory component (the archive's chart-name wrapper
// directory, Helm packaging convention), and rejects any path that still
// escapes the archive root.
func chartSafeTarPath(name string) (string, bool) {
	clean := strings.TrimPrefix(name, "/")
	if strings.Contains(clean, "\\") {
		return "", false
	}
	if strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return "", false
	}
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) == 2 {
		return parts[1], true
	}
	return "", true
}
