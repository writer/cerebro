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
	"regexp"
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

// Typed sentinel errors for chart-fetch refusals. Tests assert on these via
// errors.Is so that user-facing wording can evolve without breaking the
// contract; the structural lint forbids matching on err.Error() content.
var (
	// ErrChartOriginNotAllowed is returned (wrapped) when a URL reached
	// OTHER than by the originally-configured/allowlisted repository
	// reference -- an HTTP redirect target, or a chart-package URL an
	// already-fetched index names on a different host -- has an origin
	// that was never independently allowlisted.
	ErrChartOriginNotAllowed = errors.New("cloudidentitysource: origin is not itself allowlisted")
	// ErrChartRedirectLimitExceeded is returned (wrapped) when a single
	// chart fetch follows more than chartMaxRedirects HTTP redirect hops.
	ErrChartRedirectLimitExceeded = errors.New("cloudidentitysource: chart fetch exceeded the redirect hop bound")
	// ErrOCIAuthChallengeMissingRealm is returned (wrapped) when an OCI
	// registry's WWW-Authenticate: Bearer challenge has no realm
	// parameter to fetch a token from.
	ErrOCIAuthChallengeMissingRealm = errors.New("cloudidentitysource: OCI auth challenge has no realm")
	// ErrOCIAuthChallengeUnsupportedScheme is returned (wrapped) when an
	// OCI registry's WWW-Authenticate challenge uses a scheme other than
	// Bearer.
	ErrOCIAuthChallengeUnsupportedScheme = errors.New("cloudidentitysource: OCI auth challenge scheme is not supported (only Bearer)")
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

// chartMaxRedirects bounds the number of HTTP redirect hops
// getBoundedAccept will follow for a single chart fetch.
const chartMaxRedirects = 5

// chartOriginAllowed reports whether rawURL's own origin (exact
// scheme+host, never substring/wildcard) matches the origin of an entry
// in r.allowed. This is the trust decision for any URL reached OTHER than
// by direct configuration -- a chart repository's HTTP redirect target
// (getBoundedAccept) or a chart-package URL an already-fetched,
// allowlisted index names on a different host (readHTTPChart): both are
// refused unless the target's own origin was independently, explicitly
// allowlisted, never followed/accepted just because it was reached from
// an already-allowlisted repository. OCI allowlist entries ("oci://...")
// never match here (chart fetches only redirect over https); they are
// simply skipped.
func (r *chartReader) chartOriginAllowed(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return false
	}
	for _, a := range r.allowed {
		au, err := url.Parse(a)
		if err != nil || au.Scheme != "https" {
			continue
		}
		if au.Host == u.Host {
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
	indexBytes, indexURL, err := r.getBounded(ctx, base+"/index.yaml")
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
		// A relative chart-package URL is resolved against the index
		// file's OWN (possibly redirected) fetch location, exactly like
		// an HTML relative link -- never against the originally
		// configured repository URL, which may no longer be where the
		// index content actually came from once a redirect was followed.
		indexBase, err := url.Parse(indexURL)
		if err != nil {
			return ci.Repository{}, fmt.Errorf("parse fetched index URL %q: %w", indexURL, err)
		}
		resolved, err := indexBase.Parse(chartURL)
		if err != nil {
			return ci.Repository{}, fmt.Errorf("resolve chart package URL %q against index URL %q: %w", chartURL, indexURL, err)
		}
		chartURL = resolved.String()
	}
	// A chart's own index is free to name its package on a different
	// host than the index itself (GitHub-Pages index + GitHub-Releases
	// tarball is a common, real publishing pattern -- the pinned
	// external-secrets and argocd-image-updater
	// subchart dependencies both use it); that different host is only
	// trusted when it is itself independently allowlisted, exactly like a
	// redirect target (chartOriginAllowed), never merely because the
	// already-trusted index named it.
	if !strings.HasPrefix(chartURL, base+"/") && !r.chartOriginAllowed(chartURL) {
		return ci.Repository{}, fmt.Errorf("chart package URL %q is outside the allowlisted repository: %w", chartURL, ErrChartOriginNotAllowed)
	}
	pkg, _, err := r.getBounded(ctx, chartURL)
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
	manifestBytes, err := r.ociFetch(ctx, ref.Repository, manifestURL, "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
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
	pkg, err := r.ociFetch(ctx, ref.Repository, blobURL, "")
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

// chartAuthChallengeError carries an OCI/Docker-distribution-spec 401
// response's WWW-Authenticate header so ociFetch can attempt the standard
// anonymous Bearer-token exchange real public OCI registries (ghcr.io,
// public.ecr.aws, ...) require even for anonymous pulls. It is never
// returned from readHTTPChart's plain Helm HTTP(S) path -- fetchOnce only
// returns it when callers pass a non-empty expectAuth, which only
// ociFetch does.
type chartAuthChallengeError struct {
	wwwAuthenticate string
}

func (e *chartAuthChallengeError) Error() string {
	return fmt.Sprintf("received 401 with WWW-Authenticate %q", e.wwwAuthenticate)
}

// chartOCIAuthChallengeParamPattern parses a standard OCI/Docker
// distribution Bearer challenge's comma-separated key="value" parameters,
// e.g. `Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="..."`.
var chartOCIAuthChallengeParamPattern = regexp.MustCompile(`(\w+)="([^"]*)"`)

// ociFetch performs a GET against an OCI distribution-spec endpoint,
// transparently handling the anonymous Bearer-token auth challenge real
// public OCI registries require even for anonymous pulls: on a 401 with a
// `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge, it
// fetches a token from the challenge's own realm (ociToken -- https only,
// the same host-safety checks as any other chart fetch, never
// loopback/private unless AllowLoopback, no credentials ever sent) and
// retries exactly once with the obtained token. repository is used only
// to report a precise error naming which allowlisted repository the
// challenge could not be satisfied for.
func (r *chartReader) ociFetch(ctx context.Context, repository, rawURL, accept string) ([]byte, error) {
	data, _, err := r.getBoundedAccept(ctx, rawURL, accept, true, "")
	var challenge *chartAuthChallengeError
	if errors.As(err, &challenge) {
		token, tokenErr := r.ociToken(ctx, challenge.wwwAuthenticate)
		if tokenErr != nil {
			return nil, fmt.Errorf("OCI registry %q requires authentication and the token challenge could not be satisfied: %w", repository, tokenErr)
		}
		data, _, err = r.getBoundedAccept(ctx, rawURL, accept, false, "Bearer "+token)
	}
	return data, err
}

// ociToken satisfies a Bearer auth challenge by fetching a token from its
// own realm: an anonymous GET (no Authorization header) with the
// challenge's service/scope parameters applied as query parameters,
// exactly as `docker pull`/`helm pull` do for a public, unauthenticated
// registry. The realm must itself be https and pass the same
// unsafe-host check as any other chart fetch; no further redirect from
// the realm is attempted unless its target is independently allowlisted
// (getBoundedAccept's normal redirect policy).
func (r *chartReader) ociToken(ctx context.Context, wwwAuthenticate string) (string, error) {
	if !strings.HasPrefix(wwwAuthenticate, "Bearer ") {
		return "", fmt.Errorf("challenge %q: %w", wwwAuthenticate, ErrOCIAuthChallengeUnsupportedScheme)
	}
	params := map[string]string{}
	for _, m := range chartOCIAuthChallengeParamPattern.FindAllStringSubmatch(wwwAuthenticate, -1) {
		params[m[1]] = m[2]
	}
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("challenge %q: %w", wwwAuthenticate, ErrOCIAuthChallengeMissingRealm)
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse token realm %q: %w", realm, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("refusing non-https token realm %q", realm)
	}
	if !r.allowLoopback && sourcecdk.IsUnsafeHost(u.Hostname()) {
		return "", fmt.Errorf("refusing token realm fetch to unsafe host %q", u.Hostname())
	}
	q := u.Query()
	if service := params["service"]; service != "" {
		q.Set("service", service)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()
	body, _, err := r.getBoundedAccept(ctx, u.String(), "application/json", false, "")
	if err != nil {
		return "", fmt.Errorf("fetch token from realm %q: %w", realm, err)
	}
	var parsed struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode token response from realm %q: %w", realm, err)
	}
	token := parsed.Token
	if token == "" {
		token = parsed.AccessToken
	}
	if token == "" {
		return "", fmt.Errorf("token response from realm %q had no token/access_token field", realm)
	}
	return token, nil
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

// getBounded fetches rawURL and returns its content alongside the final
// URL it was actually fetched from (identical to rawURL unless a redirect
// was followed) -- callers that resolve relative URLs found in the
// response (readHTTPChart's chart-package URL) must resolve against this
// final URL, not rawURL, per standard relative-link semantics.
func (r *chartReader) getBounded(ctx context.Context, rawURL string) ([]byte, string, error) {
	return r.getBoundedAccept(ctx, rawURL, "", false, "")
}

// getBoundedAccept fetches rawURL, following HTTP redirects exactly like
// Helm's own HTTP client does for both chart index and chart package
// fetches -- but bounded (chartMaxRedirects hops) and gated: a redirect is
// only followed when its target is https and the target's own origin is
// itself allowlisted (chartOriginAllowed), matching the identical trust
// decision readHTTPChart's chart-package-URL containment check makes for a
// chart-entry URL named on a different host. Anything else (non-https
// target, unallowlisted target origin, missing/unparseable Location, too
// many hops) is refused outright -- the caller surfaces this as a
// cloud_identity.manifest.chart_dependency_fetch_failed gap, never a
// silent drop. expectAuth and authorization are OCI-only (ociFetch): when
// expectAuth is true, a 401 response returns *chartAuthChallengeError
// instead of a plain error so the caller can attempt the anonymous
// Bearer-token exchange; authorization, when non-empty, is sent as the
// request's Authorization header on every hop.
func (r *chartReader) getBoundedAccept(ctx context.Context, rawURL, accept string, expectAuth bool, authorization string) ([]byte, string, error) {
	current := rawURL
	for redirects := 0; ; redirects++ {
		data, redirectTo, err := r.fetchOnce(ctx, current, accept, expectAuth, authorization)
		if err != nil {
			return nil, "", err
		}
		if redirectTo == "" {
			return data, current, nil
		}
		if redirects >= chartMaxRedirects {
			return nil, "", fmt.Errorf("chart fetch %q redirected to %q: %w", rawURL, redirectTo, ErrChartRedirectLimitExceeded)
		}
		current = redirectTo
	}
}

// fetchOnce performs a single, non-redirect-following GET of rawURL. A 3xx
// response returns ("", target, nil) with target validated (https, origin
// allowlisted) but not yet fetched -- getBoundedAccept's caller decides
// whether/how many more hops to take. Any other status outside 2xx, or a
// 3xx that fails validation, returns a descriptive error.
func (r *chartReader) fetchOnce(ctx context.Context, rawURL, accept string, expectAuth bool, authorization string) (data []byte, redirectTo string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme != "https" {
		return nil, "", fmt.Errorf("refusing non-https chart fetch %q", rawURL)
	}
	if !r.allowLoopback && sourcecdk.IsUnsafeHost(u.Hostname()) {
		return nil, "", fmt.Errorf("refusing chart fetch to unsafe host %q", u.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, "", fmt.Errorf("chart fetch %q redirected (status %d) with no Location header", rawURL, resp.StatusCode)
		}
		target, err := u.Parse(location)
		if err != nil {
			return nil, "", fmt.Errorf("chart fetch %q redirected to an unparseable location %q: %w", rawURL, location, err)
		}
		resolved := target.String()
		if target.Scheme != "https" {
			return nil, "", fmt.Errorf("refusing chart fetch %q: redirected to a non-https location %q", rawURL, resolved)
		}
		if !r.chartOriginAllowed(resolved) {
			return nil, "", fmt.Errorf("refusing chart fetch %q: redirected to %q: %w", rawURL, resolved, ErrChartOriginNotAllowed)
		}
		return nil, resolved, nil
	}
	if expectAuth && resp.StatusCode == http.StatusUnauthorized {
		return nil, "", &chartAuthChallengeError{wwwAuthenticate: resp.Header.Get("Www-Authenticate")}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("unexpected status %d fetching %q", resp.StatusCode, rawURL)
	}
	limited := io.LimitReader(resp.Body, r.maxArchive+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > r.maxArchive {
		return nil, "", fmt.Errorf("response for %q exceeded the %d byte bound", rawURL, r.maxArchive)
	}
	return body, "", nil
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
