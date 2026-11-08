package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// chartReaderInsecureClient builds an *http.Client that trusts any TLS
// certificate, needed only because two independent httptest.NewTLSServer
// instances each mint their own self-signed cert (unlike server.Client(),
// which trusts exactly one server) -- these tests deliberately exercise
// cross-origin redirects/URLs between two such servers.
func chartReaderInsecureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- test-only client trusting two httptest.NewTLSServer self-signed certs, never used against real traffic.
}

// TestChartReaderFollowsAllowlistedRedirectForIndex reproduces the real
// charts.external-secrets.io finding: its index.yaml 302-redirects to a
// different host (external-secrets.io). A redirect is followed when the
// target is https and its own origin is independently allowlisted.
func TestChartReaderFollowsAllowlistedRedirectForIndex(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := sha256Hex(pkg)

	var target *httptest.Server
	origin := http.NewServeMux()
	origin.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/index.yaml", http.StatusFound)
	})
	originServer := httptest.NewTLSServer(origin)
	defer originServer.Close()

	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "entries:\n  sub:\n  - name: sub\n    version: 1.0.0\n    digest: %s\n    urls:\n    - sub-1.0.0.tgz\n", digest)
	})
	targetMux.HandleFunc("/sub-1.0.0.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	targetServer := httptest.NewTLSServer(targetMux)
	defer targetServer.Close()
	target = targetServer

	reader, err := NewChartReader(ChartReaderOptions{
		AllowedRepositories: []string{originServer.URL, targetServer.URL},
		AllowLoopback:       true,
		HTTPClient:          chartReaderInsecureClient(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: originServer.URL, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("expected the index.yaml redirect to an allowlisted origin to be followed, got: %v", err)
	}
	if repo.Pin.Digest != "sha256:"+digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
}

// TestChartReaderRefusesRedirectToUnallowlistedOrigin is the negative
// control: a redirect target whose own origin was never allowlisted is
// refused outright, never silently followed just because the original
// repository was allowlisted.
func TestChartReaderRefusesRedirectToUnallowlistedOrigin(t *testing.T) {
	var target *httptest.Server
	origin := http.NewServeMux()
	origin.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/index.yaml", http.StatusFound)
	})
	originServer := httptest.NewTLSServer(origin)
	defer originServer.Close()

	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "entries: {}\n")
	})
	targetServer := httptest.NewTLSServer(targetMux)
	defer targetServer.Close()
	target = targetServer

	reader, err := NewChartReader(ChartReaderOptions{
		AllowedRepositories: []string{originServer.URL},
		AllowLoopback:       true,
		HTTPClient:          chartReaderInsecureClient(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: originServer.URL, Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected the redirect to an unallowlisted origin to be refused")
	}
	if !errors.Is(err, ErrChartOriginNotAllowed) {
		t.Fatalf("expected ErrChartOriginNotAllowed, got: %v", err)
	}
}

// TestChartReaderAcceptsChartPackageURLOnIndependentlyAllowlistedOrigin
// reproduces the real pinned external-secrets/argocd-image-updater finding:
// a chart index names its package's tarball on a different host than the
// index itself (GitHub-Pages index + GitHub-Releases tarball), with no
// redirect involved at all. That different host is fetched when its own
// origin is independently allowlisted.
func TestChartReaderAcceptsChartPackageURLOnIndependentlyAllowlistedOrigin(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := sha256Hex(pkg)

	var pkgServer *httptest.Server
	indexMux := http.NewServeMux()
	indexMux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "entries:\n  sub:\n  - name: sub\n    version: 1.0.0\n    digest: %s\n    urls:\n    - %s/sub-1.0.0.tgz\n", digest, pkgServer.URL)
	})
	indexServer := httptest.NewTLSServer(indexMux)
	defer indexServer.Close()

	pkgMux := http.NewServeMux()
	pkgMux.HandleFunc("/sub-1.0.0.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	pkgTLS := httptest.NewTLSServer(pkgMux)
	defer pkgTLS.Close()
	pkgServer = pkgTLS

	reader, err := NewChartReader(ChartReaderOptions{
		AllowedRepositories: []string{indexServer.URL, pkgServer.URL},
		AllowLoopback:       true,
		HTTPClient:          chartReaderInsecureClient(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: indexServer.URL, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("expected the chart package URL on an independently allowlisted origin to be fetched, got: %v", err)
	}
	if repo.Pin.Digest != "sha256:"+digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
}

// TestChartReaderRejectsChartPackageURLOnUnallowlistedOrigin is the
// negative control: when the different host named by the index was never
// independently allowlisted, the fetch is refused rather than silently
// trusted just because the index itself was allowlisted.
func TestChartReaderRejectsChartPackageURLOnUnallowlistedOrigin(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := sha256Hex(pkg)

	var pkgServer *httptest.Server
	indexMux := http.NewServeMux()
	indexMux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "entries:\n  sub:\n  - name: sub\n    version: 1.0.0\n    digest: %s\n    urls:\n    - %s/sub-1.0.0.tgz\n", digest, pkgServer.URL)
	})
	indexServer := httptest.NewTLSServer(indexMux)
	defer indexServer.Close()

	pkgMux := http.NewServeMux()
	pkgMux.HandleFunc("/sub-1.0.0.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	pkgTLS := httptest.NewTLSServer(pkgMux)
	defer pkgTLS.Close()
	pkgServer = pkgTLS

	reader, err := NewChartReader(ChartReaderOptions{
		AllowedRepositories: []string{indexServer.URL},
		AllowLoopback:       true,
		HTTPClient:          chartReaderInsecureClient(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: indexServer.URL, Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected the chart package URL on an unallowlisted origin to be refused")
	}
	if !errors.Is(err, ErrChartOriginNotAllowed) {
		t.Fatalf("expected ErrChartOriginNotAllowed, got: %v", err)
	}
}

// TestChartReaderBoundsRedirectHops confirms redirect-following is bounded
// (chartMaxRedirects), not an unbounded/potentially-infinite loop, even
// when every hop stays within an allowlisted origin.
func TestChartReaderBoundsRedirectHops(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/index-1.yaml", http.StatusFound)
	})
	for i := 1; i <= chartMaxRedirects+2; i++ {
		i := i
		mux.HandleFunc(fmt.Sprintf("/index-%d.yaml", i), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("/index-%d.yaml", i+1), http.StatusFound)
		})
	}
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{server.URL}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: server.URL, Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected a bounded number of redirect hops to be enforced")
	}
	if !errors.Is(err, ErrChartRedirectLimitExceeded) {
		t.Fatalf("expected ErrChartRedirectLimitExceeded, got: %v", err)
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

// TestChartReaderOCIAnonymousBearerTokenChallenge reproduces a real
// public OCI registry (ghcr.io, public.ecr.aws, ...): the manifest and
// blob endpoints 401 with a WWW-Authenticate Bearer challenge even for an
// anonymous pull, and ReadChart must satisfy it (fetch a token from the
// challenge's own realm, retry with the token) rather than failing.
func TestChartReaderOCIAnonymousBearerTokenChallenge(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := "sha256:" + sha256Hex(pkg)
	const token = "anon-token-123"

	var realmURL string
	requireToken := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer "+token {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realmURL+`",service="registry.example.com",scope="repository:charts/sub:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("expected an anonymous (no Authorization header) token request, got %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("service") == "" || r.URL.Query().Get("scope") == "" {
			t.Fatalf("expected service/scope query parameters from the challenge, got %q", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
	mux.HandleFunc("/v2/charts/sub/manifests/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		manifest := map[string]any{
			"schemaVersion": 2,
			"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": "sha256:deadbeef", "size": 2},
			"layers":        []map[string]any{{"mediaType": ociChartLayerMediaType, "digest": digest, "size": len(pkg)}},
		}
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/v2/charts/sub/blobs/"+digest, func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		_, _ = w.Write(pkg)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	realmURL = server.URL + "/token"

	ociRepo := "oci://" + strings.TrimPrefix(server.URL, "https://") + "/charts"
	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{ociRepo}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: ociRepo, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("expected the anonymous Bearer-token challenge to be satisfied, got: %v", err)
	}
	if repo.Pin.Digest != digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
}

// TestChartReaderOCITokenRealmOnDifferentHost confirms the token realm may
// be a completely different host than the registry itself (a real,
// common pattern -- e.g. Docker Hub's registry-1.docker.io challenges
// with realm https://auth.docker.io/token), subject only to the same
// https/unsafe-host checks as any other fetch, never requiring the realm
// host itself to be allowlisted as a chart repository.
func TestChartReaderOCITokenRealmOnDifferentHost(t *testing.T) {
	pkg := buildTarGz(map[string]string{"sub/Chart.yaml": "apiVersion: v2\nname: sub\nversion: 1.0.0\n"})
	digest := "sha256:" + sha256Hex(pkg)
	const token = "cross-host-token"

	var realmURL string
	requireToken := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer "+token {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realmURL+`",service="registry.example.com",scope="repository:charts/sub:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	tokenMux := http.NewServeMux()
	tokenMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
	tokenServer := httptest.NewTLSServer(tokenMux)
	defer tokenServer.Close()
	realmURL = tokenServer.URL + "/token"

	regMux := http.NewServeMux()
	regMux.HandleFunc("/v2/charts/sub/manifests/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		manifest := map[string]any{
			"schemaVersion": 2,
			"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": "sha256:deadbeef", "size": 2},
			"layers":        []map[string]any{{"mediaType": ociChartLayerMediaType, "digest": digest, "size": len(pkg)}},
		}
		_ = json.NewEncoder(w).Encode(manifest)
	})
	regMux.HandleFunc("/v2/charts/sub/blobs/"+digest, func(w http.ResponseWriter, r *http.Request) {
		if !requireToken(w, r) {
			return
		}
		_, _ = w.Write(pkg)
	})
	regServer := httptest.NewTLSServer(regMux)
	defer regServer.Close()

	ociRepo := "oci://" + strings.TrimPrefix(regServer.URL, "https://") + "/charts"
	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{ociRepo}, AllowLoopback: true, HTTPClient: chartReaderInsecureClient()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo, err := reader.ReadChart(testContext(), ci.ChartReference{Repository: ociRepo, Name: "sub", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("expected a token realm on a different, non-allowlisted host to be fetched (only https/unsafe-host checks apply), got: %v", err)
	}
	if repo.Pin.Digest != digest {
		t.Fatalf("unexpected digest: %s", repo.Pin.Digest)
	}
}

// TestChartReaderOCIMalformedChallengeReturnsExplicitError covers two
// malformed-challenge shapes (missing realm, non-Bearer scheme): both must
// surface a clear, descriptive error -- never a panic, an infinite loop,
// or a silent empty-chart result.
func TestChartReaderOCIMalformedChallengeReturnsExplicitError(t *testing.T) {
	cases := []struct {
		name            string
		wwwAuthenticate string
		wantErr         error
	}{
		{"missing realm", `Bearer service="registry.example.com",scope="repository:charts/sub:pull"`, ErrOCIAuthChallengeMissingRealm},
		{"non-bearer scheme", `Basic realm="https://example.com/token"`, ErrOCIAuthChallengeUnsupportedScheme},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/v2/charts/sub/manifests/1.0.0", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("WWW-Authenticate", tc.wwwAuthenticate)
				w.WriteHeader(http.StatusUnauthorized)
			})
			server := httptest.NewTLSServer(mux)
			defer server.Close()

			ociRepo := "oci://" + strings.TrimPrefix(server.URL, "https://") + "/charts"
			reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{ociRepo}, AllowLoopback: true, HTTPClient: server.Client()})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: ociRepo, Name: "sub", Version: "1.0.0"})
			if err == nil {
				t.Fatalf("expected a malformed auth challenge to produce an explicit error")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error to wrap %v, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestChartReaderOCIUnallowlistedRepositoryNeverFetched confirms a
// not-allowlisted OCI repository is refused before any HTTP call --
// including the auth-challenge dance -- is ever made.
func TestChartReaderOCIUnallowlistedRepositoryNeverFetched(t *testing.T) {
	var fetched bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/charts/sub/manifests/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://example.com/token",service="registry.example.com",scope="repository:charts/sub:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	ociRepo := "oci://" + strings.TrimPrefix(server.URL, "https://") + "/charts"
	reader, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{"oci://trusted.example.com/charts"}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = reader.ReadChart(testContext(), ci.ChartReference{Repository: ociRepo, Name: "sub", Version: "1.0.0"})
	if err == nil {
		t.Fatalf("expected an error for a non-allowlisted OCI repository")
	}
	if fetched {
		t.Fatalf("expected the registry to never be contacted for a non-allowlisted repository")
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
	var aggregateErr *ErrArchiveAggregateBoundExceeded
	if !errors.As(err, &aggregateErr) {
		t.Fatalf("expected the aggregate decompressed byte bound to be enforced, got %v", err)
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
	var entryErr *ErrArchiveEntryBoundExceeded
	if !errors.As(err, &entryErr) {
		t.Fatalf("expected the %d directory headers plus 1 regular file (%d total) to exceed the %d entry bound, got %v", dirCount, dirCount+1, maxFiles, err)
	}
}
