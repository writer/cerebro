package cloudidentitysource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/oauth2"
)

// ---- fake OCI distribution + ECR control-plane server ----

type fakeRegistryRequest struct {
	Method        string
	Path          string
	Authorization string
}

type fakeRegistry struct {
	mu                   sync.Mutex
	manifests            map[string][]byte
	manifestContentTypes map[string]string
	blobs                map[string][]byte
	requests             []fakeRegistryRequest
	ecrToken             string
	// ecrRepoMutability maps an ECR repository name to its
	// imageTagMutability for DescribeRepositories fake responses.
	ecrRepoMutability map[string]string
	// arRepositories maps "projects/{p}/locations/{l}/repositories/{r}" to
	// a raw Artifact Registry repository JSON response body.
	arRepositories map[string][]byte
	// ecrDescribeRepositoriesCalls/arRepositoryGetCalls count control-plane
	// repository-description calls, so tests can assert a tag-only
	// reference never even queries them (the removed tag-immutability
	// pinning path must stay dead code, not just unused).
	ecrDescribeRepositoriesCalls int
	arRepositoryGetCalls         int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		manifests:            map[string][]byte{},
		manifestContentTypes: map[string]string{},
		blobs:                map[string][]byte{},
		ecrToken:             base64.StdEncoding.EncodeToString([]byte("AWS:fake-ecr-password")),
		ecrRepoMutability:    map[string]string{},
		arRepositories:       map[string][]byte{},
	}
}

func (f *fakeRegistry) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeRegistry) setManifest(repo, ref string, body []byte, contentType string) {
	f.manifests[repo+"@"+ref] = body
	f.manifestContentTypes[repo+"@"+ref] = contentType
}

// setManifestByDigest registers body under its own computed digest, as a real
// registry does for digest-addressed pulls, and returns that digest.
func (f *fakeRegistry) setManifestByDigest(body []byte, contentType string) string {
	digest := computeDigest(body)
	f.setManifest("acme/widgets", digest, body, contentType)
	return digest
}

func (f *fakeRegistry) setBlob(repo, digest string, content []byte) {
	f.blobs[repo+"@"+digest] = content
}

// setECRRepositoryMutability registers the imageTagMutability
// DescribeRepositories must report for repo.
func (f *fakeRegistry) setECRRepositoryMutability(repo, mutability string) {
	f.mu.Lock()
	f.ecrRepoMutability[repo] = mutability
	f.mu.Unlock()
}

// setARRepository registers an Artifact Registry repository control-plane
// response for projects/{project}/locations/{location}/repositories/{repo}.
func (f *fakeRegistry) setARRepository(project, location, repo string, mode string, immutableTags bool) {
	body, err := json.Marshal(map[string]any{
		"name":   fmt.Sprintf("projects/%s/locations/%s/repositories/%s", project, location, repo),
		"format": "DOCKER",
		"mode":   mode,
		"dockerConfig": map[string]any{
			"immutableTags": immutableTags,
		},
	})
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	f.arRepositories[fmt.Sprintf("projects/%s/locations/%s/repositories/%s", project, location, repo)] = body
	f.mu.Unlock()
}

func (f *fakeRegistry) lastAuthorization() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return ""
	}
	return f.requests[len(f.requests)-1].Authorization
}

func (f *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, fakeRegistryRequest{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization")})
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/" && r.Header.Get("X-Amz-Target") == "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories":
		f.handleECRDescribeRepositories(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/":
		f.handleECRToken(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/projects/") && strings.Contains(r.URL.Path, "/repositories/"):
		f.handleARRepository(w, r)
	case strings.Contains(r.URL.Path, "/manifests/"):
		f.handleManifest(w, r)
	case strings.Contains(r.URL.Path, "/blobs/"):
		f.handleBlob(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeRegistry) ecrDescribeRepositoriesCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ecrDescribeRepositoriesCalls
}

func (f *fakeRegistry) arRepositoryGetCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.arRepositoryGetCalls
}

func (f *fakeRegistry) handleECRDescribeRepositories(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RepositoryNames []string `json:"repositoryNames"`
	}
	_ = json.NewDecoder(r.Body).Decode(&input)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ecrDescribeRepositoriesCalls++
	var repos []map[string]any
	for _, name := range input.RepositoryNames {
		mutability, ok := f.ecrRepoMutability[name]
		if !ok {
			continue
		}
		repos = append(repos, map[string]any{
			"repositoryName":     name,
			"imageTagMutability": mutability,
		})
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(map[string]any{"repositories": repos})
}

func (f *fakeRegistry) handleARRepository(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.mu.Lock()
	f.arRepositoryGetCalls++
	body, ok := f.arRepositories[key]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (f *fakeRegistry) handleECRToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"authorizationData": []map[string]any{
			{"authorizationToken": f.ecrToken, "proxyEndpoint": "https://123456789012.dkr.ecr.us-east-1.amazonaws.com"},
		},
	})
}

func (f *fakeRegistry) repoAndKeyFromPath(path, marker string) (repo, key string) {
	trimmed := strings.TrimPrefix(path, "/v2/")
	idx := strings.Index(trimmed, marker)
	if idx < 0 {
		return "", ""
	}
	return trimmed[:idx], trimmed[idx+len(marker):]
}

func (f *fakeRegistry) handleManifest(w http.ResponseWriter, r *http.Request) {
	repo, ref := f.repoAndKeyFromPath(r.URL.Path, "/manifests/")
	f.mu.Lock()
	body, ok := f.manifests[repo+"@"+ref]
	contentType := f.manifestContentTypes[repo+"@"+ref]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Docker-Content-Digest", computeDigest(body))
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (f *fakeRegistry) handleBlob(w http.ResponseWriter, r *http.Request) {
	repo, digest := f.repoAndKeyFromPath(r.URL.Path, "/blobs/")
	f.mu.Lock()
	content, ok := f.blobs[repo+"@"+digest]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func newTestImageConfig(labels map[string]string) []byte {
	var cfg ociImageConfig
	cfg.Config.Labels = labels
	body, err := json.Marshal(cfg)
	if err != nil {
		panic(err)
	}
	return body
}

func newTestManifest(configDigest string, configSize int) []byte {
	manifest := ociManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config:        ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: configDigest, Size: int64(configSize)},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return body
}

func newECRAWSConfig(server *httptest.Server) aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "SECRETTEST", ""),
		HTTPClient:  server.Client(),
	}
}

const ecrImageHost = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
const garImageHost = "us-docker.pkg.dev"

// ---- tests ----

func TestReadImageECRExactDigestPin(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{
		"org.opencontainers.image.source":   "https://github.com/acme/widgets",
		"org.opencontainers.image.revision": "abc123def456abc123def456abc123def456abc1",
	})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	manifestDigest := registry.setManifestByDigest(manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}

	image := ecrImageHost + "/acme/widgets:v1@" + manifestDigest
	provenance, err := reader.ReadImage(context.Background(), image)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Digest != manifestDigest {
		t.Fatalf("Digest = %q, want %q", provenance.Digest, manifestDigest)
	}
	if !provenance.Source.Exact {
		t.Fatalf("Source.Exact = false, want true (revision label present)")
	}
	if provenance.Source.Repository != "acme/widgets" {
		t.Fatalf("Source.Repository = %q, want acme/widgets", provenance.Source.Repository)
	}
	if provenance.Source.Revision != "abc123def456abc123def456abc123def456abc1" {
		t.Fatalf("Source.Revision = %q, want abc123def456abc123def456abc123def456abc1", provenance.Source.Revision)
	}
	if got := registry.lastAuthorization(); got != "Basic "+registry.ecrToken {
		t.Fatalf("last Authorization header = %q, want ECR basic token", got)
	}
}

func TestReadImageTagOnlyNeverPromotedToExact(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{
		"org.opencontainers.image.source":   "https://github.com/acme/widgets",
		"org.opencontainers.image.ref.name": "main",
	})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setManifest("acme/widgets", "latest", manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}

	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets:latest")
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Digest == "" {
		t.Fatalf("Digest is empty, want the fetched manifest digest even for a mutable tag")
	}
	if provenance.Source.Exact {
		t.Fatalf("Source.Exact = true, want false: a mutable tag must never be promoted to an exact pin")
	}
	if provenance.Source.Revision != "main" {
		t.Fatalf("Source.Revision = %q, want the inferred ref.name main", provenance.Source.Revision)
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.source_revision_inferred" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.source_revision_inferred gap, got %+v", provenance.Gaps)
	}
}

func TestReadImageDigestMismatchHardError(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "sha1"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setBlob("acme/widgets", configDigest, configBytes)

	// Simulate a registry response served under a digest reference that does
	// not match the content's own hash (corrupted/mismatched transport);
	// ReadImage must detect this rather than trust the requested digest.
	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	registry.setManifest("acme/widgets", wrongDigest, manifestBytes, "application/vnd.oci.image.manifest.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	_, err = reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+wrongDigest)
	var mismatchErr *ErrDigestMismatch
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("ReadImage() error = %v, want *ErrDigestMismatch", err)
	}
}

// TestReadImageChildManifestDigestMismatchRejected reproduces VAL item 2: a
// manifest index declares a child platform manifest's digest, but the bytes
// the registry actually serves under that digest hash to something else
// (corrupted mirror, cache poisoning, or a malicious registry). fetchManifest
// must hard-reject any digest-addressed fetch whose computed content digest
// does not match the requested digest, including child manifests fetched
// while resolving platform source agreement — never silently accept
// mismatched bytes as that platform's evidence.
func TestReadImageChildManifestDigestMismatchRejected(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	amd64Config := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	amd64ConfigDigest := computeDigest(amd64Config)
	registry.setBlob("acme/widgets", amd64ConfigDigest, amd64Config)
	amd64Manifest := newTestManifest(amd64ConfigDigest, len(amd64Config))
	amd64Digest := registry.setManifestByDigest(amd64Manifest, "application/vnd.oci.image.manifest.v1+json")

	// The arm64 entry's descriptor claims a digest that does not match the
	// bytes actually registered under it: the registry is lying about (or
	// has corrupted) this child manifest's content.
	armManifest := newTestManifest(amd64ConfigDigest, len(amd64Config))
	claimedARMDigest := "sha256:" + strings.Repeat("5", 64)
	registry.setManifest("acme/widgets", claimedARMDigest, armManifest, "application/vnd.oci.image.manifest.v1+json")

	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: claimedARMDigest, Size: int64(len(armManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "arm64"}},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: amd64Digest, Size: int64(len(amd64Manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v, want partial success (index itself is valid)", err)
	}
	if provenance.Source.Exact {
		t.Fatalf("Source.Exact = true, want false: the arm64 child manifest's declared digest does not match its served content and must not be trusted")
	}
	foundUnreadable := false
	foundMismatch := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.config_unavailable" {
			foundUnreadable = true
		}
		if gap.Code == "registry.source_revision_platform_mismatch" {
			foundMismatch = true
		}
	}
	if !foundUnreadable {
		t.Fatalf("expected a registry.config_unavailable gap for the digest-mismatched arm64 platform, got %+v", provenance.Gaps)
	}
	if !foundMismatch {
		t.Fatalf("expected registry.source_revision_platform_mismatch gap since one platform could not be verified, got %+v", provenance.Gaps)
	}
}

func TestReadImageUnsupportedRegistryHost(t *testing.T) {
	reader, err := NewRegistryReader(RegistryOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	_, err = reader.ReadImage(context.Background(), "docker.io/library/nginx:latest")
	if !errors.Is(err, ErrUnsupportedRegistryHost) {
		t.Fatalf("ReadImage() error = %v, want ErrUnsupportedRegistryHost", err)
	}
}

func TestReadImageMultiPlatformAgreementIsExact(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	// Both runnable platforms carry the same source revision label, so
	// ReadImage may assert an exact pin for the whole multi-arch image.
	sharedConfig := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	sharedConfigDigest := computeDigest(sharedConfig)
	registry.setBlob("acme/widgets", sharedConfigDigest, sharedConfig)

	amd64Manifest := newTestManifest(sharedConfigDigest, len(sharedConfig))
	amd64Digest := registry.setManifestByDigest(amd64Manifest, "application/vnd.oci.image.manifest.v1+json")
	armManifest := newTestManifest(sharedConfigDigest, len(sharedConfig))
	armDigest := registry.setManifestByDigest(armManifest, "application/vnd.oci.image.manifest.v1+json")

	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: armDigest, Size: int64(len(armManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "arm64"}},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: amd64Digest, Size: int64(len(amd64Manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
			// Attestation/signature-style entry with no real platform: must
			// be ignored, not treated as a disagreeing runnable variant.
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: armDigest, Size: int64(len(armManifest)), Platform: &ociPlatform{OS: "unknown", Architecture: "unknown"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Digest != indexDigest {
		t.Fatalf("Digest = %q, want the requested index's own digest %q, never a child manifest digest", provenance.Digest, indexDigest)
	}
	if !provenance.Source.Exact {
		t.Fatalf("Source.Exact = false, want true: every runnable platform agreed on the same revision")
	}
	if provenance.Source.Revision != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("Source.Revision = %q, want aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", provenance.Source.Revision)
	}
}

func TestReadImageMultiPlatformDisagreementNeverExact(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	amd64Config := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "amd64rev"})
	amd64ConfigDigest := computeDigest(amd64Config)
	registry.setBlob("acme/widgets", amd64ConfigDigest, amd64Config)
	amd64Manifest := newTestManifest(amd64ConfigDigest, len(amd64Config))
	amd64Digest := registry.setManifestByDigest(amd64Manifest, "application/vnd.oci.image.manifest.v1+json")

	armConfig := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "armrev"})
	armConfigDigest := computeDigest(armConfig)
	registry.setBlob("acme/widgets", armConfigDigest, armConfig)
	armManifest := newTestManifest(armConfigDigest, len(armConfig))
	armDigest := registry.setManifestByDigest(armManifest, "application/vnd.oci.image.manifest.v1+json")

	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: armDigest, Size: int64(len(armManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "arm64"}},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: amd64Digest, Size: int64(len(amd64Manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Digest != indexDigest {
		t.Fatalf("Digest = %q, want the requested index's own digest %q", provenance.Digest, indexDigest)
	}
	if provenance.Source.Exact {
		t.Fatalf("Source.Exact = true, want false: platforms disagree on source revision (amd64rev vs armrev), a default platform must never be certified")
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.source_revision_platform_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.source_revision_platform_mismatch gap, got %+v", provenance.Gaps)
	}
}

// TestReadImageTruncatedPlatformIndexNeverExact reproduces VAL item 3: a
// manifest index with more than maxPlatformManifestsForAgreement runnable
// platform entries is bounded for the agreement check, but entries past the
// bound are never actually verified, so even full agreement among the
// checked subset must never certify the whole multi-platform image as an
// exact pin.
func TestReadImageTruncatedPlatformIndexNeverExact(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	sharedConfig := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	sharedConfigDigest := computeDigest(sharedConfig)
	registry.setBlob("acme/widgets", sharedConfigDigest, sharedConfig)
	sharedManifest := newTestManifest(sharedConfigDigest, len(sharedConfig))
	sharedManifestDigest := registry.setManifestByDigest(sharedManifest, "application/vnd.oci.image.manifest.v1+json")

	// maxPlatformManifestsForAgreement+1 runnable entries all agree on the
	// same revision and would, without truncation, certify an exact pin.
	const platformCount = maxPlatformManifestsForAgreement + 1
	var manifests []ociDescriptor
	for i := range platformCount {
		manifests = append(manifests, ociDescriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    sharedManifestDigest,
			Size:      int64(len(sharedManifest)),
			Platform:  &ociPlatform{OS: "linux", Architecture: fmt.Sprintf("arch%d", i)},
		})
	}
	index := ociIndex{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: manifests}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Source.Exact {
		t.Fatalf("Source.Exact = true, want false: %d runnable platforms exceed the %d checked bound, so the unchecked ones cannot be certified", platformCount, maxPlatformManifestsForAgreement)
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.platform_manifests_truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.platform_manifests_truncated gap, got %+v", provenance.Gaps)
	}
}

func TestReadImageSourceLabelMissing(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(nil)
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setManifest("acme/widgets", "latest", manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets:latest")
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Source.Repository != "" || provenance.Source.Exact {
		t.Fatalf("Source = %+v, want a zero-value source pin", provenance.Source)
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.source_label_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.source_label_missing gap, got %+v", provenance.Gaps)
	}
}

func TestReadImagePartialRetrievalConfigUnavailable(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "rev"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	manifestDigest := registry.setManifestByDigest(manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	// Deliberately do not register the config blob: fetchBlob will 404.

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+manifestDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v, want partial success (no error)", err)
	}
	if provenance.Digest != manifestDigest {
		t.Fatalf("Digest = %q, want %q even though config fetch failed", provenance.Digest, manifestDigest)
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.config_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.config_unavailable gap, got %+v", provenance.Gaps)
	}
}

func TestReadImageGARUsesOAuth2AccessTokenBasicAuth(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "gar-rev"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setManifest("acme/widgets", "v1", manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp-access-token"})
	reader, err := NewRegistryReader(RegistryOptions{
		GoogleTokenSource:    tokenSource,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{garImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), garImageHost+"/acme/widgets:v1")
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Source.Revision != "gar-rev" {
		t.Fatalf("Source.Revision = %q, want gar-rev", provenance.Source.Revision)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("oauth2accesstoken:gcp-access-token"))
	if got := registry.lastAuthorization(); got != wantAuth {
		t.Fatalf("last Authorization header = %q, want %q", got, wantAuth)
	}
}

func TestReadImageGARWithoutTokenSourceErrors(t *testing.T) {
	reader, err := NewRegistryReader(RegistryOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	_, err = reader.ReadImage(context.Background(), garImageHost+"/acme/widgets:v1")
	if !errors.Is(err, ErrGoogleCredentialsNotConfigured) {
		t.Fatalf("ReadImage() error = %v, want ErrGoogleCredentialsNotConfigured", err)
	}
}

func TestECRClientPerAccountRoleAssumption(t *testing.T) {
	readerIface, err := NewRegistryReader(RegistryOptions{
		AWSConfig:   aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "SECRETTEST", "")},
		AWSRoleName: "cerebro-org-scan-role",
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	reader, ok := readerIface.(*registryReader)
	if !ok {
		t.Fatalf("NewRegistryReader() returned %T, want *registryReader", readerIface)
	}

	clientA1 := reader.ecrClient("111111111111", "us-east-1")
	clientA2 := reader.ecrClient("111111111111", "us-east-1")
	clientB := reader.ecrClient("222222222222", "us-east-1")
	if clientA1 != clientA2 {
		t.Fatal("ecrClient() returned a new client for a repeated (account, region) pair, want the cached instance")
	}
	if clientA1 == clientB {
		t.Fatal("ecrClient() returned the same client for two different accounts under AWSRoleName; cross-account reads must each assume their own account's role")
	}
}

func TestECRClientSharedWithoutRoleName(t *testing.T) {
	readerIface, err := NewRegistryReader(RegistryOptions{
		AWSConfig: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "SECRETTEST", "")},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	reader, ok := readerIface.(*registryReader)
	if !ok {
		t.Fatalf("NewRegistryReader() returned %T, want *registryReader", readerIface)
	}
	// Without AWSRoleName, a given region's client always uses the base
	// AWSConfig credentials directly, unchanged from single-account
	// behavior, regardless of which account ID is passed.
	clientA := reader.ecrClient("111111111111", "us-east-1")
	clientB := reader.ecrClient("222222222222", "us-east-1")
	if clientA == clientB {
		t.Fatal("ecrClient() unexpectedly shared a cache entry across distinct accountID cache keys")
	}
}

// TestReadImageGARTagNeverPinnedEvenWhenRepositoryIsImmutable reproduces the
// provenance counterexample: a workload was deployed from a mutable tag
// (the deployed digest was whatever the tag named at deploy time), the tag
// was later re-pointed to a different digest, and only afterward was the
// Artifact Registry repository's immutableTags flag turned on. A scan
// reading the tag today sees the current digest plus a currently-immutable
// repository; neither fact proves what the tag named when the workload was
// actually deployed, so DeploymentPinned must stay false and this adapter
// must never even query the Artifact Registry repositories.get API for a
// tag-only reference (that control-plane pinning path is dead code, not
// merely unused).
//
// Before the fix this exact fixture made ReadImage set
// DeploymentPinned=true (see TestReadImageGARImmutableStandardRepoPinnedTag
// in prior history) solely because the repository happened to enforce
// immutable tags at scan time.
func TestReadImageGARTagNeverPinnedEvenWhenRepositoryIsImmutable(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "main"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setManifest("myproject/myrepo/widgets", "v1", manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("myproject/myrepo/widgets", configDigest, configBytes)
	// Immutability enabled only after the (earlier, different-digest)
	// deployment happened; the production code must never consult this.
	registry.setARRepository("myproject", "us", "myrepo", "STANDARD_REPOSITORY", true)

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp-access-token"})
	reader, err := NewRegistryReader(RegistryOptions{
		GoogleTokenSource:    tokenSource,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL: map[string]string{
			garImageHost:                      server.URL,
			"artifactregistry.googleapis.com": server.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), garImageHost+"/myproject/myrepo/widgets:v1")
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.DeploymentPinned {
		t.Fatalf("DeploymentPinned = true, want false: a tag-only reference must never be pinned, regardless of current registry immutable-tag settings")
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.tag_not_pinned" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.tag_not_pinned gap, got %+v", provenance.Gaps)
	}
	if got := registry.arRepositoryGetCallCount(); got != 0 {
		t.Fatalf("Artifact Registry repositories.get calls = %d, want 0: tag-only pinning must never query repository immutability", got)
	}
}

// TestReadImageECRTagNeverPinnedEvenWhenRepositoryIsImmutable is the ECR
// counterpart: the same counterexample (deploy-time digest vs. current
// tag resolution) with imageTagMutability=IMMUTABLE, and ecr:DescribeRepositories
// must never even be called for a tag-only reference.
func TestReadImageECRTagNeverPinnedEvenWhenRepositoryIsImmutable(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.ref.name": "v1"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	registry.setManifest("acme/widgets", "v1", manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)
	registry.setECRRepositoryMutability("acme/widgets", "IMMUTABLE")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets:v1")
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.DeploymentPinned {
		t.Fatalf("DeploymentPinned = true, want false: a tag-only reference must never be pinned, regardless of current ECR imageTagMutability")
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.tag_not_pinned" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.tag_not_pinned gap, got %+v", provenance.Gaps)
	}
	if got := registry.ecrDescribeRepositoriesCallCount(); got != 0 {
		t.Fatalf("ecr:DescribeRepositories calls = %d, want 0: tag-only pinning must never query repository immutability", got)
	}
}

// TestReadImageIndexChildWithoutPlatformIsIncludedInAgreement reproduces
// the second R04 counterexample: a manifest index has a normal
// linux/amd64 child plus a second child that declares no "platform" object
// at all. Dropping any no-platform child as if it were an
// attestation/signature let a real, runnable, conflicting-revision image
// variant escape source agreement entirely, certifying an exact pin from
// the single checked (amd64) child alone. The no-platform child here is a
// genuine runnable image (its config has the standard OCI image config
// media type) with a DIFFERENT revision than the amd64 child, so it must
// now be read and must break agreement.
func TestReadImageIndexChildWithoutPlatformIsIncludedInAgreement(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	amd64Config := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	amd64ConfigDigest := computeDigest(amd64Config)
	registry.setBlob("acme/widgets", amd64ConfigDigest, amd64Config)
	amd64Manifest := newTestManifest(amd64ConfigDigest, len(amd64Config))
	amd64Digest := registry.setManifestByDigest(amd64Manifest, "application/vnd.oci.image.manifest.v1+json")

	// A real runnable image variant (standard image config media type) but
	// with NO platform object and a conflicting revision.
	noPlatformConfig := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	noPlatformConfigDigest := computeDigest(noPlatformConfig)
	registry.setBlob("acme/widgets", noPlatformConfigDigest, noPlatformConfig)
	noPlatformManifest := newTestManifest(noPlatformConfigDigest, len(noPlatformConfig))
	noPlatformDigest := registry.setManifestByDigest(noPlatformManifest, "application/vnd.oci.image.manifest.v1+json")

	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: amd64Digest, Size: int64(len(amd64Manifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: noPlatformDigest, Size: int64(len(noPlatformManifest))},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if provenance.Source.Exact {
		t.Fatalf("Source.Exact = true, want false: the no-platform child is a runnable image with a conflicting revision and must not be dropped before agreement")
	}
	found := false
	for _, gap := range provenance.Gaps {
		if gap.Code == "registry.source_revision_platform_mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected registry.source_revision_platform_mismatch gap, got %+v", provenance.Gaps)
	}
}

// TestReadImageAttestationManifestChildExcludedFromAgreement is the
// positive control for the index-children fix: a child entry that carries
// genuine non-runnable evidence (a Docker buildx-style attestation-manifest
// reference annotation, no platform object, and a non-image config media
// type) must still be excluded, so a real single-platform image's
// agreement is unaffected by its presence.
func TestReadImageAttestationManifestChildExcludedFromAgreement(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	imageConfig := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "cccccccccccccccccccccccccccccccccccccccc"})
	imageConfigDigest := computeDigest(imageConfig)
	registry.setBlob("acme/widgets", imageConfigDigest, imageConfig)
	imageManifest := newTestManifest(imageConfigDigest, len(imageConfig))
	imageDigest := registry.setManifestByDigest(imageManifest, "application/vnd.oci.image.manifest.v1+json")

	// An attestation manifest attached to the index: no platform, a
	// non-image (in-toto) config media type, and a buildx-style reference
	// annotation naming the subject it attests to.
	attestationManifest := ociManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config:        ociDescriptor{MediaType: "application/vnd.in-toto+json", Digest: "sha256:" + strings.Repeat("9", 64), Size: 2},
	}
	attestationBytes, err := json.Marshal(attestationManifest)
	if err != nil {
		t.Fatalf("marshal attestation manifest: %v", err)
	}
	attestationDigest := registry.setManifestByDigest(attestationBytes, "application/vnd.oci.image.manifest.v1+json")

	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.index.v1+json",
		Manifests: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: imageDigest, Size: int64(len(imageManifest)), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}},
			{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: attestationDigest, Size: int64(len(attestationBytes)), Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": imageDigest}},
		},
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	indexDigest := registry.setManifestByDigest(indexBytes, "application/vnd.oci.image.index.v1+json")

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+indexDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if !provenance.Source.Exact {
		t.Fatalf("Source.Exact = false, want true: the attestation-manifest child must be excluded, leaving the single real image variant agreeing with itself")
	}
	if provenance.Source.Revision != "cccccccccccccccccccccccccccccccccccccccc" {
		t.Fatalf("Source.Revision = %q, want the image child's revision", provenance.Source.Revision)
	}
}

// TestReadImageDigestReferenceNeverUsesRegistryMutabilityCheck ensures a
// digest-qualified reference's DeploymentPinned stays derived solely from
// the verified digest, never from (or gated behind) a registry mutability
// lookup: the ECR control plane is never even queried.
func TestReadImageDigestReferenceNeverUsesRegistryMutabilityCheck(t *testing.T) {
	registry := newFakeRegistry()
	server := registry.server()
	defer server.Close()

	configBytes := newTestImageConfig(map[string]string{"org.opencontainers.image.source": "https://github.com/acme/widgets", "org.opencontainers.image.revision": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"})
	configDigest := computeDigest(configBytes)
	manifestBytes := newTestManifest(configDigest, len(configBytes))
	manifestDigest := registry.setManifestByDigest(manifestBytes, "application/vnd.oci.image.manifest.v1+json")
	registry.setBlob("acme/widgets", configDigest, configBytes)
	// Deliberately do not register ECR repository mutability: a digest
	// reference must never need it.

	reader, err := NewRegistryReader(RegistryOptions{
		AWSConfig:            newECRAWSConfig(server),
		ECRBaseEndpoint:      server.URL,
		HTTPClient:           server.Client(),
		AllowLoopbackBaseURL: true,
		RegistryBaseURL:      map[string]string{ecrImageHost: server.URL},
	})
	if err != nil {
		t.Fatalf("NewRegistryReader() error = %v", err)
	}
	provenance, err := reader.ReadImage(context.Background(), ecrImageHost+"/acme/widgets@"+manifestDigest)
	if err != nil {
		t.Fatalf("ReadImage() error = %v", err)
	}
	if !provenance.DeploymentPinned {
		t.Fatalf("DeploymentPinned = false, want true for a verified digest reference")
	}
}
