package cloudidentitysource

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReadModuleGitHubShorthandDelegatesToRepositoryTree(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "modules", "v1.2.3", "a1a1000000000000000000000000000000000a")
	fake.setRepoPrivate("acme", "modules", false)
	entry, sha := blobEntry("modules/foo/main.tf", []byte("module content"))
	fake.setBlob(sha, []byte("module content"))
	fake.setTree("acme", "modules", "a1a1000000000000000000000000000000000a", false, []fakeTreeEntry{entry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, err := AsModuleReader(reader)
	if err != nil {
		t.Fatalf("AsModuleReader() error = %v", err)
	}

	repo, err := moduleReader.ReadModule(context.Background(), "github.com/acme/modules//modules/foo", "v1.2.3")
	if err != nil {
		t.Fatalf("ReadModule() error = %v", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "modules/foo/main.tf" {
		t.Fatalf("Files = %+v, want modules/foo/main.tf", repo.Files)
	}
	if repo.Pin.Revision != "a1a1000000000000000000000000000000000a" {
		t.Fatalf("Pin.Revision = %q, want resolved commit", repo.Pin.Revision)
	}
}

func TestReadModuleEmptyVersionRefused(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "github.com/acme/modules", "")
	if !errors.Is(err, ErrRevisionRequired) {
		t.Fatalf("ReadModule() error = %v, want ErrRevisionRequired", err)
	}
}

func TestReadModuleGitHubNotAllowlisted(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "github.com/evil/other", "v1.0.0")
	if !errors.Is(err, ErrModuleNotAllowed) {
		t.Fatalf("ReadModule() error = %v, want ErrModuleNotAllowed", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("expected no HTTP calls for denied module, got %v", fake.requests)
	}
}

func TestReadModuleRegistryResolution(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("acme-ns", "vpc", "aws", "3.1.0", "git::https://github.com/acme/modules.git?ref=v3.1.0")
	fake.setCommit("acme", "modules", "v3.1.0", "b2b2000000000000000000000000000000000b")
	fake.setRepoPrivate("acme", "modules", false)
	entry, sha := blobEntry("main.tf", []byte("vpc module"))
	fake.setBlob(sha, []byte("vpc module"))
	fake.setTree("acme", "modules", "b2b2000000000000000000000000000000000b", false, []fakeTreeEntry{entry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)

	repo, err := moduleReader.ReadModule(context.Background(), "acme-ns/vpc/aws", "3.1.0")
	if err != nil {
		t.Fatalf("ReadModule() error = %v", err)
	}
	if repo.Pin.Revision != "b2b2000000000000000000000000000000000b" {
		t.Fatalf("Pin.Revision = %q, want resolved commit for v3.1.0 ref", repo.Pin.Revision)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "main.tf" {
		t.Fatalf("Files = %+v, want main.tf", repo.Files)
	}
}

func TestReadModuleRegistryNotAllowlisted(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("other-ns", "thing", "aws", "1.0.0", "git::https://github.com/acme/modules.git?ref=v1.0.0")

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "other-ns/thing/aws", "1.0.0")
	if !errors.Is(err, ErrModuleNotAllowed) {
		t.Fatalf("ReadModule() error = %v, want ErrModuleNotAllowed", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("expected no HTTP calls for denied registry module, got %v", fake.requests)
	}
}

func TestReadModuleRegistryResolvedToUnsupportedHostRefused(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("acme-ns", "vpc", "aws", "3.1.0", "https://evil.example.com/archive.tar.gz")

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "acme-ns/vpc/aws", "3.1.0")
	if !errors.Is(err, ErrUnsupportedModuleSource) {
		t.Fatalf("ReadModule() error = %v, want ErrUnsupportedModuleSource", err)
	}
}

func TestReadModuleRegistryMissingDownloadHeaderErrors(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	// No setRegistryDownload call registered: fake server returns 404.

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "acme-ns/vpc/aws", "9.9.9")
	if err == nil {
		t.Fatal("ReadModule() error = nil, want an error for missing registry download info")
	}
}

func TestReadModuleUnsupportedSourceShape(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "https://example.com/not-a-module.zip", "1.0.0")
	if !errors.Is(err, ErrUnsupportedModuleSource) {
		t.Fatalf("ReadModule() error = %v, want ErrUnsupportedModuleSource", err)
	}
}

func TestReadModulePrivateRepoWithoutAppDenied(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "modules", "v1.0.0", "c3c3000000000000000000000000000000000c")
	fake.setRepoPrivate("acme", "modules", true)

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "github.com/acme/modules", "v1.0.0")
	if !errors.Is(err, ErrModulePrivateWithoutApp) {
		t.Fatalf("ReadModule() error = %v, want ErrModulePrivateWithoutApp", err)
	}
	// The private repository's tree must never be walked.
	for _, req := range fake.requests {
		if strings.Contains(req, "/git/trees/") {
			t.Fatalf("tree was fetched for a denied private repository: %v", req)
		}
	}
}

func TestReadModuleVisibilityUnverifiableDenied(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "modules", "v1.0.0", "d4d4000000000000000000000000000000000d")
	// Deliberately do not register repo visibility at all: the fake repo
	// metadata endpoint 404s, simulating a lookup failure/rate limit.

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	_, err = moduleReader.ReadModule(context.Background(), "github.com/acme/modules", "v1.0.0")
	if err == nil {
		t.Fatal("ReadModule() error = nil, want an error when visibility cannot be verified")
	}
}

func TestReadModulePublicVisibilityCheckedOncePerRepo(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "modules", "v1.0.0", "e5e5000000000000000000000000000000000e")
	fake.setRepoPrivate("acme", "modules", false)
	entry, sha := blobEntry("a/main.tf", []byte("a"))
	fake.setBlob(sha, []byte("a"))
	fake.setTree("acme", "modules", "e5e5000000000000000000000000000000000e", false, []fakeTreeEntry{entry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	if _, err := moduleReader.ReadModule(context.Background(), "github.com/acme/modules//a", "v1.0.0"); err != nil {
		t.Fatalf("ReadModule() first call error = %v", err)
	}
	if _, err := moduleReader.ReadModule(context.Background(), "github.com/acme/modules//a", "v1.0.0"); err != nil {
		t.Fatalf("ReadModule() second call error = %v", err)
	}
	if got := fake.repoMetadataCallCount("acme", "modules"); got != 1 {
		t.Fatalf("repo metadata calls = %d, want 1 (cached visibility)", got)
	}
}

// TestReadModuleSCPStyleGitSourcePinnedByRef exercises an SCP-style
// "git@github.com:owner/repo//subdir?ref=..." source with no separate
// `version` attribute. The source's own "?ref=" query must be accepted as
// the pin (finding 1).
func TestReadModuleSCPStyleGitSourcePinnedByRef(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("example-org", "infra-modules", "gke_cluster/1.2.3", "f6f6000000000000000000000000000000000f")
	fake.setRepoPrivate("example-org", "infra-modules", false)
	entry, sha := blobEntry("modules/gke_cluster/main.tf", []byte("gke module"))
	fake.setBlob(sha, []byte("gke module"))
	fake.setTree("example-org", "infra-modules", "f6f6000000000000000000000000000000000f", false, []fakeTreeEntry{entry})

	opts := newTestRepositoryOptions(t, server.URL, nil)
	opts.AllowedModules = []string{"example-org/infra-modules"}
	reader, err := NewRepositoryReader(opts)
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, err := AsModuleReader(reader)
	if err != nil {
		t.Fatalf("AsModuleReader() error = %v", err)
	}

	repo, err := moduleReader.ReadModule(context.Background(),
		"git@github.com:example-org/infra-modules//modules/gke_cluster?ref=gke_cluster/1.2.3", "")
	if err != nil {
		t.Fatalf("ReadModule() error = %v, want success for SCP-style ref-pinned source", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "modules/gke_cluster/main.tf" {
		t.Fatalf("Files = %+v, want modules/gke_cluster/main.tf", repo.Files)
	}
	if repo.Pin.Root != "modules/gke_cluster" {
		t.Fatalf("Pin.Root = %q, want modules/gke_cluster", repo.Pin.Root)
	}
	if repo.Pin.Revision != "f6f6000000000000000000000000000000000f" {
		t.Fatalf("Pin.Revision = %q, want resolved commit for the ref pin", repo.Pin.Revision)
	}
}

// TestReadModuleRegistrySubdirPreserved reproduces the configured
// terraform-google-modules/kubernetes-engine/google//modules/workload-identity
// source: a registry package address with a requested "//subdir" (finding 2).
func TestReadModuleRegistrySubdirPreserved(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("terraform-google-modules", "kubernetes-engine", "google", "29.0.0", "git::https://github.com/terraform-google-modules/terraform-google-kubernetes-engine.git?ref=v29.0.0")
	fake.setCommit("terraform-google-modules", "terraform-google-kubernetes-engine", "v29.0.0", "a7a7000000000000000000000000000000000a")
	fake.setRepoPrivate("terraform-google-modules", "terraform-google-kubernetes-engine", false)
	entry, sha := blobEntry("modules/workload-identity/main.tf", []byte("workload identity module"))
	fake.setBlob(sha, []byte("workload identity module"))
	fake.setTree("terraform-google-modules", "terraform-google-kubernetes-engine", "a7a7000000000000000000000000000000000a", false, []fakeTreeEntry{entry})

	opts := newTestRepositoryOptions(t, server.URL, nil)
	opts.RegistryModules = []string{"terraform-google-modules/kubernetes-engine/google"}
	reader, err := NewRepositoryReader(opts)
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)

	repo, err := moduleReader.ReadModule(context.Background(),
		"terraform-google-modules/kubernetes-engine/google//modules/workload-identity", "29.0.0")
	if err != nil {
		t.Fatalf("ReadModule() error = %v, want success for registry source with subdir", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "modules/workload-identity/main.tf" {
		t.Fatalf("Files = %+v, want modules/workload-identity/main.tf", repo.Files)
	}
	if repo.Pin.Root != "modules/workload-identity" {
		t.Fatalf("Pin.Root = %q, want modules/workload-identity", repo.Pin.Root)
	}
}

// TestReadModuleRegistryAllowlistAloneSufficient reproduces the deployed
// configuration's separate allowlists: RegistryModules names official
// third-party packages while AllowedModules only names this org's own
// repositories. A registry package allowed via RegistryModules must resolve
// even though its upstream GitHub repository never appears in
// AllowedModules/AllowedRepositories (finding 3).
func TestReadModuleRegistryAllowlistAloneSufficient(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("terraform-aws-modules", "iam", "aws", "5.0.0", "git::https://github.com/terraform-aws-modules/terraform-aws-iam.git?ref=v5.0.0")
	fake.setCommit("terraform-aws-modules", "terraform-aws-iam", "v5.0.0", "c9c9000000000000000000000000000000000c")
	fake.setRepoPrivate("terraform-aws-modules", "terraform-aws-iam", false)
	entry, sha := blobEntry("modules/iam-role-for-service-accounts/main.tf", []byte("irsa module"))
	fake.setBlob(sha, []byte("irsa module"))
	fake.setTree("terraform-aws-modules", "terraform-aws-iam", "c9c9000000000000000000000000000000000c", false, []fakeTreeEntry{entry})

	reader, err := NewRepositoryReader(RepositoryOptions{
		AllowedRepositories:  []string{"example-org/infra-modules"},
		AllowedModules:       []string{"example-org/infra-modules"},
		RegistryModules:      []string{"terraform-aws-modules/iam/aws"},
		RegistryBaseURL:      server.URL + "/registry",
		BaseURL:              server.URL,
		AllowLoopbackBaseURL: true,
	})
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)

	repo, err := moduleReader.ReadModule(context.Background(),
		"terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts", "5.0.0")
	if err != nil {
		t.Fatalf("ReadModule() error = %v, want success: the registry package allowlist alone is sufficient", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "modules/iam-role-for-service-accounts/main.tf" {
		t.Fatalf("Files = %+v, want modules/iam-role-for-service-accounts/main.tf", repo.Files)
	}
}

// TestReadModuleRegistryExplicitDefaultHostNormalized reproduces the
// configured EKS module source
// "registry.terraform.io/terraform-aws-modules/eks/aws": an explicit
// "registry.terraform.io/" host prefix on an otherwise ordinary
// namespace/name/provider registry address must resolve exactly like the
// bare 3-segment form once that package is allowlisted (R08 finding 1).
// Pre-fix, parseRegistrySource saw 4 "/"-separated segments and rejected
// the source as ErrUnsupportedModuleSource even though the package itself
// was allowlisted.
func TestReadModuleRegistryExplicitDefaultHostNormalized(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setRegistryDownload("terraform-aws-modules", "eks", "aws", "20.0.0", "git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=v20.0.0")
	fake.setCommit("terraform-aws-modules", "terraform-aws-eks", "v20.0.0", "e5e5000000000000000000000000000000000e")
	fake.setRepoPrivate("terraform-aws-modules", "terraform-aws-eks", false)
	entry, sha := blobEntry("main.tf", []byte("eks module"))
	fake.setBlob(sha, []byte("eks module"))
	fake.setTree("terraform-aws-modules", "terraform-aws-eks", "e5e5000000000000000000000000000000000e", false, []fakeTreeEntry{entry})

	opts := newTestRepositoryOptions(t, server.URL, nil)
	opts.RegistryModules = []string{"terraform-aws-modules/eks/aws"}
	reader, err := NewRepositoryReader(opts)
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)

	repo, err := moduleReader.ReadModule(context.Background(),
		"registry.terraform.io/terraform-aws-modules/eks/aws", "20.0.0")
	if err != nil {
		t.Fatalf("ReadModule() error = %v, want success for explicit registry.terraform.io host on an allowlisted package", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "main.tf" {
		t.Fatalf("Files = %+v, want main.tf", repo.Files)
	}
}

// TestReadModuleRegistryOtherExplicitHostRefused is the control for
// TestReadModuleRegistryExplicitDefaultHostNormalized: a non-default
// registry host (e.g. a private Terraform Enterprise registry) written as
// the same leading "<host>/namespace/name/provider" shape must NEVER be
// normalized away and silently treated as the public default registry,
// even when the trailing 3 segments happen to match an allowlisted
// package.
func TestReadModuleRegistryOtherExplicitHostRefused(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()

	opts := newTestRepositoryOptions(t, server.URL, nil)
	opts.RegistryModules = []string{"terraform-aws-modules/eks/aws"}
	reader, err := NewRepositoryReader(opts)
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)

	_, err = moduleReader.ReadModule(context.Background(),
		"app.terraform.io/terraform-aws-modules/eks/aws", "20.0.0")
	if !errors.Is(err, ErrUnsupportedModuleSource) {
		t.Fatalf("ReadModule() error = %v, want ErrUnsupportedModuleSource for a non-default explicit registry host", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("expected no HTTP calls for an unsupported explicit registry host, got %v", fake.requests)
	}
}

// TestReadModuleGitHubSubdirMaterializesContainingRepo reproduces R14
// finding 4 (static): a remote module entered at "//modules/app" must
// still materialize a legal local sibling child ("../shared" ->
// "modules/shared") alongside it, not just the requested subdir itself.
// Pre-fix, readTree was called with root=subdir directly, so sibling
// directories were never fetched at all and a legal "../shared" reference
// could never resolve. Pin.Root must still report the originally
// requested subdir.
func TestReadModuleGitHubSubdirMaterializesContainingRepo(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "modules", "v1.0.0", "d1d1000000000000000000000000000000000d")
	fake.setRepoPrivate("acme", "modules", false)
	appEntry, appSHA := blobEntry("modules/app/main.tf", []byte("app module"))
	sharedEntry, sharedSHA := blobEntry("modules/shared/main.tf", []byte("shared module"))
	fake.setBlob(appSHA, []byte("app module"))
	fake.setBlob(sharedSHA, []byte("shared module"))
	fake.setTree("acme", "modules", "d1d1000000000000000000000000000000000d", false, []fakeTreeEntry{appEntry, sharedEntry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, _ := AsModuleReader(reader)
	repo, err := moduleReader.ReadModule(context.Background(), "github.com/acme/modules//modules/app", "v1.0.0")
	if err != nil {
		t.Fatalf("ReadModule() error = %v", err)
	}
	if repo.Pin.Root != "modules/app" {
		t.Fatalf("Pin.Root = %q, want modules/app (the requested entry point, preserved)", repo.Pin.Root)
	}
	paths := map[string]bool{}
	for _, f := range repo.Files {
		paths[f.Path] = true
	}
	if !paths["modules/app/main.tf"] {
		t.Errorf("Files = %v, want modules/app/main.tf present", repo.Files)
	}
	if !paths["modules/shared/main.tf"] {
		t.Errorf("Files = %v, want the sibling modules/shared/main.tf present so a local \"../shared\" child module reference resolves", repo.Files)
	}
}
