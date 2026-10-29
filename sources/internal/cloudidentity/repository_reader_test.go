package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- test fixtures must match git's own blob SHA-1 addressing.
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcehttp"
)

// ---- shared fake GitHub REST API server (used by repository + module tests) ----

type fakeTreeEntry struct {
	Path string
	Mode string
	Type string
	SHA  string
	Size int
}

type fakeGitHub struct {
	t *testing.T

	mu                sync.Mutex
	commits           map[string]string // "owner/repo@ref" -> resolved sha
	trees             map[string][]fakeTreeEntry
	treeTrunc         map[string]bool
	blobs             map[string][]byte
	commitCalls       map[string]int
	tokenCalls        map[string]int
	tarballCalls      map[string]int
	requests          []string
	registryDownloads map[string]string
	repoPrivate       map[string]bool
	repoMetadataCalls map[string]int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	return &fakeGitHub{
		t:            t,
		commits:      map[string]string{},
		trees:        map[string][]fakeTreeEntry{},
		treeTrunc:    map[string]bool{},
		blobs:        map[string][]byte{},
		commitCalls:  map[string]int{},
		tokenCalls:   map[string]int{},
		tarballCalls: map[string]int{},
	}
}

func (f *fakeGitHub) setCommit(owner, repo, ref, sha string) {
	f.commits[owner+"/"+repo+"@"+ref] = sha
}

func (f *fakeGitHub) setTree(owner, repo, sha string, truncated bool, entries []fakeTreeEntry) {
	f.trees[owner+"/"+repo+"@"+sha] = entries
	f.treeTrunc[owner+"/"+repo+"@"+sha] = truncated
}

func (f *fakeGitHub) setBlob(sha string, content []byte) {
	f.blobs[sha] = content
}

func (f *fakeGitHub) commitCallCount(owner, repo, ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commitCalls[owner+"/"+repo+"@"+ref]
}

func (f *fakeGitHub) tarballCallCount(owner, repo, ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tarballCalls[owner+"/"+repo+"@"+ref]
}

func (f *fakeGitHub) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(f.handle))
}

func (f *fakeGitHub) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/registry/v1/modules/"):
		f.handleRegistryDownload(w, r)
	case strings.HasSuffix(r.URL.Path, "/access_tokens") && r.Method == http.MethodPost:
		f.handleToken(w, r)
	case r.Method == http.MethodGet && isRepoMetadataPath(r.URL.Path):
		f.handleRepoMetadata(w, r)
	case strings.Contains(r.URL.Path, "/git/trees/"):
		f.handleTree(w, r)
	case strings.Contains(r.URL.Path, "/tarball/"):
		f.handleTarball(w, r)
	case strings.HasPrefix(r.URL.Path, "/archive-download/"):
		f.handleArchiveDownload(w, r)
	case strings.Contains(r.URL.Path, "/commits/"):
		f.handleCommit(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}
}

// isRepoMetadataPath matches GET .../repos/{owner}/{repo} exactly (the repo
// metadata endpoint), not any deeper sub-resource like commits/git/trees.
func isRepoMetadataPath(path string) bool {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i, segment := range segments {
		if segment == "repos" && len(segments) == i+3 {
			return true
		}
	}
	return false
}

func (f *fakeGitHub) setRepoPrivate(owner, repo string, private bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repoPrivate == nil {
		f.repoPrivate = map[string]bool{}
	}
	f.repoPrivate[owner+"/"+repo] = private
}

func (f *fakeGitHub) repoMetadataCallCount(owner, repo string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.repoMetadataCalls[owner+"/"+repo]
}

func (f *fakeGitHub) handleRepoMetadata(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	owner, repo := segments[len(segments)-2], segments[len(segments)-1]
	f.mu.Lock()
	if f.repoMetadataCalls == nil {
		f.repoMetadataCalls = map[string]int{}
	}
	f.repoMetadataCalls[owner+"/"+repo]++
	private, ok := f.repoPrivate[owner+"/"+repo]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"private": private, "full_name": owner + "/" + repo})
}

func (f *fakeGitHub) setRegistryDownload(namespace, name, provider, version, sourceHeader string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registryDownloads == nil {
		f.registryDownloads = map[string]string{}
	}
	f.registryDownloads[namespace+"/"+name+"/"+provider+"@"+version] = sourceHeader
}

func (f *fakeGitHub) handleRegistryDownload(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/registry/v1/modules/")
	trimmed = strings.TrimSuffix(trimmed, "/download")
	segments := strings.Split(trimmed, "/")
	if len(segments) != 4 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	key := segments[0] + "/" + segments[1] + "/" + segments[2] + "@" + segments[3]
	f.mu.Lock()
	sourceHeader, ok := f.registryDownloads[key]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("X-Terraform-Get", sourceHeader)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeGitHub) handleToken(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	installationID := parts[len(parts)-2]
	f.mu.Lock()
	f.tokenCalls[installationID]++
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":      "fake-installation-token-" + installationID,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

func (f *fakeGitHub) repoAndRefFromPath(path, marker string) (owner, repo, ref string) {
	trimmed := strings.Trim(path, "/")
	idx := strings.Index(trimmed, marker)
	before := trimmed[:idx]
	after := trimmed[idx+len(marker):]
	beforeParts := strings.Split(before, "/")
	// before = ".../repos/{owner}/{repo}/<marker-prefix>"
	n := len(beforeParts)
	owner = beforeParts[n-2]
	repo = beforeParts[n-1]
	ref = after
	if q := strings.Index(ref, "?"); q >= 0 {
		ref = ref[:q]
	}
	return owner, repo, ref
}

func (f *fakeGitHub) handleCommit(w http.ResponseWriter, r *http.Request) {
	owner, repo, ref := f.repoAndRefFromPath(r.URL.Path, "/commits/")
	f.mu.Lock()
	f.commitCalls[owner+"/"+repo+"@"+ref]++
	sha, ok := f.commits[owner+"/"+repo+"@"+ref]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"no commit found for ref"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sha))
}

func (f *fakeGitHub) handleTree(w http.ResponseWriter, r *http.Request) {
	owner, repo, sha := f.repoAndRefFromPath(r.URL.Path, "/git/trees/")
	f.mu.Lock()
	entries, ok := f.trees[owner+"/"+repo+"@"+sha]
	truncated := f.treeTrunc[owner+"/"+repo+"@"+sha]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	type wireEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int    `json:"size,omitempty"`
		URL  string `json:"url"`
	}
	wireEntries := make([]wireEntry, 0, len(entries))
	for _, e := range entries {
		wireEntries = append(wireEntries, wireEntry{Path: e.Path, Mode: e.Mode, Type: e.Type, SHA: e.SHA, Size: e.Size, URL: "https://example.invalid"})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sha":       sha,
		"tree":      wireEntries,
		"truncated": truncated,
	})
}

// handleTarball serves GitHub's archive-link redirect: it returns a 302
// whose Location points at handleArchiveDownload on this same test server,
// mirroring the real github.com -> codeload.github.com indirection.
func (f *fakeGitHub) handleTarball(w http.ResponseWriter, r *http.Request) {
	owner, repo, ref := f.repoAndRefFromPath(r.URL.Path, "/tarball/")
	f.mu.Lock()
	f.tarballCalls[owner+"/"+repo+"@"+ref]++
	f.mu.Unlock()
	w.Header().Set("Location", "http://"+r.Host+"/archive-download/"+owner+"/"+repo+"/"+ref)
	w.WriteHeader(http.StatusFound)
}

// handleArchiveDownload serves a gzipped tarball built on the fly from the
// registered tree + blob fixtures, wrapped in GitHub's own
// "owner-repo-shortsha/" top-level directory convention, so existing
// setTree/setBlob fixtures transparently back the archive-based reader
// without any test needing its own archive-building code.
func (f *fakeGitHub) handleArchiveDownload(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/archive-download/")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) != 3 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	owner, repo, ref := parts[0], parts[1], parts[2]
	f.mu.Lock()
	entries := f.trees[owner+"/"+repo+"@"+ref]
	f.mu.Unlock()

	short := ref
	if len(short) > 7 {
		short = short[:7]
	}
	wrapper := owner + "-" + repo + "-" + short

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		if entry.Type != gitTreeEntryTypeBlob {
			continue
		}
		f.mu.Lock()
		content, ok := f.blobs[entry.SHA]
		f.mu.Unlock()
		if !ok {
			continue
		}
		_ = tw.WriteHeader(&tar.Header{Name: wrapper + "/" + entry.Path, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))})
		_, _ = tw.Write(content)
	}
	_ = tw.Close()
	_ = gz.Close()
	w.Header().Set("Content-Type", "application/x-gzip")
	_, _ = w.Write(buf.Bytes())
}

// gitBlobSHA computes the git object SHA-1 for content, matching
// verifyGitBlobSHA so fixtures are internally consistent by default; tests
// that want a mismatch pass a different literal string instead.
func gitBlobSHA(content []byte) string {
	header := fmt.Sprintf("blob %d\x00", len(content))
	hash := sha1.New() // #nosec G401 -- fixture must match git's own object addressing.
	hash.Write([]byte(header))
	hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func blobEntry(path string, content []byte) (fakeTreeEntry, string) {
	sha := gitBlobSHA(content)
	return fakeTreeEntry{Path: path, Mode: "100644", Type: gitTreeEntryTypeBlob, SHA: sha, Size: len(content)}, sha
}

func testGitHubAppPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func newTestRepositoryOptions(t *testing.T, baseURL string, apps map[string]sourcehttp.GitHubAppAuthConfig) RepositoryOptions {
	t.Helper()
	return RepositoryOptions{
		Apps:                 apps,
		AllowedRepositories:  []string{"acme/widgets"},
		AllowedModules:       []string{"acme/modules"},
		RegistryModules:      []string{"acme-ns/vpc/aws"},
		RegistryBaseURL:      baseURL + "/registry",
		BaseURL:              baseURL,
		AllowLoopbackBaseURL: true,
	}
}

func newTestApps(t *testing.T) map[string]sourcehttp.GitHubAppAuthConfig {
	t.Helper()
	return map[string]sourcehttp.GitHubAppAuthConfig{
		"acme": {AppID: "1", InstallationID: "100", PrivateKey: testGitHubAppPrivateKeyPEM(t)},
	}
}

// ---- ReadRepository tests ----

func TestReadRepositoryHappyPath(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()

	fake.setCommit("acme", "widgets", "main", "c0ffee0000000000000000000000000000000001")
	mainTF := []byte("resource \"aws_iam_role\" \"x\" {}\n")
	readme := []byte("# widgets\n")
	entryMain, shaMain := blobEntry("terraform/main.tf", mainTF)
	entryReadme, shaReadme := blobEntry("README.md", readme)
	fake.setTree("acme", "widgets", "c0ffee0000000000000000000000000000000001", false, []fakeTreeEntry{entryMain, entryReadme})
	fake.setBlob(shaMain, mainTF)
	fake.setBlob(shaReadme, readme)

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}

	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main", Root: "terraform"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if repo.Pin.Revision != "c0ffee0000000000000000000000000000000001" {
		t.Fatalf("Pin.Revision = %q, want resolved commit", repo.Pin.Revision)
	}
	if !repo.Pin.Exact {
		t.Fatalf("Pin.Exact = false, want true")
	}
	if len(repo.Files) != 1 {
		t.Fatalf("len(Files) = %d, want 1 (root filter); got %+v", len(repo.Files), repo.Files)
	}
	if repo.Files[0].Path != "terraform/main.tf" {
		t.Fatalf("Files[0].Path = %q, want repository-relative path", repo.Files[0].Path)
	}
	if string(repo.Files[0].Content) != string(mainTF) {
		t.Fatalf("Files[0].Content mismatch")
	}
	if len(repo.Gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", repo.Gaps)
	}
}

func TestReadRepositoryDeniedRepository(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	_, err = reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "evil/other", Revision: "main"})
	if !errors.Is(err, ErrRepositoryNotAllowed) {
		t.Fatalf("ReadRepository() error = %v, want ErrRepositoryNotAllowed", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("expected no HTTP calls for denied repository, got %v", fake.requests)
	}
}

func TestReadRepositoryMissingRevisionRefused(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	_, err = reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets"})
	if !errors.Is(err, ErrRevisionRequired) {
		t.Fatalf("ReadRepository() error = %v, want ErrRevisionRequired", err)
	}
}

func TestReadRepositoryNoGitHubAppConfigured(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, nil))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	_, err = reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if !errors.Is(err, ErrGitHubAppNotConfigured) {
		t.Fatalf("ReadRepository() error = %v, want ErrGitHubAppNotConfigured", err)
	}
}

func TestReadRepositoryAppRoutingPerOwner(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "aaaa000000000000000000000000000000000a")
	fake.setTree("acme", "widgets", "aaaa000000000000000000000000000000000a", false, nil)

	apps := map[string]sourcehttp.GitHubAppAuthConfig{
		"acme": {AppID: "1", InstallationID: "100", PrivateKey: testGitHubAppPrivateKeyPEM(t)},
	}
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, apps))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	if _, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"}); err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if fake.tokenCalls["100"] != 1 {
		t.Fatalf("installation 100 token calls = %d, want 1", fake.tokenCalls["100"])
	}
}

func TestReadRepositoryFloatingRefResolvedOnce(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "bbbb000000000000000000000000000000000b")
	fileA, shaA := blobEntry("a/one.tf", []byte("a"))
	fileB, shaB := blobEntry("b/two.tf", []byte("b"))
	fake.setTree("acme", "widgets", "bbbb000000000000000000000000000000000b", false, []fakeTreeEntry{fileA, fileB})
	fake.setBlob(shaA, []byte("a"))
	fake.setBlob(shaB, []byte("b"))

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	ctx := context.Background()
	if _, err := reader.ReadRepository(ctx, ci.SourcePin{Repository: "acme/widgets", Revision: "main", Root: "a"}); err != nil {
		t.Fatalf("ReadRepository(root=a) error = %v", err)
	}
	if _, err := reader.ReadRepository(ctx, ci.SourcePin{Repository: "acme/widgets", Revision: "main", Root: "b"}); err != nil {
		t.Fatalf("ReadRepository(root=b) error = %v", err)
	}
	if got := fake.commitCallCount("acme", "widgets", "main"); got != 1 {
		t.Fatalf("commit resolution calls = %d, want 1 (cached across roots)", got)
	}
	// Finding 5: one archive (tarball) download per (repo, commit), reused
	// across different root-scoped reads of the same commit, not one
	// GitHub API call per file.
	if got := fake.tarballCallCount("acme", "widgets", "bbbb000000000000000000000000000000000b"); got != 1 {
		t.Fatalf("archive download calls = %d, want 1 (one tarball per (repo, commit), reused across roots)", got)
	}
}

func TestReadRepositorySkipsSymlinksSubmodulesAndTraversal(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "cccc000000000000000000000000000000000c")
	keep, shaKeep := blobEntry("keep.tf", []byte("keep"))
	fake.setBlob(shaKeep, []byte("keep"))
	entries := []fakeTreeEntry{
		keep,
		{Path: "link", Mode: gitTreeModeSymlink, Type: gitTreeEntryTypeBlob, SHA: "deadbeef", Size: 4},
		{Path: "vendor/sub", Mode: gitTreeModeSubmodule, Type: "commit", SHA: "deadbeef", Size: 0},
		{Path: "../escape.tf", Mode: "100644", Type: gitTreeEntryTypeBlob, SHA: "deadbeef", Size: 4},
	}
	fake.setTree("acme", "widgets", "cccc000000000000000000000000000000000c", false, entries)

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "keep.tf" {
		t.Fatalf("Files = %+v, want only keep.tf", repo.Files)
	}
	wantCodes := map[string]bool{"repository.symlink_skipped": true, "repository.submodule_skipped": true, "repository.path_rejected": true}
	gotCodes := map[string]bool{}
	for _, gap := range repo.Gaps {
		gotCodes[gap.Code] = true
	}
	for code := range wantCodes {
		if !gotCodes[code] {
			t.Errorf("missing expected gap code %q in %+v", code, repo.Gaps)
		}
	}
}

func TestReadRepositoryDeniesCredentialFiles(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "dddd000000000000000000000000000000000d")
	stateEntry, shaState := blobEntry("terraform.tfstate", []byte("secret-state"))
	envEntry, shaEnv := blobEntry(".env", []byte("SECRET=1"))
	keyEntry, shaKey := blobEntry("deploy.pem", []byte("-----BEGIN KEY-----"))
	keepEntry, shaKeep := blobEntry("main.tf", []byte("ok"))
	// Every denied entry's content IS present in the archive (unlike a
	// missing blob, which would just hard-error): if credentialFileDenied
	// ever let a denied path reach the extraction step, its real content
	// would come back in repo.Files instead of being silently dropped.
	fake.setBlob(shaState, []byte("secret-state"))
	fake.setBlob(shaEnv, []byte("SECRET=1"))
	fake.setBlob(shaKey, []byte("-----BEGIN KEY-----"))
	fake.setBlob(shaKeep, []byte("ok"))
	fake.setTree("acme", "widgets", "dddd000000000000000000000000000000000d", false, []fakeTreeEntry{stateEntry, envEntry, keyEntry, keepEntry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "main.tf" {
		t.Fatalf("Files = %+v, want only main.tf", repo.Files)
	}
	found := false
	for _, gap := range repo.Gaps {
		if gap.Code == "repository.file_denied" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected repository.file_denied gap, got %+v", repo.Gaps)
	}
}

func TestReadRepositoryTruncatedTreeGap(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "eeee000000000000000000000000000000000e")
	fake.setTree("acme", "widgets", "eeee000000000000000000000000000000000e", true, nil)

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	found := false
	for _, gap := range repo.Gaps {
		if gap.Code == "repository.tree_truncated" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected repository.tree_truncated gap, got %+v", repo.Gaps)
	}
}

func TestReadRepositoryBudgetExceeded(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "ffff00000000000000000000000000000000ff")
	e1, s1 := blobEntry("a.tf", []byte("a"))
	e2, s2 := blobEntry("b.tf", []byte("b"))
	fake.setBlob(s1, []byte("a"))
	fake.setBlob(s2, []byte("b"))
	fake.setTree("acme", "widgets", "ffff00000000000000000000000000000000ff", false, []fakeTreeEntry{e1, e2})

	options := newTestRepositoryOptions(t, server.URL, newTestApps(t))
	options.MaxFiles = 1
	reader, err := NewRepositoryReader(options)
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if len(repo.Files) != 1 {
		t.Fatalf("len(Files) = %d, want 1", len(repo.Files))
	}
	found := false
	for _, gap := range repo.Gaps {
		if gap.Code == "repository.budget_exceeded" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected repository.budget_exceeded gap, got %+v", repo.Gaps)
	}
}

func TestReadRepositoryBlobIntegrityMismatch(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "1111000000000000000000000000000000001a")
	// Declare an entry whose SHA doesn't match the blob content the server
	// will actually serve for that SHA (tampered/corrupted transport).
	entry := fakeTreeEntry{Path: "main.tf", Mode: "100644", Type: gitTreeEntryTypeBlob, SHA: "feedface00000000000000000000000000beef", Size: 4}
	fake.setTree("acme", "widgets", "1111000000000000000000000000000000001a", false, []fakeTreeEntry{entry})
	fake.setBlob("feedface00000000000000000000000000beef", []byte("evil"))

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	_, err = reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err == nil || !strings.Contains(err.Error(), "integrity verification") {
		t.Fatalf("ReadRepository() error = %v, want integrity verification failure", err)
	}
}

func TestAsModuleReader(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	moduleReader, err := AsModuleReader(reader)
	if err != nil {
		t.Fatalf("AsModuleReader() error = %v", err)
	}
	if moduleReader == nil {
		t.Fatal("AsModuleReader() returned nil")
	}
}

func TestReadRepositoryArchiveMissingExpectedFileErrors(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "2222000000000000000000000000000000002b")
	// Declare a tree entry but never register its blob content: the
	// archive served for this commit therefore will not contain it, even
	// though the tree says it should exist.
	entry := fakeTreeEntry{Path: "missing.tf", Mode: "100644", Type: gitTreeEntryTypeBlob, SHA: "cafef00d00000000000000000000000000d00d", Size: 4}
	fake.setTree("acme", "widgets", "2222000000000000000000000000000000002b", false, []fakeTreeEntry{entry})

	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	_, err = reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "acme/widgets", Revision: "main"})
	if err == nil || !strings.Contains(err.Error(), "did not contain expected file") {
		t.Fatalf("ReadRepository() error = %v, want an archive/tree mismatch failure", err)
	}
}

func TestParseRepositoryCoordinateAcceptsGitHubSCPForm(t *testing.T) {
	tests := []struct {
		raw       string
		wantOwner string
		wantName  string
		wantErr   bool
	}{
		{raw: "git@github.com:example-org/gitops.git", wantOwner: "example-org", wantName: "gitops"},
		{raw: "git@github.com:example-org/gitops", wantOwner: "example-org", wantName: "gitops"},
		{raw: "git@gitlab.com:example-org/gitops.git", wantErr: true},
		{raw: "git@github.com:example-org/gitops/extra", wantErr: true},
		{raw: "owner/repo", wantOwner: "owner", wantName: "repo"},
		{raw: "https://github.com/owner/repo.git", wantOwner: "owner", wantName: "repo"},
	}
	for _, tt := range tests {
		owner, name, err := parseRepositoryCoordinate(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseRepositoryCoordinate(%q) error = nil, want error", tt.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRepositoryCoordinate(%q) unexpected error: %v", tt.raw, err)
			continue
		}
		if owner != tt.wantOwner || name != tt.wantName {
			t.Errorf("parseRepositoryCoordinate(%q) = (%q, %q), want (%q, %q)", tt.raw, owner, name, tt.wantOwner, tt.wantName)
		}
	}
}

func TestReadRepositoryAcceptsGitHubSCPCoordinate(t *testing.T) {
	fake := newFakeGitHub(t)
	server := fake.server()
	defer server.Close()
	fake.setCommit("acme", "widgets", "main", "3333000000000000000000000000000000003c")
	entry, sha := blobEntry("main.tf", []byte("ok"))
	fake.setBlob(sha, []byte("ok"))
	fake.setTree("acme", "widgets", "3333000000000000000000000000000000003c", false, []fakeTreeEntry{entry})

	// AllowedRepositories is configured as plain "acme/widgets" (see
	// newTestRepositoryOptions); the pin itself uses the SCP form actually
	// used throughout the deployed Argo CD values.
	reader, err := NewRepositoryReader(newTestRepositoryOptions(t, server.URL, newTestApps(t)))
	if err != nil {
		t.Fatalf("NewRepositoryReader() error = %v", err)
	}
	repo, err := reader.ReadRepository(context.Background(), ci.SourcePin{Repository: "git@github.com:acme/widgets.git", Revision: "main"})
	if err != nil {
		t.Fatalf("ReadRepository() error = %v", err)
	}
	if len(repo.Files) != 1 || repo.Files[0].Path != "main.tf" {
		t.Fatalf("Files = %+v, want only main.tf", repo.Files)
	}
}

// TestRepositoryExtractArchiveEntriesBoundsUnwantedEntryBytes reproduces the
// R18 static finding: an archive entry outside wanted was skipped without
// any aggregate decompressed-byte bound, so a highly compressible unwanted
// entry could be drained without limit. Before the fix, calling
// repositoryExtractArchiveEntries on this exact fixture (keep.txt, 2 bytes,
// wanted; skip.bin, 5 MiB, unwanted) returned success with no error at all
// (verified directly: see prior PRE-FIX PROBE run). Now the unwanted 5 MiB
// entry must blow the tiny configured aggregate bound.
func TestRepositoryExtractArchiveEntriesBoundsUnwantedEntryBytes(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	wrapper := "acme-widgets-abc1234"
	// An UNWANTED entry whose decompressed size is far larger than the
	// configured aggregate bound (highly compressible: all zero bytes),
	// written FIRST so it is drained before the wanted entry below could
	// ever trigger the "stop once found" early return.
	skip := bytes.Repeat([]byte{0}, 5<<20)
	if err := tw.WriteHeader(&tar.Header{Name: wrapper + "/skip.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(skip))}); err != nil {
		t.Fatalf("write skip header: %v", err)
	}
	if _, err := tw.Write(skip); err != nil {
		t.Fatalf("write skip content: %v", err)
	}
	keep := []byte("ok")
	if err := tw.WriteHeader(&tar.Header{Name: wrapper + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(keep))}); err != nil {
		t.Fatalf("write keep header: %v", err)
	}
	if _, err := tw.Write(keep); err != nil {
		t.Fatalf("write keep content: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()

	wanted := map[string]bool{"keep.txt": true}
	_, err := repositoryExtractArchiveEntries(context.Background(), buf.Bytes(), wanted, 1<<20, 1000, 4096)
	if err == nil {
		t.Fatalf("expected the unwanted 5 MiB entry to exceed the aggregate decompressed byte bound")
	}
	if !strings.Contains(err.Error(), "aggregate decompressed byte bound") {
		t.Fatalf("expected an aggregate decompressed byte bound error, got %v", err)
	}
}

// TestRepositoryExtractArchiveEntriesCountsEveryHeader reproduces the
// companion static finding: only wanted regular-file entries were ever
// counted, so an archive padded with many non-regular/unwanted headers
// (each still costing full tar-header parsing and gzip decompression work)
// could bypass any entry-count budget.
func TestRepositoryExtractArchiveEntriesCountsEveryHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	wrapper := "acme-widgets-abc1234"
	const unwantedCount = 500
	for i := range unwantedCount {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("%s/dir%04d/", wrapper, i), Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatalf("write dir header: %v", err)
		}
	}
	keep := []byte("ok")
	if err := tw.WriteHeader(&tar.Header{Name: wrapper + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(keep))}); err != nil {
		t.Fatalf("write keep header: %v", err)
	}
	if _, err := tw.Write(keep); err != nil {
		t.Fatalf("write keep content: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()

	wanted := map[string]bool{"keep.txt": true}
	const maxEntries = 100
	_, err := repositoryExtractArchiveEntries(context.Background(), buf.Bytes(), wanted, 1<<20, maxEntries, 1<<30)
	if err == nil {
		t.Fatalf("expected %d directory headers plus 1 file (%d total) to exceed the %d entry bound", unwantedCount, unwantedCount+1, maxEntries)
	}
	if !strings.Contains(err.Error(), "entry bound") {
		t.Fatalf("expected an entry-bound error, got %v", err)
	}
}

// TestRepositoryExtractArchiveEntriesStopsOnceWantedFound is the positive
// control: once every wanted entry has been found, extraction must stop
// without reading the rest of the archive. Proven here by a 10-byte
// aggregate budget that keep.txt (2 bytes) fits inside but that a
// subsequent, much larger unwanted entry would blow if it were ever
// touched -- success proves the huge trailing entry was never read.
func TestRepositoryExtractArchiveEntriesStopsOnceWantedFound(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	wrapper := "acme-widgets-abc1234"
	keep := []byte("ok")
	if err := tw.WriteHeader(&tar.Header{Name: wrapper + "/keep.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(keep))}); err != nil {
		t.Fatalf("write keep header: %v", err)
	}
	if _, err := tw.Write(keep); err != nil {
		t.Fatalf("write keep content: %v", err)
	}
	trailing := bytes.Repeat([]byte{0}, 1<<20)
	if err := tw.WriteHeader(&tar.Header{Name: wrapper + "/trailing.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(trailing))}); err != nil {
		t.Fatalf("write trailing header: %v", err)
	}
	if _, err := tw.Write(trailing); err != nil {
		t.Fatalf("write trailing content: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()

	wanted := map[string]bool{"keep.txt": true}
	extracted, err := repositoryExtractArchiveEntries(context.Background(), buf.Bytes(), wanted, 1<<20, 1000, 10)
	if err != nil {
		t.Fatalf("ReadAll() error = %v, want nil: extraction should stop once keep.txt was found, never touching the oversized trailing entry", err)
	}
	if string(extracted["keep.txt"]) != "ok" {
		t.Fatalf("extracted[keep.txt] = %q, want %q", extracted["keep.txt"], "ok")
	}
}
