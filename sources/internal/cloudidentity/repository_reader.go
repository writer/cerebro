// Package cloudidentitysource implements the cloud-identity Source CDK
// extension: typed, bounded external I/O (GitHub repositories/modules and
// container registries) behind the pure internal/cloudidentity ports. No
// cloud or secret calls happen at package init time; every call is explicit
// and bounded by caller-supplied options.
package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" // #nosec G505 -- required to verify GitHub git-object blob SHAs, not for secrecy.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	repositorySourceID = "cloud_identity_repository"

	// defaultRepositoryMaxFiles/defaultRepositoryMaxTotalBytes are sized
	// with headroom over the largest configured repositories actually
	// scanned today -- large GitOps and Terraform monorepos with
	// thousands of files and tens of MB each on disk -- not an arbitrary
	// round number.
	defaultRepositoryMaxFiles      = 8192
	defaultRepositoryMaxFileBytes  = 1 << 20   // 1 MiB per file
	defaultRepositoryMaxTotalBytes = 128 << 20 // 128 MiB per ReadRepository/ReadModule call
	// defaultRepositoryMaxArchiveBytes bounds the single whole-repository
	// tarball download per (repo, commit) that backs every root-scoped
	// read of that commit; it is intentionally far larger than
	// defaultRepositoryMaxTotalBytes because the archive always contains
	// the entire repository regardless of which root is being read.
	defaultRepositoryMaxArchiveBytes = 256 << 20
	// defaultRepositoryMaxArchiveDecompressedBytes bounds the total
	// decompressed bytes read from the whole-repository archive stream,
	// across every entry (wanted or not, including directories and other
	// non-regular headers), independent of defaultRepositoryMaxTotalBytes
	// which only bounds the sum of content actually selected/extracted.
	// A highly compressible archive within the bounded compressed
	// download size (defaultRepositoryMaxArchiveBytes) could otherwise
	// still decompress to an effectively unbounded size; this generously
	// allows for legitimate large repositories (binary assets, vendored
	// dependencies, …) that are never selected for extraction while still
	// capping worst-case expansion.
	defaultRepositoryMaxArchiveDecompressedBytes int64 = 2 << 30 // 2 GiB
	// defaultRepositoryMaxArchiveEntries bounds the total number of tar
	// header entries read from the whole-repository archive (including
	// directories and entries outside the selected/wanted subset),
	// independent of defaultRepositoryMaxFiles which only bounds the
	// selected candidate subset.
	defaultRepositoryMaxArchiveEntries = 200000
	defaultRepositoryTimeout           = 30 * time.Second

	gitTreeEntryTypeBlob   = "blob"
	gitTreeEntryTypeCommit = "commit" // submodule gitlink reference
	gitTreeModeSymlink     = "120000"
	gitTreeModeSubmodule   = "160000"
	gitBlobEncodingBase64  = "base64"
)

// Sentinel errors so callers/tests can assert on the denial category without
// parsing message text.
var (
	ErrRepositoryNotAllowed   = errors.New("repository is not in the configured allowlist")
	ErrModuleNotAllowed       = errors.New("module source is not in the configured allowlist")
	ErrRevisionRequired       = errors.New("source pin revision is required; default branch resolution is refused")
	ErrGitHubAppNotConfigured = errors.New("no github app installation is configured for this owner")
	// ErrModulePrivateWithoutApp guards module reads: an owner with no
	// configured GitHub App installation only ever gets an anonymous,
	// verified-public read. A private repository (or one whose visibility
	// could not be verified) is refused rather than silently attempted.
	ErrModulePrivateWithoutApp = errors.New("repository is private (or its visibility could not be verified) and no github app installation is configured for its owner")
)

// ErrArchiveMissingExpectedFile indicates the whole-repository archive
// fetched for a commit did not contain a file the repository tree declared
// at that commit -- an archive/tree mismatch (corrupted archive, GitHub
// archive-generation inconsistency, or a race with a force-push) rather
// than a budget or allowlist denial.
type ErrArchiveMissingExpectedFile struct {
	Owner, Repo, Commit, Path string
}

func (e *ErrArchiveMissingExpectedFile) Error() string {
	return fmt.Sprintf("cloudidentitysource: archive for %s/%s@%s did not contain expected file %q", e.Owner, e.Repo, e.Commit, e.Path)
}

// ErrBlobIntegrityMismatch indicates a fetched archive blob's content does
// not hash to the git SHA-1 the repository tree already reported for it
// (corrupted or tampered transport). This is a content-integrity failure,
// distinct from the archive/tree consistency failure above.
type ErrBlobIntegrityMismatch struct {
	Path string
	SHA  string
}

func (e *ErrBlobIntegrityMismatch) Error() string {
	return fmt.Sprintf("cloudidentitysource: blob %s failed git sha1 integrity verification", e.Path)
}

// RepositoryOptions configures NewRepositoryReader. Every GitHub owner routes
// through its own GitHub App installation; only allow-listed owner/repo pairs
// and module coordinates may ever be fetched.
type RepositoryOptions struct {
	// Apps maps a lower-cased GitHub owner (org or user login) to the GitHub
	// App installation credentials used to read that owner's repositories.
	// ReadRepository requires an entry for the pin's owner; ReadModule falls
	// back to an unauthenticated client when the module's owner has none.
	Apps map[string]sourcehttp.GitHubAppAuthConfig
	// AllowedRepositories lists "owner/repo" pairs (case-insensitive) that
	// ReadRepository may fetch.
	AllowedRepositories []string
	// AllowedModules lists additional "owner/repo" pairs reachable through
	// ReadModule's github.com-style module sources. May overlap
	// AllowedRepositories.
	AllowedModules []string
	// RegistryModules lists "namespace/name/provider" Terraform Registry
	// module addresses ReadModule may resolve.
	RegistryModules []string
	// RegistryBaseURL overrides the Terraform Registry origin; defaults to
	// https://registry.terraform.io.
	RegistryBaseURL string
	// HTTPClient is the base client each owner's hardened, authenticated
	// client wraps. A nil value starts from http.DefaultTransport.
	HTTPClient *http.Client
	// BaseURL overrides the GitHub REST API origin (GitHub Enterprise or
	// tests); production defaults to the public GitHub API.
	BaseURL string
	// AllowLoopbackBaseURL permits loopback/private BaseURL/RegistryBaseURL
	// hosts; tests only.
	AllowLoopbackBaseURL bool
	// LookupIPAddrs overrides DNS resolution for host-safety pinning; tests
	// only.
	LookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)
	// MaxFiles bounds the number of files a single ReadRepository/ReadModule
	// call returns. Defaults to 8192.
	MaxFiles int
	// MaxFileBytes bounds a single file's content length. Defaults to 1 MiB.
	MaxFileBytes int
	// MaxTotalBytes bounds the sum of all returned file content lengths.
	// Defaults to 128 MiB.
	MaxTotalBytes int
	// MaxArchiveBytes bounds the single whole-repository tarball download
	// per (repo, commit). Defaults to 256 MiB.
	MaxArchiveBytes int
	// MaxArchiveEntries bounds the total number of tar header entries read
	// from the whole-repository archive stream (including directories and
	// entries outside the selected/wanted subset). Defaults to 200000.
	MaxArchiveEntries int
	// MaxArchiveDecompressedBytes bounds the total decompressed bytes read
	// from the whole-repository archive stream across every entry,
	// independent of MaxTotalBytes which only bounds the sum of content
	// actually selected/extracted. Defaults to 2 GiB.
	MaxArchiveDecompressedBytes int64
	// Timeout bounds every outbound HTTP request. Defaults to 30s.
	Timeout time.Duration
}

type repositoryReader struct {
	apps                        map[string]sourcehttp.GitHubAppAuthConfig
	allowedRepositories         map[string]bool
	allowedModules              map[string]bool
	registryModules             map[string]bool
	registryBaseURL             string
	baseHTTPClient              *http.Client
	githubBaseURL               string
	allowLoopback               bool
	lookupIPAddrs               func(context.Context, string) ([]net.IPAddr, error)
	maxFiles                    int
	maxFileBytes                int
	maxTotalBytes               int
	maxArchiveBytes             int
	maxArchiveEntries           int
	maxArchiveDecompressedBytes int64
	timeout                     time.Duration

	clients              *repositoryClientCache
	refs                 *repositoryRefCache
	moduleRegistryClient *repositoryLazyClient
	archiveClient        *repositoryLazyClient
	archives             *repositoryArchiveCache
	materialized         *repositoryMaterializedCache
	visibility           *repositoryVisibilityCache
}

// repositoryClientCache memoizes hardened, authenticated GitHub REST API
// clients per lower-cased owner ("" = anonymous), built once per reader
// instance. getOrBuild runs the whole get-or-build sequence under one lock
// so two concurrent callers for the same owner never race to build (and
// discard) duplicate clients.
type repositoryClientCache struct {
	mu      sync.Mutex
	clients map[string]*gogithub.Client
}

func newRepositoryClientCache() *repositoryClientCache {
	return &repositoryClientCache{clients: make(map[string]*gogithub.Client)}
}

func (c *repositoryClientCache) getOrBuild(key string, build func() (*gogithub.Client, error)) (*gogithub.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[key]; ok {
		return client, nil
	}
	client, err := build()
	if err != nil {
		return nil, err
	}
	c.clients[key] = client
	return client, nil
}

// repositoryRefCache memoizes "owner/repo@revision" -> resolved commit sha,
// cached per reader instance.
type repositoryRefCache struct {
	mu   sync.Mutex
	refs map[string]string
}

func newRepositoryRefCache() *repositoryRefCache {
	return &repositoryRefCache{refs: make(map[string]string)}
}

func (c *repositoryRefCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sha, ok := c.refs[key]
	return sha, ok
}

func (c *repositoryRefCache) store(key, sha string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refs[key] = sha
}

// repositoryLazyClient lazily builds and memoizes one *http.Client exactly
// once for the lifetime of a reader instance.
type repositoryLazyClient struct {
	once   sync.Once
	client *http.Client
}

func (l *repositoryLazyClient) get(build func() *http.Client) *http.Client {
	l.once.Do(func() { l.client = build() })
	return l.client
}

// repositoryArchiveCache caches the raw downloaded tarball bytes for one
// (repo, commit) -- the archive always contains the whole repository
// regardless of root, so a second root-scoped read of the same commit
// reuses the already-downloaded bytes instead of a second network fetch,
// satisfying "one archive download per (repo, commit)" even across many
// different-root reads in the same reader run.
type repositoryArchiveCache struct {
	mu   sync.Mutex
	data map[string][]byte // "owner/repo@commit" -> raw tar.gz bytes
}

func newRepositoryArchiveCache() *repositoryArchiveCache {
	return &repositoryArchiveCache{data: make(map[string][]byte)}
}

func (c *repositoryArchiveCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, ok := c.data[key]
	return data, ok
}

func (c *repositoryArchiveCache) store(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = data
}

// repositoryMaterializedCache caches the fully built, root-scoped result
// per reader run so an identical (repo, commit, root) read is never redone
// at all.
type repositoryMaterializedCache struct {
	mu      sync.Mutex
	results map[string]ci.Repository // "owner/repo@commit#root" -> result
}

func newRepositoryMaterializedCache() *repositoryMaterializedCache {
	return &repositoryMaterializedCache{results: make(map[string]ci.Repository)}
}

func (c *repositoryMaterializedCache) get(key string) (ci.Repository, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result, ok := c.results[key]
	return result, ok
}

func (c *repositoryMaterializedCache) store(key string, result ci.Repository) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[key] = result
}

// repositoryVisibilityCache caches whether a repository is public, keyed by
// coordinateKey, per reader instance.
type repositoryVisibilityCache struct {
	mu         sync.Mutex
	visibility map[string]bool
}

func newRepositoryVisibilityCache() *repositoryVisibilityCache {
	return &repositoryVisibilityCache{visibility: make(map[string]bool)}
}

func (c *repositoryVisibilityCache) get(key string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	public, ok := c.visibility[key]
	return public, ok
}

func (c *repositoryVisibilityCache) store(key string, public bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visibility[key] = public
}

// NewRepositoryReader builds a GitHub-backed ci.RepositoryReader. The
// returned value also implements ci.ModuleReader; use AsModuleReader to
// obtain that view without an unchecked type assertion.
func NewRepositoryReader(options RepositoryOptions) (ci.RepositoryReader, error) {
	allowedRepositories, err := normalizeCoordinateSet(options.AllowedRepositories)
	if err != nil {
		return nil, fmt.Errorf("cloudidentitysource: allowed_repositories: %w", err)
	}
	allowedModules, err := normalizeCoordinateSet(options.AllowedModules)
	if err != nil {
		return nil, fmt.Errorf("cloudidentitysource: allowed_modules: %w", err)
	}
	registryModules, err := normalizeModuleAddressSet(options.RegistryModules)
	if err != nil {
		return nil, fmt.Errorf("cloudidentitysource: registry_modules: %w", err)
	}
	if len(allowedRepositories) == 0 && len(allowedModules) == 0 && len(registryModules) == 0 {
		return nil, fmt.Errorf("cloudidentitysource: at least one of allowed_repositories, allowed_modules, or registry_modules is required")
	}

	apps := make(map[string]sourcehttp.GitHubAppAuthConfig, len(options.Apps))
	for owner, cfg := range options.Apps {
		owner = strings.ToLower(strings.TrimSpace(owner))
		if owner == "" {
			continue
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("cloudidentitysource: github app config for owner %q: %w", owner, err)
		}
		apps[owner] = cfg
	}

	githubBaseURL := ""
	if strings.TrimSpace(options.BaseURL) != "" {
		normalized, _, err := sourcehttp.NormalizeBaseURLWithOptions(repositorySourceID, options.BaseURL, sourcehttp.URLValidationOptions{AllowLoopback: options.AllowLoopbackBaseURL})
		if err != nil {
			return nil, fmt.Errorf("cloudidentitysource: base_url: %w", err)
		}
		githubBaseURL = normalized
	}

	registryBaseURLInput := strings.TrimSpace(options.RegistryBaseURL)
	if registryBaseURLInput == "" {
		registryBaseURLInput = defaultTerraformRegistryBaseURL
	}
	registryBaseURL, _, err := sourcehttp.NormalizeBaseURLWithOptions(moduleRegistrySourceID, registryBaseURLInput, sourcehttp.URLValidationOptions{AllowLoopback: options.AllowLoopbackBaseURL})
	if err != nil {
		return nil, fmt.Errorf("cloudidentitysource: registry_base_url: %w", err)
	}

	maxFiles := options.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultRepositoryMaxFiles
	}
	maxFileBytes := options.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = defaultRepositoryMaxFileBytes
	}
	maxTotalBytes := options.MaxTotalBytes
	if maxTotalBytes <= 0 {
		maxTotalBytes = defaultRepositoryMaxTotalBytes
	}
	maxArchiveBytes := options.MaxArchiveBytes
	if maxArchiveBytes <= 0 {
		maxArchiveBytes = defaultRepositoryMaxArchiveBytes
	}
	maxArchiveEntries := options.MaxArchiveEntries
	if maxArchiveEntries <= 0 {
		maxArchiveEntries = defaultRepositoryMaxArchiveEntries
	}
	maxArchiveDecompressedBytes := options.MaxArchiveDecompressedBytes
	if maxArchiveDecompressedBytes <= 0 {
		maxArchiveDecompressedBytes = defaultRepositoryMaxArchiveDecompressedBytes
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultRepositoryTimeout
	}

	return &repositoryReader{
		apps:                        apps,
		allowedRepositories:         allowedRepositories,
		allowedModules:              allowedModules,
		registryModules:             registryModules,
		registryBaseURL:             registryBaseURL,
		baseHTTPClient:              options.HTTPClient,
		githubBaseURL:               githubBaseURL,
		allowLoopback:               options.AllowLoopbackBaseURL,
		lookupIPAddrs:               options.LookupIPAddrs,
		maxFiles:                    maxFiles,
		maxFileBytes:                maxFileBytes,
		maxTotalBytes:               maxTotalBytes,
		maxArchiveBytes:             maxArchiveBytes,
		maxArchiveEntries:           maxArchiveEntries,
		maxArchiveDecompressedBytes: maxArchiveDecompressedBytes,
		timeout:                     timeout,
		clients:                     newRepositoryClientCache(),
		refs:                        newRepositoryRefCache(),
		moduleRegistryClient:        &repositoryLazyClient{},
		archiveClient:               &repositoryLazyClient{},
		archives:                    newRepositoryArchiveCache(),
		materialized:                newRepositoryMaterializedCache(),
		visibility:                  newRepositoryVisibilityCache(),
	}, nil
}

// AsModuleReader exposes the ModuleReader side of a reader built by
// NewRepositoryReader without requiring callers to perform an unchecked type
// assertion on the concrete (unexported) implementation.
func AsModuleReader(reader ci.RepositoryReader) (ci.ModuleReader, error) {
	moduleReader, ok := reader.(ci.ModuleReader)
	if !ok {
		return nil, fmt.Errorf("cloudidentitysource: repository reader %T does not implement ModuleReader", reader)
	}
	return moduleReader, nil
}

// ReadRepository fetches the exact pinned commit tree for pin.Repository,
// resolving pin.Revision to an immutable commit SHA before reading any file
// content. It never falls back to a default branch.
func (r *repositoryReader) ReadRepository(ctx context.Context, pin ci.SourcePin) (ci.Repository, error) {
	owner, name, err := parseRepositoryCoordinate(pin.Repository)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: %w", err)
	}
	if !r.allowedRepositories[coordinateKey(owner, name)] {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: %s/%s: %w", owner, name, ErrRepositoryNotAllowed)
	}
	revision := strings.TrimSpace(pin.Revision)
	if revision == "" {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: %s/%s: %w", owner, name, ErrRevisionRequired)
	}
	client, err := r.githubClient(owner, true)
	if err != nil {
		return ci.Repository{}, err
	}
	commit, err := r.resolveCommit(ctx, client, owner, name, revision)
	if err != nil {
		return ci.Repository{}, err
	}
	return r.readTree(ctx, client, owner, name, commit, pin.Root)
}

// githubClient returns a cached, hardened, per-owner authenticated client.
// When required is false and no App installation is configured for owner, an
// anonymous (unauthenticated) hardened client is returned instead, which is
// only appropriate for public module reads, never for primary app-source
// evidence.
func (r *repositoryReader) githubClient(owner string, required bool) (*gogithub.Client, error) {
	ownerKey := strings.ToLower(owner)
	cfg, hasApp := r.apps[ownerKey]
	cacheKey := ownerKey
	if !hasApp {
		if required {
			return nil, fmt.Errorf("cloudidentitysource: owner %q: %w", owner, ErrGitHubAppNotConfigured)
		}
		cacheKey = ""
	}
	return r.clients.getOrBuild(cacheKey, func() (*gogithub.Client, error) {
		hardened := sourcehttp.HardenSourceClient(r.baseHTTPClient, repositorySourceID, r.timeout, r.allowLoopback, r.lookupIPAddrs)
		httpClient := hardened
		if hasApp {
			if strings.TrimSpace(cfg.BaseURL) == "" {
				cfg.BaseURL = r.githubBaseURL
			}
			wrapped, err := sourcehttp.WithGitHubAppAuth(hardened, cfg)
			if err != nil {
				return nil, fmt.Errorf("cloudidentitysource: configure github app auth for owner %q: %w", owner, err)
			}
			httpClient = wrapped
		}

		client := gogithub.NewClient(httpClient)
		if r.githubBaseURL != "" {
			enterprise, err := client.WithEnterpriseURLs(r.githubBaseURL, r.githubBaseURL)
			if err != nil {
				return nil, fmt.Errorf("cloudidentitysource: parse github base url: %w", err)
			}
			client = enterprise
		}
		return client, nil
	})
}

// hasGitHubApp reports whether owner has a configured GitHub App
// installation. Module reads use this to decide whether an anonymous read
// requires an explicit public-visibility check first.
func (r *repositoryReader) hasGitHubApp(owner string) bool {
	_, ok := r.apps[strings.ToLower(owner)]
	return ok
}

// ensurePublicForAnonymousRead verifies, before issuing any content read
// with an unauthenticated client, that owner/name is actually a public
// repository. It never lets an anonymous module read fall through against a
// private repository just because that repository's owner happens to have
// no App installation; the result is cached per reader instance.
func (r *repositoryReader) ensurePublicForAnonymousRead(ctx context.Context, client *gogithub.Client, owner, name string) error {
	key := coordinateKey(owner, name)
	if public, ok := r.visibility.get(key); ok {
		if !public {
			return fmt.Errorf("cloudidentitysource: %s/%s: %w", owner, name, ErrModulePrivateWithoutApp)
		}
		return nil
	}

	repo, _, err := client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return fmt.Errorf("cloudidentitysource: verify %s/%s visibility before an anonymous module read: %w", owner, name, err)
	}
	public := !repo.GetPrivate()

	r.visibility.store(key, public)

	if !public {
		return fmt.Errorf("cloudidentitysource: %s/%s: %w", owner, name, ErrModulePrivateWithoutApp)
	}
	return nil
}

// resolveCommit resolves a possibly-floating ref (branch, tag, or SHA) to an
// immutable commit SHA exactly once per (owner/repo, revision) pair for the
// lifetime of this reader, so repeated calls across different SourcePin.Root
// values against the same repo/ref never observe different commits.
func (r *repositoryReader) resolveCommit(ctx context.Context, client *gogithub.Client, owner, name, revision string) (string, error) {
	key := coordinateKey(owner, name) + "@" + revision
	if sha, ok := r.refs.get(key); ok {
		return sha, nil
	}

	sha, _, err := client.Repositories.GetCommitSHA1(ctx, owner, name, revision, "")
	if err != nil {
		return "", fmt.Errorf("cloudidentitysource: resolve %s/%s@%s to a commit: %w", owner, name, revision, err)
	}
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return "", fmt.Errorf("cloudidentitysource: github returned an empty commit sha for %s/%s@%s", owner, name, revision)
	}

	r.refs.store(key, sha)
	return sha, nil
}

// readTree walks the recursive git tree at commit, keeping only plain-file
// entries under root, rejecting symlinks/submodules/unsafe paths and
// credential-shaped filenames, then materializes the surviving,
// budget-selected candidates from one whole-repository tarball download
// per (repo, commit) (never a separate GitHub API call per file -- a
// repository with thousands of tracked files would otherwise exhaust a
// GitHub App's rate limit on its own), verifying each extracted file's
// content against the git blob SHA-1 the tree already reported before
// trusting it. Returned file paths are always repository-relative (root
// only filters, never rewrites). Results are cached per reader instance,
// keyed by (repo, commit, root).
func (r *repositoryReader) readTree(ctx context.Context, client *gogithub.Client, owner, name, commit, root string) (ci.Repository, error) {
	cacheKey := coordinateKey(owner, name) + "@" + commit + "#" + root
	if cached, ok := r.materialized.get(cacheKey); ok {
		return cached, nil
	}

	tree, _, err := client.Git.GetTree(ctx, owner, name, commit, true)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: list %s/%s@%s tree: %w", owner, name, commit, err)
	}

	var gaps []ci.Gap
	reference := ci.Reference{Repository: owner + "/" + name, Revision: commit, API: "github.git.getTree"}
	if tree.GetTruncated() {
		gaps = append(gaps, ci.Gap{
			Code:       "repository.tree_truncated",
			Scope:      "repository",
			Message:    fmt.Sprintf("github truncated the recursive tree listing for %s/%s@%s; coverage may be incomplete", owner, name, commit),
			References: []ci.Reference{reference},
		})
	}

	rootClean := cleanRelativePath(root)
	skips := newRepositoryGapAccumulator()
	var candidates []*gogithub.TreeEntry
	for _, entry := range tree.Entries {
		if entry == nil {
			continue
		}
		entryType := entry.GetType()
		if entryType != gitTreeEntryTypeBlob && entryType != gitTreeEntryTypeCommit {
			// Directory ("tree") markers: recursive=true already flattens
			// their file contents into separate blob entries, so the
			// directory marker itself carries nothing to read.
			continue
		}
		rawPath := entry.GetPath()
		if !pathTraversalSafe(rawPath) {
			skips.add("repository.path_rejected", rawPath)
			continue
		}
		cleanPath := cleanRelativePath(rawPath)
		if !withinRoot(rootClean, cleanPath) {
			continue
		}
		if entryType == gitTreeEntryTypeCommit {
			// Submodule reference (gitlink); its content lives in another
			// repository entirely and is out of scope.
			skips.add("repository.submodule_skipped", cleanPath)
			continue
		}
		if entry.GetMode() == gitTreeModeSymlink {
			skips.add("repository.symlink_skipped", cleanPath)
			continue
		}
		if denied, _ := credentialFileDenied(cleanPath); denied {
			// Denied files are never added to candidates, so they are
			// never extracted from the archive below.
			skips.add("repository.file_denied", cleanPath)
			continue
		}
		candidates = append(candidates, entry)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].GetPath() < candidates[j].GetPath() })

	var selected []*gogithub.TreeEntry
	var totalBytes int
	for _, entry := range candidates {
		size := entry.GetSize()
		if len(selected) >= r.maxFiles || size > r.maxFileBytes || totalBytes+size > r.maxTotalBytes {
			skips.add("repository.budget_exceeded", entry.GetPath())
			continue
		}
		selected = append(selected, entry)
		totalBytes += size
	}

	var files []ci.SourceFile
	if len(selected) > 0 {
		archive, err := r.fetchArchive(ctx, client, owner, name, commit)
		if err != nil {
			return ci.Repository{}, fmt.Errorf("cloudidentitysource: download %s/%s@%s archive: %w", owner, name, commit, err)
		}
		wanted := make(map[string]bool, len(selected))
		for _, entry := range selected {
			wanted[entry.GetPath()] = true
		}
		extracted, err := repositoryExtractArchiveEntries(ctx, archive, wanted, r.maxFileBytes, r.maxArchiveEntries, r.maxArchiveDecompressedBytes)
		if err != nil {
			return ci.Repository{}, fmt.Errorf("cloudidentitysource: extract %s/%s@%s archive: %w", owner, name, commit, err)
		}
		files = make([]ci.SourceFile, 0, len(selected))
		for _, entry := range selected {
			content, ok := extracted[entry.GetPath()]
			if !ok {
				return ci.Repository{}, &ErrArchiveMissingExpectedFile{Owner: owner, Repo: name, Commit: commit, Path: entry.GetPath()}
			}
			if !verifyGitBlobSHA(content, entry.GetSHA()) {
				return ci.Repository{}, &ErrBlobIntegrityMismatch{Path: entry.GetPath(), SHA: entry.GetSHA()}
			}
			files = append(files, ci.SourceFile{Path: entry.GetPath(), Content: content, Digest: "sha1:" + entry.GetSHA()})
		}
	}

	gaps = append(gaps, skips.gaps(reference)...)

	digest, err := contentDigest(files)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: digest %s/%s@%s content: %w", owner, name, commit, err)
	}
	pin := ci.SourcePin{
		Repository: owner + "/" + name,
		Revision:   commit,
		Root:       root,
		Digest:     digest,
		Exact:      true,
	}
	result := ci.Repository{Pin: pin, Files: files, Gaps: gaps}

	r.materialized.store(cacheKey, result)
	return result, nil
}

// fetchArchive downloads (and caches, per reader instance, keyed by
// (repo, commit)) the whole-repository gzipped tarball for commit through
// GitHub's archive-link API: one authenticated GET through client resolves
// a short-lived archive URL, then one bounded GET through the hardened
// archive client fetches the bytes. A second root-scoped read of the same
// commit never re-downloads.
func (r *repositoryReader) fetchArchive(ctx context.Context, client *gogithub.Client, owner, name, commit string) ([]byte, error) {
	key := coordinateKey(owner, name) + "@" + commit
	if data, ok := r.archives.get(key); ok {
		return data, nil
	}

	link, _, err := client.Repositories.GetArchiveLink(ctx, owner, name, gogithub.Tarball, &gogithub.RepositoryContentGetOptions{Ref: commit}, 0)
	if err != nil {
		return nil, fmt.Errorf("resolve archive link: %w", err)
	}
	data, err := r.downloadArchiveBytes(ctx, link.String())
	if err != nil {
		return nil, fmt.Errorf("download archive: %w", err)
	}

	r.archives.store(key, data)
	return data, nil
}

// downloadArchiveBytes fetches rawURL (the short-lived, pre-authorized
// location GitHub's archive-link API returned) through a dedicated hardened
// client, bounded by maxArchiveBytes.
func (r *repositoryReader) downloadArchiveBytes(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse archive url: %w", err)
	}
	allowInsecureLoopback := r.allowLoopback && u.Scheme == "http" && sourcehttp.IsLoopbackHost(u.Hostname())
	if u.Scheme != "https" && !allowInsecureLoopback {
		return nil, fmt.Errorf("refusing non-https archive fetch %q", rawURL)
	}
	if !r.allowLoopback && sourcecdk.IsUnsafeHost(u.Hostname()) {
		return nil, fmt.Errorf("refusing archive fetch to unsafe host %q", u.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.archiveHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d fetching archive %q", resp.StatusCode, rawURL)
	}
	limited := io.LimitReader(resp.Body, int64(r.maxArchiveBytes)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > r.maxArchiveBytes {
		return nil, fmt.Errorf("archive response exceeded the %d byte bound", r.maxArchiveBytes)
	}
	return data, nil
}

// archiveHTTPClient lazily builds the hardened (but unauthenticated) client
// used only to fetch an already-resolved, pre-authorized archive download
// URL -- it carries no GitHub App bearer token, since the resolved URL is
// itself short-lived and self-authorizing.
func (r *repositoryReader) archiveHTTPClient() *http.Client {
	return r.archiveClient.get(func() *http.Client {
		return sourcehttp.HardenSourceClient(r.baseHTTPClient, repositorySourceID, r.timeout, r.allowLoopback, r.lookupIPAddrs)
	})
}

// repositoryExtractArchiveEntries streams archive (a gzipped tar, GitHub's
// standard repository-archive layout: one top-level "owner-repo-shortsha/"
// wrapper directory) and returns the content of every regular-file entry
// whose wrapper-stripped, repository-relative path is a key of wanted.
// Every header read from the stream -- including directories, other
// non-regular entries, and entries outside wanted -- counts against
// maxEntries, and has its declared body drained through the same
// aggregate maxTotalBytes decompressed-byte bound as bytes actually kept
// for a wanted entry: an unwanted entry is never left for the tar reader
// to silently discard an unbounded amount of decompressed data for when
// advancing past it. Extraction stops as soon as every wanted entry has
// been found (the rest of a large repository archive is never read), or
// ctx is canceled.
func repositoryExtractArchiveEntries(ctx context.Context, archive []byte, wanted map[string]bool, maxFileBytes, maxEntries int, maxTotalBytes int64) (map[string][]byte, error) {
	found := make(map[string][]byte, len(wanted))
	if len(wanted) == 0 {
		return found, nil
	}
	gzr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gzr.Close() }()
	tr := tar.NewReader(gzr)
	entries := 0
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
			return nil, fmt.Errorf("read archive entry: %w", err)
		}
		entries++
		if entries > maxEntries {
			return nil, &ErrArchiveEntryBoundExceeded{Limit: maxEntries}
		}

		remaining := maxTotalBytes - totalBytes
		if remaining < 0 {
			remaining = 0
		}

		var rel string
		wantEntry := false
		if hdr.Typeflag == tar.TypeReg {
			if r, ok := repositoryArchiveEntryPath(hdr.Name); ok && wanted[r] {
				rel = r
				wantEntry = true
			}
		}

		if wantEntry {
			entryLimit := int64(maxFileBytes)
			if remaining < entryLimit {
				entryLimit = remaining
			}
			content, err := io.ReadAll(io.LimitReader(tr, entryLimit+1))
			if err != nil {
				return nil, fmt.Errorf("read archive entry %q: %w", rel, err)
			}
			if len(content) > maxFileBytes {
				return nil, fmt.Errorf("archive entry %q exceeded the %d byte bound", rel, maxFileBytes)
			}
			totalBytes += int64(len(content))
			if totalBytes > maxTotalBytes {
				return nil, &ErrArchiveAggregateBoundExceeded{Limit: maxTotalBytes}
			}
			found[rel] = content
			if len(found) >= len(wanted) {
				return found, nil
			}
			continue
		}

		// Unwanted (or non-regular) entry: still drain its declared body
		// through the aggregate bound rather than letting the tar reader
		// discard an unlimited amount of decompressed data on the next
		// Next() call.
		n, err := io.Copy(io.Discard, io.LimitReader(tr, remaining+1))
		if err != nil {
			return nil, fmt.Errorf("read archive entry %q: %w", hdr.Name, err)
		}
		totalBytes += n
		if totalBytes > maxTotalBytes {
			return nil, &ErrArchiveAggregateBoundExceeded{Limit: maxTotalBytes}
		}
	}
	return found, nil
}

// repositoryArchiveEntryPath strips GitHub archive's single top-level
// wrapper directory ("owner-repo-shortsha/path/to/file") from a tar entry
// name, returning the repository-relative path. Entries outside any
// wrapper directory (or the wrapper directory marker itself) are rejected.
func repositoryArchiveEntryPath(name string) (string, bool) {
	clean := strings.Trim(path.Clean("/"+name), "/")
	if clean == "" || clean == "." {
		return "", false
	}
	idx := strings.IndexByte(clean, '/')
	if idx < 0 {
		return "", false
	}
	rel := clean[idx+1:]
	if rel == "" {
		return "", false
	}
	return rel, true
}

// repositoryGapMessages gives each skip code a scope-aware template:
// "<count>" then "<scope>".
var repositoryGapMessages = map[string]string{
	"repository.path_rejected":     "skipped %d tree entries with unsafe paths under %q",
	"repository.symlink_skipped":   "skipped %d symlink tree entries under %q; symlink targets are never followed",
	"repository.submodule_skipped": "skipped %d submodule tree entries under %q; submodule content is out of scope",
	"repository.file_denied":       "skipped %d files under %q matching the credential/secret/state deny policy",
	"repository.budget_exceeded":   "skipped %d files under %q exceeding the configured file-count/size budget",
}

// repositoryGapAccumulator groups skipped-entry counts by (code, top-level
// path scope) instead of one opaque repository-wide count, so a gap on a
// huge generated subtree (vendor/, .terraform/, charts/, generated k8s
// manifests, …) tells a caller which area is incomplete.
type repositoryGapAccumulator struct {
	entries map[string]*repositoryGapEntry
	order   []string
}

type repositoryGapEntry struct {
	code    string
	scope   string
	count   int
	samples []string
}

func newRepositoryGapAccumulator() *repositoryGapAccumulator {
	return &repositoryGapAccumulator{entries: map[string]*repositoryGapEntry{}}
}

func (a *repositoryGapAccumulator) add(code, relPath string) {
	scope := topLevelPathScope(relPath)
	key := code + "\x00" + scope
	entry, ok := a.entries[key]
	if !ok {
		entry = &repositoryGapEntry{code: code, scope: scope}
		a.entries[key] = entry
		a.order = append(a.order, key)
	}
	entry.count++
	if len(entry.samples) < 3 {
		entry.samples = append(entry.samples, relPath)
	}
}

func (a *repositoryGapAccumulator) gaps(reference ci.Reference) []ci.Gap {
	if len(a.entries) == 0 {
		return nil
	}
	sort.Strings(a.order)
	gaps := make([]ci.Gap, 0, len(a.order))
	for _, key := range a.order {
		entry := a.entries[key]
		template := repositoryGapMessages[entry.code]
		message := fmt.Sprintf(template, entry.count, entry.scope)
		if len(entry.samples) > 0 {
			message += fmt.Sprintf(" (examples: %s)", strings.Join(entry.samples, ", "))
		}
		ref := reference
		ref.Path = entry.scope
		gaps = append(gaps, ci.Gap{Code: entry.code, Scope: entry.scope, Message: message, References: []ci.Reference{ref}})
	}
	return gaps
}

func topLevelPathScope(relPath string) string {
	if idx := strings.Index(relPath, "/"); idx >= 0 {
		return relPath[:idx]
	}
	return relPath
}

// verifyGitBlobSHA recomputes the git blob object SHA-1 for content and
// compares it against the SHA GitHub reported in the tree entry, so a
// tampered or truncated transport response is detected rather than trusted.
func verifyGitBlobSHA(content []byte, sha string) bool {
	header := fmt.Sprintf("blob %d\x00", len(content))
	hash := sha1.New() // #nosec G401 -- matches git's own object addressing, not a security boundary.
	hash.Write([]byte(header))
	hash.Write(content)
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), strings.TrimSpace(sha))
}

// contentDigest is the canonical whole-repository content digest, delegated
// to ci.RepositoryDigest so there is exactly one algorithm shared with the
// requirements validator: it is computed from each file's actual content
// bytes, never by trusting the git blob SHA this adapter already verified
// (SourceFile.Digest) as proof.
func contentDigest(files []ci.SourceFile) (string, error) {
	return ci.RepositoryDigest(files)
}

// pathTraversalSafe rejects raw tree paths with empty/"."/".." segments or a
// leading slash before any normalization happens, independent of what
// path.Clean would later resolve them to.
func pathTraversalSafe(raw string) bool {
	if raw == "" || strings.HasPrefix(raw, "/") {
		return false
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func cleanRelativePath(raw string) string {
	cleaned := strings.Trim(path.Clean("/"+raw), "/")
	if cleaned == "." {
		return ""
	}
	return cleaned
}

func withinRoot(root, candidate string) bool {
	if candidate == "" {
		return false
	}
	if root == "" {
		return true
	}
	return candidate == root || strings.HasPrefix(candidate, root+"/")
}

var (
	deniedFileBaseNames = map[string]bool{
		".env":                                 true,
		".netrc":                               true,
		".npmrc":                               true,
		"credentials":                          true,
		"credentials.json":                     true,
		"application_default_credentials.json": true,
		"id_rsa":                               true,
		"id_dsa":                               true,
		"id_ecdsa":                             true,
		"id_ed25519":                           true,
		"terraform.tfstate":                    true,
	}
	deniedFileSuffixes = []string{".tfstate", ".tfstate.backup", ".pem", ".key", ".pfx", ".p12", ".ppk"}
	deniedPathSegments = map[string]bool{".aws": true, ".ssh": true, ".gcloud": true, ".kube": true, ".git": true, ".terraform": true}
)

// credentialFileDenied reports whether relPath names a credential, secret, or
// Terraform state file that must never be forwarded to a model or stored,
// even though it was reachable in the pinned tree.
func credentialFileDenied(relPath string) (bool, string) {
	lower := strings.ToLower(relPath)
	base := path.Base(lower)
	if deniedFileBaseNames[base] {
		return true, "denied credential/state filename"
	}
	if strings.HasPrefix(base, ".env.") {
		return true, "denied environment file"
	}
	if strings.HasSuffix(base, ".json") && (strings.Contains(base, "service_account") || strings.Contains(base, "service-account")) {
		return true, "denied service account key file"
	}
	if strings.Contains(base, "kubeconfig") {
		return true, "denied kubeconfig file"
	}
	for _, suffix := range deniedFileSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true, "denied secret/state file extension"
		}
	}
	for _, segment := range strings.Split(lower, "/") {
		if deniedPathSegments[segment] {
			return true, "denied credential directory"
		}
	}
	return false, ""
}

var repositoryCoordinateSegment = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// parseRepositoryCoordinate accepts "owner/repo", "github.com/owner/repo",
// "https://github.com/owner/repo[.git]", or the exact GitHub SCP/SSH form
// "git@github.com:owner/repo[.git]" (as used throughout Argo CD
// repoURL values) and returns the validated owner/repo pair. It never
// accepts any other host, in either URL or SCP form, or path traversal
// segments.
func parseRepositoryCoordinate(raw string) (owner, name string, err error) {
	trimmed := strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(trimmed, "git@github.com:"); ok {
		trimmed = rest
	} else {
		trimmed = strings.TrimPrefix(trimmed, "https://github.com/")
		trimmed = strings.TrimPrefix(trimmed, "http://github.com/")
		trimmed = strings.TrimPrefix(trimmed, "github.com/")
	}
	trimmed = strings.TrimSuffix(trimmed, ".git")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("repository %q must be an owner/repo coordinate", raw)
	}
	owner, name = parts[0], parts[1]
	if !repositoryCoordinateSegment.MatchString(owner) || !repositoryCoordinateSegment.MatchString(name) {
		return "", "", fmt.Errorf("repository %q has an invalid owner or name segment", raw)
	}
	return owner, name, nil
}

func coordinateKey(owner, name string) string {
	return strings.ToLower(owner) + "/" + strings.ToLower(name)
}

func normalizeCoordinateSet(raw []string) (map[string]bool, error) {
	set := make(map[string]bool, len(raw))
	for _, entry := range raw {
		owner, name, err := parseRepositoryCoordinate(entry)
		if err != nil {
			return nil, err
		}
		set[coordinateKey(owner, name)] = true
	}
	return set, nil
}
