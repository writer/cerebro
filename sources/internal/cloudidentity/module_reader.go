package cloudidentitysource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	defaultTerraformRegistryBaseURL = "https://registry.terraform.io"
	moduleRegistrySourceID          = "cloud_identity_module_registry"
	maxModuleRegistryBodyBytes      = 1 << 16 // 64 KiB; download-info responses are small JSON/header-only payloads.
)

// ErrUnsupportedModuleSource is returned when a module source/registry
// download points at anything other than an approved github.com coordinate.
// Pinned local modules (relative paths) are out of scope here; the pure
// Terraform evaluator in internal/cloudidentity/iac handles those directly.
var ErrUnsupportedModuleSource = errors.New("module source is not an approved github.com or registry module address")

// ReadModule resolves a Terraform module source to its pinned, immutable
// content. source is either a github.com coordinate
// ("github.com/owner/repo[//subdir]", "git@github.com:owner/repo[.git][//subdir]",
// optionally "git::"-prefixed) or a Terraform Registry address
// ("namespace/name/provider[//subdir]"). The source is parsed first: a Git
// module pinned entirely through its own "?ref=" query (the common SCP-style
// shape, e.g. "git@github.com:org/repo//modules/x?ref=x/1.2.3") has no
// separate `version` attribute in Terraform and is still a valid, fully
// pinned source -- its query ref is the pin. version, when non-empty, always
// takes precedence (it is the sole pin for Registry addresses, which never
// carry their own ref). There is no default-branch or default-version
// fallback: a source that resolves to neither a literal `version` nor a
// source-embedded ref is always an error.
func (r *repositoryReader) ReadModule(ctx context.Context, source string, version string) (ci.Repository, error) {
	version = strings.TrimSpace(version)
	trimmed := strings.TrimSpace(source)
	trimmed = strings.TrimPrefix(trimmed, "git::")

	if owner, name, subdir, ref, ok := parseGitHubModuleSource(trimmed); ok {
		pin := version
		if pin == "" {
			pin = ref
		}
		if pin == "" {
			return ci.Repository{}, fmt.Errorf("cloudidentitysource: module %q: %w", source, ErrRevisionRequired)
		}
		return r.readGitHubModule(ctx, owner, name, subdir, pin)
	}
	if namespace, name, subdir, provider, ok := parseRegistrySource(trimmed); ok {
		if version == "" {
			return ci.Repository{}, fmt.Errorf("cloudidentitysource: module %q: %w", source, ErrRevisionRequired)
		}
		return r.readRegistryModule(ctx, namespace, name, provider, subdir, version)
	}
	return ci.Repository{}, fmt.Errorf("cloudidentitysource: module source %q: %w", source, ErrUnsupportedModuleSource)
}

// readGitHubModule materializes the whole bounded containing package (the
// git repository at the pinned commit -- see readTree's root="" call
// below), not just the requested "//subdir", so a legal local child module
// reference from inside subdir (e.g. "../shared", a sibling directory) can
// still resolve against the package index (R14 finding 4; the package
// boundary itself is the repository root, so there is nothing above it to
// escape into). The requested subdir is preserved as Pin.Root so callers
// still see this module's own entry point, exactly as before.
func (r *repositoryReader) readGitHubModule(ctx context.Context, owner, name, subdir, version string) (ci.Repository, error) {
	if !r.allowedModules[coordinateKey(owner, name)] && !r.allowedRepositories[coordinateKey(owner, name)] {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: module %s/%s: %w", owner, name, ErrModuleNotAllowed)
	}
	// Public module reads degrade to an anonymous client when the owner has
	// no configured App installation, but only after independently verifying
	// the repository is actually public; primary app-source reads never
	// degrade to anonymous at all (githubClient required=true above).
	client, err := r.githubClient(owner, false)
	if err != nil {
		return ci.Repository{}, err
	}
	if !r.hasGitHubApp(owner) {
		if err := r.ensurePublicForAnonymousRead(ctx, client, owner, name); err != nil {
			return ci.Repository{}, err
		}
	}
	commit, err := r.resolveCommit(ctx, client, owner, name, version)
	if err != nil {
		return ci.Repository{}, err
	}
	repo, err := r.readTree(ctx, client, owner, name, commit, "")
	if err != nil {
		return ci.Repository{}, err
	}
	repo.Pin.Root = subdir
	return repo, nil
}

// readRegistryModule resolves a Terraform Registry package address, honoring
// a requested "//subdir" written on the module source alongside the
// registry package itself (e.g.
// "terraform-google-modules/kubernetes-engine/google//modules/workload-identity").
// The registry download-info response may itself resolve to a go-getter
// source carrying its own subdir (rare, for packages nested in a monorepo);
// requestedSubdir is safely joined under that resolved subdir, never
// allowed to escape it. Materialization itself is bounded to the
// registry-resolved package root (registrySubdir), not the narrower
// combined subdir, so a legal local child module reference from inside
// requestedSubdir (e.g. "../shared", a sibling directory still within the
// registry's own published package) can resolve against the package index
// (R14 finding 4); the registry-resolved root is the package boundary, so
// readTree's own root-filtering already refuses anything above it. The
// combined subdir is preserved as Pin.Root so callers still see this
// module's own entry point, exactly as before. Once the package address
// itself has passed the dedicated RegistryModules allowlist and the
// resolved source has passed the github.com-only host restriction in
// parseResolvedModuleSource, the resolved upstream owner/repo is not
// required to separately appear in AllowedModules/AllowedRepositories:
// those two allowlists are configured disjointly on purpose (AllowedModules
// names this org's own internal repositories; RegistryModules names
// official third-party registry packages), and requiring both would make
// every configured registry module unreachable without unreviewed
// duplication.
func (r *repositoryReader) readRegistryModule(ctx context.Context, namespace, name, provider, requestedSubdir, version string) (ci.Repository, error) {
	address := namespace + "/" + name + "/" + provider
	if !r.registryModules[address] {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: registry module %s: %w", address, ErrModuleNotAllowed)
	}
	if requestedSubdir != "" && !pathTraversalSafe(requestedSubdir) {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: registry module %s: requested subdirectory %q is invalid", address, requestedSubdir)
	}
	resolvedSource, err := r.resolveRegistryModuleSource(ctx, namespace, name, provider, version)
	if err != nil {
		return ci.Repository{}, err
	}
	owner, repoName, registrySubdir, ref, err := parseResolvedModuleSource(resolvedSource)
	if err != nil {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: registry module %s: %w", address, err)
	}
	subdir, ok := joinModuleSubdirs(registrySubdir, requestedSubdir)
	if !ok {
		return ci.Repository{}, fmt.Errorf("cloudidentitysource: registry module %s: requested subdirectory %q escapes the resolved package %q", address, requestedSubdir, registrySubdir)
	}
	if ref == "" {
		// The registry's own immutable version is the fallback pin, never a
		// branch default: go-getter sources for registry modules normally
		// carry their own ?ref=, but when absent the requested (immutable)
		// registry version is still an explicit, caller-supplied pin.
		ref = version
	}
	client, err := r.githubClient(owner, false)
	if err != nil {
		return ci.Repository{}, err
	}
	if !r.hasGitHubApp(owner) {
		if err := r.ensurePublicForAnonymousRead(ctx, client, owner, repoName); err != nil {
			return ci.Repository{}, err
		}
	}
	commit, err := r.resolveCommit(ctx, client, owner, repoName, ref)
	if err != nil {
		return ci.Repository{}, err
	}
	repo, err := r.readTree(ctx, client, owner, repoName, commit, registrySubdir)
	if err != nil {
		return ci.Repository{}, err
	}
	repo.Pin.Root = subdir
	return repo, nil
}

// resolveRegistryModuleSource fetches the Terraform Registry Protocol
// download-info response (https://developer.hashicorp.com/terraform/internals/module-registry-protocol#download-source-code-for-a-specific-module-version)
// and returns the raw X-Terraform-Get (or 3xx Location) source string. The
// configured client never follows redirects automatically, so no credential
// is ever attached to whatever host that source string names.
func (r *repositoryReader) resolveRegistryModuleSource(ctx context.Context, namespace, name, provider, version string) (string, error) {
	requestPath := fmt.Sprintf("/v1/modules/%s/%s/%s/%s/download",
		url.PathEscape(namespace), url.PathEscape(name), url.PathEscape(provider), url.PathEscape(version))
	req, err := sourcehttp.NewRequest(ctx, moduleRegistrySourceID, r.registryBaseURL, r.allowLoopback, http.MethodGet, requestPath, nil, nil)
	if err != nil {
		return "", fmt.Errorf("build terraform registry download request for %s/%s/%s@%s: %w", namespace, name, provider, version, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := sourcehttp.DoWithRetry(ctx, r.moduleRegistryHTTPClient(), req, sourcehttp.RetryOptions{MaxBodyBytes: maxModuleRegistryBodyBytes})
	if err != nil {
		return "", fmt.Errorf("fetch terraform registry download info for %s/%s/%s@%s: %w", namespace, name, provider, version, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("terraform registry download info for %s/%s/%s@%s returned HTTP %d", namespace, name, provider, version, resp.StatusCode)
	}
	sourceHeader := strings.TrimSpace(resp.Header.Get("X-Terraform-Get"))
	if sourceHeader == "" {
		sourceHeader = strings.TrimSpace(resp.Header.Get("Location"))
	}
	if sourceHeader == "" {
		return "", fmt.Errorf("terraform registry returned no module source for %s/%s/%s@%s", namespace, name, provider, version)
	}
	return sourceHeader, nil
}

func (r *repositoryReader) moduleRegistryHTTPClient() *http.Client {
	r.moduleRegistryClientOnce.Do(func() {
		r.moduleRegistryClient = sourcehttp.HardenSourceClient(r.baseHTTPClient, moduleRegistrySourceID, r.timeout, r.allowLoopback, r.lookupIPAddrs)
	})
	return r.moduleRegistryClient
}

// splitOnDoubleSlash separates a go-getter "//" subdirectory marker from the
// base source path.
func splitOnDoubleSlash(raw string) (base, subdir string) {
	if idx := strings.Index(raw, "//"); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, ""
}

// gitHubSCPPrefix is the SCP-style ("scp-like") git remote prefix go-getter
// and Terraform both auto-detect without a "git::" forcing prefix. Only the
// exact "github.com" host is recognized here (this package never fetches
// any other git host), case-insensitively.
const gitHubSCPPrefix = "git@github.com:"

// parseGitHubModuleSource recognizes "github.com/owner/repo[//subdir]",
// "https://github.com/owner/repo[//subdir]", "owner/repo[//subdir]" (the
// common raw git shorthand, distinct from a 3-segment registry address), and
// the SCP-style "git@github.com:owner/repo[.git][//subdir]" form Git modules
// are commonly pinned with (e.g.
// "git@github.com:org/repo//modules/x?ref=x/1.2.3"). ref is the source's own
// "?ref=" query value, if present; ReadModule prefers an explicit `version`
// but falls back to this ref so a Git module pinned entirely through its
// source string (no separate `version` attribute, which Terraform does not
// require for Git sources) is still accepted as pinned.
func parseGitHubModuleSource(trimmed string) (owner, name, subdir, ref string, ok bool) {
	hasHostPrefix := false
	if strings.HasPrefix(strings.ToLower(trimmed), gitHubSCPPrefix) {
		trimmed = trimmed[len(gitHubSCPPrefix):]
		hasHostPrefix = true
	} else {
		for _, prefix := range []string{"https://github.com/", "http://github.com/", "github.com/"} {
			if strings.HasPrefix(strings.ToLower(trimmed), prefix) {
				trimmed = trimmed[len(prefix):]
				hasHostPrefix = true
				break
			}
		}
	}
	if idx := strings.Index(trimmed, "?"); idx >= 0 {
		query := trimmed[idx+1:]
		trimmed = trimmed[:idx]
		if qv, err := url.ParseQuery(query); err == nil {
			ref = qv.Get("ref")
		}
	}
	base, subdir := splitOnDoubleSlash(trimmed)
	base = strings.TrimSuffix(base, ".git")
	segments := strings.Split(base, "/")
	if !hasHostPrefix && len(segments) != 2 {
		return "", "", "", "", false
	}
	if len(segments) < 2 {
		return "", "", "", "", false
	}
	owner, name = segments[0], segments[1]
	if !repositoryCoordinateSegment.MatchString(owner) || !repositoryCoordinateSegment.MatchString(name) {
		return "", "", "", "", false
	}
	return owner, name, subdir, ref, true
}

// defaultRegistryHostPrefix is the exact (case-insensitive) default
// Terraform Registry hostname, written explicitly as a 4th leading segment
// on an otherwise ordinary 3-segment package address
// ("registry.terraform.io/namespace/name/provider"). Terraform itself
// treats this explicit form as identical to the implicit
// "namespace/name/provider" shorthand
// (https://developer.hashicorp.com/terraform/language/modules/sources#terraform-registry),
// so it is the ONLY host ever stripped here: any other host (a private
// registry, Terraform Enterprise, or an unrecognized hostname) is never
// normalized and is rejected as unsupported by parseRegistryModuleAddress's
// strict 3-segment check below.
const defaultRegistryHostPrefix = "registry.terraform.io/"

// parseRegistrySource splits a module source into its 3-segment Terraform
// Registry package address and an optional requested "//subdir" within that
// package (e.g.
// "terraform-google-modules/kubernetes-engine/google//modules/workload-identity").
// A leading explicit "registry.terraform.io/" host segment is normalized
// away first (see defaultRegistryHostPrefix); every other leading host
// segment is left intact, so it is never mistaken for part of the
// namespace/name/provider address and is rejected by the 3-segment check.
func parseRegistrySource(raw string) (namespace, name, subdir, provider string, ok bool) {
	base, requestedSubdir := splitOnDoubleSlash(raw)
	if len(base) >= len(defaultRegistryHostPrefix) && strings.EqualFold(base[:len(defaultRegistryHostPrefix)], defaultRegistryHostPrefix) {
		base = base[len(defaultRegistryHostPrefix):]
	}
	namespace, name, provider, ok = parseRegistryModuleAddress(base)
	return namespace, name, requestedSubdir, provider, ok
}

// joinModuleSubdirs safely combines a registry-resolved subdir (from the
// go-getter source the registry itself returned) with a caller-requested
// subdir (from the module source's own "//subdir"), rejecting any ".."
// segment in either input so the combination can never escape the resolved
// package root. Either input may be empty.
func joinModuleSubdirs(resolved, requested string) (string, bool) {
	if resolved != "" && !pathTraversalSafe(resolved) {
		return "", false
	}
	combined := strings.TrimSuffix(resolved, "/")
	if requested != "" {
		if combined != "" {
			combined += "/" + requested
		} else {
			combined = requested
		}
	}
	if combined == "" {
		return "", true
	}
	if !pathTraversalSafe(combined) {
		return "", false
	}
	return cleanRelativePath(combined), true
}

var registryAddressSegment = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// parseRegistryModuleAddress recognizes a strict 3-segment Terraform
// Registry module address: namespace/name/provider.
func parseRegistryModuleAddress(raw string) (namespace, name, provider string, ok bool) {
	segments := strings.Split(raw, "/")
	if len(segments) != 3 {
		return "", "", "", false
	}
	for _, segment := range segments {
		if !registryAddressSegment.MatchString(strings.ToLower(segment)) {
			return "", "", "", false
		}
	}
	return strings.ToLower(segments[0]), strings.ToLower(segments[1]), strings.ToLower(segments[2]), true
}

func normalizeModuleAddressSet(raw []string) (map[string]bool, error) {
	set := make(map[string]bool, len(raw))
	for _, entry := range raw {
		namespace, name, provider, ok := parseRegistryModuleAddress(strings.TrimSpace(entry))
		if !ok {
			return nil, fmt.Errorf("registry module address %q must be namespace/name/provider", entry)
		}
		set[namespace+"/"+name+"/"+provider] = true
	}
	return set, nil
}

// parseResolvedModuleSource parses a go-getter source string returned by the
// Terraform Registry Protocol (X-Terraform-Get/Location) and extracts an
// owner/repo/subdir/ref. Only github.com sources are approved; any other
// host (including arbitrary archive URLs) is refused rather than fetched, so
// a compromised or unexpected registry response can never redirect reads to
// attacker infrastructure.
func parseResolvedModuleSource(raw string) (owner, name, subdir, ref string, err error) {
	candidate := strings.TrimPrefix(strings.TrimSpace(raw), "git::")
	withScheme := candidate
	if !strings.Contains(withScheme, "://") {
		withScheme = "https://" + withScheme
	}
	parsed, parseErr := url.Parse(withScheme)
	if parseErr != nil {
		return "", "", "", "", fmt.Errorf("parse resolved module source %q: %w", raw, parseErr)
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" {
		return "", "", "", "", fmt.Errorf("resolved module source host %q is not an approved host (only github.com is supported): %w", host, ErrUnsupportedModuleSource)
	}
	ref = parsed.Query().Get("ref")
	trimmedPath := strings.Trim(parsed.Path, "/")
	base, subdirPart := splitOnDoubleSlash(trimmedPath)
	base = strings.TrimSuffix(base, ".git")
	segments := strings.Split(base, "/")
	if len(segments) != 2 {
		return "", "", "", "", fmt.Errorf("resolved module source path %q must be an owner/repo coordinate", trimmedPath)
	}
	owner, name = segments[0], segments[1]
	if !repositoryCoordinateSegment.MatchString(owner) || !repositoryCoordinateSegment.MatchString(name) {
		return "", "", "", "", fmt.Errorf("resolved module source %q has an invalid owner or name segment", raw)
	}
	return owner, name, subdirPart, ref, nil
}
