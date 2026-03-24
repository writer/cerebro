package repohistoryscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/scm"
)

const defaultCheckoutBasePath = ".cerebro/repo-history-scan"

type Materializer interface {
	Materialize(ctx context.Context, runID string, target ScanTarget) (*RepositoryDescriptor, *CheckoutArtifact, error)
	Cleanup(ctx context.Context, artifact *CheckoutArtifact) error
}

type LocalMaterializer struct {
	basePath string
	client   scm.Client
	now      func() time.Time
}

func NewLocalMaterializer(basePath string, client scm.Client) *LocalMaterializer {
	if strings.TrimSpace(basePath) == "" {
		basePath = defaultCheckoutBasePath
	}
	if client == nil {
		client = scm.NewLocalClient("")
	}
	return &LocalMaterializer{
		basePath: strings.TrimSpace(basePath),
		client:   client,
		now:      time.Now,
	}
}

func (m *LocalMaterializer) Materialize(ctx context.Context, runID string, target ScanTarget) (*RepositoryDescriptor, *CheckoutArtifact, error) {
	if m == nil || m.client == nil {
		return nil, nil, fmt.Errorf("repo history scan materializer requires an scm client")
	}
	if err := scm.ValidateGitRef(target.Ref); err != nil {
		return nil, nil, err
	}
	if err := scm.ValidateSinceCommit(target.SinceCommit); err != nil {
		return nil, nil, err
	}
	repoURL := strings.TrimSpace(target.RepoURL)
	if repoURL == "" {
		return nil, nil, fmt.Errorf("repo URL is required")
	}
	checkoutPath := filepath.Join(m.basePath, "checkouts", sanitizeRunID(runID))
	cachePath := filepath.Join(m.basePath, "cache", cacheKeyForTarget(target))
	if err := os.RemoveAll(checkoutPath); err != nil {
		return nil, nil, fmt.Errorf("remove stale checkout %s: %w", checkoutPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(checkoutPath), 0o750); err != nil {
		return nil, nil, fmt.Errorf("create checkout parent %s: %w", checkoutPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o750); err != nil {
		return nil, nil, fmt.Errorf("create cache parent %s: %w", cachePath, err)
	}

	cacheStrategy := "clone"
	if isGitRepository(cachePath) {
		fetcher, ok := m.client.(scm.FetchClient)
		if !ok {
			return nil, nil, fmt.Errorf("repo history scan scm client does not support incremental fetch")
		}
		if err := fetcher.Fetch(ctx, repoURL, cachePath); err != nil {
			return nil, nil, err
		}
		if out, err := exec.CommandContext(ctx, "git", "-C", cachePath, "pull", "--ff-only").CombinedOutput(); err != nil { // #nosec G204 -- fixed binary/args
			return nil, nil, fmt.Errorf("fast-forward cache checkout: %s: %w", strings.TrimSpace(string(out)), err)
		}
		cacheStrategy = "fetch"
	} else {
		if err := os.RemoveAll(cachePath); err != nil {
			return nil, nil, fmt.Errorf("remove stale cache %s: %w", cachePath, err)
		}
		if err := m.client.Clone(ctx, repoURL, cachePath); err != nil {
			return nil, nil, err
		}
	}

	if out, err := exec.CommandContext(ctx, "git", "clone", "--no-hardlinks", cachePath, checkoutPath).CombinedOutput(); err != nil { // #nosec G204 -- fixed binary/args
		return nil, nil, fmt.Errorf("clone checkout from cache: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if out, err := exec.CommandContext(ctx, "git", "-C", checkoutPath, "remote", "set-url", "origin", repoURL).CombinedOutput(); err != nil { // #nosec G204 -- fixed binary/args
		return nil, nil, fmt.Errorf("set checkout origin: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if ref := strings.TrimSpace(target.Ref); ref != "" {
		if out, err := exec.CommandContext(ctx, "git", "-C", checkoutPath, "checkout", ref).CombinedOutput(); err != nil { // #nosec G204 -- fixed binary/args
			return nil, nil, fmt.Errorf("checkout ref %s: %s: %w", ref, strings.TrimSpace(string(out)), err)
		}
	}
	descriptor := &RepositoryDescriptor{
		RepoURL:      firstNonEmpty(gitOutput(ctx, checkoutPath, "config", "--get", "remote.origin.url"), repoURL),
		Repository:   firstNonEmpty(strings.TrimSpace(target.Repository), inferRepositoryName(repoURL)),
		RequestedRef: strings.TrimSpace(target.Ref),
		ResolvedRef:  strings.TrimSpace(gitOutput(ctx, checkoutPath, "symbolic-ref", "--quiet", "--short", "HEAD")),
		CommitSHA:    strings.TrimSpace(gitOutput(ctx, checkoutPath, "rev-parse", "HEAD")),
	}
	artifact := &CheckoutArtifact{
		Path:           checkoutPath,
		MaterializedAt: m.now().UTC(),
		Metadata: map[string]any{
			"repo_url":         repoURL,
			"cache_path":       cachePath,
			"cache_strategy":   cacheStrategy,
			"cache_commit_sha": strings.TrimSpace(gitOutput(ctx, cachePath, "rev-parse", "HEAD")),
		},
	}
	if descriptor.RequestedRef != "" {
		artifact.Metadata["requested_ref"] = descriptor.RequestedRef
	}
	if strings.TrimSpace(target.SinceCommit) != "" {
		artifact.Metadata["since_commit"] = strings.TrimSpace(target.SinceCommit)
	}
	return descriptor, artifact, nil
}

func (m *LocalMaterializer) Cleanup(_ context.Context, artifact *CheckoutArtifact) error {
	if artifact == nil || strings.TrimSpace(artifact.Path) == "" {
		return nil
	}
	return os.RemoveAll(artifact.Path)
}

func gitOutput(ctx context.Context, repoPath string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoPath}, args...)...) // #nosec G204 -- fixed binary/args
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func sanitizeRunID(runID string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	trimmed := replacer.Replace(strings.TrimSpace(runID))
	if trimmed == "" {
		return "repo_history_scan"
	}
	return trimmed
}

func inferRepositoryName(repoURL string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(repoURL), ".git")
	trimmed = strings.TrimRight(trimmed, "/")
	if trimmed == "" {
		return ""
	}
	return filepath.Base(trimmed)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func cacheKeyForTarget(target ScanTarget) string {
	identity := sanitizeRepositoryURL(target.RepoURL)
	if identity == "" {
		identity = strings.TrimSpace(target.Repository)
	}
	if identity == "" {
		identity = "repo_history_scan"
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:8])
}

func isGitRepository(path string) bool {
	info, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil && info != nil
}
