package reposcan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/scm"
)

const defaultCheckoutBasePath = ".cerebro/repo-scan/checkouts"

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
		return nil, nil, fmt.Errorf("repo scan materializer requires an scm client")
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
	checkoutPath := filepath.Join(m.basePath, sanitizeRunID(runID))
	if err := os.RemoveAll(checkoutPath); err != nil {
		return nil, nil, fmt.Errorf("remove stale checkout %s: %w", checkoutPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(checkoutPath), 0o750); err != nil {
		return nil, nil, fmt.Errorf("create checkout parent %s: %w", checkoutPath, err)
	}
	if err := cloneRepository(ctx, m.client, repoURL, checkoutPath, target); err != nil {
		return nil, nil, err
	}
	if ref := strings.TrimSpace(target.Ref); ref != "" {
		if err := checkoutRef(ctx, checkoutPath, ref); err != nil {
			return nil, nil, err
		}
	}
	if sinceCommit := strings.TrimSpace(target.SinceCommit); sinceCommit != "" {
		if err := ensureCommitAvailable(ctx, checkoutPath, sinceCommit); err != nil {
			return nil, nil, err
		}
	}
	descriptor := &RepositoryDescriptor{
		RepoURL:      firstNonEmpty(repoURL, gitOutput(ctx, checkoutPath, "config", "--get", "remote.origin.url")),
		Repository:   firstNonEmpty(strings.TrimSpace(target.Repository), inferRepositoryName(repoURL)),
		RequestedRef: strings.TrimSpace(target.Ref),
		ResolvedRef:  strings.TrimSpace(gitOutput(ctx, checkoutPath, "symbolic-ref", "--quiet", "--short", "HEAD")),
		CommitSHA:    strings.TrimSpace(gitOutput(ctx, checkoutPath, "rev-parse", "HEAD")),
	}
	artifact := &CheckoutArtifact{
		Path:           checkoutPath,
		MaterializedAt: m.now().UTC(),
		Metadata: map[string]any{
			"repo_url": repoURL,
		},
	}
	if descriptor.RequestedRef != "" {
		artifact.Metadata["requested_ref"] = descriptor.RequestedRef
	}
	if sinceCommit := strings.TrimSpace(target.SinceCommit); sinceCommit != "" {
		artifact.Metadata["since_commit"] = sinceCommit
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
		return "repo_scan"
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

func cloneRepository(ctx context.Context, client scm.Client, repoURL, checkoutPath string, target ScanTarget) error {
	if client == nil {
		return fmt.Errorf("repo scan materializer requires an scm client")
	}
	if cloner, ok := client.(scm.CloneOptionsClient); ok {
		ref := strings.TrimSpace(target.Ref)
		if looksLikeCommitSHA(ref) {
			ref = ""
		}
		return cloner.CloneWithOptions(ctx, repoURL, checkoutPath, scm.CloneOptions{
			Depth: 1,
			Ref:   ref,
		})
	}
	return client.Clone(ctx, repoURL, checkoutPath)
}

func checkoutRef(ctx context.Context, checkoutPath, ref string) error {
	if err := scm.ValidateGitRef(ref); err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "git", "-C", checkoutPath, "checkout", ref).CombinedOutput(); err == nil { // #nosec G204 -- fixed binary/args
		return nil
	} else {
		fetchOut, fetchErr := exec.CommandContext(ctx, "git", "-C", checkoutPath, "fetch", "--depth", "1", "origin", "--", ref).CombinedOutput() // #nosec G204 -- fixed binary/args
		if fetchErr != nil {
			return fmt.Errorf("checkout ref %s: %s: %w", ref, strings.TrimSpace(string(out)), err)
		}
		if checkoutFetchOut, checkoutFetchErr := exec.CommandContext(ctx, "git", "-C", checkoutPath, "checkout", "FETCH_HEAD").CombinedOutput(); checkoutFetchErr != nil { // #nosec G204 -- fixed binary/args
			return fmt.Errorf("checkout ref %s after fetch %s: %s: %w", ref, strings.TrimSpace(string(fetchOut)), strings.TrimSpace(string(checkoutFetchOut)), checkoutFetchErr)
		}
	}
	return nil
}

func ensureCommitAvailable(ctx context.Context, checkoutPath, commitSHA string) error {
	if strings.TrimSpace(commitSHA) == "" {
		return nil
	}
	if err := scm.ValidateSinceCommit(commitSHA); err != nil {
		return err
	}
	if exec.CommandContext(ctx, "git", "-C", checkoutPath, "cat-file", "-e", strings.TrimSpace(commitSHA)+"^{commit}").Run() == nil { // #nosec G204 -- fixed binary/args
		return nil
	}
	out, err := exec.CommandContext(ctx, "git", "-C", checkoutPath, "fetch", "--depth", "1", "origin", "--", strings.TrimSpace(commitSHA)).CombinedOutput() // #nosec G204 -- fixed binary/args
	if err != nil {
		return fmt.Errorf("fetch incremental base commit %s: %s: %w", strings.TrimSpace(commitSHA), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func looksLikeCommitSHA(ref string) bool {
	return scm.IsCommitSHA(ref)
}
