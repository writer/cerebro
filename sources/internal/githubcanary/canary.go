package githubcanary

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	RepositoryKind            = "newest_updated_resource"
	AuditLogKind              = "newest_audit_event"
	RepositoryManifestVersion = "github_repository_canary_v1"
	AuditLogManifestVersion   = "github_audit_log_canary_v1"
	MaxSkipDuration           = 6 * time.Hour
	ReconciliationInterval    = 24 * time.Hour
	MaxConsecutiveSkips       = 3
)

type Result struct {
	Metadata             map[string]string
	Watermark            time.Time
	ObservedAt           time.Time
	ShortCircuit         bool
	Checkpoint           *cerebrov1.SourceCheckpoint
	ReconciliationReason sourcecdk.PullReconciliationReason
}

type RepositoryReadOptions struct {
	Owner      string
	Repo       string
	PerPage    int
	ConfigHash string
	Cursor     *cerebrov1.SourceCursor
	Checkpoint *cerebrov1.SourceCheckpoint
	Build      func(*gogithub.Repository) (*primitives.Event, error)
}

func ReadRepositories(ctx context.Context, client *gogithub.Client, options RepositoryReadOptions) (sourcecdk.Pull, error) {
	readCheckpoint := sourcecdk.IncrementalCheckpointForCursor("github", "repository", options.Cursor, options.Checkpoint)
	page, err := sourcecdk.CursorPage(options.Cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	var canary *Result
	if strings.TrimSpace(options.Repo) == "" && page == 1 && sourcecdk.CursorToken(options.Cursor) == "" {
		canary, err = ProbeRepository(ctx, client, options.Owner, options.Checkpoint, options.ConfigHash, time.Now().UTC())
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		if pull, ok := canary.ShortCircuitPull(); ok {
			return pull, nil
		}
	}
	if strings.TrimSpace(options.Repo) != "" {
		if page > 1 {
			return sourcecdk.EmptyIncrementalWatermarkPull("github", "repository", readCheckpoint), nil
		}
		repo, err := getRepository(ctx, client, options.Owner, options.Repo)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		return sourcecdk.IncrementalPullFromRecords("github", "repository", []*gogithub.Repository{repo}, "", readCheckpoint, options.Build)
	}
	repos, resp, err := listRepositoriesPage(ctx, client, options.Owner, page, options.PerPage)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	nextCursor := ""
	if resp != nil && resp.NextPage > 0 {
		nextCursor = strconv.Itoa(resp.NextPage)
	}
	pull, err := sourcecdk.IncrementalPullFromRecords("github", "repository", repos, nextCursor, readCheckpoint, options.Build)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	return canary.Apply(pull, "github", "repository"), nil
}

func (r *Result) ShortCircuitPull() (sourcecdk.Pull, bool) {
	if r == nil || !r.ShortCircuit {
		return sourcecdk.Pull{}, false
	}
	return sourcecdk.Pull{
		Checkpoint:         r.Checkpoint,
		ShortCircuitReason: sourcecdk.PullShortCircuitReasonNotModified,
	}, true
}

func (r *Result) Apply(pull sourcecdk.Pull, source, family string) sourcecdk.Pull {
	if r == nil {
		return pull
	}
	pull.Checkpoint = sourcecdk.ReconciledFingerprintCheckpoint(pull.Checkpoint, source, family, r.Watermark, r.Metadata, r.ObservedAt)
	pull.ReconciliationReason = r.ReconciliationReason
	return pull
}

func ProbeRepository(ctx context.Context, client *gogithub.Client, owner string, checkpoint *cerebrov1.SourceCheckpoint, configHash string, observedAt time.Time) (*Result, error) {
	repos, err := newestRepository(ctx, client, owner)
	if err != nil {
		return nil, err
	}
	metadata, watermark := RepositoryMetadata(owner, repos, configHash, observedAt)
	return evaluate(checkpoint, "github", "repository", metadata, watermark, observedAt, policy(sourcecdk.CanaryConfidenceHeuristic, RepositoryManifestVersion, configHash, observedAt)), nil
}

func ProbeAuditLog(ctx context.Context, client *gogithub.Client, owner string, checkpoint *cerebrov1.SourceCheckpoint, configHash string, observedAt time.Time) (*Result, error) {
	entries, _, err := client.Organizations.GetAuditLog(ctx, owner, &gogithub.GetAuditLogOptions{
		Include: gogithub.String("all"),
		Order:   gogithub.String("desc"),
		ListCursorOptions: gogithub.ListCursorOptions{
			PerPage: 1,
		},
	})
	if err != nil {
		if AuditLogUnavailable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("github audit log canary for org %s: %w", owner, err)
	}
	metadata, watermark := AuditLogMetadata(owner, entries, configHash, observedAt)
	return evaluate(checkpoint, "github", "org_inventory", metadata, watermark, observedAt, policy(sourcecdk.CanaryConfidenceHeuristic, AuditLogManifestVersion, configHash, observedAt)), nil
}

func RepositoryMetadata(owner string, repos []*gogithub.Repository, configHash string, observedAt time.Time) (map[string]string, time.Time) {
	observedAt = observedAt.UTC()
	fields := map[string]string{"source": "github", "family": "repository", "owner": owner}
	resourceID := "none"
	updatedAt := observedAt
	if len(repos) > 0 && repos[0] != nil {
		repo := repos[0]
		fullName := repositoryFullName(owner, repo)
		repoID := ""
		if repo.GetID() != 0 {
			repoID = strconv.FormatInt(repo.GetID(), 10)
		}
		resourceID = firstNonEmpty(repoID, fullName)
		updatedAt = repositoryUpdatedAt(repo, observedAt)
		fields["repo_id"] = repoID
		fields["full_name"] = fullName
		fields["resource_id"] = resourceID
		fields["updated_at"] = updatedAt.Format(time.RFC3339Nano)
		if pushedAt := timestamp(repo.PushedAt); pushedAt != nil {
			fields["pushed_at"] = pushedAt.UTC().Format(time.RFC3339Nano)
		}
	} else {
		fields["empty"] = "true"
	}
	return metadata(RepositoryKind, resourceID, RepositoryManifestVersion, configHash, updatedAt, observedAt, fields), updatedAt
}

func AuditLogMetadata(owner string, entries []*gogithub.AuditEntry, configHash string, observedAt time.Time) (map[string]string, time.Time) {
	observedAt = observedAt.UTC()
	fields := map[string]string{"source": "github", "family": "org_inventory", "owner": owner}
	resourceID := "none"
	updatedAt := observedAt
	if len(entries) > 0 && entries[0] != nil {
		entry := entries[0]
		updatedAt = auditOccurredAt(entry)
		if updatedAt.IsZero() {
			updatedAt = observedAt
		}
		resourceID = firstNonEmpty(entry.GetDocumentID(), entry.GetAction(), strconv.FormatInt(updatedAt.UnixMilli(), 10))
		fields["document_id"] = entry.GetDocumentID()
		fields["action"] = entry.GetAction()
		fields["resource_id"] = resourceID
		fields["updated_at"] = updatedAt.Format(time.RFC3339Nano)
	} else {
		fields["empty"] = "true"
	}
	return metadata(AuditLogKind, resourceID, AuditLogManifestVersion, configHash, updatedAt, observedAt, fields), updatedAt
}

func AuditLogUnavailable(err error) bool {
	var apiErr *gogithub.ErrorResponse
	if !errors.As(err, &apiErr) || apiErr.Response == nil {
		return false
	}
	switch apiErr.Response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

func evaluate(checkpoint *cerebrov1.SourceCheckpoint, source, family string, metadata map[string]string, watermark time.Time, observedAt time.Time, policy sourcecdk.CanaryReconciliationPolicy) *Result {
	result := &Result{Metadata: metadata, Watermark: watermark, ObservedAt: observedAt.UTC()}
	stored := sourcecdk.CheckpointFingerprint(checkpoint, source, family)
	if strings.TrimSpace(stored[sourcecdk.CanaryHashKey]) == "" || stored[sourcecdk.CanaryHashKey] != metadata[sourcecdk.CanaryHashKey] {
		return result
	}
	if reason := sourcecdk.FreshnessProbeReconciliationReason(stored, policy); reason != "" {
		result.ReconciliationReason = reason
		return result
	}
	result.ShortCircuit = true
	result.Checkpoint = sourcecdk.SkippedFingerprintCheckpoint(checkpoint, source, family, metadata, observedAt)
	return result
}

func policy(confidence, manifestVersion, configHash string, now time.Time) sourcecdk.CanaryReconciliationPolicy {
	return sourcecdk.CanaryReconciliationPolicy{
		Confidence:             confidence,
		MaxSkipDuration:        MaxSkipDuration,
		MaxConsecutiveSkips:    MaxConsecutiveSkips,
		ReconciliationInterval: ReconciliationInterval,
		ManifestVersion:        manifestVersion,
		ConfigHash:             configHash,
		Now:                    now,
	}
}

func newestRepository(ctx context.Context, client *gogithub.Client, owner string) ([]*gogithub.Repository, error) {
	repos, _, err := listRepositoriesPage(ctx, client, owner, 1, 1)
	return repos, err
}

func listRepositoriesPage(ctx context.Context, client *gogithub.Client, owner string, page int, perPage int) ([]*gogithub.Repository, *gogithub.Response, error) {
	repos, resp, err := client.Repositories.ListByOrg(ctx, owner, &gogithub.RepositoryListByOrgOptions{
		Type:      "all",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	})
	if err == nil {
		return repos, resp, nil
	}
	if !isNotFound(err) {
		return nil, nil, fmt.Errorf("list github org repos for %s: %w", owner, err)
	}
	repos, resp, err = client.Repositories.ListByUser(ctx, owner, &gogithub.RepositoryListByUserOptions{
		Type:      "owner",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("github owner %s: %w", owner, err)
	}
	return repos, resp, nil
}

func getRepository(ctx context.Context, client *gogithub.Client, owner string, repo string) (*gogithub.Repository, error) {
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("github repo %s/%s: %w", owner, repo, err)
	}
	return repository, nil
}

func metadata(kind, resourceID, manifestVersion, configHash string, updatedAt time.Time, observedAt time.Time, fields map[string]string) map[string]string {
	out := map[string]string{
		sourcecdk.CanaryKindKey:       kind,
		sourcecdk.CanaryResourceIDKey: resourceID,
		sourcecdk.CanaryObservedAtKey: observedAt.UTC().Format(time.RFC3339Nano),
		sourcecdk.CanaryUpdatedAtKey:  updatedAt.UTC().Format(time.RFC3339Nano),
		sourcecdk.CanaryHashKey:       sourcecdk.FingerprintHash(fields),
		sourcecdk.CanaryConfidenceKey: sourcecdk.CanaryConfidenceHeuristic,
		sourcecdk.ManifestVersionKey:  manifestVersion,
		sourcecdk.CanaryConfigHashKey: configHash,
	}
	return out
}

func repositoryFullName(owner string, repo *gogithub.Repository) string {
	if repo == nil {
		return ""
	}
	if fullName := strings.TrimSpace(repo.GetFullName()); fullName != "" {
		return fullName
	}
	name := strings.TrimSpace(repo.GetName())
	if name == "" {
		return ""
	}
	return strings.TrimSpace(owner) + "/" + name
}

func repositoryUpdatedAt(repo *gogithub.Repository, fallback time.Time) time.Time {
	if repo == nil {
		return fallback.UTC()
	}
	if updatedAt := repo.GetUpdatedAt(); !updatedAt.IsZero() {
		return updatedAt.Time.UTC()
	}
	if pushedAt := timestamp(repo.PushedAt); pushedAt != nil {
		return pushedAt.UTC()
	}
	if createdAt := repo.GetCreatedAt(); !createdAt.IsZero() {
		return createdAt.Time.UTC()
	}
	return fallback.UTC()
}

func auditOccurredAt(entry *gogithub.AuditEntry) time.Time {
	if entry == nil {
		return time.Time{}
	}
	if stamp := entry.GetTimestamp(); !stamp.IsZero() {
		return stamp.UTC()
	}
	if stamp := entry.GetCreatedAt(); !stamp.IsZero() {
		return stamp.UTC()
	}
	return time.Time{}
}

func timestamp(value *gogithub.Timestamp) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

func isNotFound(err error) bool {
	var apiErr *gogithub.ErrorResponse
	return errors.As(err, &apiErr) && apiErr.Response != nil && apiErr.Response.StatusCode == http.StatusNotFound
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
