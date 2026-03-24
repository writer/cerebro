package imagescan

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const defaultSweepStaleAfter = 90 * 24 * time.Hour

type SweepRequest struct {
	Registry     RegistryKind      `json:"registry"`
	RegistryHost string            `json:"registry_host,omitempty"`
	RequestedBy  string            `json:"requested_by,omitempty"`
	DryRun       bool              `json:"dry_run,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	StaleAfter   time.Duration     `json:"stale_after,omitempty"`
}

type SweepItem struct {
	Repository   string    `json:"repository"`
	Tag          string    `json:"tag"`
	Digest       string    `json:"digest,omitempty"`
	PushedAt     time.Time `json:"pushed_at,omitempty"`
	SizeBytes    int64     `json:"size_bytes,omitempty"`
	Stale        bool      `json:"stale,omitempty"`
	ScanRequired bool      `json:"scan_required,omitempty"`
	ScanRunID    string    `json:"scan_run_id,omitempty"`
	SkipReason   string    `json:"skip_reason,omitempty"`
}

type SweepReport struct {
	Registry    RegistryKind `json:"registry"`
	Scanned     int          `json:"scanned"`
	Skipped     int          `json:"skipped"`
	Stale       int          `json:"stale"`
	Items       []SweepItem  `json:"items,omitempty"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
}

func (r *Runner) RunRegistrySweep(ctx context.Context, req SweepRequest) (*SweepReport, error) {
	if r == nil {
		return nil, fmt.Errorf("image scan runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := r.resolveRegistryClient(req.Registry, req.RegistryHost)
	if err != nil {
		return nil, err
	}

	started := r.now().UTC()
	report := &SweepReport{
		Registry:  req.Registry,
		StartedAt: started,
	}
	staleAfter := req.StaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultSweepStaleAfter
	}
	effectiveHost := normalizeRegistryHost(firstNonEmpty(strings.TrimSpace(req.RegistryHost), client.RegistryHost()))

	existing, err := r.existingSuccessfulDigests(ctx, req.Registry, effectiveHost)
	if err != nil {
		return nil, err
	}
	planned := make(map[string]string)

	repositories, err := client.ListRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	for _, repository := range repositories {
		tags, err := client.ListTags(ctx, repository.Name)
		if err != nil {
			return nil, fmt.Errorf("list tags for %s: %w", repository.Name, err)
		}
		for _, tag := range tags {
			item := SweepItem{
				Repository: repository.Name,
				Tag:        strings.TrimSpace(tag.Name),
				Digest:     strings.TrimSpace(tag.Digest),
				PushedAt:   tag.PushedAt,
				SizeBytes:  tag.SizeBytes,
			}
			if !tag.PushedAt.IsZero() && started.Sub(tag.PushedAt.UTC()) > staleAfter {
				item.Stale = true
				report.Stale++
			}

			digestKey := successfulDigestKey(effectiveHost, repository.Name, item.Digest)
			switch {
			case item.Digest != "" && existing[digestKey] != "":
				item.SkipReason = "unchanged_digest"
				report.Skipped++
			case item.Digest != "" && planned[digestKey] != "":
				item.SkipReason = "digest_already_planned"
				item.ScanRunID = planned[digestKey]
				report.Skipped++
			default:
				item.ScanRequired = true
				run, err := r.RunImageScan(ctx, ScanRequest{
					RequestedBy: strings.TrimSpace(req.RequestedBy),
					Target: ScanTarget{
						Registry:     req.Registry,
						RegistryHost: effectiveHost,
						Repository:   repository.Name,
						Tag:          strings.TrimSpace(tag.Name),
						Digest:       strings.TrimSpace(tag.Digest),
					},
					DryRun:      req.DryRun,
					Metadata:    cloneStringMap(req.Metadata),
					SubmittedAt: started,
				})
				if err != nil {
					return nil, err
				}
				if run != nil {
					item.ScanRunID = run.ID
					if item.Digest != "" {
						planned[digestKey] = run.ID
					}
				}
				report.Scanned++
			}

			report.Items = append(report.Items, item)
		}
	}

	report.CompletedAt = r.now().UTC()
	return report, nil
}

func (r *Runner) existingSuccessfulDigests(ctx context.Context, registry RegistryKind, registryHost string) (map[string]string, error) {
	existing := make(map[string]string)
	if r == nil || r.store == nil {
		return existing, nil
	}

	runs, err := r.store.ListRuns(ctx, RunListOptions{
		Statuses: []RunStatus{RunStatusSucceeded},
		Limit:    10000,
	})
	if err != nil {
		return nil, fmt.Errorf("list successful image scans: %w", err)
	}
	for _, run := range runs {
		if run.Registry != registry || run.DryRun {
			continue
		}
		repo := strings.TrimSpace(run.Target.Repository)
		if repo == "" {
			continue
		}
		digest := strings.TrimSpace(run.Target.Digest)
		if digest == "" && run.Manifest != nil {
			digest = strings.TrimSpace(run.Manifest.Digest)
		}
		if digest == "" {
			continue
		}
		existing[successfulDigestKey(run.Target.RegistryHost, repo, digest)] = run.ID
	}
	return existing, nil
}

func successfulDigestKey(registryHost, repository, digest string) string {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if repository == "" || digest == "" {
		return ""
	}
	host := normalizeRegistryHost(registryHost)
	if host == "" {
		return repository + "@" + digest
	}
	return host + "/" + repository + "@" + digest
}

func normalizeRegistryHost(raw string) string {
	host := strings.TrimSpace(strings.ToLower(raw))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && strings.TrimSpace(parsed.Host) != "" {
			host = parsed.Host
		}
	}
	return strings.TrimRight(host, "/")
}
