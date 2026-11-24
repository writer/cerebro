package vulnpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const maxPullPages = 1000

// Puller fetches vulnerability payloads for a profile on a schedule. Pullers
// only fetch; every page goes through the same Ingest path as pushed data.
type Puller interface {
	// Kind is the stable pull kind stored on profiles.
	Kind() string
	// SecretKeys lists config keys that must hold credential or secret-store
	// references rather than raw values.
	SecretKeys() []string
	// ValidateConfig checks unresolved profile config.
	ValidateConfig(config map[string]string) error
	// Pull fetches pages and hands each to emit. Config holds resolved
	// secrets; Cursor is the value the previous successful run returned.
	Pull(ctx context.Context, request PullRequest, emit func(PullPage) error) (PullOutcome, error)
}

// PullRequest is the input of one pull run.
type PullRequest struct {
	TenantID  string
	ProfileID string
	Config    map[string]string
	Cursor    string
}

// PullPage is one fetched payload.
type PullPage struct {
	Payload        []byte
	ContentType    string
	Format         string
	IdempotencyKey string
}

// PullOutcome describes a completed pull run.
type PullOutcome struct {
	// Cursor is persisted and handed to the next run.
	Cursor string
	// Snapshot reports that the emitted pages together are the complete
	// current set of open vulnerabilities, so absent records are resolved.
	Snapshot bool
}

// PullRunResult summarizes one pull run.
type PullRunResult struct {
	ProfileID   string   `json:"profile_id"`
	SourceID    string   `json:"source_id"`
	Kind        string   `json:"kind"`
	Status      string   `json:"status"`
	Pages       int      `json:"pages"`
	Received    int      `json:"received"`
	Accepted    int      `json:"accepted"`
	Quarantined int      `json:"quarantined"`
	Resolved    int      `json:"resolved"`
	Snapshot    bool     `json:"snapshot"`
	BatchIDs    []string `json:"batch_ids,omitempty"`
	Problems    []string `json:"problems,omitempty"`
	Error       string   `json:"error,omitempty"`
}

// SyncProfile runs a profile's pull transport now.
func (s *Service) SyncProfile(ctx context.Context, tenantID string, profileID string, actor string) (*PullRunResult, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profile, err := s.profile(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(profileID))
	if err != nil {
		return nil, err
	}
	if profile.PullKind == "" {
		return nil, fmt.Errorf("%w: profile %q has no pull transport", ErrInvalidRequest, profile.ID)
	}
	if !profile.Enabled {
		return nil, fmt.Errorf("%w: profile %q is disabled", ErrInvalidRequest, profile.ID)
	}
	return s.runPull(ctx, profile, actor), nil
}

// RunDuePulls claims profiles whose pull is due, runs them, and schedules
// their next run. It returns the runs it performed.
func (s *Service) RunDuePulls(ctx context.Context, owner string) ([]*PullRunResult, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	profiles, err := s.store.ClaimDueVulnerabilityProfiles(ctx, s.clock(), owner, claimTTL, claimBatch)
	if err != nil {
		return nil, err
	}
	results := make([]*PullRunResult, 0, len(profiles))
	var errs []error
	for _, profile := range profiles {
		if ctx.Err() != nil {
			break
		}
		result := s.runPull(ctx, profile, "scheduler")
		results = append(results, result)
		interval := time.Duration(profile.PullIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = defaultPullInterval
		}
		if err := s.store.CompleteVulnerabilityProfileClaim(ctx, profile.TenantID, profile.ID, owner, s.clock().Add(interval)); err != nil {
			errs = append(errs, fmt.Errorf("complete pull claim for %s: %w", profile.ID, err))
		}
	}
	return results, errors.Join(errs...)
}

func (s *Service) runPull(ctx context.Context, profile *ports.VulnerabilityProfile, actor string) *PullRunResult {
	result := &PullRunResult{ProfileID: profile.ID, SourceID: profile.SourceID, Kind: profile.PullKind}
	fail := func(err error) *PullRunResult {
		result.Status = ProfileStatusFailed
		result.Error = truncate(err.Error(), 1024)
		_ = s.store.RecordVulnerabilityProfileIngest(ctx, profile.TenantID, profile.ID, ports.VulnerabilityProfileIngestUpdate{
			At: s.clock(), Status: ProfileStatusFailed, Error: result.Error,
		})
		return result
	}
	puller, ok := s.pullers[profile.PullKind]
	if !ok {
		return fail(fmt.Errorf("pull kind %q is not available in this runtime", profile.PullKind))
	}
	config := map[string]string{}
	if strings.TrimSpace(profile.PullConfigJSON) != "" {
		if err := json.Unmarshal([]byte(profile.PullConfigJSON), &config); err != nil {
			return fail(fmt.Errorf("decode pull config: %w", err))
		}
	}
	if err := puller.ValidateConfig(config); err != nil {
		return fail(err)
	}
	if s.resolveConfig != nil {
		resolved, err := s.resolveConfig(ctx, profile, config)
		if err != nil {
			return fail(fmt.Errorf("resolve pull credentials: %w", err))
		}
		config = resolved
	} else if len(puller.SecretKeys()) > 0 {
		for _, key := range puller.SecretKeys() {
			if _, ok := config[key]; ok {
				return fail(errors.New("pull credentials cannot be resolved in this runtime"))
			}
		}
	}

	started := s.clock()
	// Absent records are resolved only when every page normalized fresh data
	// through a trusted path; a held, failed, or replayed page means this run
	// did not observe the complete current set.
	trusted := true
	genericAccepted := false
	sawGeneric := false
	status := ProfileStatusHealthy
	emit := func(page PullPage) error {
		if result.Pages >= maxPullPages {
			return fmt.Errorf("pull exceeded %d pages", maxPullPages)
		}
		result.Pages++
		ingested, err := s.ingest(ctx, profile, IngestRequest{
			TenantID:       profile.TenantID,
			ProfileID:      profile.ID,
			Transport:      TransportPull,
			ContentType:    page.ContentType,
			IdempotencyKey: page.IdempotencyKey,
			Actor:          actor,
			Format:         page.Format,
			Payload:        page.Payload,
		})
		if ingested != nil {
			result.BatchIDs = append(result.BatchIDs, ingested.BatchID)
			result.Received += ingested.Received
			result.Accepted += ingested.Accepted
			result.Quarantined += ingested.Quarantined
			for _, problem := range ingested.Problems {
				if len(result.Problems) < maxProblemSamples {
					result.Problems = append(result.Problems, problem)
				}
			}
			if ingested.Replayed || ingested.Status == BatchPendingMapping || ingested.Status == BatchFailed || ingested.Status == BatchQuarantined {
				trusted = false
			}
			if ingested.Format == FormatGeneric {
				sawGeneric = true
				genericAccepted = genericAccepted || ingested.Accepted > 0
				if ingested.DriftRatio > driftThreshold && status == ProfileStatusHealthy {
					status = ProfileStatusDrift
				}
			}
			if ingested.Status == BatchPendingMapping {
				status = ProfileStatusPendingMapping
			}
		}
		return err
	}
	outcome, err := puller.Pull(ctx, PullRequest{TenantID: profile.TenantID, ProfileID: profile.ID, Config: config, Cursor: profile.PullCursor}, emit)
	if err != nil {
		return fail(err)
	}
	if outcome.Snapshot && trusted && (!sawGeneric || genericAccepted) {
		resolved, err := s.store.ResolveAbsentVulnerabilityObservations(ctx, profile.TenantID, profile.ID, started, s.clock())
		if err != nil {
			return fail(fmt.Errorf("resolve absent observations: %w", err))
		}
		result.Resolved = resolved
		result.Snapshot = true
	} else if outcome.Snapshot {
		result.Problems = append(result.Problems, "snapshot did not resolve absent observations because not every page normalized fresh data")
	}
	cursor := outcome.Cursor
	result.Status = status
	if err := s.store.RecordVulnerabilityProfileIngest(ctx, profile.TenantID, profile.ID, ports.VulnerabilityProfileIngestUpdate{
		At: s.clock(), Status: status, PullCursor: &cursor,
	}); err != nil {
		result.Error = truncate(err.Error(), 1024)
	}
	return result
}

func configValue(config map[string]string, key string, fallback string) string {
	if value := strings.TrimSpace(config[key]); value != "" {
		return value
	}
	return fallback
}

func configBool(config map[string]string, key string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(config[key])) {
	case "", "false", "0", "no":
		return false, nil
	case "true", "1", "yes":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false", key)
	}
}

// maxPullUnits bounds pages or objects fetched by one pull run.
const maxPullUnits = 500

func configPositiveInt(config map[string]string, key string, fallback int) (int, error) {
	raw := strings.TrimSpace(config[key])
	if raw == "" {
		return fallback, nil
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil || fmt.Sprint(value) != raw {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if value < 1 || value > maxPullUnits {
		return 0, fmt.Errorf("%s must be between 1 and %d", key, maxPullUnits)
	}
	return value, nil
}

func rejectUnknownKeys(config map[string]string, allowed ...string) error {
	known := map[string]bool{}
	for _, key := range allowed {
		known[key] = true
	}
	for key := range config {
		if !known[key] {
			return fmt.Errorf("unknown pull config key %q", key)
		}
	}
	return nil
}
