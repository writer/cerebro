package vulnpipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/panicsafe"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	maxPullPages = 1000
	// pullRunTimeout stays well below claimTTL so a run ends before its lease
	// can expire and another replica claims the same profile.
	pullRunTimeout = 20 * time.Minute
	// maxPullRunBytes bounds the payload bytes one run ingests; a run that
	// reaches it stops early and is never treated as a snapshot.
	maxPullRunBytes = 256 << 20
	// pullWorkers is how many profiles one scheduler poll runs at once, so a
	// slow profile does not hold back the others.
	pullWorkers     = 4
	maxPullsPerPoll = 40
	// pendingMappingBackoff spaces out pulls of a profile whose data is held
	// until an operator activates its draft mapping.
	pendingMappingBackoff = 6 * time.Hour
	pullRecordTimeout     = 15 * time.Second
)

// PullStatusQueued is the PullRunResult status of a manual sync that was
// queued for the scheduler.
const PullStatusQueued = "queued"

// errPullStopped ends a pull early without failing it. Pages already ingested
// stand, the cursor advances to the last ingested unit, and the run is never
// treated as a complete snapshot.
var errPullStopped = errors.New("pull stopped early")

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
	// On error, a puller may return the cursor of the last unit it fully
	// ingested so the next run resumes after it.
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
	// Skipped describes units that can never be read (for example an
	// oversized or corrupt object) and that the puller moved past.
	Skipped []string
}

// PullRunResult summarizes one pull run, or a queued manual sync.
type PullRunResult struct {
	ProfileID   string     `json:"profile_id"`
	SourceID    string     `json:"source_id"`
	Kind        string     `json:"kind"`
	Status      string     `json:"status"`
	QueuedAt    *time.Time `json:"queued_at,omitempty"`
	Pages       int        `json:"pages"`
	Received    int        `json:"received"`
	Accepted    int        `json:"accepted"`
	Quarantined int        `json:"quarantined"`
	Resolved    int        `json:"resolved"`
	Skipped     int        `json:"skipped,omitempty"`
	Snapshot    bool       `json:"snapshot"`
	BatchIDs    []string   `json:"batch_ids,omitempty"`
	Problems    []string   `json:"problems,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// SyncProfile queues a profile's pull for the next scheduler poll and returns
// a result with status "queued". The run happens in the scheduler, outside
// the request: it is not bound by the request deadline, and it resolves
// credential references with the runtime's authority (references were
// authorized for the caller when the profile was saved).
func (s *Service) SyncProfile(ctx context.Context, tenantID string, profileID string, _ string) (*PullRunResult, error) {
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
	now := s.clock()
	if profile.ClaimOwner != "" && profile.ClaimExpiresAt != nil && profile.ClaimExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: a pull for profile %q is already running", ErrConflict, profile.ID)
	}
	queued := now
	if profile.NextPullAt != nil && !profile.NextPullAt.After(now) {
		queued = *profile.NextPullAt
	} else if err := s.store.CompleteVulnerabilityProfileClaim(ctx, profile.TenantID, profile.ID, "", now); err != nil {
		// Completing the empty claim moves next_pull_at only while no
		// scheduler holds the profile, so it cannot disturb a running pull.
		return nil, err
	}
	return &PullRunResult{ProfileID: profile.ID, SourceID: profile.SourceID, Kind: profile.PullKind, Status: PullStatusQueued, QueuedAt: &queued}, nil
}

// RunDuePulls claims due profiles one at a time across a small worker pool,
// runs them, and schedules their next run. It returns the runs it performed.
func (s *Service) RunDuePulls(ctx context.Context, owner string) ([]*PullRunResult, error) {
	if !s.Available() {
		return nil, ErrUnavailable
	}
	var (
		mu      sync.Mutex
		results []*PullRunResult
		errs    []error
		started int
	)
	take := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if started >= maxPullsPerPoll {
			return false
		}
		started++
		return true
	}
	workers := make([]<-chan struct{}, 0, pullWorkers)
	for range pullWorkers {
		workers = append(workers, panicsafe.Go(ctx, "vulnerability_pull.worker", func() {
			for ctx.Err() == nil && take() {
				result, more, err := s.runNextDuePull(ctx, owner)
				mu.Lock()
				if result != nil {
					results = append(results, result)
				}
				if err != nil {
					errs = append(errs, err)
				}
				mu.Unlock()
				if !more {
					return
				}
			}
		}))
	}
	for _, done := range workers {
		<-done
	}
	return results, errors.Join(errs...)
}

// runNextDuePull claims and runs one due profile. It reports whether another
// claim may find work.
func (s *Service) runNextDuePull(ctx context.Context, owner string) (*PullRunResult, bool, error) {
	profiles, err := s.store.ClaimDueVulnerabilityProfiles(ctx, s.clock(), owner, claimTTL, 1)
	if err != nil {
		return nil, false, err
	}
	if len(profiles) == 0 {
		return nil, false, nil
	}
	profile := profiles[0]
	result := s.runPull(ctx, profile, "scheduler")
	next := s.clock().Add(nextPullDelay(profile, result))
	if ctx.Err() != nil {
		// Shutting down: hand the profile back so another replica runs it.
		next = s.clock()
	}
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pullRecordTimeout)
	defer cancel()
	if err := s.store.CompleteVulnerabilityProfileClaim(releaseCtx, profile.TenantID, profile.ID, owner, next); err != nil {
		return result, true, fmt.Errorf("complete pull claim for %s: %w", profile.ID, err)
	}
	return result, true, nil
}

func nextPullDelay(profile *ports.VulnerabilityProfile, result *PullRunResult) time.Duration {
	interval := time.Duration(profile.PullIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultPullInterval
	}
	if result != nil && result.Status == ProfileStatusPendingMapping {
		interval = min(max(interval, pendingMappingBackoff), maxPullInterval)
	}
	return interval
}

func (s *Service) runPull(ctx context.Context, profile *ports.VulnerabilityProfile, actor string) (result *PullRunResult) {
	result = &PullRunResult{ProfileID: profile.ID, SourceID: profile.SourceID, Kind: profile.PullKind}
	// Outcomes are recorded even when the run was cancelled or timed out.
	record := func(update ports.VulnerabilityProfileIngestUpdate) error {
		recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pullRecordTimeout)
		defer cancel()
		return s.store.RecordVulnerabilityProfileIngest(recordCtx, profile.TenantID, profile.ID, update)
	}
	fail := func(err error, cursor string) *PullRunResult {
		result.Status = ProfileStatusFailed
		result.Error = truncate(err.Error(), 1024)
		update := ports.VulnerabilityProfileIngestUpdate{At: s.clock(), Status: ProfileStatusFailed, Error: result.Error}
		if cursor != "" {
			update.PullCursor = &cursor
		}
		_ = record(update)
		return result
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			result = fail(fmt.Errorf("pull transport %q panicked", profile.PullKind), "")
		}
	}()
	runCtx, cancel := context.WithTimeout(ctx, pullRunTimeout)
	defer cancel()

	puller, ok := s.pullers[profile.PullKind]
	if !ok {
		return fail(fmt.Errorf("pull kind %q is not available in this runtime", profile.PullKind), "")
	}
	config := map[string]string{}
	if strings.TrimSpace(profile.PullConfigJSON) != "" {
		if err := json.Unmarshal([]byte(profile.PullConfigJSON), &config); err != nil {
			return fail(fmt.Errorf("decode pull config: %w", err), "")
		}
	}
	if err := puller.ValidateConfig(config); err != nil {
		return fail(err, "")
	}
	if s.resolveConfig != nil {
		resolved, err := s.resolveConfig(runCtx, profile, config)
		if err != nil {
			return fail(fmt.Errorf("resolve pull credentials: %w", err), "")
		}
		config = resolved
	} else if len(puller.SecretKeys()) > 0 {
		for _, key := range puller.SecretKeys() {
			if _, ok := config[key]; ok {
				return fail(errors.New("pull credentials cannot be resolved in this runtime"), "")
			}
		}
	}

	started := s.clock()
	// Absent records are resolved only when every page normalized fresh data
	// through a trusted path; a held, failed, replayed, or partly quarantined
	// page means this run did not observe the complete current set.
	trusted := true
	genericAccepted := false
	sawGeneric := false
	status := ProfileStatusHealthy
	fetched := 0
	// Without an active mapping every generic page is held, so unchanged pages
	// are deduplicated by content instead of stored again each run. Pages that
	// may normalize through a built-in format keep no key: a replayed page
	// would block snapshot resolution.
	unmapped := strings.TrimSpace(profile.MappingJSON) == ""
	holding := func(page PullPage) bool {
		return unmapped && (strings.TrimSpace(profile.DraftMappingJSON) != "" || profile.Format == FormatGeneric || page.Format == FormatGeneric)
	}
	emit := func(page PullPage) error {
		if result.Pages >= maxPullPages {
			return fmt.Errorf("pull exceeded %d pages", maxPullPages)
		}
		if fetched+len(page.Payload) > maxPullRunBytes {
			return fmt.Errorf("%w: the run reached its %d byte budget; the rest is fetched next run", errPullStopped, maxPullRunBytes)
		}
		keyed := page.IdempotencyKey != ""
		if !keyed && holding(page) {
			page.IdempotencyKey = "pull:" + shortHash(profile.ID, payloadDigest(page.Payload))
		}
		result.Pages++
		fetched += len(page.Payload)
		ingested, err := s.ingest(runCtx, profile, IngestRequest{
			TenantID:       profile.TenantID,
			ProfileID:      profile.ID,
			Transport:      TransportPull,
			ContentType:    page.ContentType,
			IdempotencyKey: page.IdempotencyKey,
			Actor:          actor,
			Format:         page.Format,
			Payload:        page.Payload,
		})
		if ingested == nil {
			return err
		}
		result.BatchIDs = append(result.BatchIDs, ingested.BatchID)
		result.Received += ingested.Received
		result.Accepted += ingested.Accepted
		result.Quarantined += ingested.Quarantined
		for _, problem := range ingested.Problems {
			result.addProblem(problem)
		}
		if ingested.Replayed || ingested.Quarantined > 0 || ingested.Status != BatchCompleted {
			trusted = false
		}
		if ingested.Format == FormatGeneric {
			sawGeneric = true
			genericAccepted = genericAccepted || ingested.Accepted > 0
			if ingested.DriftRatio > driftThreshold && status == ProfileStatusHealthy {
				status = ProfileStatusDrift
			}
		}
		if err == nil && ingested.Status == BatchFailed {
			err = fmt.Errorf("ingest page: %s", ingested.Error)
		}
		if ingested.Status == BatchPendingMapping {
			status = ProfileStatusPendingMapping
			// Later pages of an unkeyed listing would only be held too.
			if err == nil && !keyed {
				return fmt.Errorf("%w: later pages are fetched after the draft mapping is activated", errPullStopped)
			}
		}
		return err
	}
	outcome, err := puller.Pull(runCtx, PullRequest{TenantID: profile.TenantID, ProfileID: profile.ID, Config: config, Cursor: profile.PullCursor}, emit)
	stopped := errors.Is(err, errPullStopped)
	if err != nil && !stopped {
		return fail(err, outcome.Cursor)
	}
	if stopped {
		result.addProblem(truncate(err.Error(), 512))
	}
	for _, skipped := range outcome.Skipped {
		result.Skipped++
		result.addProblem(truncate(skipped, 512))
	}
	snapshot := outcome.Snapshot && !stopped
	withheld := ""
	if snapshot && trusted && (!sawGeneric || genericAccepted) {
		resolved, warning, err := s.resolvePullSnapshot(runCtx, profile, started)
		if err != nil {
			return fail(fmt.Errorf("resolve absent observations: %w", err), outcome.Cursor)
		}
		result.Resolved = resolved
		result.Snapshot = true
		if warning != "" {
			result.addProblem(warning)
			withheld = warning
		}
	} else if snapshot {
		result.addProblem("snapshot did not resolve absent observations because not every page normalized fresh data")
	}
	cursor := outcome.Cursor
	result.Status = status
	update := ports.VulnerabilityProfileIngestUpdate{At: s.clock(), Status: status, PullCursor: &cursor}
	if result.Skipped > 0 {
		update.Error = truncate(fmt.Sprintf("skipped %d unreadable unit(s); first: %s", result.Skipped, outcome.Skipped[0]), 1024)
	}
	if withheld != "" {
		update.Error = truncate(withheld, 1024)
	}
	if err := record(update); err != nil {
		result.Error = truncate(err.Error(), 1024)
	}
	return result
}

// pullDestinationKeys decide where a pull sends its credentials. Changing one
// drops stored secrets unless the same request supplies them again, so a
// stored token cannot be redirected to a caller-chosen endpoint.
var pullDestinationKeys = []string{"url", "base_url", "auth_header", "auth_scheme", "bucket", "role_arn"}

// scopePullConfigChange drops stored secrets after a destination change.
// previous is empty when the pull kind changed, in which case nothing carries
// over anyway. Cursors need no reset here: the store keeps them across
// profile updates, and pullers scope them to the listing they came from.
func scopePullConfigChange(puller Puller, previous map[string]string, next map[string]string, supplied map[string]string) {
	if len(previous) == 0 {
		return
	}
	changed := func(keys []string) bool {
		for _, key := range keys {
			if previous[key] != next[key] {
				return true
			}
		}
		return false
	}
	if !changed(pullDestinationKeys) {
		return
	}
	secret := map[string]bool{}
	for _, key := range puller.SecretKeys() {
		secret[key] = true
	}
	resupplied := map[string]bool{}
	for key, value := range supplied {
		if strings.TrimSpace(value) != "" {
			resupplied[strings.TrimSpace(key)] = true
		}
	}
	for key := range next {
		if (secret[key] || sourceconfig.SensitiveKey(key)) && !resupplied[key] {
			delete(next, key)
		}
	}
}
func (r *PullRunResult) addProblem(problem string) {
	if len(r.Problems) < maxProblemSamples {
		r.Problems = append(r.Problems, problem)
	}
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

// resolvePullSnapshot applies the same guarded, serialized resolution as push
// snapshots. profile is the copy claimed before the run, so its last error
// still reflects the previous run rather than this run's page updates.
func (s *Service) resolvePullSnapshot(ctx context.Context, profile *ports.VulnerabilityProfile, started time.Time) (int, string, error) {
	unlock, err := s.store.LockVulnerabilityProfileSnapshot(ctx, profile.TenantID, profile.ID)
	if err != nil {
		return 0, "", err
	}
	defer unlock()
	return s.resolveAbsentGuarded(ctx, profile, started, s.clock())
}
