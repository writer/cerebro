package vulndb

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	DefaultSyncJobLeaseTTL = 30 * time.Minute
	DefaultSyncJobLimit    = 10
)

// FeedOpener opens one advisory feed URL or path for import.
type FeedOpener func(context.Context, SyncJob) (io.ReadCloser, error)

// FeedClient opens advisory feed URLs or paths.
type FeedClient interface {
	Open(context.Context, string, bool) (io.ReadCloser, error)
}

// SyncFeed identifies one advisory feed to import.
type SyncFeed struct {
	Source            string
	URL               string
	AllowInsecureHTTP bool
}

// SyncResult summarizes a direct multi-feed sync operation.
type SyncResult struct {
	Results map[string]ImportResult `json:"results"`
}

// SyncService imports direct feeds and executes durable sync jobs.
type SyncService struct {
	store  Store
	client FeedClient
}

// NewSyncService constructs a vulnerability advisory feed sync service.
func NewSyncService(store Store, client FeedClient) (*SyncService, error) {
	if store == nil {
		return nil, fmt.Errorf("vulnerability store is required")
	}
	if client == nil {
		return nil, fmt.Errorf("vulndb feed client is required")
	}
	return &SyncService{store: store, client: client}, nil
}

// Sync imports all supplied feeds into the shared vulnerability store.
func (s *SyncService) Sync(ctx context.Context, feeds []SyncFeed) (SyncResult, error) {
	if s == nil {
		return SyncResult{}, fmt.Errorf("vulndb sync service is required")
	}
	result := SyncResult{Results: make(map[string]ImportResult, len(feeds))}
	for _, feed := range feeds {
		source := normalizeSource(feed.Source)
		if source == "" {
			return SyncResult{}, fmt.Errorf("feed source is required")
		}
		reader, err := s.client.Open(ctx, feed.URL, feed.AllowInsecureHTTP)
		if err != nil {
			_ = recordSyncFailure(ctx, s.store, source, err)
			return result, err
		}
		imported, importErr := ImportFeed(ctx, s.store, source, reader)
		closeErr := reader.Close()
		if importErr != nil {
			_ = recordSyncFailure(ctx, s.store, source, importErr)
			return result, importErr
		}
		if closeErr != nil {
			_ = recordSyncFailure(ctx, s.store, source, closeErr)
			return result, closeErr
		}
		result.Results[source] = imported
	}
	return result, nil
}

// RunSyncJob executes one durable sync job.
func (s *SyncService) RunSyncJob(ctx context.Context, jobs SyncJobStore, jobID string, owner string, leaseTTL time.Duration) (ImportResult, error) {
	runner, err := NewSyncRunner(s.store, jobs, s.openJobFeed)
	if err != nil {
		return ImportResult{}, err
	}
	run, err := runner.WithOwner(owner).WithLeaseTTL(leaseTTL).RunJob(ctx, jobID)
	if err != nil {
		return ImportResult{}, err
	}
	if run.Imported == nil {
		if run.Error != "" {
			return ImportResult{}, fmt.Errorf("%s", run.Error)
		}
		return ImportResult{}, fmt.Errorf("sync job %q was not run: %s", jobID, run.Status)
	}
	return *run.Imported, nil
}

// RunDueSyncJobs executes currently due durable sync jobs.
func (s *SyncService) RunDueSyncJobs(ctx context.Context, jobs SyncJobStore, _ time.Time, owner string, leaseTTL time.Duration, limit int) (SyncDueJobsResult, error) {
	runner, err := NewSyncRunner(s.store, jobs, s.openJobFeed)
	if err != nil {
		return SyncDueJobsResult{}, err
	}
	return runner.WithOwner(owner).WithLeaseTTL(leaseTTL).RunDue(ctx, limit)
}

func (s *SyncService) openJobFeed(ctx context.Context, job SyncJob) (io.ReadCloser, error) {
	return s.client.Open(ctx, job.FeedURL, job.AllowInsecureHTTP)
}

// SyncJobRunResult describes one attempted advisory feed sync job run.
type SyncJobRunResult struct {
	JobID     string        `json:"job_id"`
	Source    string        `json:"source"`
	Status    string        `json:"status"`
	Imported  *ImportResult `json:"imported,omitempty"`
	NextRunAt time.Time     `json:"next_run_at,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// SyncDueJobsResult summarizes one due-job polling pass.
type SyncDueJobsResult struct {
	Jobs []SyncJobRunResult `json:"jobs"`
}

// SyncRunner executes durable advisory feed sync jobs against a shared store.
type SyncRunner struct {
	store    Store
	jobs     SyncJobStore
	openFeed FeedOpener
	owner    string
	leaseTTL time.Duration
	now      func() time.Time
}

// NewSyncRunner constructs a durable advisory feed sync runner.
func NewSyncRunner(store Store, jobs SyncJobStore, openFeed FeedOpener) (*SyncRunner, error) {
	if store == nil {
		return nil, fmt.Errorf("vulnerability store is required")
	}
	if jobs == nil {
		return nil, fmt.Errorf("vulndb sync job store is required")
	}
	if openFeed == nil {
		return nil, fmt.Errorf("vulndb feed opener is required")
	}
	return &SyncRunner{
		store:    store,
		jobs:     jobs,
		openFeed: openFeed,
		leaseTTL: DefaultSyncJobLeaseTTL,
		now:      func() time.Time { return time.Now().UTC() },
	}, nil
}

// WithOwner configures the lease owner used for job execution.
func (r *SyncRunner) WithOwner(owner string) *SyncRunner {
	if r != nil {
		r.owner = strings.TrimSpace(owner)
	}
	return r
}

// WithLeaseTTL configures the per-job lease TTL.
func (r *SyncRunner) WithLeaseTTL(ttl time.Duration) *SyncRunner {
	if r != nil && ttl > 0 {
		r.leaseTTL = ttl
	}
	return r
}

// RunDue runs currently due sync jobs up to the supplied limit.
func (r *SyncRunner) RunDue(ctx context.Context, limit int) (SyncDueJobsResult, error) {
	if r == nil {
		return SyncDueJobsResult{}, fmt.Errorf("vulndb sync runner is required")
	}
	if limit <= 0 {
		limit = DefaultSyncJobLimit
	}
	jobs, err := r.jobs.ListDueSyncJobs(ctx, r.now(), limit)
	if err != nil {
		return SyncDueJobsResult{}, err
	}
	result := SyncDueJobsResult{Jobs: make([]SyncJobRunResult, 0, len(jobs))}
	for _, job := range jobs {
		run, err := r.runJob(ctx, job.ID, true)
		if err != nil {
			run = SyncJobRunResult{
				JobID:  strings.TrimSpace(job.ID),
				Source: strings.TrimSpace(job.Source),
				Status: "failed",
				Error:  err.Error(),
			}
		}
		result.Jobs = append(result.Jobs, run)
	}
	return result, nil
}

// RunJob runs one durable sync job by ID with lease protection.
func (r *SyncRunner) RunJob(ctx context.Context, id string) (SyncJobRunResult, error) {
	return r.runJob(ctx, id, false)
}

func (r *SyncRunner) runJob(ctx context.Context, id string, requireDue bool) (SyncJobRunResult, error) {
	if r == nil {
		return SyncJobRunResult{}, fmt.Errorf("vulndb sync runner is required")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return SyncJobRunResult{}, fmt.Errorf("sync job id is required")
	}
	job, ok, err := r.jobs.GetSyncJob(ctx, id)
	if err != nil {
		return SyncJobRunResult{}, err
	}
	if !ok {
		return SyncJobRunResult{}, fmt.Errorf("%w: %s", ErrSyncJobNotFound, id)
	}
	owner := r.leaseOwner()
	acquired, err := r.jobs.AcquireSyncJobLease(ctx, job.ID, owner, r.leaseTTL)
	if err != nil {
		return SyncJobRunResult{}, err
	}
	if !acquired {
		return SyncJobRunResult{
			JobID:  job.ID,
			Source: job.Source,
			Status: "leased",
		}, nil
	}
	if requireDue {
		refreshed, ok, err := r.jobs.GetSyncJob(ctx, job.ID)
		if err != nil {
			_ = r.jobs.ReleaseSyncJobLease(ctx, job.ID, owner)
			return SyncJobRunResult{}, err
		}
		if !ok {
			_ = r.jobs.ReleaseSyncJobLease(ctx, job.ID, owner)
			return SyncJobRunResult{}, fmt.Errorf("%w: %s", ErrSyncJobNotFound, job.ID)
		}
		if !refreshed.NextRunAt.IsZero() && refreshed.NextRunAt.After(r.now()) {
			_ = r.jobs.ReleaseSyncJobLease(ctx, job.ID, owner)
			return SyncJobRunResult{JobID: refreshed.ID, Source: refreshed.Source, Status: "not_due", NextRunAt: refreshed.NextRunAt}, nil
		}
		job = refreshed
	}
	run := SyncJobRunResult{JobID: job.ID, Source: job.Source, Status: "failed"}
	nextRunAt := r.nextRunAt(job)
	reader, err := r.openFeed(ctx, job)
	if err == nil {
		defer func() {
			_ = reader.Close()
		}()
		var imported ImportResult
		imported, err = ImportFeed(ctx, r.store, job.Source, reader)
		if err == nil {
			run.Status = "completed"
			run.Imported = &imported
			run.NextRunAt = nextRunAt
			if completeErr := r.jobs.CompleteSyncJob(ctx, job.ID, owner, nextRunAt); completeErr != nil {
				return run, completeErr
			}
			return run, nil
		}
	}
	if err == nil {
		err = fmt.Errorf("sync job failed")
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_ = recordSyncFailure(cleanupCtx, r.store, job.Source, err)
	run.Error = err.Error()
	run.NextRunAt = nextRunAt
	if failErr := r.jobs.FailSyncJob(cleanupCtx, job.ID, owner, nextRunAt, err); failErr != nil {
		return run, failErr
	}
	return run, nil
}

func (r *SyncRunner) leaseOwner() string {
	if strings.TrimSpace(r.owner) != "" {
		return strings.TrimSpace(r.owner)
	}
	return fmt.Sprintf("vulndb-sync:%d", time.Now().UnixNano())
}

func (r *SyncRunner) nextRunAt(job SyncJob) time.Time {
	if job.Interval <= 0 {
		return time.Time{}
	}
	return r.now().Add(job.Interval)
}

// ImportFeed imports one advisory feed by normalized source label.
func ImportFeed(ctx context.Context, store Store, source string, reader io.Reader) (ImportResult, error) {
	switch normalizeSource(source) {
	case SourceOSV:
		return ImportOSV(ctx, store, reader)
	case SourceCISAKEV:
		return ImportCISAKEV(ctx, store, reader)
	case SourceEPSS:
		return ImportEPSS(ctx, store, reader)
	case SourceNVD:
		return ImportNVD(ctx, store, reader)
	default:
		return ImportResult{}, fmt.Errorf("unsupported vulndb feed source %q", strings.TrimSpace(source))
	}
}

// IsSupportedFeedSource reports whether source can be imported by ImportFeed.
func IsSupportedFeedSource(source string) bool {
	switch normalizeSource(source) {
	case SourceOSV, SourceCISAKEV, SourceEPSS, SourceNVD:
		return true
	default:
		return false
	}
}

func recordSyncSuccess(ctx context.Context, store Store, source string) error {
	state, _, err := store.GetSyncState(ctx, source)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state.Source = normalizeSource(source)
	state.LastSyncedAt = now
	state.LastSuccessAt = now
	state.LastError = ""
	return store.PutSyncState(ctx, state)
}

func recordSyncFailure(ctx context.Context, store Store, source string, syncErr error) error {
	state, _, err := store.GetSyncState(ctx, source)
	if err != nil {
		return err
	}
	state.Source = normalizeSource(source)
	state.LastSyncedAt = time.Now().UTC()
	if syncErr != nil {
		state.LastError = syncErr.Error()
	}
	return store.PutSyncState(ctx, state)
}
