package vulndb

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type staticFeedClient map[string]string

func (c staticFeedClient) Open(_ context.Context, source string, _ bool) (io.ReadCloser, error) {
	payload, ok := c[source]
	if !ok {
		return nil, errors.New("feed not found")
	}
	return io.NopCloser(strings.NewReader(payload)), nil
}

type failingFeedClient struct{}

func (failingFeedClient) Open(context.Context, string, bool) (io.ReadCloser, error) {
	return nil, errors.New("feed down")
}

type brokenGetSyncJobStore struct {
	*MemoryStore
}

func (s brokenGetSyncJobStore) GetSyncJob(context.Context, string) (SyncJob, bool, error) {
	return SyncJob{}, false, errors.New("metadata unavailable")
}

func TestSyncServiceRecordsFailureState(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service, err := NewSyncService(store, failingFeedClient{})
	if err != nil {
		t.Fatalf("new sync service: %v", err)
	}
	if _, err := service.Sync(ctx, []SyncFeed{{Source: SourceOSV, URL: "https://example.com/osv.json"}}); err == nil {
		t.Fatal("Sync() error = nil, want feed failure")
	}
	state, ok, err := store.GetSyncState(ctx, SourceOSV)
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !ok {
		t.Fatal("expected sync state after failure")
	}
	if !strings.Contains(state.LastError, "feed down") || state.LastSyncedAt.IsZero() {
		t.Fatalf("unexpected failure sync state: %+v", state)
	}
}

func TestSyncRunnerRunDueSurfacesJobMetadataErrors(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.PutSyncJob(ctx, SyncJob{
		ID:       "osv-hourly",
		Source:   SourceOSV,
		FeedURL:  "osv-feed",
		Interval: time.Hour,
	}); err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	runner, err := NewSyncRunner(store, brokenGetSyncJobStore{MemoryStore: store}, func(context.Context, SyncJob) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(`[]`)), nil
	})
	if err != nil {
		t.Fatalf("new sync runner: %v", err)
	}
	result, err := runner.RunDue(ctx, 10)
	if err != nil {
		t.Fatalf("run due: %v", err)
	}
	if len(result.Jobs) != 1 {
		t.Fatalf("jobs = %+v, want one failure", result.Jobs)
	}
	if result.Jobs[0].JobID != "osv-hourly" || result.Jobs[0].Status != "failed" || !strings.Contains(result.Jobs[0].Error, "metadata unavailable") {
		t.Fatalf("unexpected job result: %+v", result.Jobs[0])
	}
}

func TestSyncRunnerLeasesAndCompletesJob(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.PutSyncJob(ctx, SyncJob{
		ID:       "osv-hourly",
		Source:   SourceOSV,
		FeedURL:  "osv-feed",
		Interval: time.Hour,
	}); err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	service, err := NewSyncService(store, staticFeedClient{
		"osv-feed": `[{"id":"CVE-2026-12121","summary":"synced vuln"}]`,
	})
	if err != nil {
		t.Fatalf("new sync service: %v", err)
	}
	imported, err := service.RunSyncJob(ctx, store, "osv-hourly", "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("run sync job: %v", err)
	}
	if imported.Vulnerabilities != 1 {
		t.Fatalf("imported = %+v, want one vulnerability", imported)
	}
	job, ok, err := store.GetSyncJob(ctx, "osv-hourly")
	if err != nil {
		t.Fatalf("get sync job: %v", err)
	}
	if !ok {
		t.Fatal("expected stored sync job")
	}
	if job.Runs != 1 || job.LastSuccessAt.IsZero() || !job.LeaseExpiresAt.IsZero() || job.LeaseOwner != "" || job.NextRunAt.IsZero() {
		t.Fatalf("unexpected completed job: %+v", job)
	}
	if _, ok, err := store.FindVulnerability(ctx, "CVE-2026-12121"); err != nil || !ok {
		t.Fatalf("synced vulnerability lookup ok=%v err=%v, want found", ok, err)
	}
	due, err := store.ListDueSyncJobs(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list due sync jobs: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due jobs = %+v, want none before next_run_at", due)
	}
}

func TestMemoryStoreRejectsZeroIntervalSyncJob(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.PutSyncJob(ctx, SyncJob{ID: "osv", Source: SourceOSV, FeedURL: "osv-feed"}); err == nil {
		t.Fatal("PutSyncJob() error = nil, want positive interval requirement")
	}
}

func TestMemoryStoreRejectsUnsupportedSyncJobSource(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.PutSyncJob(ctx, SyncJob{ID: "bad", Source: "typo", FeedURL: "feed", Interval: time.Hour}); err == nil {
		t.Fatal("PutSyncJob() error = nil, want unsupported source rejection")
	}
}

func TestMemoryStorePutSyncJobPreservesNextRunAt(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	nextRunAt := time.Date(2026, 5, 21, 20, 0, 0, 0, time.UTC)
	if err := store.PutSyncJob(ctx, SyncJob{
		ID:        "osv-hourly",
		Source:    SourceOSV,
		FeedURL:   "osv-feed",
		Interval:  time.Hour,
		NextRunAt: nextRunAt,
	}); err != nil {
		t.Fatalf("put scheduled sync job: %v", err)
	}
	if err := store.PutSyncJob(ctx, SyncJob{
		ID:       "osv-hourly",
		Source:   SourceOSV,
		FeedURL:  "osv-feed-updated",
		Interval: 2 * time.Hour,
	}); err != nil {
		t.Fatalf("update sync job: %v", err)
	}
	job, ok, err := store.GetSyncJob(ctx, "osv-hourly")
	if err != nil {
		t.Fatalf("get sync job: %v", err)
	}
	if !ok {
		t.Fatal("expected sync job")
	}
	if !job.NextRunAt.Equal(nextRunAt) {
		t.Fatalf("NextRunAt = %v, want preserved %v", job.NextRunAt, nextRunAt)
	}
	if job.FeedURL != "osv-feed-updated" || job.Interval != 2*time.Hour {
		t.Fatalf("expected editable fields to update, got %+v", job)
	}
}

func TestSyncRunnerRunDueRechecksNextRunAtAfterLease(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	future := time.Now().UTC().Add(time.Hour)
	if err := store.PutSyncJob(ctx, SyncJob{
		ID:        "osv-hourly",
		Source:    SourceOSV,
		FeedURL:   "osv-feed",
		Interval:  time.Hour,
		NextRunAt: future,
	}); err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	runner, err := NewSyncRunner(store, store, func(context.Context, SyncJob) (io.ReadCloser, error) {
		t.Fatal("openFeed should not be called for no-longer-due job")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("new sync runner: %v", err)
	}
	if err := store.CompleteSyncJob(ctx, "osv-hourly", "", future); err != nil {
		t.Fatalf("complete sync job: %v", err)
	}
	run, err := runner.runJob(ctx, "osv-hourly", true)
	if err != nil {
		t.Fatalf("run due job: %v", err)
	}
	if run.Status != "not_due" {
		t.Fatalf("Status = %q, want not_due", run.Status)
	}
}

func TestFileStorePersistsSyncJobRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.json")
	store, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	if err := store.PutSyncJob(ctx, SyncJob{ID: "nvd-daily", Source: SourceNVD, FeedURL: "nvd-feed", Interval: 24 * time.Hour}); err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	acquired, err := store.AcquireSyncJobLease(ctx, "nvd-daily", "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("acquire sync job lease: %v", err)
	}
	if !acquired {
		t.Fatal("expected sync job lease")
	}
	if err := store.ReleaseSyncJobLease(ctx, "nvd-daily", "worker-1"); err != nil {
		t.Fatalf("release sync job lease: %v", err)
	}
	reopened, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}
	job, ok, err := reopened.GetSyncJob(ctx, "nvd-daily")
	if err != nil {
		t.Fatalf("get sync job: %v", err)
	}
	if !ok || job.Source != SourceNVD || job.FeedURL != "nvd-feed" || job.Interval != 24*time.Hour {
		t.Fatalf("unexpected recovered sync job: ok=%v job=%+v", ok, job)
	}
	stats, err := reopened.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.SyncJobs != 1 {
		t.Fatalf("stats.SyncJobs = %d, want 1", stats.SyncJobs)
	}
}

func TestFileStoreSyncJobLeaseReloadsBeforeAcquire(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.json")
	seed, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new seed file store: %v", err)
	}
	if err := seed.PutSyncJob(ctx, SyncJob{ID: "osv-hourly", Source: SourceOSV, FeedURL: "osv-feed", Interval: time.Hour}); err != nil {
		t.Fatalf("put sync job: %v", err)
	}
	worker1, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new worker1 store: %v", err)
	}
	worker2, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new worker2 store: %v", err)
	}
	acquired, err := worker1.AcquireSyncJobLease(ctx, "osv-hourly", "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("worker1 acquire: %v", err)
	}
	if !acquired {
		t.Fatal("expected worker1 to acquire lease")
	}
	acquired, err = worker2.AcquireSyncJobLease(ctx, "osv-hourly", "worker-2", time.Minute)
	if err != nil {
		t.Fatalf("worker2 acquire: %v", err)
	}
	if acquired {
		t.Fatal("expected worker2 to observe persisted lease and skip acquisition")
	}
}

func TestFileStoreReloadsSyncJobsBeforeRead(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vulndb.json")
	seed, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new seed file store: %v", err)
	}
	if err := seed.PutSyncJob(ctx, SyncJob{ID: "osv-hourly", Source: SourceOSV, FeedURL: "old-feed", Interval: time.Hour}); err != nil {
		t.Fatalf("put seed sync job: %v", err)
	}
	reader, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new reader store: %v", err)
	}
	writer, err := NewFileStore(ctx, path)
	if err != nil {
		t.Fatalf("new writer store: %v", err)
	}
	nextRunAt := time.Now().UTC().Add(time.Hour)
	if err := writer.PutSyncJob(ctx, SyncJob{
		ID:        "osv-hourly",
		Source:    SourceOSV,
		FeedURL:   "new-feed",
		Interval:  time.Hour,
		NextRunAt: nextRunAt,
	}); err != nil {
		t.Fatalf("update sync job: %v", err)
	}
	job, ok, err := reader.GetSyncJob(ctx, "osv-hourly")
	if err != nil {
		t.Fatalf("reader get sync job: %v", err)
	}
	if !ok || job.FeedURL != "new-feed" || !job.NextRunAt.Equal(nextRunAt) {
		t.Fatalf("reader observed stale job: ok=%v job=%+v", ok, job)
	}
	due, err := reader.ListDueSyncJobs(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("reader list due sync jobs: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due jobs = %+v, want none after reload of future next_run_at", due)
	}
}
