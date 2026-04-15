package cli

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	_ "modernc.org/sqlite"
)

var scheduleDollarPlaceholderRe = regexp.MustCompile(`\$\d+`)

func scheduleSQLiteRewrite(q string) string {
	return scheduleDollarPlaceholderRe.ReplaceAllString(q, "?")
}

func newTestScheduleSQLStore(t *testing.T) *scheduleSQLStore {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := &scheduleSQLStore{
		db:         db,
		rewriteSQL: scheduleSQLiteRewrite,
	}
	if err := store.EnsureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}

type reusableScheduleStore struct {
	inner *scheduleSQLStore
}

func (s *reusableScheduleStore) EnsureSchema(ctx context.Context) error {
	return s.inner.EnsureSchema(ctx)
}

func (s *reusableScheduleStore) List(ctx context.Context) ([]SyncSchedule, error) {
	return s.inner.List(ctx)
}

func (s *reusableScheduleStore) Get(ctx context.Context, name string) (*SyncSchedule, error) {
	return s.inner.Get(ctx, name)
}

func (s *reusableScheduleStore) Save(ctx context.Context, schedule *SyncSchedule) error {
	return s.inner.Save(ctx, schedule)
}

func (s *reusableScheduleStore) Delete(ctx context.Context, name string) error {
	return s.inner.Delete(ctx, name)
}

func (s *reusableScheduleStore) Close() error {
	return nil
}

func TestScheduleSQLStore_RoundTrip(t *testing.T) {
	store := newTestScheduleSQLStore(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 27, 12, 34, 56, 789000000, time.UTC)

	schedule := &SyncSchedule{
		Name:       "daily-aws",
		Cron:       "0 0 * * *",
		Provider:   "aws",
		Table:      "aws_iam_roles",
		Enabled:    true,
		ScanAfter:  true,
		Retry:      4,
		CreatedAt:  now,
		UpdatedAt:  now,
		LastRun:    now.Add(-time.Hour),
		LastStatus: "success",
		NextRun:    now.Add(time.Hour),
	}

	if err := store.Save(ctx, schedule); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, schedule.Name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected stored schedule")
		return
	}
	if got.Name != schedule.Name || got.Provider != schedule.Provider || got.Table != schedule.Table {
		t.Fatalf("unexpected schedule: %+v", got)
	}
	if !got.CreatedAt.Equal(schedule.CreatedAt) || !got.LastRun.Equal(schedule.LastRun) || !got.NextRun.Equal(schedule.NextRun) {
		t.Fatalf("unexpected timestamps: %+v", got)
	}

	schedule.LastStatus = "failed"
	schedule.UpdatedAt = now.Add(2 * time.Hour)
	if err := store.Save(ctx, schedule); err != nil {
		t.Fatalf("Save update: %v", err)
	}

	listed, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 || listed[0].LastStatus != "failed" {
		t.Fatalf("unexpected schedules after update: %+v", listed)
	}

	if err := store.Delete(ctx, schedule.Name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err = store.Get(ctx, schedule.Name)
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got != nil {
		t.Fatalf("expected schedule to be deleted, got %+v", got)
	}
}

func TestSchedulePersistenceWrappers_UseConfiguredStore(t *testing.T) {
	store := &reusableScheduleStore{inner: newTestScheduleSQLStore(t)}

	originalOpen := openScheduleStoreFn
	t.Cleanup(func() {
		openScheduleStoreFn = originalOpen
	})
	openScheduleStoreFn = func() (scheduleStore, error) {
		return store, nil
	}

	ctx := context.Background()
	now := time.Date(2026, 3, 27, 1, 2, 3, 456000000, time.UTC)
	schedule := &SyncSchedule{
		Name:      "hourly-okta",
		Cron:      "0 * * * *",
		Provider:  "okta",
		Enabled:   true,
		Retry:     2,
		CreatedAt: now,
		UpdatedAt: now,
		NextRun:   now.Add(time.Hour),
	}

	if err := saveSchedule(ctx, (*snowflake.Client)(nil), schedule); err != nil {
		t.Fatalf("saveSchedule: %v", err)
	}

	listed, err := listSchedules(ctx, (*snowflake.Client)(nil))
	if err != nil {
		t.Fatalf("listSchedules: %v", err)
	}
	if len(listed) != 1 || listed[0].Name != schedule.Name {
		t.Fatalf("unexpected list result: %+v", listed)
	}

	got, err := getSchedule(ctx, (*snowflake.Client)(nil), schedule.Name)
	if err != nil {
		t.Fatalf("getSchedule: %v", err)
	}
	if got == nil || got.Provider != schedule.Provider {
		t.Fatalf("unexpected schedule lookup result: %+v", got)
	}

	if err := deleteSchedule(ctx, (*snowflake.Client)(nil), schedule.Name); err != nil {
		t.Fatalf("deleteSchedule: %v", err)
	}
}
