package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type mockRetentionRepo struct {
	auditCutoff        time.Time
	sessionCutoff      time.Time
	graphCutoff        time.Time
	accessReviewCutoff time.Time

	auditCalls        int
	sessionCalls      int
	graphCalls        int
	accessReviewCalls int

	auditErr error
}

func (m *mockRetentionRepo) CleanupAuditLogs(_ context.Context, olderThan time.Time) (int64, error) {
	m.auditCalls++
	m.auditCutoff = olderThan
	if m.auditErr != nil {
		return 0, m.auditErr
	}
	return 11, nil
}

func (m *mockRetentionRepo) CleanupAgentData(_ context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error) {
	m.sessionCalls++
	m.sessionCutoff = olderThan
	return 7, 13, nil
}

func (m *mockRetentionRepo) CleanupGraphData(_ context.Context, olderThan time.Time) (pathsDeleted, edgesDeleted, nodesDeleted int64, err error) {
	m.graphCalls++
	m.graphCutoff = olderThan
	return 3, 5, 8, nil
}

func (m *mockRetentionRepo) CleanupAccessReviewData(_ context.Context, olderThan time.Time) (reviewsDeleted, itemsDeleted int64, err error) {
	m.accessReviewCalls++
	m.accessReviewCutoff = olderThan
	return 2, 4, nil
}

func TestInitScheduler_AddsRetentionJobWhenConfigured(t *testing.T) {
	repo := &mockRetentionRepo{}
	app := &App{
		Config: &Config{
			RetentionJobInterval:      12 * time.Hour,
			AuditRetentionDays:        30,
			SessionRetentionDays:      7,
			GraphRetentionDays:        14,
			AccessReviewRetentionDays: 90,
		},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetentionRepo: repo,
	}

	app.initScheduler(context.Background())

	job, ok := app.Scheduler.GetJob("data-retention")
	if !ok {
		t.Fatal("expected data-retention job to be registered")
	}
	if job.Interval != 12*time.Hour {
		t.Fatalf("expected data-retention interval 12h, got %v", job.Interval)
	}

	if err := job.Handler(context.Background()); err != nil {
		t.Fatalf("data-retention handler failed: %v", err)
	}

	if repo.auditCalls != 1 || repo.sessionCalls != 1 || repo.graphCalls != 1 || repo.accessReviewCalls != 1 {
		t.Fatalf("unexpected retention call counts: audit=%d session=%d graph=%d access_review=%d",
			repo.auditCalls, repo.sessionCalls, repo.graphCalls, repo.accessReviewCalls)
	}
	if repo.auditCutoff.IsZero() || repo.sessionCutoff.IsZero() || repo.graphCutoff.IsZero() || repo.accessReviewCutoff.IsZero() {
		t.Fatal("expected all retention cutoffs to be populated")
	}
}

func TestInitScheduler_SkipsRetentionJobWhenDisabled(t *testing.T) {
	app := &App{
		Config: &Config{
			RetentionJobInterval: 6 * time.Hour,
		},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetentionRepo: &mockRetentionRepo{},
	}

	app.initScheduler(context.Background())

	if _, ok := app.Scheduler.GetJob("data-retention"); ok {
		t.Fatal("expected data-retention job to be skipped when no retention windows are configured")
	}
}

func TestRunRetentionCleanup_PropagatesErrors(t *testing.T) {
	app := &App{
		Config: &Config{
			AuditRetentionDays: 30,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetentionRepo: &mockRetentionRepo{
			auditErr: errors.New("boom"),
		},
	}

	err := app.runRetentionCleanup(context.Background())
	if err == nil {
		t.Fatal("expected retention cleanup to fail")
	}
	if !strings.Contains(err.Error(), "cleanup audit logs") {
		t.Fatalf("expected wrapped audit cleanup error, got %v", err)
	}
}
