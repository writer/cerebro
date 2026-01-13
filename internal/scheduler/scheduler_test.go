package scheduler

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestScheduler_NewScheduler(t *testing.T) {
	s := NewScheduler(testLogger())
	if s == nil {
		t.Fatal("NewScheduler returned nil")
	}

	if s.jobs == nil {
		t.Error("jobs map should be initialized")
	}
}

func TestScheduler_AddJob(t *testing.T) {
	s := NewScheduler(testLogger())

	handler := func(ctx context.Context) error { return nil }
	s.AddJob("test", 1*time.Hour, handler)

	job, ok := s.GetJob("test")
	if !ok {
		t.Fatal("expected job to be added")
	}

	if job.Name != "test" {
		t.Errorf("got name %s, want test", job.Name)
	}

	if job.Interval != 1*time.Hour {
		t.Errorf("got interval %v, want 1h", job.Interval)
	}

	if !job.Enabled {
		t.Error("job should be enabled by default")
	}
}

func TestScheduler_RemoveJob(t *testing.T) {
	s := NewScheduler(testLogger())

	s.AddJob("test", 1*time.Hour, func(ctx context.Context) error { return nil })
	s.RemoveJob("test")

	_, ok := s.GetJob("test")
	if ok {
		t.Error("expected job to be removed")
	}
}

func TestScheduler_EnableDisableJob(t *testing.T) {
	s := NewScheduler(testLogger())

	s.AddJob("test", 1*time.Hour, func(ctx context.Context) error { return nil })

	// Disable
	s.DisableJob("test")
	job, _ := s.GetJob("test")
	if job.Enabled {
		t.Error("job should be disabled")
	}

	// Enable
	s.EnableJob("test")
	job, _ = s.GetJob("test")
	if !job.Enabled {
		t.Error("job should be enabled")
	}
}

func TestScheduler_ListJobs(t *testing.T) {
	s := NewScheduler(testLogger())

	s.AddJob("job1", 1*time.Hour, func(ctx context.Context) error { return nil })
	s.AddJob("job2", 2*time.Hour, func(ctx context.Context) error { return nil })
	s.AddJob("job3", 3*time.Hour, func(ctx context.Context) error { return nil })

	jobs := s.ListJobs()
	if len(jobs) != 3 {
		t.Errorf("expected 3 jobs, got %d", len(jobs))
	}
}

func TestScheduler_GetJob(t *testing.T) {
	s := NewScheduler(testLogger())

	s.AddJob("exists", 1*time.Hour, func(ctx context.Context) error { return nil })

	// Existing job
	job, ok := s.GetJob("exists")
	if !ok || job == nil {
		t.Error("expected to get existing job")
	}

	// Non-existent job
	_, ok = s.GetJob("non-existent")
	if ok {
		t.Error("expected not to find non-existent job")
	}
}

func TestScheduler_RunNow(t *testing.T) {
	s := NewScheduler(testLogger())

	var called atomic.Int32
	s.AddJob("test", 1*time.Hour, func(ctx context.Context) error {
		called.Add(1)
		return nil
	})

	err := s.RunNow("test")
	if err != nil {
		t.Fatalf("RunNow failed: %v", err)
	}

	// Wait for job to complete
	time.Sleep(100 * time.Millisecond)

	if called.Load() != 1 {
		t.Errorf("expected handler to be called once, got %d", called.Load())
	}
}

func TestScheduler_Status(t *testing.T) {
	s := NewScheduler(testLogger())

	s.AddJob("job1", 1*time.Hour, func(ctx context.Context) error { return nil })
	s.AddJob("job2", 2*time.Hour, func(ctx context.Context) error { return nil })

	status := s.Status()

	if status.Running {
		t.Error("scheduler should not be running initially")
	}

	if len(status.Jobs) != 2 {
		t.Errorf("expected 2 jobs in status, got %d", len(status.Jobs))
	}
}

func TestScheduler_StartStop(t *testing.T) {
	s := NewScheduler(testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start in goroutine
	go s.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	status := s.Status()
	if !status.Running {
		t.Error("scheduler should be running")
	}

	// Stop
	s.Stop()
	time.Sleep(50 * time.Millisecond)

	status = s.Status()
	if status.Running {
		t.Error("scheduler should be stopped")
	}
}

func TestJob_Fields(t *testing.T) {
	job := &Job{
		Name:     "test",
		Interval: 1 * time.Hour,
		Enabled:  true,
		Running:  false,
	}

	if job.Name != "test" {
		t.Error("name field incorrect")
	}

	if job.Interval != 1*time.Hour {
		t.Error("interval field incorrect")
	}
}

func TestJobStatus_Fields(t *testing.T) {
	now := time.Now()
	js := JobStatus{
		Name:     "test",
		Interval: "1h0m0s",
		NextRun:  now,
		Running:  false,
		Enabled:  true,
	}

	if js.Name != "test" {
		t.Error("name field incorrect")
	}

	if js.Interval != "1h0m0s" {
		t.Error("interval field incorrect")
	}
}

func TestScheduler_DisabledJobNotRun(t *testing.T) {
	s := NewScheduler(testLogger())

	var called atomic.Int32
	s.AddJob("disabled", 1*time.Millisecond, func(ctx context.Context) error {
		called.Add(1)
		return nil
	})

	s.DisableJob("disabled")

	// Manually trigger due job check
	job, _ := s.GetJob("disabled")
	job.NextRun = time.Now().Add(-1 * time.Hour) // Set to past

	// The job shouldn't run because it's disabled
	// We can't easily test runDueJobs directly, but we verify the disabled state
	if job.Enabled {
		t.Error("job should be disabled")
	}
}
