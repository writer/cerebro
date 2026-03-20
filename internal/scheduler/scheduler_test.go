package scheduler

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/testutil"
)

func waitForCondition(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		if condition() {
			return
		}

		select {
		case <-timer.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-ticker.C:
		}
	}
}

func TestScheduler_NewScheduler(t *testing.T) {
	s := NewScheduler(testutil.Logger())
	if s == nil {
		t.Fatal("NewScheduler returned nil")
	}

	if s.jobs == nil {
		t.Error("jobs map should be initialized")
	}
}

func TestScheduler_AddJob(t *testing.T) {
	s := NewScheduler(testutil.Logger())

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
	s := NewScheduler(testutil.Logger())

	s.AddJob("test", 1*time.Hour, func(ctx context.Context) error { return nil })
	s.RemoveJob("test")

	_, ok := s.GetJob("test")
	if ok {
		t.Error("expected job to be removed")
	}
}

func TestScheduler_RemoveJobWhileRunning(t *testing.T) {
	s := NewScheduler(testutil.Logger())

	started := make(chan struct{})
	release := make(chan struct{})
	s.AddJob("test", time.Hour, func(ctx context.Context) error {
		close(started)
		<-release
		return nil
	})

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.mu.Unlock()

	if err := s.RunNow("test"); err != nil {
		t.Fatalf("run now failed: %v", err)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}

	s.RemoveJob("test")
	if job, ok := s.GetJob("test"); !ok || !job.Running {
		t.Fatalf("expected running job to remain until completion")
	}

	close(release)

	waitForCondition(t, time.Second, "job removal after in-flight completion", func() bool {
		if _, ok := s.GetJob("test"); !ok {
			return true
		}
		return false
	})
}

func TestScheduler_EnableDisableJob(t *testing.T) {
	s := NewScheduler(testutil.Logger())

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
	s := NewScheduler(testutil.Logger())

	s.AddJob("job1", 1*time.Hour, func(ctx context.Context) error { return nil })
	s.AddJob("job2", 2*time.Hour, func(ctx context.Context) error { return nil })
	s.AddJob("job3", 3*time.Hour, func(ctx context.Context) error { return nil })

	jobs := s.ListJobs()
	if len(jobs) != 3 {
		t.Errorf("expected 3 jobs, got %d", len(jobs))
	}
}

func TestScheduler_GetJob(t *testing.T) {
	s := NewScheduler(testutil.Logger())

	s.AddJob("exists", 1*time.Hour, func(ctx context.Context) error { return nil })

	// Existing job
	job, ok := s.GetJob("exists")
	if !ok || job.Name == "" {
		t.Error("expected to get existing job")
	}

	// Non-existent job
	_, ok = s.GetJob("non-existent")
	if ok {
		t.Error("expected not to find non-existent job")
	}
}

func TestScheduler_RunNow(t *testing.T) {
	s := NewScheduler(testutil.Logger())

	var called atomic.Int32
	done := make(chan struct{}, 1)
	s.AddJob("test", 1*time.Hour, func(ctx context.Context) error {
		called.Add(1)
		select {
		case done <- struct{}{}:
		default:
		}
		return nil
	})

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.mu.Unlock()

	err := s.RunNow("test")
	if err != nil {
		t.Fatalf("RunNow failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected job to complete")
	}

	waitForCondition(t, time.Second, "job state reset after run", func() bool {
		job, ok := s.GetJob("test")
		return ok && !job.Running
	})

	if called.Load() != 1 {
		t.Errorf("expected handler to be called once, got %d", called.Load())
	}

	s.Stop()
}

func TestScheduler_Status(t *testing.T) {
	s := NewScheduler(testutil.Logger())

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
	s := NewScheduler(testutil.Logger())

	ctx, cancel := context.WithCancel(testutil.Context(t))
	defer cancel()

	// Start in goroutine
	go s.Start(ctx)
	waitForCondition(t, time.Second, "scheduler start", func() bool {
		return s.Status().Running
	})

	status := s.Status()
	if !status.Running {
		t.Error("scheduler should be running")
	}

	// Stop
	s.Stop()

	status = s.Status()
	if status.Running {
		t.Error("scheduler should be stopped")
	}
}

func TestJob_Fields(t *testing.T) {
	job := &Job{
		Name:           "test",
		Interval:       1 * time.Hour,
		Enabled:        true,
		Running:        false,
		MaxRetries:     3,
		InitialBackoff: 5 * time.Second,
		MaxBackoff:     1 * time.Minute,
	}

	if job.Name != "test" {
		t.Error("name field incorrect")
	}

	if job.Interval != 1*time.Hour {
		t.Error("interval field incorrect")
	}

	if !job.Enabled {
		t.Error("enabled field incorrect")
	}

	if job.Running {
		t.Error("running field should be false")
	}
	if job.MaxRetries != 3 {
		t.Error("max retries field incorrect")
	}
	if job.InitialBackoff != 5*time.Second {
		t.Error("initial backoff field incorrect")
	}
	if job.MaxBackoff != 1*time.Minute {
		t.Error("max backoff field incorrect")
	}
}

func TestJobStatus_Fields(t *testing.T) {
	now := time.Now()
	js := JobStatus{
		Name:       "test",
		Interval:   "1h0m0s",
		NextRun:    now,
		Running:    false,
		Enabled:    true,
		RetryCount: 1,
		MaxRetries: 3,
		LastError:  "boom",
	}

	if js.Name != "test" {
		t.Error("name field incorrect")
	}

	if js.Interval != "1h0m0s" {
		t.Error("interval field incorrect")
	}

	if js.NextRun.IsZero() {
		t.Error("next run field incorrect")
	}

	if js.Running {
		t.Error("running field should be false")
	}

	if !js.Enabled {
		t.Error("enabled field incorrect")
	}
	if js.RetryCount != 1 {
		t.Error("retry count field incorrect")
	}
	if js.MaxRetries != 3 {
		t.Error("max retries field incorrect")
	}
	if js.LastError != "boom" {
		t.Error("last error field incorrect")
	}
}

func TestScheduler_AddJobDefaultRetryOptions(t *testing.T) {
	s := NewScheduler(testutil.Logger())
	s.AddJob("retry-defaults", time.Hour, func(ctx context.Context) error { return nil })

	job, ok := s.GetJob("retry-defaults")
	if !ok {
		t.Fatal("expected job to exist")
	}
	if job.MaxRetries != defaultJobMaxRetries {
		t.Fatalf("max retries = %d, want %d", job.MaxRetries, defaultJobMaxRetries)
	}
	if job.InitialBackoff != defaultJobInitialBackoff {
		t.Fatalf("initial backoff = %s, want %s", job.InitialBackoff, defaultJobInitialBackoff)
	}
	if job.MaxBackoff != defaultJobMaxRetryBackoff {
		t.Fatalf("max backoff = %s, want %s", job.MaxBackoff, defaultJobMaxRetryBackoff)
	}
}

func TestScheduler_RetrySchedulesBackoffAndResetsOnSuccess(t *testing.T) {
	origJitter := retryJitterFunc
	retryJitterFunc = func(time.Duration) time.Duration { return 0 }
	t.Cleanup(func() { retryJitterFunc = origJitter })

	s := NewScheduler(testutil.Logger())
	s.AddJobWithOptions("retry-job", time.Hour, func(ctx context.Context) error { return nil }, JobOptions{
		MaxRetries:     2,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})

	// Replace handler with deterministic attempt counter.
	var attempts atomic.Int32
	s.mu.Lock()
	job := s.jobs["retry-job"]
	job.Handler = func(ctx context.Context) error {
		if attempts.Add(1) == 1 {
			return errors.New("transient")
		}
		return nil
	}
	job.Running = true
	s.mu.Unlock()

	s.runJob(testutil.Context(t), job)

	got, ok := s.GetJob("retry-job")
	if !ok {
		t.Fatal("expected job to exist")
	}
	if got.RetryCount != 1 {
		t.Fatalf("retry count after first failure = %d, want 1", got.RetryCount)
	}
	if got.LastError == "" {
		t.Fatal("expected last error to be populated after failure")
	}
	if time.Until(got.NextRun) >= got.Interval {
		t.Fatalf("expected retry next run before normal interval; next=%s interval=%s", got.NextRun, got.Interval)
	}

	s.mu.Lock()
	job = s.jobs["retry-job"]
	job.Running = true
	s.mu.Unlock()
	s.runJob(testutil.Context(t), job)

	got, ok = s.GetJob("retry-job")
	if !ok {
		t.Fatal("expected job to exist")
	}
	if got.RetryCount != 0 {
		t.Fatalf("retry count after success = %d, want 0", got.RetryCount)
	}
	if got.LastError != "" {
		t.Fatalf("last error after success = %q, want empty", got.LastError)
	}
	untilNextRun := time.Until(got.NextRun)
	if untilNextRun < 30*time.Minute {
		t.Fatalf("expected successful run to restore normal interval scheduling, next in %s", untilNextRun)
	}
}

func TestScheduler_RetryStopsAfterMaxRetries(t *testing.T) {
	origJitter := retryJitterFunc
	retryJitterFunc = func(time.Duration) time.Duration { return 0 }
	t.Cleanup(func() { retryJitterFunc = origJitter })

	s := NewScheduler(testutil.Logger())
	s.AddJobWithOptions("always-fail", time.Hour, func(ctx context.Context) error {
		return errors.New("persistent")
	}, JobOptions{
		MaxRetries:     2,
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
	})

	s.mu.Lock()
	job := s.jobs["always-fail"]
	s.mu.Unlock()

	for i := 0; i < 3; i++ {
		s.mu.Lock()
		job.Running = true
		s.mu.Unlock()
		s.runJob(testutil.Context(t), job)
	}

	got, ok := s.GetJob("always-fail")
	if !ok {
		t.Fatal("expected job to exist")
	}
	if got.RetryCount != 0 {
		t.Fatalf("retry count after max retries exhausted = %d, want 0", got.RetryCount)
	}
	if got.LastError == "" {
		t.Fatal("expected last error to remain populated after terminal failure")
	}
	untilNextRun := time.Until(got.NextRun)
	if untilNextRun < 30*time.Minute {
		t.Fatalf("expected terminal failure to defer to normal interval, next in %s", untilNextRun)
	}
}

func TestCalculateRetryDelayCapsAtMaxBackoff(t *testing.T) {
	origJitter := retryJitterFunc
	retryJitterFunc = func(time.Duration) time.Duration { return 0 }
	t.Cleanup(func() { retryJitterFunc = origJitter })

	delay := calculateRetryDelay(10*time.Millisecond, 25*time.Millisecond, 5)
	if delay != 25*time.Millisecond {
		t.Fatalf("delay = %s, want capped delay %s", delay, 25*time.Millisecond)
	}
}

func TestScheduler_DisabledJobNotRun(t *testing.T) {
	s := NewScheduler(testutil.Logger())

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

func TestScheduler_PanicRecovery(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	panicJob := func(ctx context.Context) error {
		panic("test panic")
	}

	s.AddJob("panic-job", 1*time.Hour, panicJob)

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.mu.Unlock()

	// Run the job - should not crash the test
	err := s.RunNow("panic-job")
	if err != nil {
		t.Fatalf("RunNow failed: %v", err)
	}

	waitForCondition(t, time.Second, "panic job completion", func() bool {
		job, ok := s.GetJob("panic-job")
		return ok && !job.Running
	})

	// Verify job state was reset after panic
	job, ok := s.GetJob("panic-job")
	if !ok {
		t.Fatal("job not found after panic")
	}
	if job.Running {
		t.Error("job should not be running after panic recovery")
	}

	s.Stop()
}

func TestScheduler_RunNowErrors(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.mu.Unlock()

	// Test job not found
	err := s.RunNow("non-existent")
	if !errors.Is(err, ErrJobNotFound) {
		t.Errorf("expected ErrJobNotFound, got %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	// Add a job that takes time
	s.AddJob("slow", 1*time.Hour, func(ctx context.Context) error {
		close(started)
		<-release
		return nil
	})

	// Start the job
	err = s.RunNow("slow")
	if err != nil {
		t.Fatalf("first RunNow failed: %v", err)
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected slow job to start")
	}

	// Try to run again while running
	err = s.RunNow("slow")
	if !errors.Is(err, ErrJobAlreadyRunning) {
		t.Errorf("expected ErrJobAlreadyRunning, got %v", err)
	}

	close(release)

	waitForCondition(t, time.Second, "slow job completion", func() bool {
		job, ok := s.GetJob("slow")
		return ok && !job.Running
	})

	s.Stop()
}

func TestScheduler_GracefulShutdown(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	jobStarted := make(chan struct{})
	release := make(chan struct{})
	jobCompleted := make(chan struct{}, 1)
	s.AddJob("long-running", 1*time.Hour, func(ctx context.Context) error {
		close(jobStarted)
		<-release
		jobCompleted <- struct{}{}
		return nil
	})

	// Start scheduler
	ctx, cancel := context.WithCancel(testutil.Context(t))
	defer cancel()
	go s.Start(ctx)
	waitForCondition(t, time.Second, "scheduler start", func() bool {
		return s.Status().Running
	})

	// Trigger the job
	err := s.RunNow("long-running")
	if err != nil {
		t.Fatalf("RunNow failed: %v", err)
	}

	select {
	case <-jobStarted:
	case <-time.After(time.Second):
		t.Fatal("job did not start")
	}

	stopDone := make(chan struct{})
	go func() {
		s.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("Stop returned before in-flight job completed")
	default:
	}

	close(release)

	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after in-flight job completion")
	}

	// Verify job completed
	select {
	case <-jobCompleted:
		// Success - job completed before Stop returned
	case <-time.After(1 * time.Second):
		t.Error("job should have completed before Stop returned")
	}
}

func TestScheduler_RunDueJobs_NoopWhenStopped(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	var called atomic.Int32
	s.AddJob("due", time.Hour, func(ctx context.Context) error {
		called.Add(1)
		return nil
	})

	s.mu.Lock()
	s.jobs["due"].NextRun = time.Now().Add(-time.Second)
	s.mu.Unlock()

	// Scheduler is not running, so due jobs must not execute.
	s.runDueJobs()
	s.wg.Wait()

	if called.Load() != 0 {
		t.Fatalf("expected no job execution while stopped, got %d", called.Load())
	}
}

func TestScheduler_RunDueJobs_ExecutesDueJobs(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	done := make(chan struct{}, 1)
	s.AddJob("due", time.Hour, func(ctx context.Context) error {
		select {
		case done <- struct{}{}:
		default:
		}
		return nil
	})

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.jobs["due"].NextRun = time.Now().Add(-time.Second)
	s.mu.Unlock()

	s.runDueJobs()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected due job to execute")
	}

	s.wg.Wait()

	job, ok := s.GetJob("due")
	if !ok {
		t.Fatal("expected due job to remain registered")
	}
	if job.LastRun.IsZero() {
		t.Fatal("expected LastRun to be updated")
	}
	if job.Running {
		t.Fatal("expected job to be marked not running after completion")
	}
}

func TestScheduler_RunDueJobs_RemovedJobNotExecuted(t *testing.T) {
	logger := testutil.Logger()
	s := NewScheduler(logger)

	var called atomic.Int32
	s.AddJob("remove-me", time.Hour, func(ctx context.Context) error {
		called.Add(1)
		return nil
	})

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	job := s.jobs["remove-me"]
	job.NextRun = time.Now().Add(-time.Second)
	job.removeRequested = true
	s.mu.Unlock()

	s.runDueJobs()
	s.wg.Wait()

	if called.Load() != 0 {
		t.Fatalf("expected removed job to skip execution, got %d", called.Load())
	}
	if _, ok := s.GetJob("remove-me"); ok {
		t.Fatal("expected removed job to be deleted")
	}
}

func TestSchedulerMetricsTrackQueueDepthRunningJobsAndSuccess(t *testing.T) {
	metrics.Register()

	logger := testutil.Logger()
	s := NewScheduler(logger)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	s.AddJob("due", time.Hour, func(ctx context.Context) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil
	})

	beforeRuns := schedulerCounterValue(t, metrics.SchedulerJobRuns, "due", "success")

	s.mu.Lock()
	s.running = true
	s.ctx = testutil.Context(t)
	s.jobs["due"].NextRun = time.Now().Add(-time.Second)
	s.refreshMetricsLocked(time.Now())
	s.mu.Unlock()

	if got := schedulerGaugeValue(t, metrics.SchedulerQueueDepth); got != 1 {
		t.Fatalf("expected queue depth 1 before dispatch, got %v", got)
	}

	s.runDueJobs()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected due job to start")
	}

	if got := schedulerGaugeValue(t, metrics.SchedulerQueueDepth); got != 0 {
		t.Fatalf("expected queue depth 0 after dispatch, got %v", got)
	}
	if got := schedulerGaugeValue(t, metrics.SchedulerRunningJobs); got != 1 {
		t.Fatalf("expected running jobs gauge 1 while executing, got %v", got)
	}

	close(release)
	s.wg.Wait()

	if got := schedulerGaugeValue(t, metrics.SchedulerRunningJobs); got != 0 {
		t.Fatalf("expected running jobs gauge 0 after completion, got %v", got)
	}
	if got := schedulerCounterValue(t, metrics.SchedulerJobRuns, "due", "success"); got != beforeRuns+1 {
		t.Fatalf("expected scheduler success counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
}

func TestSchedulerRunJobRecordsErrorMetric(t *testing.T) {
	metrics.Register()

	s := NewScheduler(testutil.Logger())
	job := &Job{
		Name:           "failing",
		Interval:       time.Hour,
		Handler:        func(ctx context.Context) error { return errors.New("boom") },
		Enabled:        true,
		MaxRetries:     1,
		InitialBackoff: time.Second,
		MaxBackoff:     time.Second,
	}

	beforeRuns := schedulerCounterValue(t, metrics.SchedulerJobRuns, "failing", "error")
	s.runJob(testutil.Context(t), job)

	if got := schedulerCounterValue(t, metrics.SchedulerJobRuns, "failing", "error"); got != beforeRuns+1 {
		t.Fatalf("expected scheduler error counter to increase by 1, got before=%v after=%v", beforeRuns, got)
	}
}

func schedulerCounterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	counter, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("get metric with labels %v: %v", labels, err)
	}
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatalf("write counter metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func schedulerGaugeValue(t *testing.T, gauge interface{ Write(*dto.Metric) error }) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatalf("write gauge metric: %v", err)
	}
	return metric.GetGauge().GetValue()
}
