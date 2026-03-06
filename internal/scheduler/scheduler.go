package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

var (
	// ErrJobNotFound is returned when a job does not exist
	ErrJobNotFound = errors.New("job not found")
	// ErrJobAlreadyRunning is returned when attempting to run a job that is already executing
	ErrJobAlreadyRunning = errors.New("job already running")
	// ErrSchedulerStopped is returned when the scheduler is not running
	ErrSchedulerStopped = errors.New("scheduler not running")
)

// Job represents a scheduled task
type Job struct {
	Name     string
	Interval time.Duration
	Handler  func(ctx context.Context) error
	LastRun  time.Time
	NextRun  time.Time
	Running  bool
	Enabled  bool

	removeRequested bool
}

// Scheduler manages periodic jobs
type Scheduler struct {
	jobs    map[string]*Job
	logger  *slog.Logger
	mu      sync.RWMutex
	wg      sync.WaitGroup // Tracks running jobs for graceful shutdown
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
}

// NewScheduler creates a new job scheduler
func NewScheduler(logger *slog.Logger) *Scheduler {
	return &Scheduler{
		jobs:   make(map[string]*Job),
		logger: logger,
	}
}

// AddJob registers a new periodic job
func (s *Scheduler) AddJob(name string, interval time.Duration, handler func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobs[name] = &Job{
		Name:     name,
		Interval: interval,
		Handler:  handler,
		NextRun:  time.Now().Add(interval),
		Enabled:  true,
	}
}

// RemoveJob removes a scheduled job
func (s *Scheduler) RemoveJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[name]
	if !ok {
		return
	}
	job.Enabled = false
	job.removeRequested = true
	if !job.Running {
		delete(s.jobs, name)
	}
}

// EnableJob enables a job
func (s *Scheduler) EnableJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[name]; ok {
		job.Enabled = true
		job.NextRun = time.Now().Add(job.Interval)
	}
}

// DisableJob disables a job
func (s *Scheduler) DisableJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job, ok := s.jobs[name]; ok {
		job.Enabled = false
	}
}

// Start begins the scheduler loop
func (s *Scheduler) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.ctx, s.cancel = context.WithCancel(ctx) // #nosec G118 -- cancel is stored and invoked by Stop()
	s.running = true
	jobCount := len(s.jobs)
	s.mu.Unlock()

	s.logger.Info("scheduler started", "jobs", jobCount)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.runDueJobs()
		}
	}
}

// Stop halts the scheduler and waits for running jobs to complete
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.running = false
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(30 * time.Second):
		s.logger.Warn("scheduler shutdown timed out", "timeout", "30s")
		return
	}
}

func (s *Scheduler) runDueJobs() {
	s.mu.Lock()
	if !s.running || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}

	now := time.Now()
	var dueJobs []*Job
	for _, job := range s.jobs {
		if job.Enabled && !job.Running && now.After(job.NextRun) {
			dueJobs = append(dueJobs, job)
			job.Running = true
		}
	}
	s.mu.Unlock()

	for _, job := range dueJobs {
		s.mu.RLock()
		jobCtx := s.ctx
		ctxActive := s.running && jobCtx != nil && jobCtx.Err() == nil
		removed := job.removeRequested
		s.mu.RUnlock()
		if !ctxActive || removed {
			s.mu.Lock()
			job.Running = false
			if job.removeRequested {
				delete(s.jobs, job.Name)
			}
			s.mu.Unlock()
			continue
		}
		s.wg.Add(1)
		go func(j *Job, ctx context.Context) {
			defer s.wg.Done()
			s.runJob(ctx, j)
		}(job, jobCtx)
	}
}

func (s *Scheduler) runJob(ctx context.Context, job *Job) {
	start := time.Now()
	s.logger.Info("job started", "job", job.Name)

	// Recover from panics in job handlers to prevent scheduler crash
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			job.LastRun = start
			job.Running = false
			if job.removeRequested {
				delete(s.jobs, job.Name)
				s.mu.Unlock()
			} else {
				job.NextRun = time.Now().Add(job.Interval)
				s.mu.Unlock()
			}
			s.logger.Error("job panicked", "job", job.Name, "panic", fmt.Sprintf("%v", r), "stack", string(debug.Stack()))
		}
	}()

	err := job.Handler(ctx)

	s.mu.Lock()
	job.LastRun = start
	job.Running = false
	if job.removeRequested {
		delete(s.jobs, job.Name)
		s.mu.Unlock()
	} else {
		job.NextRun = time.Now().Add(job.Interval)
		s.mu.Unlock()
	}

	if err != nil {
		s.logger.Error("job failed", "job", job.Name, "error", err, "duration", time.Since(start))
	} else {
		s.logger.Info("job completed", "job", job.Name, "duration", time.Since(start))
	}
}

// RunNow triggers a job immediately
func (s *Scheduler) RunNow(name string) error {
	s.mu.Lock()
	if !s.running || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrSchedulerStopped
	}
	job, ok := s.jobs[name]
	if !ok {
		s.mu.Unlock()
		return ErrJobNotFound
	}
	if job.Running {
		s.mu.Unlock()
		return ErrJobAlreadyRunning
	}
	job.Running = true
	ctx := s.ctx // Capture context under lock
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runJob(ctx, job)
	}()
	return nil
}

// ListJobs returns copies of all registered jobs to prevent external modification
func (s *Scheduler) ListJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, *j) // Return copy
	}
	return jobs
}

// GetJob returns a copy of a specific job to prevent external modification
func (s *Scheduler) GetJob(name string) (Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[name]
	if !ok {
		return Job{}, false
	}
	return *j, true // Return copy
}

// Status returns scheduler status
type Status struct {
	Running bool        `json:"running"`
	Jobs    []JobStatus `json:"jobs"`
}

type JobStatus struct {
	Name     string     `json:"name"`
	Interval string     `json:"interval"`
	LastRun  *time.Time `json:"last_run,omitempty"`
	NextRun  time.Time  `json:"next_run"`
	Running  bool       `json:"running"`
	Enabled  bool       `json:"enabled"`
}

func (s *Scheduler) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := Status{
		Running: s.running,
		Jobs:    make([]JobStatus, 0, len(s.jobs)),
	}

	for _, j := range s.jobs {
		js := JobStatus{
			Name:     j.Name,
			Interval: j.Interval.String(),
			NextRun:  j.NextRun,
			Running:  j.Running,
			Enabled:  j.Enabled,
		}
		if !j.LastRun.IsZero() {
			js.LastRun = &j.LastRun
		}
		status.Jobs = append(status.Jobs, js)
	}

	return status
}
