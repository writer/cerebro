package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"
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
}

// Scheduler manages periodic jobs
type Scheduler struct {
	jobs    map[string]*Job
	logger  *slog.Logger
	mu      sync.RWMutex
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
	delete(s.jobs, name)
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
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	s.mu.Unlock()

	s.logger.Info("scheduler started", "jobs", len(s.jobs))

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

// Stop halts the scheduler
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.running = false
}

func (s *Scheduler) runDueJobs() {
	s.mu.Lock()
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
		go s.runJob(job)
	}
}

func (s *Scheduler) runJob(job *Job) {
	start := time.Now()
	s.logger.Info("job started", "job", job.Name)

	err := job.Handler(s.ctx)

	s.mu.Lock()
	job.LastRun = start
	job.NextRun = time.Now().Add(job.Interval)
	job.Running = false
	s.mu.Unlock()

	if err != nil {
		s.logger.Error("job failed", "job", job.Name, "error", err, "duration", time.Since(start))
	} else {
		s.logger.Info("job completed", "job", job.Name, "duration", time.Since(start))
	}
}

// RunNow triggers a job immediately
func (s *Scheduler) RunNow(name string) error {
	s.mu.Lock()
	job, ok := s.jobs[name]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if job.Running {
		s.mu.Unlock()
		return nil
	}
	job.Running = true
	s.mu.Unlock()

	go s.runJob(job)
	return nil
}

// ListJobs returns all registered jobs
func (s *Scheduler) ListJobs() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}

// GetJob returns a specific job
func (s *Scheduler) GetJob(name string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[name]
	return j, ok
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
