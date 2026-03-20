package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/scheduler"
)

type stubSchedulerOperationsService struct {
	statusFunc     func() (scheduler.Status, error)
	listJobsFunc   func() ([]scheduler.Job, error)
	runJobFunc     func(context.Context, string, string) error
	enableJobFunc  func(string) error
	disableJobFunc func(string) error
}

func (s stubSchedulerOperationsService) Status() (scheduler.Status, error) {
	if s.statusFunc != nil {
		return s.statusFunc()
	}
	return scheduler.Status{}, nil
}

func (s stubSchedulerOperationsService) ListJobs() ([]scheduler.Job, error) {
	if s.listJobsFunc != nil {
		return s.listJobsFunc()
	}
	return nil, nil
}

func (s stubSchedulerOperationsService) RunJob(ctx context.Context, name, triggeredBy string) error {
	if s.runJobFunc != nil {
		return s.runJobFunc(ctx, name, triggeredBy)
	}
	return nil
}

func (s stubSchedulerOperationsService) EnableJob(name string) error {
	if s.enableJobFunc != nil {
		return s.enableJobFunc(name)
	}
	return nil
}

func (s stubSchedulerOperationsService) DisableJob(name string) error {
	if s.disableJobFunc != nil {
		return s.disableJobFunc(name)
	}
	return nil
}

func TestSchedulerReadHandlersUseServiceInterface(t *testing.T) {
	var (
		statusCalled bool
		listCalled   bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		schedulerOperations: stubSchedulerOperationsService{
			statusFunc: func() (scheduler.Status, error) {
				statusCalled = true
				return scheduler.Status{Running: true}, nil
			},
			listJobsFunc: func() ([]scheduler.Job, error) {
				listCalled = true
				return []scheduler.Job{{
					Name:     "job-a",
					Interval: time.Hour,
					Enabled:  true,
					NextRun:  time.Date(2026, 3, 19, 18, 0, 0, 0, time.UTC),
				}}, nil
			},
		},
	})
	s.app.Scheduler = nil
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/scheduler/status", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed scheduler status, got %d: %s", w.Code, w.Body.String())
	}
	if !statusCalled {
		t.Fatal("expected scheduler status handler to use scheduler operations service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/scheduler/jobs", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed scheduler jobs, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected scheduler jobs handler to use scheduler operations service")
	}
}

func TestSchedulerMutationHandlersUseServiceInterface(t *testing.T) {
	var (
		runCalled     bool
		enableCalled  bool
		disableCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		schedulerOperations: stubSchedulerOperationsService{
			runJobFunc: func(_ context.Context, name, triggeredBy string) error {
				runCalled = true
				if name != "job-a" {
					t.Fatalf("expected job-a, got %q", name)
				}
				if triggeredBy != "admin-1" {
					t.Fatalf("expected admin-1 trigger, got %q", triggeredBy)
				}
				return nil
			},
			enableJobFunc: func(name string) error {
				enableCalled = true
				if name != "job-a" {
					t.Fatalf("expected job-a, got %q", name)
				}
				return nil
			},
			disableJobFunc: func(name string) error {
				disableCalled = true
				if name != "job-a" {
					t.Fatalf("expected job-a, got %q", name)
				}
				return nil
			},
		},
	})
	s.app.Scheduler = nil
	t.Cleanup(func() { s.Close() })

	if w := doAsUser(t, s, "admin-1", http.MethodPost, "/api/v1/scheduler/jobs/job-a/run", nil); w.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for service-backed scheduler run, got %d: %s", w.Code, w.Body.String())
	}
	if !runCalled {
		t.Fatal("expected scheduler run handler to use scheduler operations service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/job-a/enable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed scheduler enable, got %d: %s", w.Code, w.Body.String())
	}
	if !enableCalled {
		t.Fatal("expected scheduler enable handler to use scheduler operations service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/scheduler/jobs/job-a/disable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed scheduler disable, got %d: %s", w.Code, w.Body.String())
	}
	if !disableCalled {
		t.Fatal("expected scheduler disable handler to use scheduler operations service")
	}
}
