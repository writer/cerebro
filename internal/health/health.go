// Package health provides health check functionality for monitoring application
// component status. It supports concurrent health check execution, status
// aggregation, and common check patterns (ping, threshold, timeout).
//
// The package provides:
//   - Registry for managing multiple health checks
//   - Concurrent execution of all registered checks
//   - Overall status calculation (unhealthy > degraded > healthy)
//   - Built-in check constructors for common patterns
//
// Status hierarchy:
//   - healthy: Component is operating normally
//   - degraded: Component is operational but experiencing issues
//   - unhealthy: Component is not operational
//   - unknown: Unable to determine component status
//
// Built-in check types:
//   - PingCheck: Calls a function and reports healthy/unhealthy
//   - ThresholdCheck: Monitors a value against warning/critical thresholds
//   - TimeoutCheck: Wraps a checker with a timeout
//
// Example usage:
//
//	registry := health.NewRegistry()
//	registry.Register("database", health.PingCheck("db", db.Ping))
//	registry.Register("cpu", health.ThresholdCheck("cpu", getCPU, 70, 90))
//	results := registry.RunAll(ctx)
//	if registry.OverallStatus(ctx) != health.StatusHealthy {
//	    log.Warn("service degraded", "results", results)
//	}
package health

import (
	"context"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// CheckResult holds the result of a health check.
type CheckResult struct {
	Name      string        `json:"name"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency_ms"`
	Timestamp time.Time     `json:"timestamp"`
}

// Checker is a function that performs a health check.
type Checker func(ctx context.Context) CheckResult

// Registry holds registered health checks.
type Registry struct {
	checks map[string]Checker
	mu     sync.RWMutex
}

// NewRegistry creates a new health check registry.
func NewRegistry() *Registry {
	return &Registry{
		checks: make(map[string]Checker),
	}
}

// Register adds a health check to the registry.
func (r *Registry) Register(name string, checker Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks[name] = checker
}

// Unregister removes a health check from the registry.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.checks, name)
}

// RunAll executes all registered health checks concurrently.
func (r *Registry) RunAll(ctx context.Context) map[string]CheckResult {
	r.mu.RLock()
	checks := make(map[string]Checker, len(r.checks))
	for name, checker := range r.checks {
		checks[name] = checker
	}
	r.mu.RUnlock()

	results := make(map[string]CheckResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, checker := range checks {
		wg.Add(1)
		go func(n string, c Checker) {
			defer wg.Done()
			result := c(ctx)
			mu.Lock()
			results[n] = result
			mu.Unlock()
		}(name, checker)
	}

	wg.Wait()
	return results
}

// IsHealthy returns true if all checks are healthy.
func (r *Registry) IsHealthy(ctx context.Context) bool {
	results := r.RunAll(ctx)
	for _, result := range results {
		if result.Status != StatusHealthy {
			return false
		}
	}
	return true
}

// OverallStatus returns the overall health status.
func (r *Registry) OverallStatus(ctx context.Context) Status {
	results := r.RunAll(ctx)
	hasUnhealthy := false
	hasDegraded := false

	for _, result := range results {
		switch result.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
		case StatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return StatusUnhealthy
	}
	if hasDegraded {
		return StatusDegraded
	}
	return StatusHealthy
}

// Common health check constructors

// PingCheck creates a health check that calls a ping function.
func PingCheck(name string, ping func(ctx context.Context) error) Checker {
	return func(ctx context.Context) CheckResult {
		start := time.Now()
		result := CheckResult{
			Name:      name,
			Timestamp: start,
		}

		err := ping(ctx)
		result.Latency = time.Since(start)

		if err != nil {
			result.Status = StatusUnhealthy
			result.Message = err.Error()
		} else {
			result.Status = StatusHealthy
		}

		return result
	}
}

// ThresholdCheck creates a health check based on a threshold value.
func ThresholdCheck(name string, getValue func() (float64, error), warnThreshold, critThreshold float64) Checker {
	return func(ctx context.Context) CheckResult {
		start := time.Now()
		result := CheckResult{
			Name:      name,
			Timestamp: start,
		}

		value, err := getValue()
		result.Latency = time.Since(start)

		if err != nil {
			result.Status = StatusUnknown
			result.Message = err.Error()
			return result
		}

		switch {
		case value >= critThreshold:
			result.Status = StatusUnhealthy
			result.Message = "critical threshold exceeded"
		case value >= warnThreshold:
			result.Status = StatusDegraded
			result.Message = "warning threshold exceeded"
		default:
			result.Status = StatusHealthy
		}

		return result
	}
}

// TimeoutCheck wraps a checker with a timeout.
func TimeoutCheck(checker Checker, timeout time.Duration) Checker {
	return func(ctx context.Context) CheckResult {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resultCh := make(chan CheckResult, 1)
		go func() {
			resultCh <- checker(ctx)
		}()

		select {
		case result := <-resultCh:
			return result
		case <-ctx.Done():
			return CheckResult{
				Status:    StatusUnhealthy,
				Message:   "health check timed out",
				Timestamp: time.Now(),
			}
		}
	}
}
