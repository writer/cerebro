package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegistry_RegisterAndUnregister(t *testing.T) {
	r := NewRegistry()

	// Register a check
	r.Register("test", func(ctx context.Context) CheckResult {
		return CheckResult{Status: StatusHealthy}
	})

	// Verify it's registered
	results := r.RunAll(context.Background())
	if _, ok := results["test"]; !ok {
		t.Error("expected check 'test' to be registered")
	}

	// Unregister and verify
	r.Unregister("test")
	results = r.RunAll(context.Background())
	if _, ok := results["test"]; ok {
		t.Error("expected check 'test' to be unregistered")
	}
}

func TestRegistry_RunAll(t *testing.T) {
	r := NewRegistry()

	r.Register("healthy", func(ctx context.Context) CheckResult {
		return CheckResult{Name: "healthy", Status: StatusHealthy}
	})
	r.Register("unhealthy", func(ctx context.Context) CheckResult {
		return CheckResult{Name: "unhealthy", Status: StatusUnhealthy, Message: "failed"}
	})

	results := r.RunAll(context.Background())

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	if results["healthy"].Status != StatusHealthy {
		t.Errorf("expected healthy status, got %s", results["healthy"].Status)
	}
	if results["unhealthy"].Status != StatusUnhealthy {
		t.Errorf("expected unhealthy status, got %s", results["unhealthy"].Status)
	}
}

func TestRegistry_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     bool
	}{
		{"all healthy", []Status{StatusHealthy, StatusHealthy}, true},
		{"one unhealthy", []Status{StatusHealthy, StatusUnhealthy}, false},
		{"one degraded", []Status{StatusHealthy, StatusDegraded}, false},
		{"empty", []Status{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			for i, s := range tt.statuses {
				status := s
				r.Register(string(rune('a'+i)), func(ctx context.Context) CheckResult {
					return CheckResult{Status: status}
				})
			}
			if got := r.IsHealthy(context.Background()); got != tt.want {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegistry_OverallStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     Status
	}{
		{"all healthy", []Status{StatusHealthy, StatusHealthy}, StatusHealthy},
		{"one degraded", []Status{StatusHealthy, StatusDegraded}, StatusDegraded},
		{"one unhealthy", []Status{StatusHealthy, StatusUnhealthy}, StatusUnhealthy},
		{"unhealthy takes precedence", []Status{StatusDegraded, StatusUnhealthy}, StatusUnhealthy},
		{"empty", []Status{}, StatusHealthy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			for i, s := range tt.statuses {
				status := s
				r.Register(string(rune('a'+i)), func(ctx context.Context) CheckResult {
					return CheckResult{Status: status}
				})
			}
			if got := r.OverallStatus(context.Background()); got != tt.want {
				t.Errorf("OverallStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPingCheck(t *testing.T) {
	t.Run("successful ping", func(t *testing.T) {
		checker := PingCheck("db", func(ctx context.Context) error {
			return nil
		})
		result := checker(context.Background())
		if result.Status != StatusHealthy {
			t.Errorf("expected healthy, got %s", result.Status)
		}
		if result.Name != "db" {
			t.Errorf("expected name 'db', got %s", result.Name)
		}
	})

	t.Run("failed ping", func(t *testing.T) {
		checker := PingCheck("db", func(ctx context.Context) error {
			return errors.New("connection refused")
		})
		result := checker(context.Background())
		if result.Status != StatusUnhealthy {
			t.Errorf("expected unhealthy, got %s", result.Status)
		}
		if result.Message != "connection refused" {
			t.Errorf("expected error message, got %s", result.Message)
		}
	})
}

func TestThresholdCheck(t *testing.T) {
	tests := []struct {
		name  string
		value float64
		err   error
		want  Status
	}{
		{"healthy", 50, nil, StatusHealthy},
		{"degraded", 80, nil, StatusDegraded},
		{"unhealthy", 95, nil, StatusUnhealthy},
		{"error", 0, errors.New("failed"), StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := tt.value
			err := tt.err
			checker := ThresholdCheck("cpu", func() (float64, error) {
				return value, err
			}, 75, 90)
			result := checker(context.Background())
			if result.Status != tt.want {
				t.Errorf("expected %s, got %s", tt.want, result.Status)
			}
		})
	}
}

func TestTimeoutCheck(t *testing.T) {
	t.Run("completes before timeout", func(t *testing.T) {
		inner := func(ctx context.Context) CheckResult {
			return CheckResult{Status: StatusHealthy, Name: "fast"}
		}
		checker := TimeoutCheck(inner, 100*time.Millisecond)
		result := checker(context.Background())
		if result.Status != StatusHealthy {
			t.Errorf("expected healthy, got %s", result.Status)
		}
	})

	t.Run("times out", func(t *testing.T) {
		inner := func(ctx context.Context) CheckResult {
			select {
			case <-ctx.Done():
				return CheckResult{Status: StatusUnhealthy}
			case <-time.After(200 * time.Millisecond):
				return CheckResult{Status: StatusHealthy}
			}
		}
		checker := TimeoutCheck(inner, 50*time.Millisecond)
		result := checker(context.Background())
		if result.Status != StatusUnhealthy {
			t.Errorf("expected unhealthy due to timeout, got %s", result.Status)
		}
	})
}

func TestConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	done := make(chan bool)

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		go func(n int) {
			r.Register(string(rune('a'+n)), func(ctx context.Context) CheckResult {
				return CheckResult{Status: StatusHealthy}
			})
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			r.RunAll(context.Background())
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}
}
