package jobs

import (
	"errors"
	"sync"
	"time"
)

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // Normal operation
	CircuitOpen                         // Failing, rejecting requests
	CircuitHalfOpen                     // Testing if service recovered
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreaker implements the circuit breaker pattern for handling failures.
type CircuitBreaker struct {
	mu sync.RWMutex

	// Configuration
	failureThreshold int           // Number of failures before opening
	successThreshold int           // Number of successes in half-open before closing
	timeout          time.Duration // Time to wait before transitioning from open to half-open

	// State
	state           CircuitState
	failures        int
	successes       int
	lastFailureTime time.Time
	lastStateChange time.Time
}

// CircuitBreakerConfig configures the circuit breaker.
type CircuitBreakerConfig struct {
	FailureThreshold int           // Default: 5
	SuccessThreshold int           // Default: 2
	Timeout          time.Duration // Default: 30s
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	return &CircuitBreaker{
		failureThreshold: config.FailureThreshold,
		successThreshold: config.SuccessThreshold,
		timeout:          config.Timeout,
		state:            CircuitClosed,
		lastStateChange:  time.Now(),
	}
}

// Allow checks if a request should be allowed through.
// Returns true if the request can proceed, false if circuit is open.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if timeout has elapsed
		if time.Since(cb.lastFailureTime) >= cb.timeout {
			cb.state = CircuitHalfOpen
			cb.lastStateChange = time.Now()
			cb.successes = 0
			return true
		}
		return false

	case CircuitHalfOpen:
		// Allow limited requests through to test
		return true

	default:
		return false
	}
}

// RecordSuccess records a successful operation.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.successThreshold {
			cb.state = CircuitClosed
			cb.lastStateChange = time.Now()
			cb.failures = 0
		}

	case CircuitClosed:
		cb.failures = 0 // Reset consecutive failures
	}
}

// RecordFailure records a failed operation.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failures++
		if cb.failures >= cb.failureThreshold {
			cb.state = CircuitOpen
			cb.lastStateChange = time.Now()
		}

	case CircuitHalfOpen:
		// Single failure in half-open goes back to open
		cb.state = CircuitOpen
		cb.lastStateChange = time.Now()
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns current circuit breaker statistics.
func (cb *CircuitBreaker) Stats() (state CircuitState, failures int, successes int) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state, cb.failures, cb.successes
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitClosed
	cb.failures = 0
	cb.successes = 0
	cb.lastStateChange = time.Now()
}
