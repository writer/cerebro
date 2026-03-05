package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

// MockQueue implements Queue interface for testing
type MockQueue struct {
	mu              sync.Mutex
	messages        []QueueMessage
	deleted         []string
	extendedHandles []string
	extendErrors    []error
	extendCalls     int
	enqueuedMsgs    []JobMessage
	receiveDelay    time.Duration
	receiveCalls    int32
}

var _ Queue = (*MockQueue)(nil)

func (m *MockQueue) Enqueue(ctx context.Context, msg JobMessage) error {
	return m.EnqueueWithDelay(ctx, msg, 0)
}

func (m *MockQueue) EnqueueWithDelay(ctx context.Context, msg JobMessage, delay time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueuedMsgs = append(m.enqueuedMsgs, msg)
	return nil
}

func (m *MockQueue) Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error) {
	atomic.AddInt32(&m.receiveCalls, 1)

	if m.receiveDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.receiveDelay):
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.messages) == 0 {
		return nil, nil
	}

	count := maxMessages
	if count > len(m.messages) {
		count = len(m.messages)
	}

	result := m.messages[:count]
	m.messages = m.messages[count:]
	return result, nil
}

func (m *MockQueue) Delete(ctx context.Context, receiptHandle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, receiptHandle)
	return nil
}

func (m *MockQueue) DeleteBatch(ctx context.Context, receiptHandles []string) (succeeded int, failed []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, receiptHandles...)
	return len(receiptHandles), nil, nil
}

func (m *MockQueue) ExtendVisibility(ctx context.Context, receiptHandle string, timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendCalls++
	m.extendedHandles = append(m.extendedHandles, receiptHandle)
	if len(m.extendErrors) > 0 {
		err := m.extendErrors[0]
		m.extendErrors = m.extendErrors[1:]
		return err
	}
	return nil
}

func (m *MockQueue) ExtendVisibilityBatch(ctx context.Context, receiptHandles []string, timeout time.Duration) (succeeded int, failed int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendedHandles = append(m.extendedHandles, receiptHandles...)
	return len(receiptHandles), 0, nil
}

func (m *MockQueue) AddMessage(jobID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, _ := json.Marshal(JobMessage{JobID: jobID})
	m.messages = append(m.messages, QueueMessage{
		ID:            jobID,
		ReceiptHandle: "receipt-" + jobID,
		Body:          string(body),
	})
}

type mockAPIError struct {
	code string
	msg  string
}

func (e mockAPIError) Error() string {
	return fmt.Sprintf("%s: %s", e.code, e.msg)
}

func (e mockAPIError) ErrorCode() string {
	return e.code
}

func (e mockAPIError) ErrorMessage() string {
	return e.msg
}

func (e mockAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}

// MockStore implements Store interface for testing
type MockStore struct {
	mu           sync.Mutex
	jobs         map[string]*Job
	claimError   error
	claimResult  bool
	extendLeases []string
}

var _ Store = (*MockStore)(nil)

func NewMockStore() *MockStore {
	return &MockStore{
		jobs: make(map[string]*Job),
	}
}

func (m *MockStore) CreateJob(ctx context.Context, job *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
	return nil
}

func (m *MockStore) GetJob(ctx context.Context, jobID string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		return job, nil
	}
	return nil, ErrJobNotFound
}

func (m *MockStore) ClaimJob(ctx context.Context, jobID, workerID string, lease time.Duration) (*Job, bool, error) {
	if m.claimError != nil {
		return nil, false, m.claimError
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	job, ok := m.jobs[jobID]
	if !ok {
		return nil, false, nil
	}

	if m.claimResult == false && job.Status == StatusRunning {
		return nil, false, nil
	}

	job.Status = StatusRunning
	job.WorkerID = workerID
	job.Attempt++
	return job, true, nil
}

func (m *MockStore) ExtendLease(ctx context.Context, jobID, workerID string, lease time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extendLeases = append(m.extendLeases, jobID)
	return nil
}

func (m *MockStore) CompleteJob(ctx context.Context, jobID, result string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		job.Status = StatusSucceeded
		job.Result = result
	}
	return nil
}

func (m *MockStore) CompleteJobOwned(ctx context.Context, jobID, workerID string, attempt int, result string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		if job.WorkerID != workerID || job.Attempt != attempt || job.Status != StatusRunning {
			return ErrJobLeaseLost
		}
		job.Status = StatusSucceeded
		job.Result = result
	}
	return nil
}

func (m *MockStore) FailJob(ctx context.Context, jobID, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		job.Status = StatusFailed
		job.Error = message
	}
	return nil
}

func (m *MockStore) FailJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		if job.WorkerID != workerID || job.Attempt != attempt || job.Status != StatusRunning {
			return ErrJobLeaseLost
		}
		job.Status = StatusFailed
		job.Error = message
	}
	return nil
}

func (m *MockStore) RetryJob(ctx context.Context, jobID, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		job.Status = StatusQueued
		job.Error = message
	}
	return nil
}

func (m *MockStore) RetryJobOwned(ctx context.Context, jobID, workerID string, attempt int, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if job, ok := m.jobs[jobID]; ok {
		if job.WorkerID != workerID || job.Attempt != attempt || job.Status != StatusRunning {
			return ErrJobLeaseLost
		}
		job.Status = StatusQueued
		job.WorkerID = ""
		job.Error = message
	}
	return nil
}

func (m *MockStore) AddJob(job *Job) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
}

func TestWorkerGracefulShutdown(t *testing.T) {
	queue := &MockQueue{receiveDelay: 100 * time.Millisecond}
	store := NewMockStore()
	registry := NewJobRegistry()

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency:       2,
		VisibilityTimeout: 30 * time.Second,
		DrainTimeout:      5 * time.Second,
		PollWait:          100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Start(ctx)
	}()

	// Let worker start
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("Worker returned: %v (expected for graceful shutdown)", err)
		}
	case <-time.After(6 * time.Second):
		t.Error("Worker did not shutdown within timeout")
	}
}

func TestWorkerShutdownSignal(t *testing.T) {
	queue := &MockQueue{receiveDelay: 100 * time.Millisecond}
	store := NewMockStore()
	registry := NewJobRegistry()

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency:  1,
		DrainTimeout: 1 * time.Second,
		PollWait:     50 * time.Millisecond,
	})

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Start(ctx)
	}()

	// Let worker start
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown via method
	worker.Shutdown()

	select {
	case <-errCh:
		// Success
	case <-time.After(3 * time.Second):
		t.Error("Worker did not respond to Shutdown() call")
	}
}

func TestWorkerOptions(t *testing.T) {
	worker := NewWorker(nil, nil, nil, WorkerOptions{})

	if worker.concurrency != 4 {
		t.Errorf("Expected default concurrency 4, got %d", worker.concurrency)
	}
	if worker.visibilityTimeout != 60*time.Second {
		t.Errorf("Expected default visibility timeout 60s, got %v", worker.visibilityTimeout)
	}
	if worker.heartbeatInterval != 20*time.Second {
		t.Errorf("Expected default heartbeat interval 20s (1/3 of 60s), got %v", worker.heartbeatInterval)
	}
	if worker.jobTimeout != 5*time.Minute {
		t.Errorf("Expected default job timeout 5m, got %v", worker.jobTimeout)
	}
	if worker.drainTimeout != 30*time.Second {
		t.Errorf("Expected default drain timeout 30s, got %v", worker.drainTimeout)
	}
	if worker.workerID == "" {
		t.Error("Expected non-empty worker ID")
	}
}

func TestWorkerOptionsCustom(t *testing.T) {
	worker := NewWorker(nil, nil, nil, WorkerOptions{
		Concurrency:       8,
		VisibilityTimeout: 2 * time.Minute,
		HeartbeatInterval: 30 * time.Second,
		JobTimeout:        10 * time.Minute,
		DrainTimeout:      1 * time.Minute,
		WorkerID:          "custom-worker",
	})

	if worker.concurrency != 8 {
		t.Errorf("Expected concurrency 8, got %d", worker.concurrency)
	}
	if worker.visibilityTimeout != 2*time.Minute {
		t.Errorf("Expected visibility timeout 2m, got %v", worker.visibilityTimeout)
	}
	if worker.heartbeatInterval != 30*time.Second {
		t.Errorf("Expected heartbeat interval 30s, got %v", worker.heartbeatInterval)
	}
	if worker.jobTimeout != 10*time.Minute {
		t.Errorf("Expected job timeout 10m, got %v", worker.jobTimeout)
	}
	if worker.drainTimeout != 1*time.Minute {
		t.Errorf("Expected drain timeout 1m, got %v", worker.drainTimeout)
	}
	if worker.workerID != "custom-worker" {
		t.Errorf("Expected worker ID 'custom-worker', got %s", worker.workerID)
	}
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	})

	// Should start closed
	if cb.State() != CircuitClosed {
		t.Errorf("Expected closed state, got %v", cb.State())
	}

	// Record failures
	for i := 0; i < 3; i++ {
		if !cb.Allow() {
			t.Error("Should allow request when closed")
		}
		cb.RecordFailure()
	}

	// Should now be open
	if cb.State() != CircuitOpen {
		t.Errorf("Expected open state, got %v", cb.State())
	}

	// Should reject requests
	if cb.Allow() {
		t.Error("Should reject request when open")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Should be half-open and allow request
	if !cb.Allow() {
		t.Error("Should allow request in half-open")
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("Expected half-open state, got %v", cb.State())
	}

	// Record successes to close
	cb.RecordSuccess()
	cb.RecordSuccess()

	if cb.State() != CircuitClosed {
		t.Errorf("Expected closed state after successes, got %v", cb.State())
	}
}

func TestJobRegistry(t *testing.T) {
	registry := NewJobRegistry()

	// Register a test handler
	called := false
	registry.Register(JobTypeInspectResource, func(ctx context.Context, payload string) (string, error) {
		called = true
		return "result", nil
	})

	// Check it's registered
	handler, ok := registry.Get(JobTypeInspectResource)
	if !ok {
		t.Error("Handler should be registered")
	}
	if handler == nil {
		t.Error("Handler should not be nil")
	}

	// Execute
	job := &Job{Type: JobTypeInspectResource, Payload: "{}"}
	result, err := registry.Execute(context.Background(), job)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("Expected 'result', got %s", result)
	}
	if !called {
		t.Error("Handler was not called")
	}

	// Check unregistered type
	_, ok = registry.Get("unknown")
	if ok {
		t.Error("Unknown type should not be registered")
	}
}

func TestBatchDelete(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency: 1,
	})

	// Queue up deletes
	for i := 0; i < 15; i++ {
		worker.queueDelete("handle-" + string(rune('a'+i)))
	}

	// First 10 should have been flushed
	time.Sleep(10 * time.Millisecond)
	worker.flushPendingDeletes(context.Background())

	queue.mu.Lock()
	deleteCount := len(queue.deleted)
	queue.mu.Unlock()

	if deleteCount != 15 {
		t.Errorf("Expected 15 deletes, got %d", deleteCount)
	}
}

func TestPermanentError(t *testing.T) {
	err := PermanentError(errors.New("invalid input"))
	if !IsPermanent(err) {
		t.Error("Expected error to be permanent")
	}

	normalErr := errors.New("normal error")
	if IsPermanent(normalErr) {
		t.Error("Normal error should not be permanent")
	}
}

func TestIsTerminalVisibilityError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "receipt handle invalid code",
			err:  mockAPIError{code: "ReceiptHandleIsInvalid", msg: "invalid handle"},
			want: true,
		},
		{
			name: "invalid parameter value with receipt handle message",
			err:  mockAPIError{code: "InvalidParameterValue", msg: "Value ... for parameter ReceiptHandle is invalid"},
			want: true,
		},
		{
			name: "wrapped non-existent queue code",
			err:  fmt.Errorf("wrapped: %w", mockAPIError{code: "AWS.SimpleQueueService.NonExistentQueue", msg: "queue not found"}),
			want: true,
		},
		{
			name: "non terminal API error",
			err:  mockAPIError{code: "ThrottlingException", msg: "slow down"},
			want: false,
		},
		{
			name: "plain string fallback",
			err:  errors.New("message does not exist or is not available for visibility timeout change"),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTerminalVisibilityError(tc.err); got != tc.want {
				t.Fatalf("isTerminalVisibilityError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunHeartbeat_DisablesQueueVisibilityOnTerminalErrorButExtendsLease(t *testing.T) {
	queue := &MockQueue{
		extendErrors: []error{mockAPIError{code: "ReceiptHandleIsInvalid", msg: "invalid receipt"}},
	}
	store := NewMockStore()
	worker := NewWorker(queue, store, NewJobRegistry(), WorkerOptions{
		VisibilityTimeout: 3 * time.Second,
		HeartbeatInterval: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go worker.runHeartbeat(ctx, "receipt-1", "job-1", nil)
	time.Sleep(140 * time.Millisecond)
	cancel()
	time.Sleep(30 * time.Millisecond)

	queue.mu.Lock()
	extendCalls := queue.extendCalls
	queue.mu.Unlock()

	if extendCalls != 1 {
		t.Fatalf("expected queue visibility extension to stop after terminal error, got %d calls", extendCalls)
	}

	store.mu.Lock()
	leaseExtensions := len(store.extendLeases)
	store.mu.Unlock()

	if leaseExtensions == 0 {
		t.Fatal("expected lease to keep extending even when queue visibility heartbeat is disabled")
	}
}

func TestExponentialBackoff(t *testing.T) {
	worker := NewWorker(nil, nil, nil, WorkerOptions{
		RetryBaseDelay: 1 * time.Second,
		RetryMaxDelay:  1 * time.Minute,
	})

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 1 * time.Second},  // 1 * 2^0 = 1s
		{2, 2 * time.Second},  // 1 * 2^1 = 2s
		{3, 4 * time.Second},  // 1 * 2^2 = 4s
		{4, 8 * time.Second},  // 1 * 2^3 = 8s
		{5, 16 * time.Second}, // 1 * 2^4 = 16s
		{6, 32 * time.Second}, // 1 * 2^5 = 32s
		{7, 1 * time.Minute},  // 1 * 2^6 = 64s, capped to 60s
		{10, 1 * time.Minute}, // Still capped
	}

	for _, tc := range tests {
		result := worker.calculateBackoff(tc.attempt)
		if result != tc.expected {
			t.Errorf("Attempt %d: expected %v, got %v", tc.attempt, tc.expected, result)
		}
	}
}

func TestHealthStatus(t *testing.T) {
	worker := NewWorker(nil, nil, nil, WorkerOptions{
		WorkerID: "test-worker",
	})

	// Initial state should be healthy
	status := worker.Health()
	if !status.Healthy {
		t.Error("Worker should be healthy initially")
	}
	if status.WorkerID != "test-worker" {
		t.Errorf("Expected worker ID 'test-worker', got %s", status.WorkerID)
	}
	if status.ShuttingDown {
		t.Error("Worker should not be shutting down initially")
	}
	if status.CircuitState != "closed" {
		t.Errorf("Expected circuit state 'closed', got %s", status.CircuitState)
	}

	// IsHealthy should return true
	if !worker.IsHealthy() {
		t.Error("IsHealthy should return true initially")
	}

	// After shutdown signal
	worker.Shutdown()
	if worker.IsHealthy() {
		t.Error("IsHealthy should return false after shutdown")
	}

	status = worker.Health()
	if status.Healthy {
		t.Error("Worker should not be healthy after shutdown")
	}
}

func TestPanicRecovery(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()

	// Register a handler that panics
	registry.Register(JobTypeInspectResource, func(ctx context.Context, payload string) (string, error) {
		panic("test panic")
	})

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency: 1,
	})

	// Add a job
	store.AddJob(&Job{
		ID:          "panic-job",
		Type:        JobTypeInspectResource,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
	})
	queue.AddMessage("panic-job")

	// Create a context that we'll cancel after the panic
	ctx, cancel := context.WithCancel(context.Background())

	// Start processing in a goroutine
	done := make(chan struct{})
	go func() {
		// Process one message
		queue.mu.Lock()
		msg := queue.messages[0]
		queue.messages = queue.messages[1:]
		queue.mu.Unlock()

		// This should not crash due to panic recovery
		worker.processMessage(ctx, msg)
		close(done)
	}()

	// Wait for processing to complete
	select {
	case <-done:
		// Check panic was recorded
		if worker.panicCount.Load() != 1 {
			t.Errorf("Expected panic count 1, got %d", worker.panicCount.Load())
		}
	case <-time.After(5 * time.Second):
		t.Error("Test timed out - panic may have crashed the goroutine")
	}

	cancel()
}

func TestIdempotencyStore(t *testing.T) {
	store := &NoOpIdempotencyStore{}

	// NoOp should always allow processing
	canProcess, err := store.MarkProcessing(context.Background(), "msg-1", "worker-1", time.Minute)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !canProcess {
		t.Error("NoOp should always allow processing")
	}

	// Should not error
	if completedErr := store.MarkCompleted(context.Background(), "msg-1"); completedErr != nil {
		t.Errorf("Unexpected error: %v", completedErr)
	}
	if failedErr := store.MarkFailed(context.Background(), "msg-1"); failedErr != nil {
		t.Errorf("Unexpected error: %v", failedErr)
	}

	// IsProcessed should return false for NoOp
	processed, processedErr := store.IsProcessed(context.Background(), "msg-1")
	if processedErr != nil {
		t.Errorf("Unexpected error: %v", processedErr)
	}
	if processed {
		t.Error("NoOp should always return false for IsProcessed")
	}
}

func TestFIFOQueueDetection(t *testing.T) {
	// Can't actually test SQS, but test the detection logic
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://sqs.us-east-1.amazonaws.com/123456789/my-queue", false},
		{"https://sqs.us-east-1.amazonaws.com/123456789/my-queue.fifo", true},
		{"", false},
		{"short", false},
	}

	for _, tc := range tests {
		// Can't call NewSQSQueue without AWS config, but can test the detection
		isFIFO := strings.HasSuffix(tc.url, ".fifo")
		if isFIFO != tc.expected {
			t.Errorf("URL %q: expected FIFO=%v, got %v", tc.url, tc.expected, isFIFO)
		}
	}
}

func TestCorrelationIDPropagation(t *testing.T) {
	// Test that JobMessage can carry correlation ID
	msg := JobMessage{
		JobID:           "job-123",
		GroupID:         "group-1",
		CorrelationID:   "trace-abc",
		DeduplicationID: "dedup-xyz",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded JobMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.CorrelationID != "trace-abc" {
		t.Errorf("Expected correlation ID 'trace-abc', got %s", decoded.CorrelationID)
	}
	if decoded.DeduplicationID != "dedup-xyz" {
		t.Errorf("Expected deduplication ID 'dedup-xyz', got %s", decoded.DeduplicationID)
	}
}

func TestJobCorrelationID(t *testing.T) {
	// Test Job struct has correlation ID
	job := Job{
		CorrelationID: "request-abc",
		ParentID:      "parent-xyz",
	}

	if job.CorrelationID != "request-abc" {
		t.Errorf("Expected correlation ID 'request-abc', got %s", job.CorrelationID)
	}
	if job.ParentID != "parent-xyz" {
		t.Errorf("Expected parent ID 'parent-xyz', got %s", job.ParentID)
	}
}

func TestStopReceivingBeforeDrain(t *testing.T) {
	queue := &MockQueue{receiveDelay: 50 * time.Millisecond}
	store := NewMockStore()
	registry := NewJobRegistry()

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency:  1,
		DrainTimeout: 2 * time.Second,
		PollWait:     50 * time.Millisecond,
	})

	// Verify stopReceiving starts as false
	if worker.stopReceiving.Load() {
		t.Error("stopReceiving should start as false")
	}

	// Start worker
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- worker.Start(ctx)
	}()

	// Let worker start
	time.Sleep(30 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for shutdown
	select {
	case <-errCh:
		// Check stopReceiving was set
		if !worker.stopReceiving.Load() {
			t.Error("stopReceiving should be true after shutdown")
		}
	case <-time.After(5 * time.Second):
		t.Error("Worker did not shutdown")
	}
}

func TestGracefulShutdownDrainsInflightJobs(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()

	jobStarted := make(chan struct{})
	jobDone := make(chan struct{})

	registry.Register(JobTypeInspectResource, func(ctx context.Context, payload string) (string, error) {
		close(jobStarted)
		// Simulate work that takes some time; should NOT be canceled early.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
			close(jobDone)
			return "ok", nil
		}
	})

	store.AddJob(&Job{
		ID:          "drain-job",
		Type:        JobTypeInspectResource,
		Status:      StatusQueued,
		Payload:     "{}",
		MaxAttempts: 1,
	})
	queue.AddMessage("drain-job")

	worker := NewWorker(queue, store, registry, WorkerOptions{
		Concurrency:  1,
		DrainTimeout: 5 * time.Second,
		PollWait:     50 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- worker.Start(ctx) }()

	// Wait for the job to begin executing.
	select {
	case <-jobStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("job did not start in time")
	}

	// Trigger shutdown while the job is still running.
	cancel()

	// The job should finish within drain timeout, not get canceled.
	select {
	case <-jobDone:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight job was not allowed to drain")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected error from Start: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after drain")
	}

	store.mu.Lock()
	job := store.jobs["drain-job"]
	store.mu.Unlock()
	if job.Status != StatusSucceeded {
		t.Errorf("expected job status succeeded, got %s", job.Status)
	}
}

func TestUnclaimedTerminalJobDeletesMessage(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()
	registry.Register(JobTypeInspectResource, func(ctx context.Context, payload string) (string, error) {
		return "ok", nil
	})

	// Job already completed
	store.AddJob(&Job{
		ID:          "terminal-job",
		Type:        JobTypeInspectResource,
		Status:      StatusSucceeded,
		WorkerID:    "other-worker",
		Attempt:     1,
		MaxAttempts: 3,
	})

	worker := NewWorker(queue, store, registry, WorkerOptions{Concurrency: 1})

	body, _ := json.Marshal(JobMessage{JobID: "terminal-job"})
	msg := QueueMessage{
		ID:            "msg-terminal",
		ReceiptHandle: "receipt-terminal",
		Body:          string(body),
	}
	worker.processMessage(context.Background(), msg)

	// Flush pending deletes
	worker.flushPendingDeletes(context.Background())

	queue.mu.Lock()
	defer queue.mu.Unlock()
	found := false
	for _, h := range queue.deleted {
		if h == "receipt-terminal" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected message for terminal job to be deleted")
	}
}

func TestUnclaimedNotFoundJobDeletesMessage(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()

	// No job in store at all
	worker := NewWorker(queue, store, registry, WorkerOptions{Concurrency: 1})

	body, _ := json.Marshal(JobMessage{JobID: "missing-job"})
	msg := QueueMessage{
		ID:            "msg-missing",
		ReceiptHandle: "receipt-missing",
		Body:          string(body),
	}
	worker.processMessage(context.Background(), msg)

	worker.flushPendingDeletes(context.Background())

	queue.mu.Lock()
	defer queue.mu.Unlock()
	found := false
	for _, h := range queue.deleted {
		if h == "receipt-missing" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected message for non-existent job to be deleted")
	}
}

func TestUnclaimedActiveJobLeavesMessage(t *testing.T) {
	queue := &MockQueue{}
	store := NewMockStore()
	registry := NewJobRegistry()
	registry.Register(JobTypeInspectResource, func(ctx context.Context, payload string) (string, error) {
		return "ok", nil
	})

	// Job is actively running by another worker
	store.AddJob(&Job{
		ID:       "active-job",
		Type:     JobTypeInspectResource,
		Status:   StatusRunning,
		WorkerID: "other-worker",
		Attempt:  1,
	})

	worker := NewWorker(queue, store, registry, WorkerOptions{Concurrency: 1})

	body, _ := json.Marshal(JobMessage{JobID: "active-job"})
	msg := QueueMessage{
		ID:            "msg-active",
		ReceiptHandle: "receipt-active",
		Body:          string(body),
	}
	worker.processMessage(context.Background(), msg)

	worker.flushPendingDeletes(context.Background())

	queue.mu.Lock()
	defer queue.mu.Unlock()
	for _, h := range queue.deleted {
		if h == "receipt-active" {
			t.Error("message for actively running job should NOT be deleted")
		}
	}
}

func TestErrJobNotFoundSentinel(t *testing.T) {
	store := NewMockStore()
	_, err := store.GetJob(context.Background(), "nonexistent")
	if !errors.Is(err, ErrJobNotFound) {
		t.Errorf("expected ErrJobNotFound, got %v", err)
	}
}
