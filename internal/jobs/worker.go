package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

// Error types for retry handling
var (
	// ErrPermanent indicates the job should not be retried
	ErrPermanent = errors.New("permanent error")
	// ErrRetryable indicates the job can be retried
	ErrRetryable = errors.New("retryable error")
)

// PermanentError wraps an error to indicate it should not be retried.
func PermanentError(err error) error {
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

// RetryableError wraps an error to indicate it can be retried.
func RetryableError(err error) error {
	return fmt.Errorf("%w: %w", ErrRetryable, err)
}

// IsPermanent checks if an error is marked as permanent (should not retry).
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent)
}

// Worker processes jobs from an SQS queue.
type Worker struct {
	queue       Queue
	store       Store
	registry    *JobRegistry
	metrics     MetricsRecorder
	circuit     *CircuitBreaker
	idempotency IdempotencyStore

	concurrency       int
	visibilityTimeout time.Duration
	heartbeatInterval time.Duration
	jobTimeout        time.Duration
	pollWait          time.Duration
	drainTimeout      time.Duration
	retryBaseDelay    time.Duration
	retryMaxDelay     time.Duration
	logger            *slog.Logger
	workerID          string

	runMu     sync.Mutex
	runCancel context.CancelFunc

	// Shutdown coordination
	inFlightJobs  sync.WaitGroup
	shuttingDown  atomic.Bool
	stopReceiving atomic.Bool // Stop receiving new messages first

	jobsMu     sync.Mutex
	jobsCancel context.CancelFunc

	// Pending deletes for batching
	deleteMu       sync.Mutex
	pendingDeletes []string

	// Health tracking
	healthy      atomic.Bool
	lastActivity atomic.Int64
	panicCount   atomic.Int64
}

// WorkerOptions configures the worker.
type WorkerOptions struct {
	Concurrency       int
	VisibilityTimeout time.Duration
	HeartbeatInterval time.Duration
	JobTimeout        time.Duration
	PollWait          time.Duration
	DrainTimeout      time.Duration
	RetryBaseDelay    time.Duration
	RetryMaxDelay     time.Duration
	WorkerID          string
	Logger            *slog.Logger
	Metrics           MetricsRecorder
	CircuitBreaker    *CircuitBreaker
	Idempotency       IdempotencyStore
}

// NewWorker creates a new job worker.
func NewWorker(queue Queue, store Store, registry *JobRegistry, opts WorkerOptions) *Worker {
	workerID := opts.WorkerID
	if workerID == "" {
		workerID = uuid.NewString()[:8]
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}
	visibilityTimeout := opts.VisibilityTimeout
	if visibilityTimeout <= 0 {
		visibilityTimeout = 60 * time.Second
	}
	heartbeatInterval := opts.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = visibilityTimeout / 3
	}
	jobTimeout := opts.JobTimeout
	if jobTimeout <= 0 {
		jobTimeout = 5 * time.Minute
	}
	pollWait := opts.PollWait
	if pollWait <= 0 {
		pollWait = 20 * time.Second
	}
	drainTimeout := opts.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = 30 * time.Second
	}
	retryBaseDelay := opts.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = 1 * time.Second
	}
	retryMaxDelay := opts.RetryMaxDelay
	if retryMaxDelay <= 0 {
		retryMaxDelay = 5 * time.Minute
	}

	metrics := opts.Metrics
	if metrics == nil {
		metrics = &NoOpMetrics{}
	}

	circuit := opts.CircuitBreaker
	if circuit == nil {
		circuit = NewCircuitBreaker(CircuitBreakerConfig{})
	}

	idempotency := opts.Idempotency
	if idempotency == nil {
		idempotency = &NoOpIdempotencyStore{}
	}

	w := &Worker{
		queue:             queue,
		store:             store,
		registry:          registry,
		metrics:           metrics,
		circuit:           circuit,
		idempotency:       idempotency,
		concurrency:       concurrency,
		visibilityTimeout: visibilityTimeout,
		heartbeatInterval: heartbeatInterval,
		jobTimeout:        jobTimeout,
		pollWait:          pollWait,
		drainTimeout:      drainTimeout,
		retryBaseDelay:    retryBaseDelay,
		retryMaxDelay:     retryMaxDelay,
		logger:            opts.Logger,
		workerID:          workerID,
		pendingDeletes:    make([]string, 0, 10),
	}
	w.healthy.Store(true)
	w.lastActivity.Store(time.Now().Unix())
	return w
}

// Start begins processing jobs. Blocks until context is canceled or Shutdown is called.
func (w *Worker) Start(ctx context.Context) error {
	// receiveCtx controls the poll loop; canceled immediately on shutdown.
	receiveCtx, receiveCancel := context.WithCancel(ctx)
	w.setRunCancel(receiveCancel)
	defer func() {
		receiveCancel()
		w.setRunCancel(nil)
	}()

	// jobsCtx stays alive during drain so in-flight jobs can finish.
	jobsCtx, jobsCancel := context.WithCancel(context.Background())
	w.setJobsCancel(jobsCancel)
	defer jobsCancel()

	w.logInfo("worker starting",
		"worker_id", w.workerID,
		"concurrency", w.concurrency,
		"visibility_timeout", w.visibilityTimeout,
		"job_timeout", w.jobTimeout,
	)

	// Start metrics flusher
	w.metrics.StartFlusher(receiveCtx, 60*time.Second)

	// Start batch delete flusher
	go w.batchDeleteFlusher(receiveCtx)

	// Semaphore for concurrency control
	sem := make(chan struct{}, w.concurrency)

	for {
		// Check for shutdown - stop receiving first, then drain
		select {
		case <-receiveCtx.Done():
			w.stopReceiving.Store(true)
			w.gracefulShutdown()
			return nil
		default:
		}

		if w.shuttingDown.Load() || w.stopReceiving.Load() {
			w.gracefulShutdown()
			return nil
		}

		// Check circuit breaker
		if !w.circuit.Allow() {
			w.logWarn("circuit breaker open, backing off")
			time.Sleep(5 * time.Second)
			continue
		}

		// Receive messages - use shorter poll when near shutdown
		pollTime := w.pollWait
		messages, err := w.queue.Receive(receiveCtx, w.concurrency, pollTime, w.visibilityTimeout)
		if err != nil {
			if receiveCtx.Err() != nil {
				w.stopReceiving.Store(true)
				w.gracefulShutdown()
				return nil
			}
			w.logError("receive failed", err)
			time.Sleep(time.Second)
			continue
		}

		if len(messages) == 0 {
			continue
		}

		w.metrics.RecordMessagesReceived(len(messages))
		w.lastActivity.Store(time.Now().Unix())
		w.logDebug("received messages", "count", len(messages))

		// Process messages concurrently using jobsCtx so in-flight
		// work survives receive-loop cancellation during drain.
		for _, msg := range messages {
			if w.stopReceiving.Load() {
				break
			}

			select {
			case sem <- struct{}{}:
			case <-receiveCtx.Done():
				w.stopReceiving.Store(true)
				w.gracefulShutdown()
				return nil
			}

			w.inFlightJobs.Add(1)
			go func(m QueueMessage) {
				defer func() {
					<-sem
					w.inFlightJobs.Done()
				}()
				w.processMessage(jobsCtx, m)
			}(msg)
		}
	}
}

func (w *Worker) gracefulShutdown() {
	w.shuttingDown.Store(true)
	w.healthy.Store(false)
	w.logInfo("initiating graceful shutdown", "drain_timeout", w.drainTimeout)

	done := make(chan struct{})
	go func() {
		w.inFlightJobs.Wait()
		close(done)
	}()

	select {
	case <-done:
		w.logInfo("all in-flight jobs completed")
	case <-time.After(w.drainTimeout):
		w.logWarn("drain timeout exceeded, canceling remaining jobs")
		w.cancelJobsContext()
		// Brief grace period for jobs to react to cancellation.
		t := time.NewTimer(5 * time.Second)
		select {
		case <-done:
		case <-t.C:
		}
		t.Stop()
	}

	// Flush any pending deletes
	flushCtx, flushCancel := context.WithTimeout(context.Background(), w.shutdownIOTimeout())
	w.flushPendingDeletes(flushCtx)
	flushCancel()

	// Final metrics flush
	metricsCtx, metricsCancel := context.WithTimeout(context.Background(), w.shutdownIOTimeout())
	if err := w.metrics.Flush(metricsCtx); err != nil {
		w.logWarn("failed to flush final metrics", "error", err)
	}
	metricsCancel()
}

// Shutdown signals the worker to stop processing new jobs.
func (w *Worker) Shutdown() {
	w.shuttingDown.Store(true)
	w.stopReceiving.Store(true)
	w.cancelRunContext()
}

func (w *Worker) processMessage(ctx context.Context, msg QueueMessage) {
	startTime := time.Now()
	var succeeded, timedOut bool
	var idempotencyKey string
	var correlationID string
	var jobID string

	defer func() {
		if r := recover(); r != nil {
			w.panicCount.Add(1)
			stack := debug.Stack()
			w.logError("panic in job processing", fmt.Errorf("panic: %v", r),
				"stack", string(stack),
				"message_id", msg.ID,
				"job_id", jobID,
				"correlation_id", correlationID,
			)
			w.circuit.RecordFailure()
			if idempotencyKey != "" {
				_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
			}
		}
		w.metrics.RecordJobProcessed(time.Since(startTime), succeeded, timedOut)
	}()

	// Parse job message
	var jobMsg JobMessage
	if err := json.Unmarshal([]byte(msg.Body), &jobMsg); err != nil {
		w.logError("invalid job message", err)
		w.queueDelete(msg.ReceiptHandle)
		return
	}

	jobID = jobMsg.JobID
	if jobID == "" {
		w.logError("missing job ID", fmt.Errorf("job ID required"), "message_id", msg.ID)
		w.queueDelete(msg.ReceiptHandle)
		return
	}

	// Set up correlation ID for logging context
	correlationID = jobMsg.CorrelationID
	if correlationID == "" {
		correlationID = jobID
	}

	// Idempotency check - prevent duplicate processing
	// Use message ID + job ID as key (handles SQS redelivery)
	if msg.ID != "" {
		idempotencyKey = fmt.Sprintf("%s:%s", msg.ID, jobID)
	} else {
		idempotencyKey = jobID
	}
	idempotencyTTL := w.jobTimeout
	minTTL := w.visibilityTimeout * 2
	if idempotencyTTL < minTTL {
		idempotencyTTL = minTTL
	}
	idempotencyTTL += w.visibilityTimeout
	canProcess, err := w.idempotency.MarkProcessing(ctx, idempotencyKey, w.workerID, idempotencyTTL)
	if err != nil {
		w.logError("idempotency check failed", err,
			"job_id", jobID,
			"correlation_id", correlationID,
		)
		// Continue anyway - idempotency is a safety net, not a blocker
	} else if !canProcess {
		processed, processedErr := w.idempotency.IsProcessed(ctx, idempotencyKey)
		if processedErr != nil {
			w.logWarn("failed to inspect idempotency status", "job_id", jobID, "error", processedErr)
		}
		if processed {
			w.logDebug("message already completed (idempotency)",
				"job_id", jobID,
				"correlation_id", correlationID,
				"message_id", msg.ID,
			)
			w.queueDelete(msg.ReceiptHandle)
			return
		}

		w.logDebug("message already processing elsewhere; leaving message in queue",
			"job_id", jobID,
			"correlation_id", correlationID,
			"message_id", msg.ID,
		)
		return
	}

	// Claim job in store
	job, claimed, err := w.store.ClaimJob(ctx, jobID, w.workerID, w.visibilityTimeout)
	if err != nil {
		w.logError("failed to claim job", err,
			"job_id", jobID,
			"correlation_id", correlationID,
		)
		w.circuit.RecordFailure()
		if markErr := w.idempotency.MarkFailed(ctx, idempotencyKey); markErr != nil {
			w.logWarn("failed to mark idempotency as failed", "job_id", jobID, "error", markErr)
		}
		return
	}
	if !claimed {
		w.logDebug("job not claimed, checking state",
			"job_id", jobID,
			"correlation_id", correlationID,
		)
		if markErr := w.idempotency.MarkFailed(ctx, idempotencyKey); markErr != nil {
			w.logWarn("failed to clear idempotency lock for unclaimed job", "job_id", jobID, "error", markErr)
		}
		// Determine whether the SQS message is stale so it does not loop.
		existing, getErr := w.store.GetJob(ctx, jobID)
		if getErr != nil {
			if errors.Is(getErr, ErrJobNotFound) {
				w.logInfo("deleting message for non-existent job",
					"job_id", jobID, "correlation_id", correlationID)
				w.queueDelete(msg.ReceiptHandle)
			} else {
				w.logWarn("could not inspect unclaimed job", "job_id", jobID, "error", getErr)
			}
		} else if existing.Status.Terminal() {
			w.logInfo("deleting message for terminal job",
				"job_id", jobID, "status", existing.Status, "correlation_id", correlationID)
			w.queueDelete(msg.ReceiptHandle)
		}
		return
	}

	if job.MaxAttempts <= 0 {
		job.MaxAttempts = 3
	}

	// Use correlation ID from job if message didn't have one
	if job.CorrelationID != "" {
		correlationID = job.CorrelationID
	}

	w.logInfo("processing job",
		"job_id", job.ID,
		"type", job.Type,
		"attempt", job.Attempt,
		"max_attempts", job.MaxAttempts,
		"correlation_id", correlationID,
	)

	// Create job context with timeout
	jobCtx, jobCancel := context.WithTimeout(ctx, w.jobTimeout)
	defer jobCancel()

	// Start heartbeat
	heartbeatCtx, heartbeatCancel := context.WithCancel(jobCtx)
	defer heartbeatCancel()
	go w.runHeartbeat(heartbeatCtx, msg.ReceiptHandle, job.ID, jobCancel)

	// Execute job
	result, execErr := w.executeJob(jobCtx, job)

	// Stop heartbeat
	heartbeatCancel()

	// Handle result
	if execErr != nil {
		timedOut = errors.Is(jobCtx.Err(), context.DeadlineExceeded)
		w.handleJobFailure(ctx, job, msg.ReceiptHandle, execErr, timedOut, idempotencyKey, correlationID)
		w.circuit.RecordFailure()
		return
	}

	// Mark job complete
	if err := w.store.CompleteJobOwned(ctx, job.ID, w.workerID, job.Attempt, result); err != nil {
		if errors.Is(err, ErrJobLeaseLost) {
			w.logWarn("lost job lease before completion; skipping terminal update",
				"job_id", job.ID,
				"correlation_id", correlationID,
			)
			_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
			return
		}
		w.logError("failed to complete job", err,
			"job_id", job.ID,
			"correlation_id", correlationID,
		)
		w.circuit.RecordFailure()
		if markErr := w.idempotency.MarkFailed(ctx, idempotencyKey); markErr != nil {
			w.logWarn("failed to mark idempotency as failed after completion error", "job_id", job.ID, "error", markErr)
		}
		return
	}

	// Mark idempotency as completed
	if markErr := w.idempotency.MarkCompleted(ctx, idempotencyKey); markErr != nil {
		w.logWarn("failed to mark idempotency as completed", "job_id", job.ID, "error", markErr)
	}

	// Delete message (batched)
	w.queueDelete(msg.ReceiptHandle)

	succeeded = true
	w.circuit.RecordSuccess()
	w.logInfo("job completed",
		"job_id", job.ID,
		"correlation_id", correlationID,
		"duration", time.Since(startTime),
	)
}

func (w *Worker) executeJob(ctx context.Context, job *Job) (string, error) {
	if w.registry == nil {
		return "", fmt.Errorf("no job registry configured")
	}
	return w.registry.Execute(ctx, job)
}

func (w *Worker) runHeartbeat(ctx context.Context, receiptHandle, jobID string, onLeaseLost context.CancelFunc) {
	ticker := time.NewTicker(w.heartbeatInterval)
	defer ticker.Stop()

	failures := 0
	queueHeartbeatEnabled := true
	requestTimeout := w.heartbeatRequestTimeout()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Always keep store lease alive to avoid duplicate claims even when queue heartbeat is degraded.
			leaseCtx, leaseCancel := context.WithTimeout(ctx, requestTimeout)
			if err := w.store.ExtendLease(leaseCtx, jobID, w.workerID, w.visibilityTimeout); err != nil {
				if ctx.Err() == nil {
					if errors.Is(err, ErrJobLeaseLost) {
						w.logWarn("job lease lost; canceling in-flight execution", "job_id", jobID)
						if onLeaseLost != nil {
							onLeaseLost()
						}
						leaseCancel()
						return
					}
					w.logError("lease extension failed", err, "job_id", jobID)
				}
			}
			leaseCancel()

			if !queueHeartbeatEnabled {
				continue
			}

			hbCtx, hbCancel := context.WithTimeout(ctx, requestTimeout)
			err := w.queue.ExtendVisibility(hbCtx, receiptHandle, w.visibilityTimeout)
			hbCancel()
			if err != nil {
				if ctx.Err() == nil {
					failures++
					w.metrics.RecordHeartbeat(false)

					if isTerminalVisibilityError(err) {
						queueHeartbeatEnabled = false
						w.logWarn("queue heartbeat disabled after terminal visibility error", "job_id", jobID, "failures", failures, "error", err)
						continue
					}

					w.logError("heartbeat failed", err, "job_id", jobID, "failures", failures)
				}

				backoff := w.calculateHeartbeatBackoff(failures)
				if backoff > 0 {
					timer := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
				continue
			}

			failures = 0
			w.metrics.RecordHeartbeat(true)
		}
	}
}

func (w *Worker) heartbeatRequestTimeout() time.Duration {
	timeout := w.heartbeatInterval / 2
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	if w.visibilityTimeout > 0 {
		maxFromVisibility := w.visibilityTimeout / 2
		if maxFromVisibility > 0 && timeout > maxFromVisibility {
			timeout = maxFromVisibility
		}
	}

	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	if timeout < time.Second {
		timeout = time.Second
	}

	return timeout
}

func isTerminalVisibilityError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(strings.TrimSpace(apiErr.ErrorCode()))
		msg := strings.ToLower(strings.TrimSpace(apiErr.ErrorMessage()))
		switch code {
		case "receipthandleisinvalid", "aws.simplequeueservice.nonexistentqueue", "awssimplequeueservice.nonexistentqueue":
			return true
		case "invalidparametervalue":
			if strings.Contains(msg, "receipthandle") || strings.Contains(msg, "message does not exist") || strings.Contains(msg, "not available for visibility timeout change") {
				return true
			}
		}
	}

	normalized := strings.ToLower(err.Error())
	return strings.Contains(normalized, "receipthandle is invalid") ||
		strings.Contains(normalized, "message does not exist or is not available for visibility timeout change") ||
		strings.Contains(normalized, "aws.simplequeueservice.nonexistentqueue")
}

func (w *Worker) handleJobFailure(ctx context.Context, job *Job, receiptHandle string, jobErr error, timedOut bool, idempotencyKey, correlationID string) {
	errMsg := jobErr.Error()
	if timedOut {
		errMsg = fmt.Sprintf("job timeout after %s: %s", w.jobTimeout, errMsg)
	}

	isPermanent := IsPermanent(jobErr)

	w.logError("job failed", jobErr,
		"job_id", job.ID,
		"attempt", job.Attempt,
		"max_attempts", job.MaxAttempts,
		"timed_out", timedOut,
		"permanent", isPermanent,
		"correlation_id", correlationID,
	)

	// Permanent errors - delete message and mark failed (no DLQ needed for app-level permanent errors)
	if isPermanent {
		if err := w.store.FailJobOwned(ctx, job.ID, w.workerID, job.Attempt, errMsg); err != nil {
			if errors.Is(err, ErrJobLeaseLost) {
				w.logWarn("lost job lease before permanent failure update", "job_id", job.ID, "correlation_id", correlationID)
				_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
				return
			}
			w.logError("failed to mark job failed", err,
				"job_id", job.ID,
				"correlation_id", correlationID,
			)
			_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
			return
		}
		_ = w.idempotency.MarkCompleted(ctx, idempotencyKey)
		w.queueDelete(receiptHandle)
		w.logWarn("job failed permanently (non-retryable)",
			"job_id", job.ID,
			"correlation_id", correlationID,
		)
		return
	}

	// Max retries exceeded - mark failed in DB but DON'T delete message
	// Let SQS move it to DLQ after visibility timeout expires
	if job.Attempt >= job.MaxAttempts {
		if err := w.store.FailJobOwned(ctx, job.ID, w.workerID, job.Attempt, errMsg); err != nil {
			if errors.Is(err, ErrJobLeaseLost) {
				w.logWarn("lost job lease before exhausted-retry update", "job_id", job.ID, "correlation_id", correlationID)
				_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
				return
			}
			w.logError("failed to mark job failed", err,
				"job_id", job.ID,
				"correlation_id", correlationID,
			)
		}
		_ = w.idempotency.MarkFailed(ctx, idempotencyKey)
		// Don't delete - let SQS redrive to DLQ
		w.logWarn("job exhausted retries, will move to DLQ",
			"job_id", job.ID,
			"attempts", job.Attempt,
			"correlation_id", correlationID,
		)
		return
	}

	// Retryable failure - use SQS visibility timeout for backoff
	// Calculate delay and extend visibility so message reappears after delay
	_ = w.idempotency.MarkFailed(ctx, idempotencyKey)

	if err := w.store.RetryJobOwned(ctx, job.ID, w.workerID, job.Attempt, errMsg); err != nil {
		if errors.Is(err, ErrJobLeaseLost) {
			w.logWarn("lost job lease before retry update", "job_id", job.ID, "correlation_id", correlationID)
			return
		}
		w.logError("failed to mark job for retry", err,
			"job_id", job.ID,
			"correlation_id", correlationID,
		)
		return
	}

	// Use ChangeMessageVisibility to implement backoff delay
	// Message will become visible again after the delay
	delay := w.calculateBackoff(job.Attempt)
	if err := w.queue.ExtendVisibility(ctx, receiptHandle, delay); err != nil {
		w.logError("failed to set retry delay", err,
			"job_id", job.ID,
			"delay", delay,
			"correlation_id", correlationID,
		)
		// Don't delete - let default visibility timeout handle retry
		return
	}

	w.logInfo("job scheduled for retry",
		"job_id", job.ID,
		"next_attempt", job.Attempt+1,
		"delay", delay,
		"correlation_id", correlationID,
	)
}

// calculateBackoff returns the delay for the given attempt using exponential backoff.
func (w *Worker) calculateBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		attempt = 1
	}

	shift := attempt - 1
	if shift > 30 {
		shift = 30
	}

	// Exponential backoff: base * 2^attempt
	delay := w.retryBaseDelay * time.Duration(1<<shift)
	if delay > w.retryMaxDelay {
		delay = w.retryMaxDelay
	}
	return delay
}

func (w *Worker) calculateHeartbeatBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	backoff := w.calculateBackoff(failures)
	maxBackoff := w.visibilityTimeout / 2
	if maxBackoff > 0 && backoff > maxBackoff {
		backoff = maxBackoff
	}

	return backoff
}

func (w *Worker) setRunCancel(cancel context.CancelFunc) {
	w.runMu.Lock()
	defer w.runMu.Unlock()
	w.runCancel = cancel
}

func (w *Worker) cancelRunContext() {
	w.runMu.Lock()
	cancel := w.runCancel
	w.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (w *Worker) setJobsCancel(cancel context.CancelFunc) {
	w.jobsMu.Lock()
	defer w.jobsMu.Unlock()
	w.jobsCancel = cancel
}

func (w *Worker) cancelJobsContext() {
	w.jobsMu.Lock()
	cancel := w.jobsCancel
	w.jobsMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// queueDelete adds a receipt handle to the pending delete batch.
func (w *Worker) queueDelete(receiptHandle string) {
	w.deleteMu.Lock()
	w.pendingDeletes = append(w.pendingDeletes, receiptHandle)
	shouldFlush := len(w.pendingDeletes) >= 10
	w.deleteMu.Unlock()

	if shouldFlush {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		w.flushPendingDeletes(ctx)
		cancel()
	}
}

// flushPendingDeletes sends batched deletes to SQS.
func (w *Worker) flushPendingDeletes(ctx context.Context) {
	w.deleteMu.Lock()
	if len(w.pendingDeletes) == 0 {
		w.deleteMu.Unlock()
		return
	}
	toDelete := w.pendingDeletes
	w.pendingDeletes = make([]string, 0, 10)
	w.deleteMu.Unlock()

	succeeded, failedHandles, err := w.queue.DeleteBatch(ctx, toDelete)
	if err != nil {
		w.logError("batch delete failed", err, "succeeded", succeeded, "failed", len(failedHandles))
	}
	if len(failedHandles) > 0 {
		w.logWarn("batch delete had failed messages", "failed", len(failedHandles))
		w.metrics.RecordMessagesDeleteFailed(len(failedHandles))
	}
	w.metrics.RecordMessagesDeleted(succeeded)
}

func (w *Worker) shutdownIOTimeout() time.Duration {
	timeout := w.drainTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	return timeout
}

// batchDeleteFlusher periodically flushes pending deletes.
func (w *Worker) batchDeleteFlusher(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.flushPendingDeletes(ctx)
		}
	}
}

// Logging helpers
func (w *Worker) logInfo(msg string, args ...any) {
	if w.logger != nil {
		w.logger.Info(msg, args...)
	}
}

func (w *Worker) logWarn(msg string, args ...any) {
	if w.logger != nil {
		w.logger.Warn(msg, args...)
	}
}

func (w *Worker) logDebug(msg string, args ...any) {
	if w.logger != nil {
		w.logger.Debug(msg, args...)
	}
}

func (w *Worker) logError(msg string, err error, args ...any) {
	if w.logger != nil {
		w.logger.Error(msg, append([]any{"error", err}, args...)...)
	}
}

// HealthStatus represents the worker's health state.
type HealthStatus struct {
	Healthy      bool   `json:"healthy"`
	WorkerID     string `json:"worker_id"`
	ShuttingDown bool   `json:"shutting_down"`
	CircuitState string `json:"circuit_state"`
	PanicCount   int64  `json:"panic_count"`
	LastActivity int64  `json:"last_activity_unix"`
}

// Health returns the current health status of the worker.
func (w *Worker) Health() HealthStatus {
	return HealthStatus{
		Healthy:      w.healthy.Load() && !w.shuttingDown.Load(),
		WorkerID:     w.workerID,
		ShuttingDown: w.shuttingDown.Load(),
		CircuitState: w.circuit.State().String(),
		PanicCount:   w.panicCount.Load(),
		LastActivity: w.lastActivity.Load(),
	}
}

// IsHealthy returns true if the worker is healthy and ready to process jobs.
func (w *Worker) IsHealthy() bool {
	return w.healthy.Load() && !w.shuttingDown.Load() && w.circuit.State() != CircuitOpen
}

// HealthServer provides HTTP health check endpoints for the worker.
type HealthServer struct {
	worker *Worker
	server *http.Server
	logger *slog.Logger
}

// NewHealthServer creates a new health server.
func NewHealthServer(worker *Worker, addr string, logger *slog.Logger) *HealthServer {
	hs := &HealthServer{
		worker: worker,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", hs.handleHealth)
	mux.HandleFunc("/health/live", hs.handleLive)
	mux.HandleFunc("/health/ready", hs.handleReady)

	hs.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return hs
}

// Start starts the health server in a goroutine.
func (hs *HealthServer) Start() error {
	go func() {
		if hs.logger != nil {
			hs.logger.Info("health server starting", "addr", hs.server.Addr)
		}
		if err := hs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if hs.logger != nil {
				hs.logger.Error("health server error", "error", err)
			}
		}
	}()
	return nil
}

// Shutdown gracefully shuts down the health server.
func (hs *HealthServer) Shutdown(ctx context.Context) error {
	return hs.server.Shutdown(ctx)
}

// handleHealth returns full health status as JSON.
func (hs *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := hs.worker.Health()
	w.Header().Set("Content-Type", "application/json")
	if !status.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(status)
}

// handleLive is the liveness probe - returns 200 if the process is running.
func (hs *HealthServer) handleLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReady is the readiness probe - returns 200 if ready to accept work.
func (hs *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if hs.worker.IsHealthy() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	}
}
