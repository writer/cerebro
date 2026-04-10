package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// OrphanScanner finds jobs that are stuck in "running" state with expired leases.
type OrphanScanner interface {
	FindOrphanedJobs(ctx context.Context, limit int) ([]*Job, error)
}

// PendingDispatchStore tracks jobs persisted before their JetStream publish is
// durably recorded.
type PendingDispatchStore interface {
	MarkDispatched(ctx context.Context, jobID string) error
	FindPendingDispatchJobs(ctx context.Context, limit int, olderThan time.Duration) ([]*Job, error)
}

// OrphanedJobScanner finds and recovers jobs that are stuck in "running" state
// with expired leases. This handles cases where a worker crashed after claiming
// a job but before completing it.
type OrphanedJobScanner struct {
	store    Store
	orphans  OrphanScanner
	queue    Queue
	logger   *slog.Logger
	interval time.Duration
}

// NewOrphanedJobScanner creates a new scanner.
func NewOrphanedJobScanner(store Store, orphans OrphanScanner, queue Queue, logger *slog.Logger, interval time.Duration) *OrphanedJobScanner {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &OrphanedJobScanner{
		store:    store,
		orphans:  orphans,
		queue:    queue,
		logger:   logger,
		interval: interval,
	}
}

// Start begins scanning for orphaned jobs periodically.
func (s *OrphanedJobScanner) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately
	s.scan(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan(ctx)
		}
	}
}

// scan finds and recovers orphaned jobs.
func (s *OrphanedJobScanner) scan(ctx context.Context) {
	s.log("scanning for orphaned jobs")

	jobs, err := s.orphans.FindOrphanedJobs(ctx, 100)
	if err != nil {
		s.logError("failed to scan for orphaned jobs", err)
		return
	}

	if len(jobs) == 0 {
		s.log("no orphaned jobs found")
		return
	}

	s.log("found orphaned jobs", "count", len(jobs))

	recovered := 0
	for _, job := range jobs {
		if err := s.recoverJob(ctx, job); err != nil {
			s.logError("failed to recover job", err, "job_id", job.ID)
			continue
		}
		recovered++
	}

	s.log("recovered orphaned jobs", "recovered", recovered, "total", len(jobs))
}

// recoverJob resets a job to queued status and re-enqueues it.
func (s *OrphanedJobScanner) recoverJob(ctx context.Context, job *Job) error {
	// Check if job has exceeded max attempts
	if job.Attempt >= job.MaxAttempts {
		s.log("orphaned job exceeded max attempts, marking failed", "job_id", job.ID, "attempts", job.Attempt)
		return s.store.FailJob(ctx, job.ID, "orphaned job exceeded max attempts")
	}

	// Reset to queued status
	if err := s.store.RetryJob(ctx, job.ID, "recovered from orphaned state"); err != nil {
		return fmt.Errorf("failed to reset job status: %w", err)
	}

	// Re-enqueue with the current attempt number so queue deduplication stays stable.
	if err := s.queue.Enqueue(ctx, JobMessage{
		JobID:         job.ID,
		GroupID:       job.GroupID,
		CorrelationID: job.CorrelationID,
		Attempt:       job.Attempt,
	}); err != nil {
		return fmt.Errorf("failed to re-enqueue job: %w", err)
	}
	if tracker, ok := s.store.(PendingDispatchStore); ok {
		if err := tracker.MarkDispatched(ctx, job.ID); err != nil {
			return fmt.Errorf("failed to mark re-enqueued job dispatched: %w", err)
		}
	}

	s.log("recovered orphaned job", "job_id", job.ID, "attempt", job.Attempt)
	return nil
}

func (s *OrphanedJobScanner) log(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Info(msg, args...)
	}
}

func (s *OrphanedJobScanner) logError(msg string, err error, args ...any) {
	if s.logger != nil {
		s.logger.Error(msg, append([]any{"error", err}, args...)...)
	}
}

// PendingDispatchScanner republishes queued jobs that were persisted before the
// process crashed or lost connectivity during JetStream publish.
type PendingDispatchScanner struct {
	store     PendingDispatchStore
	queue     Queue
	logger    *slog.Logger
	interval  time.Duration
	olderThan time.Duration
}

func NewPendingDispatchScanner(store PendingDispatchStore, queue Queue, logger *slog.Logger, interval, olderThan time.Duration) *PendingDispatchScanner {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if olderThan <= 0 {
		olderThan = interval
	}
	return &PendingDispatchScanner{
		store:     store,
		queue:     queue,
		logger:    logger,
		interval:  interval,
		olderThan: olderThan,
	}
}

func (s *PendingDispatchScanner) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.scan(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan(ctx)
		}
	}
}

func (s *PendingDispatchScanner) scan(ctx context.Context) {
	if s == nil || s.store == nil || s.queue == nil {
		return
	}

	jobs, err := s.store.FindPendingDispatchJobs(ctx, 100, s.olderThan)
	if err != nil {
		s.logError("failed to scan pending dispatch jobs", err)
		return
	}
	if len(jobs) == 0 {
		return
	}

	recovered := 0
	for _, job := range jobs {
		if err := s.republish(ctx, job); err != nil {
			s.logError("failed to republish pending dispatch job", err, "job_id", job.ID)
			continue
		}
		recovered++
	}
	if recovered > 0 {
		s.log("recovered pending dispatch jobs", "recovered", recovered, "total", len(jobs))
	}
}

func (s *PendingDispatchScanner) republish(ctx context.Context, job *Job) error {
	if job == nil {
		return fmt.Errorf("job is required")
	}
	if err := s.queue.Enqueue(ctx, jobMessageForEnqueue(job)); err != nil {
		return fmt.Errorf("enqueue pending dispatch job: %w", err)
	}
	if err := s.store.MarkDispatched(ctx, job.ID); err != nil {
		return fmt.Errorf("mark pending dispatch job dispatched: %w", err)
	}
	return nil
}

func (s *PendingDispatchScanner) log(msg string, args ...any) {
	if s != nil && s.logger != nil {
		s.logger.Info(msg, args...)
	}
}

func (s *PendingDispatchScanner) logError(msg string, err error, args ...any) {
	if s != nil && s.logger != nil {
		s.logger.Error(msg, append([]any{"error", err}, args...)...)
	}
}

// DLQConsumer processes messages from the dead letter queue.
type DLQConsumer struct {
	dlqQueue          Queue // The DLQ
	mainQueue         Queue // The main queue for replay
	store             Store
	logger            *slog.Logger
	pollWait          time.Duration
	visibilityTimeout time.Duration
	heartbeatInterval time.Duration
	onDeadLetter      func(ctx context.Context, msg QueueMessage, job *Job) error
}

// DLQConsumerConfig configures the DLQ consumer.
type DLQConsumerConfig struct {
	PollWait          time.Duration
	VisibilityTimeout time.Duration
	HeartbeatInterval time.Duration
	// OnDeadLetter is called for each dead letter. Can be used for alerting.
	// If nil, messages are logged and deleted.
	OnDeadLetter func(ctx context.Context, msg QueueMessage, job *Job) error
}

// NewDLQConsumer creates a new DLQ consumer.
func NewDLQConsumer(dlqQueue, mainQueue Queue, store Store, logger *slog.Logger, config DLQConsumerConfig) *DLQConsumer {
	pollWait := config.PollWait
	if pollWait <= 0 {
		pollWait = 20 * time.Second
	}

	visibilityTimeout := config.VisibilityTimeout
	if visibilityTimeout <= 0 {
		visibilityTimeout = 30 * time.Second
	}

	heartbeatInterval := config.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = visibilityTimeout / 3
	}

	return &DLQConsumer{
		dlqQueue:          dlqQueue,
		mainQueue:         mainQueue,
		store:             store,
		logger:            logger,
		pollWait:          pollWait,
		visibilityTimeout: visibilityTimeout,
		heartbeatInterval: heartbeatInterval,
		onDeadLetter:      config.OnDeadLetter,
	}
}

// Start begins consuming from the DLQ.
func (c *DLQConsumer) Start(ctx context.Context) {
	c.log("DLQ consumer starting")

	for {
		select {
		case <-ctx.Done():
			c.log("DLQ consumer stopping")
			return
		default:
		}

		messages, err := c.dlqQueue.Receive(ctx, 10, c.pollWait, c.visibilityTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logError("failed to receive from DLQ", err)
			time.Sleep(time.Second)
			continue
		}

		for _, msg := range messages {
			c.processDeadLetter(ctx, msg)
		}
	}
}

func (c *DLQConsumer) processDeadLetter(ctx context.Context, msg QueueMessage) {
	var jobMsg JobMessage
	if err := json.Unmarshal([]byte(msg.Body), &jobMsg); err != nil {
		c.logError("invalid DLQ message", err, "message_id", msg.ID)
		// Delete invalid messages
		_ = c.dlqQueue.Delete(ctx, msg.ReceiptHandle)
		return
	}

	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()
	if msg.ReceiptHandle != "" {
		go c.runHeartbeat(heartbeatCtx, msg.ReceiptHandle)
	}

	// Try to get job details
	var job *Job
	if jobMsg.JobID != "" {
		var err error
		job, err = c.store.GetJob(ctx, jobMsg.JobID)
		if err != nil {
			c.logError("failed to get job for dead letter", err, "job_id", jobMsg.JobID)
		}
	}

	c.log("processing dead letter",
		"message_id", msg.ID,
		"job_id", jobMsg.JobID,
		"correlation_id", jobMsg.CorrelationID,
	)

	// Call handler if configured
	if c.onDeadLetter != nil {
		if err := c.onDeadLetter(ctx, msg, job); err != nil {
			c.logError("dead letter handler failed", err, "job_id", jobMsg.JobID)
			// Don't delete - let it stay in DLQ for retry
			return
		}
	}

	// Mark job as failed if it exists and isn't already terminal
	if job != nil && !job.Status.Terminal() {
		errMsg := "job moved to dead letter queue after exhausting retries"
		if err := c.store.FailJob(ctx, job.ID, errMsg); err != nil {
			c.logError("failed to mark DLQ job as failed", err, "job_id", job.ID)
		}
	}

	// Delete from DLQ
	if err := c.dlqQueue.Delete(ctx, msg.ReceiptHandle); err != nil {
		c.logError("failed to delete from DLQ", err, "message_id", msg.ID)
	}
}

// ReplayMessage re-enqueues a dead letter message to the main queue.
func (c *DLQConsumer) ReplayMessage(ctx context.Context, msg QueueMessage) error {
	var jobMsg JobMessage
	if err := json.Unmarshal([]byte(msg.Body), &jobMsg); err != nil {
		return fmt.Errorf("invalid message: %w", err)
	}

	// Reset job status and get current attempt count
	var attempt int
	if jobMsg.JobID != "" {
		if err := c.store.RetryJob(ctx, jobMsg.JobID, "replayed from DLQ"); err != nil {
			c.logError("failed to reset job for replay", err, "job_id", jobMsg.JobID)
			// Continue anyway - maybe job was already reset
		}
		// Get current attempt count for deduplication.
		if job, err := c.store.GetJob(ctx, jobMsg.JobID); err == nil {
			attempt = job.Attempt
		}
	}

	// Enqueue to the main queue with the updated attempt number for deduplication.
	replayMsg := JobMessage{
		JobID:         jobMsg.JobID,
		GroupID:       jobMsg.GroupID,
		CorrelationID: jobMsg.CorrelationID,
		Attempt:       attempt,
	}
	if err := c.mainQueue.Enqueue(ctx, replayMsg); err != nil {
		return fmt.Errorf("failed to enqueue: %w", err)
	}

	// Delete from DLQ
	if err := c.dlqQueue.Delete(ctx, msg.ReceiptHandle); err != nil {
		c.logError("failed to delete replayed message from DLQ", err, "message_id", msg.ID)
	}

	c.log("replayed message from DLQ", "job_id", jobMsg.JobID, "attempt", attempt)
	return nil
}

func (c *DLQConsumer) log(msg string, args ...any) {
	if c.logger != nil {
		c.logger.Info(msg, args...)
	}
}

func (c *DLQConsumer) runHeartbeat(ctx context.Context, receiptHandle string) {
	if c.heartbeatInterval <= 0 || c.visibilityTimeout <= 0 {
		return
	}

	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.dlqQueue.ExtendVisibility(ctx, receiptHandle, c.visibilityTimeout); err != nil {
				if ctx.Err() == nil {
					failures++
					c.logError("dlq heartbeat failed", err, "failures", failures)
				}
				backoff := c.calculateHeartbeatBackoff(failures)
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
		}
	}
}

func (c *DLQConsumer) calculateHeartbeatBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	shift := failures - 1
	if shift > 30 {
		shift = 30
	}
	backoff := time.Second * time.Duration(1<<shift)
	maxBackoff := c.visibilityTimeout / 2
	if maxBackoff > 0 && backoff > maxBackoff {
		backoff = maxBackoff
	}

	return backoff
}

func (c *DLQConsumer) logError(msg string, err error, args ...any) {
	if c.logger != nil {
		c.logger.Error(msg, append([]any{"error", err}, args...)...)
	}
}
