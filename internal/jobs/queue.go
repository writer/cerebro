package jobs

import (
	"context"
	"fmt"
	"time"
)

// QueueMessage represents a message received from a queue.
type QueueMessage struct {
	ID            string
	ReceiptHandle string
	Body          string
}

// Queue defines the interface for job queue operations.
type Queue interface {
	Enqueue(ctx context.Context, msg JobMessage) error
	EnqueueWithDelay(ctx context.Context, msg JobMessage, delay time.Duration) error
	Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error)
	Delete(ctx context.Context, receiptHandle string) error
	DeleteBatch(ctx context.Context, receiptHandles []string) (succeeded int, failed []string, err error)
	ExtendVisibility(ctx context.Context, receiptHandle string, timeout time.Duration) error
	ExtendVisibilityBatch(ctx context.Context, receiptHandles []string, timeout time.Duration) (succeeded int, failed int, err error)
}

// TerminalQueueError is an interface that queue implementations can use to
// signal that an error is terminal and the operation should not be retried.
// For example, an invalid receipt handle that will never succeed.
type TerminalQueueError interface {
	error
	IsTerminal() bool
}

// deduplicationIDForMessage generates a deduplication ID for a job message.
// If the message has a custom DeduplicationID (that is not simply the JobID
// on a retry), it is used as-is. Otherwise a unique ID is generated from the
// job ID, attempt number, and current timestamp.
func deduplicationIDForMessage(msg JobMessage, now time.Time) string {
	dedupID := msg.DeduplicationID
	if dedupID == "" || (msg.Attempt > 0 && dedupID == msg.JobID) {
		dedupID = fmt.Sprintf("%s:%d:%d", msg.JobID, msg.Attempt, now.UnixNano())
	}
	return dedupID
}
