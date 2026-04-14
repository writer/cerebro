package jobs

import (
	"context"
	"fmt"
	"time"
)

type QueueMessage struct {
	ID            string
	ReceiptHandle string
	Body          string
}

type Queue interface {
	Enqueue(ctx context.Context, msg JobMessage) error
	EnqueueWithDelay(ctx context.Context, msg JobMessage, delay time.Duration) error
	Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error)
	Delete(ctx context.Context, receiptHandle string) error
	DeleteBatch(ctx context.Context, receiptHandles []string) (succeeded int, failed []string, err error)
	ExtendVisibility(ctx context.Context, receiptHandle string, timeout time.Duration) error
	ExtendVisibilityBatch(ctx context.Context, receiptHandles []string, timeout time.Duration) (succeeded int, failed int, err error)
	Retry(ctx context.Context, receiptHandle string, delay time.Duration) error
}

func deduplicationIDForMessage(msg JobMessage, now time.Time) string {
	dedupID := msg.DeduplicationID
	if dedupID == "" || (msg.Attempt > 0 && dedupID == msg.JobID) {
		dedupID = fmt.Sprintf("%s:%d:%d", msg.JobID, msg.Attempt, now.UnixNano())
	}
	return dedupID
}
