package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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
}

type SQSQueue struct {
	client   *sqs.Client
	queueURL string
	isFIFO   bool
}

// SQSQueueConfig configures the SQS queue.
type SQSQueueConfig struct {
	QueueURL string
	IsFIFO   bool // Set to true for FIFO queues (.fifo suffix)
}

func NewSQSQueue(cfg aws.Config, queueURL string) *SQSQueue {
	return NewSQSQueueWithConfig(cfg, SQSQueueConfig{
		QueueURL: queueURL,
		IsFIFO:   strings.HasSuffix(queueURL, ".fifo"),
	})
}

func NewSQSQueueWithConfig(cfg aws.Config, config SQSQueueConfig) *SQSQueue {
	return &SQSQueue{
		client:   sqs.NewFromConfig(cfg),
		queueURL: config.QueueURL,
		isFIFO:   config.IsFIFO,
	}
}

func deduplicationIDForMessage(msg JobMessage, now time.Time) string {
	dedupID := msg.DeduplicationID
	if dedupID == "" || (msg.Attempt > 0 && dedupID == msg.JobID) {
		dedupID = fmt.Sprintf("%s:%d:%d", msg.JobID, msg.Attempt, now.UnixNano())
	}
	return dedupID
}

func (q *SQSQueue) Enqueue(ctx context.Context, msg JobMessage) error {
	return q.EnqueueWithDelay(ctx, msg, 0)
}

func (q *SQSQueue) EnqueueWithDelay(ctx context.Context, msg JobMessage, delay time.Duration) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(q.queueURL),
		MessageBody: aws.String(string(body)),
	}

	// SQS max delay is 15 minutes (900 seconds)
	if delay > 0 {
		delaySec := int32(delay.Seconds())
		if delaySec > 900 {
			delaySec = 900
		}
		input.DelaySeconds = delaySec
	}

	// FIFO queue support
	if q.isFIFO {
		// MessageGroupId is required for FIFO - use GroupID or JobID
		groupID := msg.GroupID
		if groupID == "" {
			groupID = msg.JobID
		}
		input.MessageGroupId = aws.String(groupID)

		// MessageDeduplicationId prevents duplicates within 5-minute window
		// Use provided ID, or generate unique one to allow retries/replays
		input.MessageDeduplicationId = aws.String(deduplicationIDForMessage(msg, time.Now()))
	}

	_, err = q.client.SendMessage(ctx, input)
	return err
}

func (q *SQSQueue) Receive(ctx context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error) {
	if maxMessages <= 0 {
		maxMessages = 1
	}
	if maxMessages > 10 {
		maxMessages = 10
	}

	// Bound values to safe ranges before int32 conversion
	waitSec := int(waitTime.Seconds())
	if waitSec > 20 {
		waitSec = 20
	}
	if waitSec < 0 {
		waitSec = 0
	}

	input := &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(q.queueURL),
		MaxNumberOfMessages: int32(maxMessages), // Already bounded to 1-10 above
		WaitTimeSeconds:     int32(waitSec),     // Bounded to 0-20
	}
	if visibilityTimeout > 0 {
		visSec := int(visibilityTimeout.Seconds())
		if visSec > 43200 {
			visSec = 43200 // SQS max is 12h
		}
		input.VisibilityTimeout = int32(visSec)
	}

	out, err := q.client.ReceiveMessage(ctx, input)
	if err != nil {
		return nil, err
	}

	msgs := make([]QueueMessage, 0, len(out.Messages))
	for _, msg := range out.Messages {
		if msg.ReceiptHandle == nil || msg.Body == nil {
			continue
		}
		id := ""
		if msg.MessageId != nil {
			id = *msg.MessageId
		}
		msgs = append(msgs, QueueMessage{
			ID:            id,
			ReceiptHandle: *msg.ReceiptHandle,
			Body:          *msg.Body,
		})
	}

	return msgs, nil
}

func (q *SQSQueue) Delete(ctx context.Context, receiptHandle string) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	_, err := q.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(q.queueURL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	return err
}

func (q *SQSQueue) ExtendVisibility(ctx context.Context, receiptHandle string, timeout time.Duration) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	timeoutSec := int32(timeout.Seconds())
	if timeoutSec > 43200 {
		timeoutSec = 43200 // SQS max is 12 hours
	}
	_, err := q.client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:          aws.String(q.queueURL),
		ReceiptHandle:     aws.String(receiptHandle),
		VisibilityTimeout: timeoutSec,
	})
	return err
}

func (q *SQSQueue) DeleteBatch(ctx context.Context, receiptHandles []string) (succeeded int, failed []string, err error) {
	if len(receiptHandles) == 0 {
		return 0, nil, nil
	}

	// SQS allows max 10 messages per batch
	for i := 0; i < len(receiptHandles); i += 10 {
		end := i + 10
		if end > len(receiptHandles) {
			end = len(receiptHandles)
		}
		batch := receiptHandles[i:end]

		entries := make([]sqsTypes.DeleteMessageBatchRequestEntry, len(batch))
		idToHandle := make(map[string]string, len(batch))
		for j, handle := range batch {
			entryID := fmt.Sprintf("%d", i+j)
			entries[j] = sqsTypes.DeleteMessageBatchRequestEntry{
				Id:            aws.String(entryID),
				ReceiptHandle: aws.String(handle),
			}
			idToHandle[entryID] = handle
		}

		out, batchErr := q.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
			QueueUrl: aws.String(q.queueURL),
			Entries:  entries,
		})
		if batchErr != nil {
			err = batchErr
			failed = append(failed, batch...)
			continue
		}

		succeeded += len(out.Successful)
		if len(out.Failed) > 0 {
			for _, failure := range out.Failed {
				if failure.Id == nil {
					continue
				}
				if handle, ok := idToHandle[*failure.Id]; ok {
					failed = append(failed, handle)
				}
			}
			if err == nil {
				err = fmt.Errorf("batch delete failed for %d messages", len(out.Failed))
			}
		}
	}

	return succeeded, failed, err
}

func (q *SQSQueue) ExtendVisibilityBatch(ctx context.Context, receiptHandles []string, timeout time.Duration) (succeeded int, failed int, err error) {
	if len(receiptHandles) == 0 {
		return 0, 0, nil
	}

	timeoutSec := int32(timeout.Seconds())
	if timeoutSec > 43200 {
		timeoutSec = 43200
	}

	// SQS allows max 10 messages per batch
	for i := 0; i < len(receiptHandles); i += 10 {
		end := i + 10
		if end > len(receiptHandles) {
			end = len(receiptHandles)
		}
		batch := receiptHandles[i:end]

		entries := make([]sqsTypes.ChangeMessageVisibilityBatchRequestEntry, len(batch))
		for j, handle := range batch {
			entries[j] = sqsTypes.ChangeMessageVisibilityBatchRequestEntry{
				Id:                aws.String(fmt.Sprintf("%d", i+j)),
				ReceiptHandle:     aws.String(handle),
				VisibilityTimeout: timeoutSec,
			}
		}

		out, batchErr := q.client.ChangeMessageVisibilityBatch(ctx, &sqs.ChangeMessageVisibilityBatchInput{
			QueueUrl: aws.String(q.queueURL),
			Entries:  entries,
		})
		if batchErr != nil {
			err = batchErr
			failed += len(batch)
			continue
		}

		succeeded += len(out.Successful)
		failed += len(out.Failed)
	}

	return succeeded, failed, err
}
