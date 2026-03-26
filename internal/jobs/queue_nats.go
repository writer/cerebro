package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Compile-time check that NATSQueue satisfies the Queue interface.
var _ Queue = (*NATSQueue)(nil)

// NATSQueue implements Queue using NATS JetStream pull-based consumers.
type NATSQueue struct {
	js       nats.JetStreamContext
	stream   string
	subject  string
	consumer string

	// pending maps receipt handles to the underlying NATS messages so that
	// Delete / ExtendVisibility can call Ack / InProgress on the original
	// *nats.Msg.  The map is pruned on Delete.
	pending sync.Map // map[string]*nats.Msg
}

// NATSQueueConfig holds configuration for a NATS JetStream queue.
type NATSQueueConfig struct {
	// Stream is the JetStream stream name.
	Stream string
	// Subject is the NATS subject to publish/subscribe on.
	Subject string
	// Consumer is the durable consumer name used for pull subscriptions.
	Consumer string
	// CreateStream controls whether the constructor will call AddStream to
	// ensure the stream exists.  Useful for development and tests; in
	// production the stream is typically provisioned externally.
	CreateStream bool
}

// NewNATSQueue returns a new NATSQueue.  If config.CreateStream is true, it
// calls EnsureStream to create the stream (idempotent – existing streams are
// left untouched).
func NewNATSQueue(js nats.JetStreamContext, config NATSQueueConfig) *NATSQueue {
	q := &NATSQueue{
		js:       js,
		stream:   config.Stream,
		subject:  config.Subject,
		consumer: config.Consumer,
	}
	if config.CreateStream {
		// Best-effort: callers who need hard guarantees should call
		// EnsureStream explicitly and inspect the error.
		_ = q.EnsureStream(context.Background())
	}
	return q
}

// EnsureStream creates the JetStream stream if it does not already exist.
// An existing stream with the same name is left unchanged.
func (q *NATSQueue) EnsureStream(_ context.Context) error {
	_, err := q.js.AddStream(&nats.StreamConfig{
		Name:      q.stream,
		Subjects:  []string{q.subject},
		Retention: nats.WorkQueuePolicy,
	})
	if err != nil {
		return fmt.Errorf("nats: ensure stream %s: %w", q.stream, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Queue implementation
// ---------------------------------------------------------------------------

// Enqueue publishes msg to the JetStream subject.
func (q *NATSQueue) Enqueue(ctx context.Context, msg JobMessage) error {
	return q.EnqueueWithDelay(ctx, msg, 0)
}

// EnqueueWithDelay publishes msg to the JetStream subject.
//
// NOTE: NATS JetStream does not support per-message publish-time delays the
// way SQS does.  The delay parameter is therefore *not* applied at publish
// time.  For retry back-off, the consumer side uses NakWithDelay when
// redelivering messages.  Callers that depend on publish-time delays should
// be aware of this limitation.
func (q *NATSQueue) EnqueueWithDelay(_ context.Context, msg JobMessage, _ time.Duration) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("nats: marshal job message: %w", err)
	}

	dedupID := deduplicationIDForMessage(msg, time.Now())

	_, err = q.js.Publish(q.subject, body, nats.MsgId(dedupID))
	if err != nil {
		return fmt.Errorf("nats: publish to %s: %w", q.subject, err)
	}
	return nil
}

// Receive fetches up to maxMessages from the pull consumer.
//
// Each returned QueueMessage has a randomly-generated ReceiptHandle that maps
// to the underlying *nats.Msg stored in an internal sync.Map.  This handle is
// used by Delete and ExtendVisibility to locate the original message.
func (q *NATSQueue) Receive(_ context.Context, maxMessages int, waitTime time.Duration, _ time.Duration) ([]QueueMessage, error) {
	if maxMessages < 1 {
		maxMessages = 1
	}

	sub, err := q.js.PullSubscribe(q.subject, q.consumer, nats.BindStream(q.stream))
	if err != nil {
		return nil, fmt.Errorf("nats: pull subscribe %s/%s: %w", q.stream, q.consumer, err)
	}

	msgs, err := sub.Fetch(maxMessages, nats.MaxWait(waitTime))
	if err != nil {
		// Timeout / no messages is not an error for the caller – it just
		// means there is nothing to process right now.
		if errors.Is(err, nats.ErrTimeout) {
			return nil, nil
		}
		return nil, fmt.Errorf("nats: fetch from %s/%s: %w", q.stream, q.consumer, err)
	}

	result := make([]QueueMessage, 0, len(msgs))
	for _, m := range msgs {
		handle := uuid.New().String()
		q.pending.Store(handle, m)

		id := ""
		if m.Header != nil {
			id = m.Header.Get(nats.MsgIdHdr)
		}

		result = append(result, QueueMessage{
			ID:            id,
			ReceiptHandle: handle,
			Body:          string(m.Data),
		})
	}

	return result, nil
}

// Delete acknowledges the message associated with receiptHandle and removes it
// from the pending map.
func (q *NATSQueue) Delete(_ context.Context, receiptHandle string) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	v, ok := q.pending.LoadAndDelete(receiptHandle)
	if !ok {
		return fmt.Errorf("nats: unknown receipt handle %q", receiptHandle)
	}
	msg := v.(*nats.Msg)
	if err := msg.Ack(); err != nil {
		return fmt.Errorf("nats: ack message: %w", err)
	}
	return nil
}

// DeleteBatch acknowledges all messages identified by receiptHandles.
func (q *NATSQueue) DeleteBatch(ctx context.Context, receiptHandles []string) (succeeded int, failed []string, err error) {
	if len(receiptHandles) == 0 {
		return 0, nil, nil
	}

	for _, h := range receiptHandles {
		if delErr := q.Delete(ctx, h); delErr != nil {
			failed = append(failed, h)
			err = delErr
		} else {
			succeeded++
		}
	}
	return succeeded, failed, err
}

// ExtendVisibility resets the redelivery timer for the message associated with
// receiptHandle by calling InProgress on the underlying *nats.Msg.  The
// timeout parameter is accepted for interface compatibility but is not used;
// NATS resets the ack-wait window configured on the consumer.
func (q *NATSQueue) ExtendVisibility(_ context.Context, receiptHandle string, _ time.Duration) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	v, ok := q.pending.Load(receiptHandle)
	if !ok {
		return fmt.Errorf("nats: unknown receipt handle %q", receiptHandle)
	}
	msg := v.(*nats.Msg)
	if err := msg.InProgress(); err != nil {
		return fmt.Errorf("nats: in-progress for receipt %s: %w", receiptHandle, err)
	}
	return nil
}

// ExtendVisibilityBatch calls ExtendVisibility for each receipt handle.
func (q *NATSQueue) ExtendVisibilityBatch(ctx context.Context, receiptHandles []string, timeout time.Duration) (succeeded int, failed int, err error) {
	if len(receiptHandles) == 0 {
		return 0, 0, nil
	}

	for _, h := range receiptHandles {
		if extErr := q.ExtendVisibility(ctx, h, timeout); extErr != nil {
			failed++
			err = extErr
		} else {
			succeeded++
		}
	}
	return succeeded, failed, err
}

// Retry schedules redelivery using JetStream's NakWithDelay support.
func (q *NATSQueue) Retry(_ context.Context, receiptHandle string, delay time.Duration) error {
	if receiptHandle == "" {
		return fmt.Errorf("receipt handle required")
	}
	v, ok := q.pending.Load(receiptHandle)
	if !ok {
		return fmt.Errorf("nats: unknown receipt handle %q", receiptHandle)
	}
	msg := v.(*nats.Msg)
	if err := msg.NakWithDelay(delay); err != nil {
		return fmt.Errorf("nats: retry receipt %s: %w", receiptHandle, err)
	}
	q.pending.Delete(receiptHandle)
	return nil
}
