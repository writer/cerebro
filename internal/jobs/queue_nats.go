package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// Compile-time check that NATSQueue satisfies the Queue interface.
var _ Queue = (*NATSQueue)(nil)

// NATSQueue implements Queue using NATS JetStream pull-based consumers.
type NATSQueue struct {
	js           nats.JetStreamContext
	stream       string
	subject      string
	consumer     string
	createStream bool

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
		js:           js,
		stream:       config.Stream,
		subject:      config.Subject,
		consumer:     config.Consumer,
		createStream: config.CreateStream,
	}
	if config.CreateStream {
		// Best-effort: callers who need hard guarantees should call
		// EnsureStream explicitly and inspect the error.
		_ = q.EnsureStream(context.Background())
	}
	return q
}

// EnsureStream verifies the JetStream stream exists and is compatible. When
// CreateStream was enabled on construction, a missing stream is created and an
// existing stream may be updated to include the queue subject.
func (q *NATSQueue) EnsureStream(_ context.Context) error {
	if q == nil || q.js == nil {
		return fmt.Errorf("nats: jetstream context is required")
	}

	info, err := q.js.StreamInfo(q.stream)
	if err == nil {
		if streamHasSubject(info.Config.Subjects, q.subject) {
			return nil
		}
		if !q.createStream {
			return fmt.Errorf("nats: stream %s does not include subject %s", q.stream, q.subject)
		}
		updated := info.Config
		updated.Subjects = append(append([]string(nil), info.Config.Subjects...), q.subject)
		if _, err := q.js.UpdateStream(&updated); err != nil {
			return fmt.Errorf("nats: update stream %s subjects: %w", q.stream, err)
		}
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("nats: lookup stream %s: %w", q.stream, err)
	}
	if !q.createStream {
		return fmt.Errorf("nats: stream %s not found", q.stream)
	}

	_, err = q.js.AddStream(&nats.StreamConfig{
		Name:      q.stream,
		Subjects:  []string{q.subject},
		Retention: nats.WorkQueuePolicy,
	})
	if err != nil {
		return fmt.Errorf("nats: create stream %s: %w", q.stream, err)
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
// way lease/visibility based queues often do. The delay parameter is therefore *not* applied at publish
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
func (q *NATSQueue) Receive(_ context.Context, maxMessages int, waitTime time.Duration, visibilityTimeout time.Duration) ([]QueueMessage, error) {
	if maxMessages < 1 {
		maxMessages = 1
	}
	if visibilityTimeout <= 0 {
		visibilityTimeout = 30 * time.Second
	}

	if err := q.ensureConsumer(visibilityTimeout); err != nil {
		return nil, err
	}

	sub, err := q.js.PullSubscribe(q.subject, q.consumer, nats.Bind(q.stream, q.consumer))
	if err != nil {
		return nil, fmt.Errorf("nats: pull subscribe %s/%s: %w", q.stream, q.consumer, err)
	}
	defer func() { _ = sub.Unsubscribe() }()

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
// receiptHandle by calling InProgress on the underlying *nats.Msg. The timeout
// value is applied when Receive provisions the pull consumer's AckWait; each
// InProgress call resets that configured window.
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

func (q *NATSQueue) ensureConsumer(visibilityTimeout time.Duration) error {
	if q == nil || q.js == nil {
		return fmt.Errorf("nats: jetstream context is required")
	}
	if strings.TrimSpace(q.consumer) == "" {
		return fmt.Errorf("nats: consumer is required")
	}

	info, err := q.js.ConsumerInfo(q.stream, q.consumer)
	if errors.Is(err, nats.ErrConsumerNotFound) {
		_, err = q.js.AddConsumer(q.stream, &nats.ConsumerConfig{
			Durable:       q.consumer,
			AckPolicy:     nats.AckExplicitPolicy,
			AckWait:       visibilityTimeout,
			FilterSubject: q.subject,
			DeliverPolicy: nats.DeliverAllPolicy,
		})
		if err != nil {
			return fmt.Errorf("nats: create consumer %s/%s: %w", q.stream, q.consumer, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("nats: lookup consumer %s/%s: %w", q.stream, q.consumer, err)
	}

	desired := info.Config
	changed := false
	if desired.Durable != q.consumer {
		desired.Durable = q.consumer
		changed = true
	}
	if desired.AckPolicy != nats.AckExplicitPolicy {
		desired.AckPolicy = nats.AckExplicitPolicy
		changed = true
	}
	if desired.AckWait != visibilityTimeout {
		desired.AckWait = visibilityTimeout
		changed = true
	}
	if desired.FilterSubject != q.subject || len(desired.FilterSubjects) > 0 {
		desired.FilterSubject = q.subject
		desired.FilterSubjects = nil
		changed = true
	}
	if !changed {
		return nil
	}

	if _, err := q.js.UpdateConsumer(q.stream, &desired); err != nil {
		return fmt.Errorf("nats: update consumer %s/%s: %w", q.stream, q.consumer, err)
	}
	return nil
}

func streamHasSubject(subjects []string, expected string) bool {
	for _, subject := range subjects {
		if subjectMatchesPattern(subject, expected) {
			return true
		}
	}
	return false
}

func subjectMatchesPattern(pattern, subject string) bool {
	patternParts := strings.Split(pattern, ".")
	subjectParts := strings.Split(subject, ".")

	for idx, token := range patternParts {
		if token == ">" {
			return true
		}
		if idx >= len(subjectParts) {
			return false
		}
		if token != "*" && token != subjectParts[idx] {
			return false
		}
	}

	return len(patternParts) == len(subjectParts)
}
