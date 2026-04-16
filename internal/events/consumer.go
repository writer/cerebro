package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/jsonl"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultConsumerStream              = "ENSEMBLE_TAP"
	defaultConsumerDurable             = "cerebro_graph_builder"
	defaultConsumerSubject             = "ensemble.tap.>"
	defaultConsumerBatchSize           = 50
	defaultConsumerAckWait             = 120 * time.Second
	defaultConsumerFetchTimeout        = 2 * time.Second
	defaultConsumerConnectWait         = 5 * time.Second
	defaultConsumerDropLookback        = 5 * time.Minute
	defaultConsumerDropThreshold       = 1
	defaultConsumerPayloadPreviewBytes = 512
	defaultConsumerInProgressInterval  = 15 * time.Second
	defaultConsumerLagRefreshInterval  = 15 * time.Second
)

type ConsumerConfig struct {
	URLs                []string
	Stream              string
	Subject             string
	Subjects            []string
	Durable             string
	BatchSize           int
	HandlerWorkers      int
	AckWait             time.Duration
	FetchTimeout        time.Duration
	InProgressInterval  time.Duration
	ConnectTimeout      time.Duration
	MaxAckPending       int
	DeadLetterPath      string
	DropHealthLookback  time.Duration
	DropHealthThreshold int
	PayloadPreviewBytes int
	DedupEnabled        bool
	DedupStateFile      string
	DedupStore          executionstore.Store
	DedupTTL            time.Duration
	DedupMaxRecords     int

	AuthMode string
	Username string
	Password string
	NKeySeed string
	UserJWT  string

	TLSEnabled            bool
	TLSCAFile             string
	TLSCertFile           string
	TLSKeyFile            string
	TLSServerName         string
	TLSInsecureSkipVerify bool
	AllowInsecureTLS      bool
}

type EventHandler func(context.Context, CloudEvent) error

type retryWithDelayError interface {
	error
	RetryDelay() time.Duration
}

type delayedRetryError struct {
	err   error
	delay time.Duration
}

func (e delayedRetryError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e delayedRetryError) Unwrap() error {
	return e.err
}

func (e delayedRetryError) RetryDelay() time.Duration {
	return e.delay
}

func RetryWithDelay(err error, delay time.Duration) error {
	if err == nil || delay <= 0 {
		return err
	}
	return delayedRetryError{
		err:   err,
		delay: delay,
	}
}

func retryDelay(err error) (time.Duration, bool) {
	var delayed retryWithDelayError
	if !errors.As(err, &delayed) {
		return 0, false
	}
	delay := delayed.RetryDelay()
	if delay <= 0 {
		return 0, false
	}
	return delay, true
}

type Consumer struct {
	logger  *slog.Logger
	config  ConsumerConfig
	handler EventHandler
	dlq     *consumerDeadLetterSink
	nc      *nats.Conn
	js      nats.JetStreamContext
	sub     *nats.Subscription

	stopCh          chan struct{}
	drainCh         chan struct{}
	stopOnce        sync.Once
	drainOnce       sync.Once
	closeMu         sync.Mutex
	closed          bool
	wg              sync.WaitGroup
	dropMu          sync.Mutex
	drops           []time.Time
	lastDropReason  string
	lastDropAt      time.Time
	statusMu        sync.RWMutex
	lastProcessedAt time.Time
	lastEventTime   time.Time
	consumerLag     int
	consumerLagAge  time.Duration
	deduper         *consumerProcessedEventDeduper
}

type ConsumerHealthSnapshot struct {
	RecentDropped   int           `json:"recent_dropped"`
	Threshold       int           `json:"threshold"`
	Lookback        time.Duration `json:"lookback"`
	LastDropAt      time.Time     `json:"last_drop_at,omitempty"`
	LastDropReason  string        `json:"last_drop_reason,omitempty"`
	LastProcessedAt time.Time     `json:"last_processed_at,omitempty"`
	LastEventTime   time.Time     `json:"last_event_time,omitempty"`
	ConsumerLag     int           `json:"consumer_lag"`
	ConsumerLagAge  time.Duration `json:"consumer_lag_seconds"`
	GraphStaleness  time.Duration `json:"graph_staleness"`
}

func NewJetStreamConsumer(cfg ConsumerConfig, logger *slog.Logger, handler EventHandler) (*Consumer, error) {
	if handler == nil {
		return nil, errors.New("consumer handler is required")
	}
	config := cfg.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	dlq, err := newConsumerDeadLetterSink(config.DeadLetterPath)
	if err != nil {
		return nil, err
	}
	var deduper *consumerProcessedEventDeduper
	if config.DedupEnabled {
		if config.DedupStore != nil {
			deduper = newConsumerProcessedEventDeduperWithStore(config.DedupStore, config.Stream, config.Durable, config.DedupTTL, config.DedupMaxRecords)
		} else {
			deduper, err = newConsumerProcessedEventDeduper(config.DedupStateFile, config.Stream, config.Durable, config.DedupTTL, config.DedupMaxRecords)
			if err != nil {
				return nil, err
			}
		}
	}

	base := JetStreamConfig{
		URLs:                  config.URLs,
		ConnectTimeout:        config.ConnectTimeout,
		AuthMode:              config.AuthMode,
		Username:              config.Username,
		Password:              config.Password,
		NKeySeed:              config.NKeySeed,
		UserJWT:               config.UserJWT,
		TLSEnabled:            config.TLSEnabled,
		TLSCAFile:             config.TLSCAFile,
		TLSCertFile:           config.TLSCertFile,
		TLSKeyFile:            config.TLSKeyFile,
		TLSServerName:         config.TLSServerName,
		TLSInsecureSkipVerify: config.TLSInsecureSkipVerify,
		AllowInsecureTLS:      config.AllowInsecureTLS,
	}.withDefaults()

	natsOptions, err := base.natsOptions()
	if err != nil {
		return nil, err
	}

	nc, err := nats.Connect(strings.Join(config.URLs, ","), natsOptions...)
	if err != nil {
		return nil, fmt.Errorf("connect consumer to nats: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initialize jetstream consumer context: %w", err)
	}

	c := &Consumer{
		logger:  logger,
		config:  config,
		handler: handler,
		dlq:     dlq,
		deduper: deduper,
		nc:      nc,
		js:      js,
		stopCh:  make(chan struct{}),
		drainCh: make(chan struct{}),
	}

	if err := c.ensureStream(); err != nil {
		nc.Close()
		return nil, err
	}
	subjects := consumerSubjects(config)
	if err := c.ensureCompatibleConsumer(subjects); err != nil {
		nc.Close()
		return nil, err
	}
	sub, err := c.pullSubscribe(subjects)
	if errors.Is(err, nats.ErrSubjectMismatch) {
		c.logger.Warn("recreating incompatible jetstream durable consumer",
			"stream", config.Stream,
			"durable", config.Durable,
			"subjects", subjects,
		)
		if deleteErr := c.js.DeleteConsumer(config.Stream, config.Durable); deleteErr != nil && !errors.Is(deleteErr, nats.ErrConsumerNotFound) {
			nc.Close()
			return nil, fmt.Errorf("delete incompatible consumer %s/%s: %w", config.Stream, config.Durable, deleteErr)
		}
		sub, err = c.pullSubscribe(subjects)
	}
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("create consumer subscription: %w", err)
	}
	c.sub = sub
	c.wg.Add(1)
	go c.run()
	return c, nil
}

func (c *Consumer) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	c.drainOnce.Do(func() {
		close(c.drainCh)
	})
	c.wg.Wait()
	return c.cleanup()
}

func (c *Consumer) Drain(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.drainOnce.Do(func() {
		close(c.drainCh)
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.wg.Wait()
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Consumer) cleanup() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true

	var closeErr error
	if c.sub != nil {
		if err := c.sub.Unsubscribe(); err != nil && !errors.Is(err, nats.ErrBadSubscription) {
			closeErr = errors.Join(closeErr, fmt.Errorf("unsubscribe consumer: %w", err))
		}
	}
	if c.nc != nil {
		if err := c.nc.Drain(); err != nil && !errors.Is(err, nats.ErrConnectionClosed) {
			closeErr = errors.Join(closeErr, fmt.Errorf("drain consumer nats connection: %w", err))
		}
		c.nc.Close()
	}
	if c.deduper != nil {
		if err := c.deduper.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close consumer dedupe store: %w", err))
		}
	}
	return closeErr
}

func (c *Consumer) run() {
	defer c.wg.Done()
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-runCtx.Done():
		}
	}()

	lastLagRefresh := time.Time{}
	fetchBatchSize := initialAdaptiveConsumerBatchSize(c.config.BatchSize)
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.drainCh:
			c.refreshLagMetrics(time.Now().UTC())
			return
		default:
		}

		_, fetchSpan := c.startTracingSpan(runCtx, "cerebro.event.fetch",
			attribute.String("cerebro.stream", c.config.Stream),
			attribute.String("cerebro.durable", c.config.Durable),
			attribute.Int("cerebro.event.batch.requested", fetchBatchSize),
		)
		msgs, err := c.sub.Fetch(fetchBatchSize, nats.MaxWait(c.config.FetchTimeout))
		if err != nil {
			if !errors.Is(err, nats.ErrTimeout) {
				consumerRecordSpanError(fetchSpan, err)
			}
			fetchSpan.End()
			if errors.Is(err, nats.ErrTimeout) {
				if time.Since(lastLagRefresh) >= defaultConsumerLagRefreshInterval {
					c.refreshLagMetrics(time.Now().UTC())
					lastLagRefresh = time.Now().UTC()
				}
				continue
			}
			c.logger.Warn("tap consumer fetch failed", "error", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		fetchSpan.SetAttributes(attribute.Int("cerebro.event.batch.received", len(msgs)))
		fetchSpan.End()
		c.refreshLagMetrics(time.Now().UTC())
		lastLagRefresh = time.Now().UTC()

		batch := make([]consumerPipelineMessage, len(msgs))
		for _, msg := range msgs {
			if meta, err := msg.Metadata(); err == nil && meta != nil && meta.NumDelivered > 1 {
				metrics.RecordNATSConsumerRedelivery(c.config.Stream, c.config.Durable)
			}
		}
		for i, msg := range msgs {
			msg := msg
			batch[i] = consumerPipelineMessage{
				index:   i,
				subject: msg.Subject,
				payload: msg.Data,
				ack:     func() error { return msg.Ack() },
				nak:     func() error { return msg.Nak() },
				nakWithDelay: func(delay time.Duration) error {
					return msg.NakWithDelay(delay)
				},
				inProgress: func() error { return msg.InProgress() },
			}
		}
		// The fetch span is ended before batch processing starts, so the batch
		// work must stay attached to the long-lived run span instead.
		backpressured := c.processBatch(runCtx, batch)
		fetchBatchSize = nextAdaptiveConsumerBatchSize(fetchBatchSize, c.config.BatchSize, len(batch), backpressured)
	}
}

type consumerMessageResult struct {
	Processed   bool
	EventTime   time.Time
	ProcessedAt time.Time
}

type consumerPipelineMessage struct {
	index        int
	subject      string
	payload      []byte
	ack          func() error
	nak          func() error
	nakWithDelay func(time.Duration) error
	inProgress   func() error
}

type consumerDecodedMessage struct {
	message consumerPipelineMessage
	event   CloudEvent
	ctx     context.Context
	handled bool
	result  consumerMessageResult
}

func (c *Consumer) handleMessage(ctx context.Context, subject string, payload []byte, ack func() error, nak func() error, inProgress func() error) consumerMessageResult {
	decoded := c.decodePipelineMessage(ctx, consumerPipelineMessage{
		subject:    subject,
		payload:    payload,
		ack:        ack,
		nak:        nak,
		inProgress: inProgress,
	})
	if decoded.handled {
		return decoded.result
	}
	return c.handleDecodedMessage(decoded)
}

func (c *Consumer) decodePipelineMessage(ctx context.Context, message consumerPipelineMessage) consumerDecodedMessage {
	envelope := consumerTraceEnvelopeFromPayload(message.payload)
	traceCtx := consumerTraceContext(ctx, envelope.TraceParent)
	decodeCtx, decodeSpan := c.startTracingSpan(traceCtx, "cerebro.event.decode", c.consumerEnvelopeAttributes(message, envelope)...)
	defer decodeSpan.End()

	decoded := consumerDecodedMessage{
		message: message,
		ctx:     decodeCtx,
	}
	if err := json.Unmarshal(message.payload, &decoded.event); err != nil {
		consumerRecordSpanError(decodeSpan, err)
		preview := payloadPreview(message.payload, c.config.PayloadPreviewBytes)
		if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
			RecordedAt: time.Now().UTC(),
			Stream:     c.config.Stream,
			Durable:    c.config.Durable,
			Subject:    message.subject,
			Reason:     "malformed",
			Error:      err.Error(),
			Payload:    string(message.payload),
		}); dlqErr != nil {
			c.logger.Error("tap consumer failed to dead-letter malformed cloud event; message requeued",
				"error", dlqErr,
				"subject", message.subject,
				"stream", c.config.Stream,
				"durable", c.config.Durable,
				"payload_preview", preview,
			)
			if nakErr := message.nak(); nakErr != nil {
				c.logger.Warn("tap consumer nak failed after dead-letter error", "error", nakErr, "subject", message.subject)
			}
			decoded.handled = true
			return decoded
		}
		c.logger.Error("tap consumer dead-lettered malformed cloud event",
			"error", err,
			"subject", message.subject,
			"stream", c.config.Stream,
			"durable", c.config.Durable,
			"payload_preview", preview,
		)
		c.recordDropped("malformed", time.Now().UTC())
		if err := message.ack(); err != nil {
			c.logger.Warn("tap consumer ack failed after dead-lettering malformed event", "error", err, "subject", message.subject)
		}
		decoded.handled = true
		return decoded
	}
	decoded.ctx = decodeCtx
	decodeSpan.SetAttributes(c.consumerEventAttributes(message, decoded.event)...)
	return decoded
}

func (c *Consumer) handleDecodedMessage(decoded consumerDecodedMessage) consumerMessageResult {
	evt := decoded.event
	message := decoded.message
	ingestCtx, ingestSpan := c.startTracingSpan(decoded.ctx, "cerebro.event.ingest", c.consumerEventAttributes(message, evt)...)
	defer ingestSpan.End()

	dedupCtx, dedupSpan := c.startTracingSpan(ingestCtx, "cerebro.event.dedup", c.consumerEventAttributes(message, evt)...)
	if c.deduper != nil {
		record, hashMismatch, err := c.deduper.Lookup(dedupCtx, evt, message.payload, time.Now().UTC())
		if err != nil {
			consumerRecordSpanError(dedupSpan, err)
			c.logger.Warn("tap consumer dedupe lookup failed; continuing without duplicate suppression",
				"error", err,
				"event_id", evt.ID,
				"event_type", evt.Type,
			)
		} else if record != nil {
			if hashMismatch {
				if err := c.deduper.Forget(dedupCtx, evt); err != nil {
					consumerRecordSpanError(dedupSpan, err)
					c.logger.Error("tap consumer failed to clear conflicting dedupe state; message requeued",
						"error", err,
						"event_id", evt.ID,
						"event_type", evt.Type,
						"source", evt.Source,
						"processed_at", record.ProcessedAt.UTC().Format(time.RFC3339Nano),
					)
					dedupSpan.End()
					if nakErr := c.consumerAckWithTracing(ingestCtx, message, evt, "nak", message.nak); nakErr != nil {
						c.logger.Warn("tap consumer nak failed after dedupe hash mismatch state clear failure", "error", nakErr, "event_type", evt.Type)
					}
					return consumerMessageResult{}
				}
				if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
					RecordedAt: time.Now().UTC(),
					Stream:     c.config.Stream,
					Durable:    c.config.Durable,
					Subject:    message.subject,
					Reason:     "dedupe_hash_mismatch",
					Error:      fmt.Sprintf("duplicate event key matched different payload hash: processed_at=%s", record.ProcessedAt.UTC().Format(time.RFC3339Nano)),
					Payload:    string(message.payload),
				}); dlqErr != nil {
					consumerRecordSpanError(dedupSpan, dlqErr)
					c.logger.Error("tap consumer failed to dead-letter duplicate hash mismatch; message requeued",
						"error", dlqErr,
						"event_id", evt.ID,
						"event_type", evt.Type,
						"source", evt.Source,
					)
					dedupSpan.End()
					if nakErr := c.consumerAckWithTracing(ingestCtx, message, evt, "nak", message.nak); nakErr != nil {
						c.logger.Warn("tap consumer nak failed after dedupe hash mismatch dead-letter error", "error", nakErr, "event_type", evt.Type)
					}
					return consumerMessageResult{}
				}
				c.logger.Error("tap consumer dead-lettered duplicate event key with different payload hash",
					"event_id", evt.ID,
					"event_type", evt.Type,
					"source", evt.Source,
					"processed_at", record.ProcessedAt.UTC().Format(time.RFC3339Nano),
				)
				dedupSpan.End()
				if nakErr := c.consumerAckWithTracing(ingestCtx, message, evt, "nak", message.nak); nakErr != nil {
					c.logger.Warn("tap consumer nak failed after clearing dedupe hash mismatch state", "error", nakErr, "event_type", evt.Type)
				}
				return consumerMessageResult{}
			}
			dedupSpan.SetAttributes(attribute.Bool("cerebro.event.duplicate", true))
			if err := c.deduper.ObserveDuplicate(dedupCtx, evt, time.Now().UTC()); err != nil {
				consumerRecordSpanError(dedupSpan, err)
				c.logger.Warn("tap consumer failed to refresh duplicate dedupe state",
					"error", err,
					"event_id", evt.ID,
					"event_type", evt.Type,
				)
			}
			metrics.RecordNATSConsumerDeduplicated(c.config.Stream, c.config.Durable)
			dedupSpan.End()
			if err := c.consumerAckWithTracing(ingestCtx, message, evt, "ack", message.ack); err != nil {
				c.logger.Warn("tap consumer ack failed after duplicate suppression", "error", err, "event_type", evt.Type)
			}
			return consumerMessageResult{}
		}
	}
	dedupSpan.End()

	stopHeartbeat := c.startInProgressHeartbeat(ingestCtx, message.inProgress)
	defer stopHeartbeat()

	handlerCtx, handlerSpan := c.startTracingSpan(ingestCtx, "cerebro.event.handle", c.consumerEventAttributes(message, evt)...)
	handlerCtx = telemetry.ContextWithAttributes(handlerCtx, c.consumerEventAttributes(message, evt)...)
	if err := c.handler(handlerCtx, evt); err != nil {
		consumerRecordSpanError(handlerSpan, err)
		if delay, ok := retryDelay(err); ok && message.nakWithDelay != nil {
			handlerSpan.End()
			c.logger.Info("tap consumer handler deferred; message requeued with delay",
				"error", err,
				"event_type", evt.Type,
				"delay", delay,
			)
			if nakErr := c.consumerAckWithTracing(ingestCtx, message, evt, "nak_with_delay", func() error {
				return message.nakWithDelay(delay)
			}); nakErr != nil {
				c.logger.Warn("tap consumer delayed nak failed", "error", nakErr, "event_type", evt.Type, "delay", delay)
			}
			return consumerMessageResult{}
		}
		handlerSpan.End()
		c.logger.Warn("tap consumer handler failed; message requeued", "error", err, "event_type", evt.Type)
		if nakErr := c.consumerAckWithTracing(ingestCtx, message, evt, "nak", message.nak); nakErr != nil {
			c.logger.Warn("tap consumer nak failed", "error", nakErr, "event_type", evt.Type)
		}
		return consumerMessageResult{}
	}
	handlerSpan.End()

	processedAt := time.Now().UTC()
	metrics.RecordNATSConsumerProcessed(c.config.Stream, c.config.Durable)
	if c.deduper != nil {
		if err := c.deduper.Remember(ingestCtx, evt, message.payload, processedAt); err != nil {
			c.logger.Warn("tap consumer failed to persist processed event dedupe state",
				"error", err,
				"event_id", evt.ID,
				"event_type", evt.Type,
			)
		}
	}
	if err := c.consumerAckWithTracing(ingestCtx, message, evt, "ack", message.ack); err != nil {
		c.logger.Warn("tap consumer ack failed", "error", err, "event_type", evt.Type)
	}
	return consumerMessageResult{
		Processed:   true,
		EventTime:   evt.Time.UTC(),
		ProcessedAt: processedAt,
	}
}

func (c *Consumer) processBatch(ctx context.Context, messages []consumerPipelineMessage) bool {
	return c.processBatchWithPipeline(ctx, messages)
}

func consumerHandlerWorkers(cfg ConsumerConfig) int {
	if cfg.HandlerWorkers > 0 {
		if cfg.BatchSize > 0 && cfg.HandlerWorkers > cfg.BatchSize {
			return cfg.BatchSize
		}
		return cfg.HandlerWorkers
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if cfg.BatchSize > 0 && workers > cfg.BatchSize {
		return cfg.BatchSize
	}
	return workers
}

func consumerHandlerQueueDepth(cfg ConsumerConfig, workers int) int {
	if workers <= 0 {
		return 1
	}
	depth := cfg.BatchSize / workers
	if depth < 1 {
		depth = 1
	}
	return depth
}

func initialAdaptiveConsumerBatchSize(maxBatchSize int) int {
	if maxBatchSize <= 1 {
		return 1
	}
	initial := maxBatchSize / 4
	if initial < 1 {
		initial = 1
	}
	if initial > 8 {
		initial = 8
	}
	return initial
}

func nextAdaptiveConsumerBatchSize(current, maxBatchSize, fetched int, backpressured bool) int {
	if maxBatchSize <= 1 {
		return 1
	}
	if current <= 0 {
		current = initialAdaptiveConsumerBatchSize(maxBatchSize)
	}
	if backpressured {
		next := current / 2
		if next < 1 {
			next = 1
		}
		return next
	}
	if fetched >= current && current < maxBatchSize {
		next := current * 2
		if next > maxBatchSize {
			next = maxBatchSize
		}
		return next
	}
	return current
}

func consumerShardIndex(evt CloudEvent, workers int) int {
	if workers <= 1 {
		return 0
	}
	key := consumerOrderingKey(evt)
	if key == "" {
		return 0
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(key))
	hash := int(hasher.Sum32() & math.MaxInt32)
	return hash % workers
}

func consumerOrderingKey(evt CloudEvent) string {
	tenantID := strings.TrimSpace(evt.TenantID)
	entityID := extractEntityID(evt.Data)
	if entityID != "" {
		return tenantID + "|" + entityID
	}
	if key, ok := consumerProcessedEventKey(evt); ok {
		return key
	}
	if subject := strings.TrimSpace(evt.Subject); subject != "" {
		return tenantID + "|" + subject
	}
	if eventID := strings.TrimSpace(evt.ID); eventID != "" {
		return tenantID + "|" + eventID
	}
	return strings.TrimSpace(evt.Type)
}

type consumerTraceEnvelope struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Type        string `json:"type"`
	Subject     string `json:"subject,omitempty"`
	TenantID    string `json:"tenant_id"`
	TraceParent string `json:"traceparent"`
}

func consumerTraceEnvelopeFromPayload(payload []byte) consumerTraceEnvelope {
	var envelope consumerTraceEnvelope
	_ = json.Unmarshal(payload, &envelope)
	return envelope
}

func consumerTraceContext(ctx context.Context, traceParent string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	traceParent = strings.TrimSpace(traceParent)
	if traceParent == "" {
		return ctx
	}
	carrier := propagation.MapCarrier{"traceparent": traceParent}
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

func (c *Consumer) consumerEnvelopeAttributes(message consumerPipelineMessage, envelope consumerTraceEnvelope) []attribute.KeyValue {
	return c.consumerTraceAttributes(
		message.subject,
		len(message.payload),
		envelope.ID,
		envelope.Source,
		envelope.Type,
		envelope.Subject,
		envelope.TenantID,
	)
}

func (c *Consumer) consumerEventAttributes(message consumerPipelineMessage, evt CloudEvent) []attribute.KeyValue {
	return c.consumerTraceAttributes(
		message.subject,
		len(message.payload),
		evt.ID,
		evt.Source,
		evt.Type,
		evt.Subject,
		evt.TenantID,
	)
}

func (c *Consumer) consumerTraceAttributes(subject string, payloadSize int, eventID, source, eventType, eventSubject, tenantID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("cerebro.stream", c.config.Stream),
		attribute.String("cerebro.durable", c.config.Durable),
		attribute.String("messaging.system", "nats"),
		attribute.String("messaging.destination.name", strings.TrimSpace(subject)),
		attribute.Int("cerebro.event.payload_bytes", payloadSize),
	}
	if eventID = strings.TrimSpace(eventID); eventID != "" {
		attrs = append(attrs, attribute.String("cerebro.event.id", eventID))
	}
	if source = strings.TrimSpace(source); source != "" {
		attrs = append(attrs, attribute.String("cerebro.event.source", source))
	}
	if eventType = strings.TrimSpace(eventType); eventType != "" {
		attrs = append(attrs, attribute.String("cerebro.event.type", eventType))
	}
	if eventSubject = strings.TrimSpace(eventSubject); eventSubject != "" {
		attrs = append(attrs, attribute.String("cerebro.event.subject", eventSubject))
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		attrs = append(attrs, attribute.String("cerebro.tenant_id", tenantID))
	}
	return attrs
}

func (c *Consumer) startTracingSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	return telemetry.Tracer("cerebro.events").Start(ctx, name, trace.WithAttributes(attrs...))
}

func (c *Consumer) consumerAckWithTracing(ctx context.Context, message consumerPipelineMessage, evt CloudEvent, operation string, fn func() error) error {
	if fn == nil {
		return nil
	}
	_, ackSpan := c.startTracingSpan(ctx, "cerebro.event.ack",
		append(c.consumerEventAttributes(message, evt), attribute.String("cerebro.event.ack_operation", strings.TrimSpace(operation)))...,
	)
	defer ackSpan.End()
	err := fn()
	if err != nil {
		consumerRecordSpanError(ackSpan, err)
	}
	return err
}

func consumerRecordSpanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

func (c *Consumer) recordDropped(reason string, at time.Time) {
	if c == nil {
		return
	}
	at = at.UTC()
	c.dropMu.Lock()
	defer c.dropMu.Unlock()
	c.pruneDropsLocked(at)
	c.drops = append(c.drops, at)
	c.lastDropAt = at
	c.lastDropReason = strings.TrimSpace(reason)
	metrics.NATSConsumerDroppedTotal.WithLabelValues(c.config.Stream, c.config.Durable, strings.TrimSpace(reason)).Inc()
}

func (c *Consumer) HealthSnapshot(now time.Time) ConsumerHealthSnapshot {
	if c == nil {
		return ConsumerHealthSnapshot{}
	}
	now = now.UTC()
	c.dropMu.Lock()
	c.pruneDropsLocked(now)
	dropped := len(c.drops)
	lastDropAt := c.lastDropAt
	lastDropReason := c.lastDropReason
	c.dropMu.Unlock()

	c.statusMu.RLock()
	lastProcessedAt := c.lastProcessedAt
	lastEventTime := c.lastEventTime
	consumerLag := c.consumerLag
	consumerLagAge := c.consumerLagAge
	c.statusMu.RUnlock()

	graphStaleness := time.Duration(0)
	if !lastProcessedAt.IsZero() {
		graphStaleness = now.Sub(lastProcessedAt)
		if graphStaleness < 0 {
			graphStaleness = 0
		}
	}

	return ConsumerHealthSnapshot{
		RecentDropped:   dropped,
		Threshold:       c.config.DropHealthThreshold,
		Lookback:        c.config.DropHealthLookback,
		LastDropAt:      lastDropAt,
		LastDropReason:  lastDropReason,
		LastProcessedAt: lastProcessedAt,
		LastEventTime:   lastEventTime,
		ConsumerLag:     consumerLag,
		ConsumerLagAge:  consumerLagAge,
		GraphStaleness:  graphStaleness,
	}
}

func (c *Consumer) startInProgressHeartbeat(ctx context.Context, inProgress func() error) func() {
	if c == nil || inProgress == nil || c.config.InProgressInterval <= 0 {
		return func() {}
	}
	heartbeatCtx := context.WithoutCancel(ctx)
	stopCh := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(c.config.InProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				if err := inProgress(); err != nil && c.logger != nil {
					c.logger.Debug("tap consumer in-progress heartbeat failed", "error", err, "stream", c.config.Stream, "durable", c.config.Durable)
				}
			}
		}
	}()
	return func() {
		once.Do(func() { close(stopCh) })
	}
}

func (c *Consumer) startBatchInProgressHeartbeat(ctx context.Context, inProgress []func() error) (func(int), func()) {
	if c == nil || c.config.InProgressInterval <= 0 || len(inProgress) == 0 {
		return func(int) {}, func() {}
	}
	heartbeatCtx := context.WithoutCancel(ctx)
	active := make([]bool, len(inProgress))
	for i := range active {
		active[i] = inProgress[i] != nil
	}

	var (
		activeMu sync.RWMutex
		once     sync.Once
		stopCh   = make(chan struct{})
	)

	go func() {
		ticker := time.NewTicker(c.config.InProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				activeMu.RLock()
				for i, heartbeat := range inProgress {
					if !active[i] || heartbeat == nil {
						continue
					}
					if err := heartbeat(); err != nil && c.logger != nil {
						c.logger.Debug("tap consumer batch in-progress heartbeat failed", "error", err, "stream", c.config.Stream, "durable", c.config.Durable, "index", i)
					}
				}
				activeMu.RUnlock()
			}
		}
	}()

	deactivate := func(index int) {
		if index < 0 || index >= len(active) {
			return
		}
		activeMu.Lock()
		active[index] = false
		activeMu.Unlock()
	}
	stop := func() {
		once.Do(func() { close(stopCh) })
	}
	return deactivate, stop
}

func (c *Consumer) recordProcessed(processedAt, eventTime time.Time) {
	if c == nil {
		return
	}
	processedAt = processedAt.UTC()
	if processedAt.IsZero() {
		processedAt = time.Now().UTC()
	}
	if !eventTime.IsZero() {
		eventTime = eventTime.UTC()
	}

	c.statusMu.Lock()
	c.lastProcessedAt = processedAt
	if !eventTime.IsZero() {
		c.lastEventTime = eventTime
	}
	c.statusMu.Unlock()

	metrics.SetGraphLastUpdate(processedAt)
	if !eventTime.IsZero() && !processedAt.Before(eventTime) {
		metrics.ObserveEventProcessingDuration(processedAt.Sub(eventTime))
	}
}

func (c *Consumer) refreshLagMetrics(now time.Time) {
	if c == nil || c.sub == nil {
		return
	}
	info, err := c.sub.ConsumerInfo()
	if err != nil || info == nil {
		return
	}
	totalLag := saturatingAddUint64(info.NumPending, clampNegativeIntToUint64(info.NumAckPending))
	lag := saturatingUint64ToInt(totalLag)
	lagAge := time.Duration(0)
	c.statusMu.RLock()
	lastEventTime := c.lastEventTime
	lastProcessedAt := c.lastProcessedAt
	c.statusMu.RUnlock()
	if lag > 0 && !lastEventTime.IsZero() {
		lagAge = now.UTC().Sub(lastEventTime.UTC())
		if lagAge < 0 {
			lagAge = 0
		}
	}
	graphStaleness, hasGraphStaleness := graphStalenessAt(now, lastProcessedAt)

	c.statusMu.Lock()
	c.consumerLag = lag
	c.consumerLagAge = lagAge
	c.statusMu.Unlock()

	metrics.SetNATSConsumerLag(c.config.Stream, c.config.Durable, lag)
	metrics.SetNATSConsumerLagSeconds(c.config.Stream, c.config.Durable, lagAge)
	if hasGraphStaleness {
		metrics.SetGraphStaleness(graphStaleness)
	}
}

func saturatingAddUint64(left, right uint64) uint64 {
	if left > math.MaxUint64-right {
		return math.MaxUint64
	}
	return left + right
}

func saturatingUint64ToInt(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}

func clampNegativeIntToUint64(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func graphStalenessAt(now, lastProcessedAt time.Time) (time.Duration, bool) {
	if lastProcessedAt.IsZero() {
		return 0, false
	}
	graphStaleness := now.UTC().Sub(lastProcessedAt.UTC())
	if graphStaleness < 0 {
		graphStaleness = 0
	}
	return graphStaleness, true
}

func (c *Consumer) pruneDropsLocked(now time.Time) {
	if c.config.DropHealthLookback <= 0 || len(c.drops) == 0 {
		return
	}
	cutoff := now.Add(-c.config.DropHealthLookback)
	idx := 0
	for idx < len(c.drops) && c.drops[idx].Before(cutoff) {
		idx++
	}
	if idx > 0 {
		c.drops = append([]time.Time(nil), c.drops[idx:]...)
	}
}

func payloadPreview(payload []byte, limit int) string {
	trimmed := strings.TrimSpace(string(payload))
	if limit <= 0 || len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit] + "...(truncated)"
}

func (c *Consumer) ensureStream() error {
	subjects := consumerSubjects(c.config)
	if len(subjects) == 0 {
		return errors.New("consumer subject is required")
	}
	stream, err := c.js.StreamInfo(c.config.Stream)
	if err == nil {
		missing := make([]string, 0, len(subjects))
		for _, expected := range subjects {
			if streamHasSubject(stream.Config.Subjects, expected) {
				continue
			}
			missing = append(missing, expected)
		}
		if len(missing) == 0 {
			return nil
		}
		updated := stream.Config
		updated.Subjects = append(append([]string(nil), stream.Config.Subjects...), missing...)
		if _, err := c.js.UpdateStream(&updated); err != nil {
			return fmt.Errorf("update consumer stream %s subjects: %w", c.config.Stream, err)
		}
		c.logger.Info("updated jetstream consumer stream subjects",
			"stream", c.config.Stream,
			"stream_subjects", updated.Subjects,
			"added_subjects", missing,
		)
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("lookup consumer stream %s: %w", c.config.Stream, err)
	}
	_, err = c.js.AddStream(&nats.StreamConfig{
		Name:      c.config.Stream,
		Subjects:  subjects,
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		Replicas:  1,
	})
	if err != nil {
		return fmt.Errorf("create consumer stream %s: %w", c.config.Stream, err)
	}
	c.logger.Info("created jetstream consumer stream", "stream", c.config.Stream, "subjects", subjects)
	return nil
}

func (c *Consumer) pullSubscribe(subjects []string) (*nats.Subscription, error) {
	subOpts := []nats.SubOpt{
		nats.BindStream(c.config.Stream),
		nats.AckExplicit(),
		nats.AckWait(c.config.AckWait),
		nats.MaxAckPending(c.config.MaxAckPending),
	}
	subject := c.config.Subject
	if len(subjects) > 1 {
		subject = ""
		subOpts = append(subOpts, nats.ConsumerFilterSubjects(subjects...))
	} else if len(subjects) == 1 {
		subject = subjects[0]
	}
	return c.js.PullSubscribe(subject, c.config.Durable, subOpts...)
}

func (c *Consumer) ensureCompatibleConsumer(subjects []string) error {
	if c == nil || c.js == nil {
		return nil
	}
	info, err := c.js.ConsumerInfo(c.config.Stream, c.config.Durable)
	if errors.Is(err, nats.ErrConsumerNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lookup consumer %s/%s: %w", c.config.Stream, c.config.Durable, err)
	}
	if info == nil || consumerFilterSubjectsMatch(info.Config, subjects) {
		return nil
	}
	if err := c.js.DeleteConsumer(c.config.Stream, c.config.Durable); err != nil && !errors.Is(err, nats.ErrConsumerNotFound) {
		return fmt.Errorf("delete incompatible consumer %s/%s: %w", c.config.Stream, c.config.Durable, err)
	}
	c.logger.Info("deleted incompatible jetstream consumer before resubscribe",
		"stream", c.config.Stream,
		"durable", c.config.Durable,
		"existing_filter_subject", strings.TrimSpace(info.Config.FilterSubject),
		"existing_filter_subjects", info.Config.FilterSubjects,
		"expected_subjects", subjects,
	)
	return nil
}

func consumerFilterSubjectsMatch(cfg nats.ConsumerConfig, subjects []string) bool {
	expected := consumerFilterSubjects(subjects)
	actual := consumerFilterSubjects(append(append([]string(nil), cfg.FilterSubjects...), cfg.FilterSubject))
	if len(actual) != len(expected) {
		return false
	}
	for i := range actual {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}

func consumerFilterSubjects(subjects []string) []string {
	normalized := make([]string, 0, len(subjects))
	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			continue
		}
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		normalized = append(normalized, subject)
	}
	return normalized
}

func (c ConsumerConfig) withDefaults() ConsumerConfig {
	cfg := c
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{defaultJetStreamURL}
	}
	if cfg.Stream == "" {
		cfg.Stream = defaultConsumerStream
	}
	if len(cfg.Subjects) == 0 && cfg.Subject == "" {
		cfg.Subject = defaultConsumerSubject
	}
	cfg.Subjects = consumerSubjects(cfg)
	if len(cfg.Subjects) == 1 {
		cfg.Subject = cfg.Subjects[0]
	}
	if cfg.Durable == "" {
		cfg.Durable = defaultConsumerDurable
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultConsumerBatchSize
	}
	if cfg.HandlerWorkers <= 0 {
		cfg.HandlerWorkers = consumerHandlerWorkers(cfg)
	}
	if cfg.AckWait <= 0 {
		cfg.AckWait = defaultConsumerAckWait
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = defaultConsumerFetchTimeout
	}
	if cfg.InProgressInterval <= 0 {
		cfg.InProgressInterval = defaultConsumerInProgressInterval
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConsumerConnectWait
	}
	if cfg.DropHealthLookback <= 0 {
		cfg.DropHealthLookback = defaultConsumerDropLookback
	}
	if cfg.DropHealthThreshold < 0 {
		cfg.DropHealthThreshold = defaultConsumerDropThreshold
	}
	if cfg.PayloadPreviewBytes <= 0 {
		cfg.PayloadPreviewBytes = defaultConsumerPayloadPreviewBytes
	}
	if cfg.DedupTTL <= 0 {
		cfg.DedupTTL = 24 * time.Hour
	}
	if cfg.DedupMaxRecords <= 0 {
		cfg.DedupMaxRecords = 100_000
	}
	if cfg.MaxAckPending <= 0 {
		cfg.MaxAckPending = cfg.BatchSize * 10
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = defaultJetStreamAuthMode
	}
	return cfg
}

func (c ConsumerConfig) validate() error {
	if len(c.URLs) == 0 {
		return errors.New("consumer requires at least one URL")
	}
	if strings.TrimSpace(c.Stream) == "" {
		return errors.New("consumer stream is required")
	}
	if len(consumerSubjects(c)) == 0 {
		return errors.New("consumer subject is required")
	}
	if strings.TrimSpace(c.Durable) == "" {
		return errors.New("consumer durable name is required")
	}
	if strings.TrimSpace(c.DeadLetterPath) == "" {
		return errors.New("consumer dead-letter path is required")
	}
	if c.BatchSize <= 0 {
		return errors.New("consumer batch size must be > 0")
	}
	if c.HandlerWorkers <= 0 {
		return errors.New("consumer handler workers must be > 0")
	}
	if c.AckWait <= 0 {
		return errors.New("consumer ack wait must be > 0")
	}
	if c.FetchTimeout <= 0 {
		return errors.New("consumer fetch timeout must be > 0")
	}
	if c.DedupEnabled {
		if strings.TrimSpace(c.DedupStateFile) == "" {
			return errors.New("consumer dedupe state file is required when dedupe is enabled")
		}
		if c.DedupTTL <= 0 {
			return errors.New("consumer dedupe ttl must be > 0 when dedupe is enabled")
		}
		if c.DedupMaxRecords <= 0 {
			return errors.New("consumer dedupe max records must be > 0 when dedupe is enabled")
		}
	}
	return nil
}

func consumerSubjects(cfg ConsumerConfig) []string {
	seen := make(map[string]struct{}, len(cfg.Subjects)+1)
	subjects := make([]string, 0, len(cfg.Subjects)+1)
	appendSubject := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		subjects = append(subjects, raw)
	}
	for _, subject := range cfg.Subjects {
		appendSubject(subject)
	}
	appendSubject(cfg.Subject)
	return subjects
}

func streamHasSubject(streamSubjects []string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	for _, subject := range streamSubjects {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			continue
		}
		if subject == expected || subject == ">" {
			return true
		}
	}
	return false
}

type consumerDeadLetterRecord struct {
	RecordedAt time.Time `json:"recorded_at"`
	Stream     string    `json:"stream"`
	Durable    string    `json:"durable"`
	Subject    string    `json:"subject"`
	Reason     string    `json:"reason"`
	Error      string    `json:"error,omitempty"`
	Payload    string    `json:"payload,omitempty"`
}

type consumerDeadLetterSink struct {
	sink *jsonl.FileSink
}

func newConsumerDeadLetterSink(path string) (*consumerDeadLetterSink, error) {
	sink, err := jsonl.NewFileSink(path)
	if err != nil {
		return nil, fmt.Errorf("consumer dead-letter path is required: %w", err)
	}
	return &consumerDeadLetterSink{sink: sink}, nil
}

func (s *consumerDeadLetterSink) Write(record consumerDeadLetterRecord) error {
	if s == nil {
		return fmt.Errorf("consumer dead-letter sink is nil")
	}
	record.RecordedAt = record.RecordedAt.UTC()
	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	}
	return s.sink.Write(record)
}
