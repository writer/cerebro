package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/jsonl"
	"github.com/writer/cerebro/internal/metrics"
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
	Durable             string
	BatchSize           int
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
}

type EventHandler func(context.Context, CloudEvent) error

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
	sub, err := c.js.PullSubscribe(
		config.Subject,
		config.Durable,
		nats.BindStream(config.Stream),
		nats.AckExplicit(),
		nats.AckWait(config.AckWait),
		nats.MaxAckPending(config.MaxAckPending),
	)
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
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.drainCh:
			c.refreshLagMetrics(time.Now().UTC())
			return
		default:
		}

		msgs, err := c.sub.Fetch(c.config.BatchSize, nats.MaxWait(c.config.FetchTimeout))
		if err != nil {
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
		c.refreshLagMetrics(time.Now().UTC())
		lastLagRefresh = time.Now().UTC()

		batchInProgress := make([]func() error, len(msgs))
		for i, msg := range msgs {
			msg := msg
			batchInProgress[i] = func() error { return msg.InProgress() }
		}
		deactivateBatchHeartbeat, stopBatchHeartbeat := c.startBatchInProgressHeartbeat(runCtx, batchInProgress)
		for _, msg := range msgs {
			if meta, err := msg.Metadata(); err == nil && meta != nil && meta.NumDelivered > 1 {
				metrics.RecordNATSConsumerRedelivery(c.config.Stream, c.config.Durable)
			}
		}
		for i, msg := range msgs {
			deactivateBatchHeartbeat(i)
			result := c.handleMessage(
				runCtx,
				msg.Subject,
				msg.Data,
				func() error { return msg.Ack() },
				func() error { return msg.Nak() },
				batchInProgress[i],
			)
			if result.Processed {
				c.recordProcessed(result.ProcessedAt, result.EventTime)
			}
		}
		stopBatchHeartbeat()
	}
}

type consumerMessageResult struct {
	Processed   bool
	EventTime   time.Time
	ProcessedAt time.Time
}

func (c *Consumer) handleMessage(ctx context.Context, subject string, payload []byte, ack func() error, nak func() error, inProgress func() error) consumerMessageResult {
	var evt CloudEvent
	if err := json.Unmarshal(payload, &evt); err != nil {
		preview := payloadPreview(payload, c.config.PayloadPreviewBytes)
		if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
			RecordedAt: time.Now().UTC(),
			Stream:     c.config.Stream,
			Durable:    c.config.Durable,
			Subject:    subject,
			Reason:     "malformed",
			Error:      err.Error(),
			Payload:    string(payload),
		}); dlqErr != nil {
			c.logger.Error("tap consumer failed to dead-letter malformed cloud event; message requeued",
				"error", dlqErr,
				"subject", subject,
				"stream", c.config.Stream,
				"durable", c.config.Durable,
				"payload_preview", preview,
			)
			if nakErr := nak(); nakErr != nil {
				c.logger.Warn("tap consumer nak failed after dead-letter error", "error", nakErr, "subject", subject)
			}
			return consumerMessageResult{}
		}
		c.logger.Error("tap consumer dead-lettered malformed cloud event",
			"error", err,
			"subject", subject,
			"stream", c.config.Stream,
			"durable", c.config.Durable,
			"payload_preview", preview,
		)
		c.recordDropped("malformed", time.Now().UTC())
		if err := ack(); err != nil {
			c.logger.Warn("tap consumer ack failed after dead-lettering malformed event", "error", err, "subject", subject)
		}
		return consumerMessageResult{}
	}
	if c.deduper != nil {
		record, hashMismatch, err := c.deduper.Lookup(ctx, evt, payload, time.Now().UTC())
		if err != nil {
			c.logger.Warn("tap consumer dedupe lookup failed; continuing without duplicate suppression",
				"error", err,
				"event_id", evt.ID,
				"event_type", evt.Type,
			)
		} else if record != nil {
			if hashMismatch {
				if err := c.deduper.Forget(ctx, evt); err != nil {
					c.logger.Error("tap consumer failed to clear conflicting dedupe state; message requeued",
						"error", err,
						"event_id", evt.ID,
						"event_type", evt.Type,
						"source", evt.Source,
						"processed_at", record.ProcessedAt.UTC().Format(time.RFC3339Nano),
					)
					if nakErr := nak(); nakErr != nil {
						c.logger.Warn("tap consumer nak failed after dedupe hash mismatch state clear failure", "error", nakErr, "event_type", evt.Type)
					}
					return consumerMessageResult{}
				}
				if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
					RecordedAt: time.Now().UTC(),
					Stream:     c.config.Stream,
					Durable:    c.config.Durable,
					Subject:    subject,
					Reason:     "dedupe_hash_mismatch",
					Error:      fmt.Sprintf("duplicate event key matched different payload hash: processed_at=%s", record.ProcessedAt.UTC().Format(time.RFC3339Nano)),
					Payload:    string(payload),
				}); dlqErr != nil {
					c.logger.Error("tap consumer failed to dead-letter duplicate hash mismatch; message requeued",
						"error", dlqErr,
						"event_id", evt.ID,
						"event_type", evt.Type,
						"source", evt.Source,
					)
					if nakErr := nak(); nakErr != nil {
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
				if nakErr := nak(); nakErr != nil {
					c.logger.Warn("tap consumer nak failed after clearing dedupe hash mismatch state", "error", nakErr, "event_type", evt.Type)
				}
				return consumerMessageResult{}
			}
			if err := c.deduper.ObserveDuplicate(ctx, evt, time.Now().UTC()); err != nil {
				c.logger.Warn("tap consumer failed to refresh duplicate dedupe state",
					"error", err,
					"event_id", evt.ID,
					"event_type", evt.Type,
				)
			}
			metrics.RecordNATSConsumerDeduplicated(c.config.Stream, c.config.Durable)
			if err := ack(); err != nil {
				c.logger.Warn("tap consumer ack failed after duplicate suppression", "error", err, "event_type", evt.Type)
			}
			return consumerMessageResult{}
		}
	}
	stopHeartbeat := c.startInProgressHeartbeat(ctx, inProgress)
	defer stopHeartbeat()
	if err := c.handler(ctx, evt); err != nil {
		c.logger.Warn("tap consumer handler failed; message requeued", "error", err, "event_type", evt.Type)
		if nakErr := nak(); nakErr != nil {
			c.logger.Warn("tap consumer nak failed", "error", nakErr, "event_type", evt.Type)
		}
		return consumerMessageResult{}
	}
	processedAt := time.Now().UTC()
	metrics.RecordNATSConsumerProcessed(c.config.Stream, c.config.Durable)
	if c.deduper != nil {
		if err := c.deduper.Remember(ctx, evt, payload, processedAt); err != nil {
			c.logger.Warn("tap consumer failed to persist processed event dedupe state",
				"error", err,
				"event_id", evt.ID,
				"event_type", evt.Type,
			)
		}
	}
	if err := ack(); err != nil {
		c.logger.Warn("tap consumer ack failed", "error", err, "event_type", evt.Type)
	}
	return consumerMessageResult{
		Processed:   true,
		EventTime:   evt.Time.UTC(),
		ProcessedAt: processedAt,
	}
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
	stopCh := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(c.config.InProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
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
			case <-ctx.Done():
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
	stream, err := c.js.StreamInfo(c.config.Stream)
	if err == nil {
		for _, subj := range stream.Config.Subjects {
			if subj == c.config.Subject || subj == ">" || subj == "ensemble.tap.>" {
				return nil
			}
		}
		c.logger.Warn("consumer stream exists without matching subject filter",
			"stream", c.config.Stream,
			"stream_subjects", stream.Config.Subjects,
			"expected_subject", c.config.Subject,
		)
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("lookup consumer stream %s: %w", c.config.Stream, err)
	}
	_, err = c.js.AddStream(&nats.StreamConfig{
		Name:      c.config.Stream,
		Subjects:  []string{c.config.Subject},
		Retention: nats.LimitsPolicy,
		Storage:   nats.FileStorage,
		Replicas:  1,
	})
	if err != nil {
		return fmt.Errorf("create consumer stream %s: %w", c.config.Stream, err)
	}
	c.logger.Info("created jetstream consumer stream", "stream", c.config.Stream, "subject", c.config.Subject)
	return nil
}

func (c ConsumerConfig) withDefaults() ConsumerConfig {
	cfg := c
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{defaultJetStreamURL}
	}
	if cfg.Stream == "" {
		cfg.Stream = defaultConsumerStream
	}
	if cfg.Subject == "" {
		cfg.Subject = defaultConsumerSubject
	}
	if cfg.Durable == "" {
		cfg.Durable = defaultConsumerDurable
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultConsumerBatchSize
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
	if strings.TrimSpace(c.Subject) == "" {
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
