package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/jsonl"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/nats-io/nats.go"
)

const (
	defaultConsumerStream              = "ENSEMBLE_TAP"
	defaultConsumerDurable             = "cerebro_graph_builder"
	defaultConsumerSubject             = "ensemble.tap.>"
	defaultConsumerBatchSize           = 50
	defaultConsumerAckWait             = 30 * time.Second
	defaultConsumerFetchTimeout        = 2 * time.Second
	defaultConsumerConnectWait         = 5 * time.Second
	defaultConsumerDropLookback        = 5 * time.Minute
	defaultConsumerDropThreshold       = 1
	defaultConsumerPayloadPreviewBytes = 512
)

type ConsumerConfig struct {
	URLs                []string
	Stream              string
	Subject             string
	Durable             string
	BatchSize           int
	AckWait             time.Duration
	FetchTimeout        time.Duration
	ConnectTimeout      time.Duration
	MaxAckPending       int
	DeadLetterPath      string
	DropHealthLookback  time.Duration
	DropHealthThreshold int
	PayloadPreviewBytes int

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

	stopCh         chan struct{}
	stopOnce       sync.Once
	wg             sync.WaitGroup
	dropMu         sync.Mutex
	drops          []time.Time
	lastDropReason string
	lastDropAt     time.Time
}

type ConsumerHealthSnapshot struct {
	RecentDropped  int           `json:"recent_dropped"`
	Threshold      int           `json:"threshold"`
	Lookback       time.Duration `json:"lookback"`
	LastDropAt     time.Time     `json:"last_drop_at,omitempty"`
	LastDropReason string        `json:"last_drop_reason,omitempty"`
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
		nc:      nc,
		js:      js,
		stopCh:  make(chan struct{}),
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
	var closeErr error
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.wg.Wait()
		if c.sub != nil {
			if err := c.sub.Unsubscribe(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("unsubscribe consumer: %w", err))
			}
		}
		if c.nc != nil {
			if err := c.nc.Drain(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("drain consumer nats connection: %w", err))
			}
			c.nc.Close()
		}
	})
	return closeErr
}

func (c *Consumer) run() {
	defer c.wg.Done()
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cancelBridgeDone := make(chan struct{})
	go func() {
		defer close(cancelBridgeDone)
		<-c.stopCh
		cancel()
	}()
	defer func() {
		cancel()
		<-cancelBridgeDone
	}()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		msgs, err := c.sub.Fetch(c.config.BatchSize, nats.MaxWait(c.config.FetchTimeout))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue
			}
			c.logger.Warn("tap consumer fetch failed", "error", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, msg := range msgs {
			c.handleMessage(runCtx, msg.Subject, msg.Data, func() error { return msg.Ack() }, func() error { return msg.Nak() })
		}
	}
}

func (c *Consumer) handleMessage(ctx context.Context, subject string, payload []byte, ack func() error, nak func() error) {
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
			return
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
		return
	}
	if err := c.handler(ctx, evt); err != nil {
		c.logger.Warn("tap consumer handler failed; message requeued", "error", err, "event_type", evt.Type)
		if nakErr := nak(); nakErr != nil {
			c.logger.Warn("tap consumer nak failed", "error", nakErr, "event_type", evt.Type)
		}
		return
	}
	if err := ack(); err != nil {
		c.logger.Warn("tap consumer ack failed", "error", err, "event_type", evt.Type)
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
	defer c.dropMu.Unlock()
	c.pruneDropsLocked(now)
	return ConsumerHealthSnapshot{
		RecentDropped:  len(c.drops),
		Threshold:      c.config.DropHealthThreshold,
		Lookback:       c.config.DropHealthLookback,
		LastDropAt:     c.lastDropAt,
		LastDropReason: c.lastDropReason,
	}
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
