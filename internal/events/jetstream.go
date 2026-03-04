package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/writerinternal/cerebro/internal/webhooks"
)

const (
	defaultJetStreamURL           = "nats://127.0.0.1:4222"
	defaultJetStreamStream        = "CEREBRO_EVENTS"
	defaultJetStreamSubjectPrefix = "cerebro.events"
	defaultJetStreamSource        = "cerebro"
	defaultOutboxFileName         = "jetstream-outbox.jsonl"
	defaultPublishTimeout         = 3 * time.Second
	defaultPublishRetries         = 3
	defaultPublishRetryBackoff    = 500 * time.Millisecond
	defaultFlushInterval          = 10 * time.Second
)

type CloudEvent struct {
	SpecVersion     string                 `json:"specversion"`
	ID              string                 `json:"id"`
	Source          string                 `json:"source"`
	Type            string                 `json:"type"`
	Subject         string                 `json:"subject,omitempty"`
	Time            time.Time              `json:"time"`
	DataContentType string                 `json:"datacontenttype"`
	Data            map[string]interface{} `json:"data,omitempty"`
}

type JetStreamConfig struct {
	URLs           []string
	Stream         string
	SubjectPrefix  string
	Source         string
	OutboxPath     string
	PublishTimeout time.Duration
	RetryAttempts  int
	RetryBackoff   time.Duration
	FlushInterval  time.Duration
}

type Publisher struct {
	logger   *slog.Logger
	config   JetStreamConfig
	nc       *nats.Conn
	js       nats.JetStreamContext
	outbox   *fileOutbox
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

var _ webhooks.EventPublisher = (*Publisher)(nil)

func NewJetStreamPublisher(cfg JetStreamConfig, logger *slog.Logger) (*Publisher, error) {
	config := cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}

	url := strings.Join(config.URLs, ",")
	nc, err := nats.Connect(url,
		nats.Name("cerebro-jetstream-publisher"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to nats: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initialize jetstream context: %w", err)
	}

	publisher := &Publisher{
		logger: logger,
		config: config,
		nc:     nc,
		js:     js,
		outbox: newFileOutbox(config.OutboxPath),
		stopCh: make(chan struct{}),
	}

	if err := publisher.ensureStream(); err != nil {
		nc.Close()
		return nil, err
	}

	if err := publisher.flushOutbox(context.Background()); err != nil {
		logger.Warn("failed to flush jetstream outbox during startup", "error", err)
	}

	publisher.wg.Add(1)
	go publisher.flushLoop()

	return publisher, nil
}

func (p *Publisher) Publish(ctx context.Context, event webhooks.Event) error {
	if ctx == nil {
		ctx = context.Background()
	}

	subject := p.subjectFor(event.Type)
	ce := cloudEventFromWebhook(p.config.Source, event)
	payload, err := json.Marshal(ce)
	if err != nil {
		return fmt.Errorf("marshal cloud event: %w", err)
	}

	if err := p.publishWithRetry(ctx, subject, payload); err == nil {
		return nil
	} else {
		record := outboxRecord{Subject: subject, Payload: payload}
		if queueErr := p.outbox.enqueue(record); queueErr != nil {
			return errors.Join(err, fmt.Errorf("enqueue event in outbox: %w", queueErr))
		}
		p.logger.Warn("jetstream publish failed, queued event in outbox",
			"subject", subject,
			"event_type", string(event.Type),
			"event_id", event.ID,
			"error", err,
		)
		return nil
	}
}

func (p *Publisher) Close() error {
	var closeErr error

	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.wg.Wait()

		if err := p.flushOutbox(context.Background()); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("flush outbox on close: %w", err))
		}

		if p.nc != nil {
			if err := p.nc.Drain(); err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("drain nats connection: %w", err))
			}
			p.nc.Close()
		}
	})

	return closeErr
}

func (p *Publisher) flushLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			if err := p.flushOutbox(context.Background()); err != nil {
				p.logger.Warn("failed to flush jetstream outbox", "error", err)
			}
		}
	}
}

func (p *Publisher) flushOutbox(ctx context.Context) error {
	published, err := p.outbox.flush(func(record outboxRecord) error {
		return p.publishWithRetry(ctx, record.Subject, record.Payload)
	})
	if published > 0 {
		p.logger.Info("flushed jetstream outbox", "published", published)
	}
	if err != nil {
		return fmt.Errorf("flush outbox: %w", err)
	}
	return nil
}

func (p *Publisher) publishWithRetry(ctx context.Context, subject string, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var lastErr error
	for attempt := 1; attempt <= p.config.RetryAttempts; attempt++ {
		publishCtx := ctx
		cancel := func() {}
		if p.config.PublishTimeout > 0 {
			publishCtx, cancel = context.WithTimeout(ctx, p.config.PublishTimeout)
		}

		_, lastErr = p.js.Publish(subject, payload, nats.Context(publishCtx))
		cancel()
		if lastErr == nil {
			return nil
		}

		if attempt < p.config.RetryAttempts {
			if err := waitForRetry(ctx, p.config.RetryBackoff); err != nil {
				return lastErr
			}
		}
	}

	return lastErr
}

func waitForRetry(ctx context.Context, backoff time.Duration) error {
	timer := time.NewTimer(backoff)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Publisher) ensureStream() error {
	streamSubject := p.config.SubjectPrefix + ".>"

	streamInfo, err := p.js.StreamInfo(p.config.Stream)
	if err == nil {
		if !containsSubject(streamInfo.Config.Subjects, streamSubject) {
			p.logger.Warn("jetstream stream does not include subject prefix",
				"stream", p.config.Stream,
				"required_subject", streamSubject,
			)
		}
		return nil
	}

	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("lookup jetstream stream %s: %w", p.config.Stream, err)
	}

	_, err = p.js.AddStream(&nats.StreamConfig{
		Name:      p.config.Stream,
		Subjects:  []string{streamSubject},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		Discard:   nats.DiscardOld,
	})
	if err != nil {
		return fmt.Errorf("create jetstream stream %s: %w", p.config.Stream, err)
	}

	p.logger.Info("created jetstream stream",
		"stream", p.config.Stream,
		"subject", streamSubject,
	)

	return nil
}

func containsSubject(subjects []string, wanted string) bool {
	for _, subject := range subjects {
		if subject == wanted {
			return true
		}
	}
	return false
}

func (p *Publisher) subjectFor(eventType webhooks.EventType) string {
	value := strings.TrimSpace(string(eventType))
	if value == "" {
		value = "unknown"
	}
	value = strings.ReplaceAll(value, " ", "_")
	return p.config.SubjectPrefix + "." + value
}

func cloudEventFromWebhook(source string, event webhooks.Event) CloudEvent {
	eventID := strings.TrimSpace(event.ID)
	if eventID == "" {
		eventID = uuid.NewString()
	}

	eventTime := event.Timestamp.UTC()
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	eventSource := strings.TrimSpace(source)
	if eventSource == "" {
		eventSource = defaultJetStreamSource
	}

	dataCopy := make(map[string]interface{}, len(event.Data))
	for key, value := range event.Data {
		dataCopy[key] = value
	}

	return CloudEvent{
		SpecVersion:     "1.0",
		ID:              eventID,
		Source:          eventSource,
		Type:            string(event.Type),
		Subject:         string(event.Type),
		Time:            eventTime,
		DataContentType: "application/json",
		Data:            dataCopy,
	}
}

func (c JetStreamConfig) withDefaults() JetStreamConfig {
	config := c

	if len(config.URLs) == 0 {
		config.URLs = []string{defaultJetStreamURL}
	}

	if strings.TrimSpace(config.Stream) == "" {
		config.Stream = defaultJetStreamStream
	}

	if strings.TrimSpace(config.SubjectPrefix) == "" {
		config.SubjectPrefix = defaultJetStreamSubjectPrefix
	}

	if strings.TrimSpace(config.Source) == "" {
		config.Source = defaultJetStreamSource
	}

	if config.PublishTimeout <= 0 {
		config.PublishTimeout = defaultPublishTimeout
	}

	if config.RetryAttempts <= 0 {
		config.RetryAttempts = defaultPublishRetries
	}

	if config.RetryBackoff <= 0 {
		config.RetryBackoff = defaultPublishRetryBackoff
	}

	if config.FlushInterval <= 0 {
		config.FlushInterval = defaultFlushInterval
	}

	if strings.TrimSpace(config.OutboxPath) == "" {
		config.OutboxPath = filepath.Join(os.TempDir(), defaultOutboxFileName)
	}

	return config
}
