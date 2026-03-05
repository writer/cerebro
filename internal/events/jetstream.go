package events

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/webhooks"
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
	defaultConnectTimeout         = 5 * time.Second

	defaultOutboxMaxRecords  = 10_000
	defaultOutboxMaxAge      = 7 * 24 * time.Hour
	defaultOutboxMaxAttempts = 10

	defaultOutboxWarnPercent     = 70
	defaultOutboxCriticalPercent = 90
	defaultOutboxWarnAge         = time.Hour
	defaultOutboxCriticalAge     = 6 * time.Hour

	defaultJetStreamAuthMode = "none"
	authModeUserPass         = "userpass"
	authModeNKey             = "nkey"
	authModeJWT              = "jwt"

	cloudEventSpecVersion  = "1.0"
	cloudEventSchemaV1     = "v1"
	cloudEventSchemaPrefix = "urn:cerebro:events"

	backpressureLevelNormal   = "normal"
	backpressureLevelWarning  = "warning"
	backpressureLevelCritical = "critical"
	backpressureLevelUnknown  = "unknown"
)

type CloudEvent struct {
	SpecVersion     string                 `json:"specversion"`
	ID              string                 `json:"id"`
	Source          string                 `json:"source"`
	Type            string                 `json:"type"`
	Subject         string                 `json:"subject,omitempty"`
	Time            time.Time              `json:"time"`
	DataSchema      string                 `json:"dataschema"`
	SchemaVersion   string                 `json:"schema_version"`
	TenantID        string                 `json:"tenant_id"`
	TraceParent     string                 `json:"traceparent"`
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
	ConnectTimeout time.Duration

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

	OutboxDLQPath         string
	OutboxMaxRecords      int
	OutboxMaxAge          time.Duration
	OutboxMaxAttempts     int
	OutboxWarnPercent     int
	OutboxCriticalPercent int
	OutboxWarnAge         time.Duration
	OutboxCriticalAge     time.Duration
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

	publishedTotal     atomic.Uint64
	queuedTotal        atomic.Uint64
	flushFailuresTotal atomic.Uint64
	quarantinedTotal   atomic.Uint64

	statusMu               sync.RWMutex
	lastError              string
	lastPublishAt          time.Time
	lastFlushAt            time.Time
	lastBackpressureLevel  string
	lastBackpressureReason string
}

type outboxBackpressureState struct {
	Level  string
	Reason string
}

var _ webhooks.EventPublisher = (*Publisher)(nil)
var _ webhooks.EventPublisherReadiness = (*Publisher)(nil)
var _ webhooks.EventPublisherStatusReporter = (*Publisher)(nil)

var errJetStreamUnavailable = errors.New("jetstream connection unavailable")

func NewJetStreamPublisher(cfg JetStreamConfig, logger *slog.Logger) (*Publisher, error) {
	config := cfg.withDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}

	if logger == nil {
		logger = slog.Default()
	}

	url := strings.Join(config.URLs, ",")
	natsOptions, err := config.natsOptions()
	if err != nil {
		return nil, err
	}

	nc, err := nats.Connect(url, natsOptions...)
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
		outbox: newFileOutbox(config.OutboxPath, outboxConfig{
			MaxRecords:  config.OutboxMaxRecords,
			MaxAge:      config.OutboxMaxAge,
			MaxAttempts: config.OutboxMaxAttempts,
			DLQPath:     config.OutboxDLQPath,
		}),
		stopCh: make(chan struct{}),
	}

	if err := publisher.ensureStream(); err != nil {
		nc.Close()
		return nil, err
	}

	if err := publisher.flushOutbox(context.Background()); err != nil {
		logger.Warn("failed to flush jetstream outbox during startup", "error", err)
	}
	publisher.refreshOperationalMetrics()

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

	if !p.canPublishLive() {
		return p.queueOutboxEvent(subject, event, ce.ID, payload, errJetStreamUnavailable)
	}

	if err := p.publishWithRetry(ctx, subject, payload, ce.ID); err == nil {
		p.publishedTotal.Add(1)
		p.setLastPublish(time.Now().UTC())
		p.clearLastError()
		metrics.RecordJetStreamPublish(p.config.Stream, "published")
		p.refreshOperationalMetrics()
		return nil
	}

	return p.queueOutboxEvent(subject, event, ce.ID, payload, err)
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
			metrics.SetJetStreamPublisherReady(p.config.Stream, false)
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
			if !p.canPublishLive() {
				p.refreshOperationalMetrics()
				continue
			}
			if err := p.flushOutbox(context.Background()); err != nil {
				p.logger.Warn("failed to flush jetstream outbox", "error", err)
			}
		}
	}
}

func (p *Publisher) queueOutboxEvent(subject string, event webhooks.Event, messageID string, payload []byte, publishErr error) error {
	record := outboxRecord{Subject: subject, Payload: payload, MessageID: messageID}
	if queueErr := p.outbox.enqueue(record); queueErr != nil {
		p.setLastError(errors.Join(publishErr, queueErr))
		metrics.RecordJetStreamPublish(p.config.Stream, "failed")
		p.refreshOperationalMetrics()
		if publishErr == nil {
			return fmt.Errorf("enqueue event in outbox: %w", queueErr)
		}
		return errors.Join(publishErr, fmt.Errorf("enqueue event in outbox: %w", queueErr))
	}

	p.queuedTotal.Add(1)
	if publishErr != nil {
		p.setLastError(publishErr)
	}
	metrics.RecordJetStreamPublish(p.config.Stream, "queued")
	p.refreshOperationalMetrics()
	p.logger.Warn("jetstream publish failed, queued event in outbox",
		"subject", subject,
		"event_type", string(event.Type),
		"event_id", event.ID,
		"error", publishErr,
	)
	return nil
}

func (p *Publisher) flushOutbox(ctx context.Context) error {
	result, err := p.outbox.flush(func(record outboxRecord) error {
		return p.publishWithRetry(ctx, record.Subject, record.Payload, record.MessageID)
	})

	if result.Published > 0 {
		p.publishedTotal.Add(uint64(result.Published))
		p.setLastPublish(time.Now().UTC())
		metrics.RecordJetStreamOutboxFlush(p.config.Stream, "published", result.Published)
		p.logger.Info("flushed jetstream outbox", "published", result.Published)
	}
	if result.Quarantined > 0 {
		p.quarantinedTotal.Add(uint64(result.Quarantined))
		metrics.RecordJetStreamOutboxFlush(p.config.Stream, "quarantined", result.Quarantined)
		p.logger.Warn("quarantined poisoned outbox records", "count", result.Quarantined)
	}

	p.setLastFlush(time.Now().UTC())
	p.refreshOperationalMetrics()

	if err != nil {
		p.flushFailuresTotal.Add(1)
		p.setLastError(err)
		metrics.RecordJetStreamOutboxFlush(p.config.Stream, "error", 1)
		p.refreshOperationalMetrics()
		return fmt.Errorf("flush outbox: %w", err)
	}
	p.clearLastError()
	return nil
}

func (p *Publisher) publishWithRetry(ctx context.Context, subject string, payload []byte, messageID string) error {
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

		opts := []nats.PubOpt{nats.Context(publishCtx)}
		if strings.TrimSpace(messageID) != "" {
			opts = append(opts, nats.MsgId(strings.TrimSpace(messageID)))
		}

		_, lastErr = p.js.Publish(subject, payload, opts...)
		cancel()
		if lastErr == nil {
			return nil
		}

		if shouldEnsureJetStreamStream(lastErr) {
			if ensureErr := p.ensureStream(); ensureErr == nil {
				_, lastErr = p.js.Publish(subject, payload, opts...)
				if lastErr == nil {
					return nil
				}
			} else {
				lastErr = errors.Join(lastErr, fmt.Errorf("ensure jetstream stream: %w", ensureErr))
			}
		}

		if attempt < p.config.RetryAttempts {
			if err := waitForRetry(ctx, p.config.RetryBackoff); err != nil {
				return lastErr
			}
		}
	}

	return lastErr
}

func shouldEnsureJetStreamStream(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, nats.ErrNoStreamResponse) ||
		errors.Is(err, nats.ErrStreamNotFound) ||
		errors.Is(err, nats.ErrNoResponders)
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

func (p *Publisher) Ready(ctx context.Context) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	stats, err := p.outbox.stats()
	if err != nil {
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		return fmt.Errorf("read outbox stats: %w", err)
	}
	p.recordOutboxMetrics(stats)

	if p.nc == nil || !p.nc.IsConnected() {
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		return errors.New("nats connection is not connected")
	}
	if p.config.OutboxMaxRecords > 0 && stats.Depth >= p.config.OutboxMaxRecords {
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		return fmt.Errorf("outbox depth %d reached configured limit %d", stats.Depth, p.config.OutboxMaxRecords)
	}
	if p.config.OutboxMaxAge > 0 && stats.Depth > 0 && stats.OldestAge > p.config.OutboxMaxAge {
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		return fmt.Errorf("oldest outbox record age %s exceeded limit %s", stats.OldestAge, p.config.OutboxMaxAge)
	}

	backpressure := p.config.evaluateOutboxBackpressure(stats)
	if backpressure.Level == backpressureLevelCritical {
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		return fmt.Errorf("jetstream outbox backpressure critical: %s", backpressure.Reason)
	}

	metrics.SetJetStreamPublisherReady(p.config.Stream, true)
	return nil
}

func (p *Publisher) Status(ctx context.Context) map[string]interface{} {
	stats, statsErr := p.outbox.stats()
	if statsErr == nil {
		p.recordOutboxMetrics(stats)
	}

	readyErr := p.Ready(ctx)

	p.statusMu.RLock()
	lastError := p.lastError
	lastPublishAt := p.lastPublishAt
	lastFlushAt := p.lastFlushAt
	lastBackpressureLevel := p.lastBackpressureLevel
	lastBackpressureReason := p.lastBackpressureReason
	p.statusMu.RUnlock()

	backpressure := p.config.evaluateOutboxBackpressure(stats)
	if statsErr != nil {
		backpressure = outboxBackpressureState{Level: backpressureLevelUnknown, Reason: statsErr.Error()}
	} else if lastBackpressureLevel != "" {
		backpressure.Level = lastBackpressureLevel
		if strings.TrimSpace(lastBackpressureReason) != "" {
			backpressure.Reason = lastBackpressureReason
		}
	}

	status := map[string]interface{}{
		"enabled":                   true,
		"stream":                    p.config.Stream,
		"subject_prefix":            p.config.SubjectPrefix,
		"connected":                 p.nc != nil && p.nc.IsConnected(),
		"ready":                     readyErr == nil,
		"outbox_depth":              stats.Depth,
		"outbox_oldest_age_seconds": stats.OldestAge.Seconds(),
		"published_total":           p.publishedTotal.Load(),
		"queued_total":              p.queuedTotal.Load(),
		"flush_failures_total":      p.flushFailuresTotal.Load(),
		"quarantined_total":         p.quarantinedTotal.Load(),
		"backpressure_level":        backpressure.Level,
	}
	if strings.TrimSpace(backpressure.Reason) != "" {
		status["backpressure_reason"] = backpressure.Reason
	}

	if !lastPublishAt.IsZero() {
		status["last_publish_at"] = lastPublishAt
	}
	if !lastFlushAt.IsZero() {
		status["last_flush_at"] = lastFlushAt
	}

	if readyErr != nil {
		status["message"] = readyErr.Error()
	}
	if statsErr != nil {
		status["outbox_error"] = statsErr.Error()
	}
	if strings.TrimSpace(lastError) != "" {
		status["last_error"] = lastError
	}

	return status
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

	eventType := strings.TrimSpace(string(event.Type))
	if eventType == "" {
		eventType = "unknown"
	}

	dataCopy := make(map[string]interface{}, len(event.Data)+3)
	for key, value := range event.Data {
		dataCopy[key] = value
	}

	tenantID := dataValueString(dataCopy, "tenant_id", "tenantId", "tenant")
	if tenantID == "" {
		tenantID = "unknown"
	}

	traceParent := dataValueString(dataCopy, "traceparent", "trace_parent", "traceParent")
	if traceParent == "" {
		traceParent = generateTraceParent()
	}

	if _, ok := dataCopy["tenant_id"]; !ok {
		dataCopy["tenant_id"] = tenantID
	}
	if _, ok := dataCopy["traceparent"]; !ok {
		dataCopy["traceparent"] = traceParent
	}
	dataCopy["schema_version"] = cloudEventSchemaV1

	return CloudEvent{
		SpecVersion:     cloudEventSpecVersion,
		ID:              eventID,
		Source:          eventSource,
		Type:            eventType,
		Subject:         eventType,
		Time:            eventTime,
		DataSchema:      cloudEventSchemaFor(eventType),
		SchemaVersion:   cloudEventSchemaV1,
		TenantID:        tenantID,
		TraceParent:     traceParent,
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

	if config.ConnectTimeout <= 0 {
		config.ConnectTimeout = defaultConnectTimeout
	}

	config.AuthMode = strings.ToLower(strings.TrimSpace(config.AuthMode))
	if config.AuthMode == "" {
		config.AuthMode = defaultJetStreamAuthMode
	}

	if config.OutboxMaxRecords <= 0 {
		config.OutboxMaxRecords = defaultOutboxMaxRecords
	}
	if config.OutboxMaxAge <= 0 {
		config.OutboxMaxAge = defaultOutboxMaxAge
	}
	if config.OutboxMaxAttempts <= 0 {
		config.OutboxMaxAttempts = defaultOutboxMaxAttempts
	}
	if config.OutboxWarnPercent <= 0 {
		config.OutboxWarnPercent = defaultOutboxWarnPercent
	}
	if config.OutboxCriticalPercent <= 0 {
		config.OutboxCriticalPercent = defaultOutboxCriticalPercent
	}
	if config.OutboxWarnAge <= 0 {
		config.OutboxWarnAge = defaultOutboxWarnAge
	}
	if config.OutboxCriticalAge <= 0 {
		config.OutboxCriticalAge = defaultOutboxCriticalAge
	}

	if strings.TrimSpace(config.OutboxPath) == "" {
		config.OutboxPath = filepath.Join(os.TempDir(), defaultOutboxFileName)
	}
	if strings.TrimSpace(config.OutboxDLQPath) == "" {
		config.OutboxDLQPath = config.OutboxPath + ".dlq.jsonl"
	}

	if !config.TLSEnabled && (strings.TrimSpace(config.TLSCAFile) != "" || strings.TrimSpace(config.TLSCertFile) != "" || strings.TrimSpace(config.TLSKeyFile) != "") {
		config.TLSEnabled = true
	}
	if !config.TLSEnabled {
		for _, rawURL := range config.URLs {
			parsed, err := url.Parse(rawURL)
			if err == nil && strings.EqualFold(parsed.Scheme, "tls") {
				config.TLSEnabled = true
				break
			}
		}
	}

	return config
}

func (c JetStreamConfig) validate() error {
	if len(c.URLs) == 0 {
		return errors.New("jetstream requires at least one URL")
	}

	for _, rawURL := range c.URLs {
		parsed, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil {
			return fmt.Errorf("invalid nats URL %q: %w", rawURL, err)
		}
		if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
			return fmt.Errorf("invalid nats URL %q", rawURL)
		}
	}

	switch c.AuthMode {
	case defaultJetStreamAuthMode:
	case authModeUserPass:
		if strings.TrimSpace(c.Username) == "" || strings.TrimSpace(c.Password) == "" {
			return errors.New("auth mode userpass requires username and password")
		}
	case authModeNKey:
		if strings.TrimSpace(c.NKeySeed) == "" {
			return errors.New("auth mode nkey requires nkey seed")
		}
	case authModeJWT:
		if strings.TrimSpace(c.UserJWT) == "" || strings.TrimSpace(c.NKeySeed) == "" {
			return errors.New("auth mode jwt requires user jwt and nkey seed")
		}
	default:
		return fmt.Errorf("unsupported jetstream auth mode: %s", c.AuthMode)
	}

	certFile := strings.TrimSpace(c.TLSCertFile)
	keyFile := strings.TrimSpace(c.TLSKeyFile)
	if (certFile == "") != (keyFile == "") {
		return errors.New("tls cert and key files must be provided together")
	}

	for _, filePath := range []string{strings.TrimSpace(c.TLSCAFile), certFile, keyFile} {
		if filePath == "" {
			continue
		}
		if _, err := os.Stat(filePath); err != nil {
			return fmt.Errorf("tls file %q: %w", filePath, err)
		}
	}

	if c.OutboxWarnPercent <= 0 || c.OutboxWarnPercent > 100 {
		return fmt.Errorf("outbox warn percent must be between 1 and 100, got %d", c.OutboxWarnPercent)
	}
	if c.OutboxCriticalPercent <= 0 || c.OutboxCriticalPercent > 100 {
		return fmt.Errorf("outbox critical percent must be between 1 and 100, got %d", c.OutboxCriticalPercent)
	}
	if c.OutboxWarnPercent > c.OutboxCriticalPercent {
		return fmt.Errorf("outbox warn percent %d cannot exceed critical percent %d", c.OutboxWarnPercent, c.OutboxCriticalPercent)
	}
	if c.OutboxWarnAge <= 0 {
		return fmt.Errorf("outbox warn age must be > 0, got %s", c.OutboxWarnAge)
	}
	if c.OutboxCriticalAge <= 0 {
		return fmt.Errorf("outbox critical age must be > 0, got %s", c.OutboxCriticalAge)
	}
	if c.OutboxWarnAge > c.OutboxCriticalAge {
		return fmt.Errorf("outbox warn age %s cannot exceed critical age %s", c.OutboxWarnAge, c.OutboxCriticalAge)
	}

	return nil
}

func (c JetStreamConfig) natsOptions() ([]nats.Option, error) {
	options := []nats.Option{
		nats.Name("cerebro-jetstream-publisher"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	}
	if c.ConnectTimeout > 0 {
		options = append(options, nats.Timeout(c.ConnectTimeout))
	}

	authOptions, err := c.authOptions()
	if err != nil {
		return nil, err
	}
	options = append(options, authOptions...)

	if c.TLSEnabled {
		tlsConfig, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		options = append(options, nats.Secure(tlsConfig))
	}

	return options, nil
}

func (c JetStreamConfig) authOptions() ([]nats.Option, error) {
	switch c.AuthMode {
	case defaultJetStreamAuthMode:
		return nil, nil
	case authModeUserPass:
		return []nats.Option{nats.UserInfo(c.Username, c.Password)}, nil
	case authModeNKey:
		publicKey, signer, err := signerFromSeed(c.NKeySeed)
		if err != nil {
			return nil, err
		}
		return []nats.Option{nats.Nkey(publicKey, signer)}, nil
	case authModeJWT:
		_, signer, err := signerFromSeed(c.NKeySeed)
		if err != nil {
			return nil, err
		}
		jwt := strings.TrimSpace(c.UserJWT)
		return []nats.Option{nats.UserJWT(func() (string, error) { return jwt, nil }, signer)}, nil
	default:
		return nil, fmt.Errorf("unsupported jetstream auth mode: %s", c.AuthMode)
	}
}

func signerFromSeed(seed string) (string, func([]byte) ([]byte, error), error) {
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(seed)))
	if err != nil {
		return "", nil, fmt.Errorf("parse nkey seed: %w", err)
	}

	publicKey, err := kp.PublicKey()
	if err != nil {
		return "", nil, fmt.Errorf("derive nkey public key: %w", err)
	}

	signer := func(nonce []byte) ([]byte, error) {
		return kp.Sign(nonce)
	}

	return publicKey, signer, nil
}

func (c JetStreamConfig) tlsConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.TLSInsecureSkipVerify,
	}
	if serverName := strings.TrimSpace(c.TLSServerName); serverName != "" {
		tlsConfig.ServerName = serverName
	}

	if caFile := strings.TrimSpace(c.TLSCAFile); caFile != "" {
		caPEM, err := os.ReadFile(caFile) // #nosec G304 -- TLS CA path is explicit operator configuration
		if err != nil {
			return nil, fmt.Errorf("read tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("load tls ca certs from %q", caFile)
		}
		tlsConfig.RootCAs = pool
	}

	certFile := strings.TrimSpace(c.TLSCertFile)
	keyFile := strings.TrimSpace(c.TLSKeyFile)
	if certFile != "" && keyFile != "" {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, nil
}

func (p *Publisher) canPublishLive() bool {
	return p.nc != nil && p.nc.IsConnected()
}

func (p *Publisher) refreshOperationalMetrics() {
	stats, err := p.outbox.stats()
	if err != nil {
		p.setLastError(err)
		metrics.SetJetStreamPublisherReady(p.config.Stream, false)
		metrics.SetJetStreamOutboxBackpressureLevel(p.config.Stream, backpressureLevelUnknown)
		p.setBackpressureState(outboxBackpressureState{Level: backpressureLevelUnknown, Reason: err.Error()})
		return
	}
	p.recordOutboxMetrics(stats)

	backpressure := p.config.evaluateOutboxBackpressure(stats)
	previous := p.setBackpressureState(backpressure)
	p.recordBackpressureTransition(previous, backpressure, stats)
	metrics.SetJetStreamOutboxBackpressureLevel(p.config.Stream, backpressure.Level)

	ready := p.nc != nil && p.nc.IsConnected()
	if ready && p.config.OutboxMaxRecords > 0 && stats.Depth >= p.config.OutboxMaxRecords {
		ready = false
	}
	if ready && p.config.OutboxMaxAge > 0 && stats.Depth > 0 && stats.OldestAge > p.config.OutboxMaxAge {
		ready = false
	}
	if ready && backpressure.Level == backpressureLevelCritical {
		ready = false
	}

	metrics.SetJetStreamPublisherReady(p.config.Stream, ready)
}

func (p *Publisher) recordOutboxMetrics(stats outboxStats) {
	metrics.SetJetStreamOutboxDepth(p.config.Stream, stats.Depth)
	metrics.SetJetStreamOutboxOldestAge(p.config.Stream, stats.OldestAge)
}

func (p *Publisher) setLastError(err error) {
	if err == nil {
		return
	}
	p.statusMu.Lock()
	p.lastError = err.Error()
	p.statusMu.Unlock()
}

func (p *Publisher) clearLastError() {
	p.statusMu.Lock()
	p.lastError = ""
	p.statusMu.Unlock()
}

func (p *Publisher) setLastPublish(at time.Time) {
	p.statusMu.Lock()
	p.lastPublishAt = at
	p.statusMu.Unlock()
}

func (p *Publisher) setLastFlush(at time.Time) {
	p.statusMu.Lock()
	p.lastFlushAt = at
	p.statusMu.Unlock()
}

func (p *Publisher) setBackpressureState(state outboxBackpressureState) string {
	p.statusMu.Lock()
	previous := p.lastBackpressureLevel
	p.lastBackpressureLevel = state.Level
	p.lastBackpressureReason = state.Reason
	p.statusMu.Unlock()
	return previous
}

func (p *Publisher) recordBackpressureTransition(previous string, current outboxBackpressureState, stats outboxStats) {
	prev := strings.TrimSpace(previous)
	if prev == "" {
		prev = backpressureLevelNormal
	}
	if prev == current.Level {
		return
	}

	switch current.Level {
	case backpressureLevelWarning, backpressureLevelCritical:
		metrics.RecordJetStreamBackpressureAlert(p.config.Stream, current.Level)
		p.logger.Warn("jetstream outbox backpressure",
			"level", current.Level,
			"reason", current.Reason,
			"depth", stats.Depth,
			"oldest_age", stats.OldestAge.String(),
		)
	case backpressureLevelNormal:
		if prev == backpressureLevelWarning || prev == backpressureLevelCritical {
			metrics.RecordJetStreamBackpressureAlert(p.config.Stream, "recovered")
			p.logger.Info("jetstream outbox backpressure recovered",
				"previous_level", prev,
				"depth", stats.Depth,
				"oldest_age", stats.OldestAge.String(),
			)
		}
	}
}

func (c JetStreamConfig) evaluateOutboxBackpressure(stats outboxStats) outboxBackpressureState {
	depthRatio := 0.0
	if c.OutboxMaxRecords > 0 {
		depthRatio = (float64(stats.Depth) / float64(c.OutboxMaxRecords)) * 100
	}

	criticalReasons := make([]string, 0, 2)
	if c.OutboxCriticalPercent > 0 && c.OutboxMaxRecords > 0 && depthRatio >= float64(c.OutboxCriticalPercent) {
		criticalReasons = append(criticalReasons, fmt.Sprintf("depth %.1f%% >= %d%%", depthRatio, c.OutboxCriticalPercent))
	}
	if c.OutboxCriticalAge > 0 && stats.Depth > 0 && stats.OldestAge >= c.OutboxCriticalAge {
		criticalReasons = append(criticalReasons, fmt.Sprintf("oldest_age %s >= %s", stats.OldestAge.Truncate(time.Second), c.OutboxCriticalAge))
	}
	if len(criticalReasons) > 0 {
		return outboxBackpressureState{Level: backpressureLevelCritical, Reason: strings.Join(criticalReasons, ", ")}
	}

	warningReasons := make([]string, 0, 2)
	if c.OutboxWarnPercent > 0 && c.OutboxMaxRecords > 0 && depthRatio >= float64(c.OutboxWarnPercent) {
		warningReasons = append(warningReasons, fmt.Sprintf("depth %.1f%% >= %d%%", depthRatio, c.OutboxWarnPercent))
	}
	if c.OutboxWarnAge > 0 && stats.Depth > 0 && stats.OldestAge >= c.OutboxWarnAge {
		warningReasons = append(warningReasons, fmt.Sprintf("oldest_age %s >= %s", stats.OldestAge.Truncate(time.Second), c.OutboxWarnAge))
	}
	if len(warningReasons) > 0 {
		return outboxBackpressureState{Level: backpressureLevelWarning, Reason: strings.Join(warningReasons, ", ")}
	}

	return outboxBackpressureState{Level: backpressureLevelNormal}
}

func cloudEventSchemaFor(eventType string) string {
	normalized := strings.ToLower(strings.TrimSpace(eventType))
	if normalized == "" {
		normalized = "unknown"
	}
	normalized = strings.ReplaceAll(normalized, " ", "-")
	return fmt.Sprintf("%s/%s/%s", cloudEventSchemaPrefix, normalized, cloudEventSchemaV1)
}

func dataValueString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := data[key]; ok {
			switch typed := value.(type) {
			case string:
				if trimmed := strings.TrimSpace(typed); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return ""
}

func generateTraceParent() string {
	traceID := make([]byte, 16)
	spanID := make([]byte, 8)
	if _, err := rand.Read(traceID); err != nil {
		fallback := strings.ReplaceAll(uuid.NewString(), "-", "")
		if len(fallback) < 32 {
			fallback = fallback + strings.Repeat("0", 32-len(fallback))
		}
		return fmt.Sprintf("00-%s-%s-01", fallback[:32], fallback[16:32])
	}
	if _, err := rand.Read(spanID); err != nil {
		fallback := strings.ReplaceAll(uuid.NewString(), "-", "")
		if len(fallback) < 16 {
			fallback = fallback + strings.Repeat("0", 16-len(fallback))
		}
		return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID), fallback[:16])
	}

	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID), hex.EncodeToString(spanID))
}
