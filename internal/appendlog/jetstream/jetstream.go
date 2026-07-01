package jetstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/telemetry"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	connectTimeout               = 5 * time.Second
	defaultReplayLimit           = 100
	maxReplayLimit               = 1000
	maxReplayCandidates          = 5000
	publishRetryAttempts         = 10
	publishRetryInitialBackoff   = 250 * time.Millisecond
	publishRetryMaxBackoff       = 5 * time.Second
	publishClientRetryAttempts   = 5
	publishClientRetryWait       = 500 * time.Millisecond
	publishAttemptTimeout        = 30 * time.Second
	publishRetryMaxElapsed       = 90 * time.Second
	jetstreamCanaryKind          = "cerebro.health.jetstream_canary"
	jetstreamCanaryMinInterval   = time.Minute
	defaultRuntimeIndexScanBatch = 1000
	maxRuntimeIndexScanBatch     = 5000
)

const (
	replayStrategyEmptyStream       = "empty_stream"
	replayStrategyLegacyReverseScan = "legacy_reverse_scan"
	replayStrategySubjectIndex      = "subject_index"
	replayStrategyRuntimeIndex      = "runtime_index"
)

const (
	publishBulkheadScopeGlobal   = "global"
	publishBulkheadScopeFindings = "findings"
)

var errRuntimeReplayIndexRequired = errors.New("runtime replay index required")

var waitBeforePublishRetryFunc = waitBeforePublishRetry

type publisher interface {
	AccountInfo(context.Context) (*jetstream.AccountInfo, error)
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

type replayManager interface {
	Streams(context.Context) ([]*jetstream.StreamInfo, error)
	Stream(context.Context, string) (replayStream, error)
}

type replayStream interface {
	GetMsg(context.Context, uint64) (*jetstream.RawStreamMsg, error)
	GetNextMsgForSubject(context.Context, uint64, string) (*jetstream.RawStreamMsg, error)
}

type publishTelemetry struct {
	Attempts               int
	MaxAttempts            int
	RetryCount             int
	LastBackoff            time.Duration
	LastRetryable          bool
	Duration               time.Duration
	RetryBudget            time.Duration
	AttemptTimeout         time.Duration
	MaxBackoff             time.Duration
	ClientRetries          int
	ClientWait             time.Duration
	RetryExhausted         bool
	MaxExhausted           bool
	BulkheadWait           time.Duration
	BulkheadLimit          int
	BulkheadEffectiveLimit int
	Bulkheads              []publishBulkheadTelemetry
	AckStream              string
	AckSequence            uint64
	AckDuplicate           bool
	AckUnavailable         bool
}

type publishBulkheadTelemetry struct {
	Scope string
	Limit int
	Wait  time.Duration
}

type publishRetryConfig struct {
	MaxAttempts         int
	InitialBackoff      time.Duration
	MaxBackoff          time.Duration
	ClientRetryAttempts int
	ClientRetryWait     time.Duration
	AttemptTimeout      time.Duration
	MaxElapsed          time.Duration
}

type jetStreamReplayManager struct {
	js jetstream.JetStream
}

func (m *jetStreamReplayManager) Streams(ctx context.Context) ([]*jetstream.StreamInfo, error) {
	lister := m.js.ListStreams(ctx)
	streams := make([]*jetstream.StreamInfo, 0)
	for info := range lister.Info() {
		streams = append(streams, info)
	}
	if err := lister.Err(); err != nil {
		return nil, err
	}
	return streams, nil
}

func (m *jetStreamReplayManager) Stream(ctx context.Context, stream string) (replayStream, error) {
	streamRef, err := m.js.Stream(ctx, stream)
	if err != nil {
		return nil, err
	}
	return &jetStreamReplayStream{stream: streamRef}, nil
}

type jetStreamReplayStream struct {
	stream jetstream.Stream
}

func (s *jetStreamReplayStream) GetMsg(ctx context.Context, seq uint64) (*jetstream.RawStreamMsg, error) {
	return s.stream.GetMsg(ctx, seq)
}

func (s *jetStreamReplayStream) GetNextMsgForSubject(ctx context.Context, seq uint64, subject string) (*jetstream.RawStreamMsg, error) {
	return s.stream.GetMsg(ctx, seq, jetstream.WithGetMsgSubject(subject))
}

// Log is the JetStream-backed append-log implementation.
type Log struct {
	conn          *nats.Conn
	js            publisher
	replay        replayManager
	streamName    string
	subjectPrefix string
	publishSlots  chan struct{}
	findingSlots  chan struct{}
	publishRetry  publishRetryConfig
	canaryMu      sync.Mutex
	lastCanary    time.Time
	runtimeIndex  ports.RuntimeReplayIndex
}

// SetRuntimeReplayIndex enables runtime-scoped replay acceleration backed by the
// per-runtime append-log index. A nil index leaves replay on the subject/legacy
// strategies. Replay stays correct regardless: the index only contributes
// candidate sequences, and the un-indexed tail is always merged directly.
func (l *Log) SetRuntimeReplayIndex(index ports.RuntimeReplayIndex) {
	if l == nil {
		return
	}
	l.runtimeIndex = index
}

// Open dials JetStream and returns an append-log implementation.
func Open(cfg config.AppendLogConfig) (*Log, error) {
	url := strings.TrimSpace(cfg.JetStreamURL)
	if url == "" {
		return nil, errors.New("jetstream url is required")
	}
	prefix, err := normalizeSubjectPrefix(cfg.JetStreamSubjectPrefix)
	if err != nil {
		return nil, err
	}
	streamName, err := normalizeStreamName(cfg.JetStreamStreamName)
	if err != nil {
		return nil, err
	}
	options := []nats.Option{
		nats.Name("cerebro"),
		nats.Timeout(connectTimeout),
		nats.RetryOnFailedConnect(false),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Printf("nats disconnected: %v", err)
		}),
		nats.ReconnectHandler(func(conn *nats.Conn) {
			log.Printf("nats reconnected: %s", redactNATSURL(conn.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			log.Print("nats connection closed")
		}),
	}
	if cfg.JetStreamDrainTimeout > 0 {
		options = append(options, nats.DrainTimeout(cfg.JetStreamDrainTimeout))
	}
	nc, err := nats.Connect(url, options...)
	if err != nil {
		return nil, fmt.Errorf("connect nats: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("new jetstream client: %w", err)
	}
	log := &Log{
		conn:          nc,
		js:            js,
		replay:        &jetStreamReplayManager{js: js},
		streamName:    streamName,
		subjectPrefix: prefix,
		publishRetry:  publishRetryConfigFromAppendLog(cfg),
	}
	if cfg.JetStreamPublishMaxInFlight > 0 {
		log.publishSlots = make(chan struct{}, cfg.JetStreamPublishMaxInFlight)
	}
	if cfg.JetStreamPublishFindingsMaxInFlight > 0 {
		log.findingSlots = make(chan struct{}, cfg.JetStreamPublishFindingsMaxInFlight)
	}
	return log, nil
}

func publishRetryConfigFromAppendLog(cfg config.AppendLogConfig) publishRetryConfig {
	retry := defaultPublishRetryConfig()
	if cfg.JetStreamPublishRetryAttempts > 0 {
		retry.MaxAttempts = cfg.JetStreamPublishRetryAttempts
	}
	if cfg.JetStreamPublishRetryInitialBackoff > 0 {
		retry.InitialBackoff = cfg.JetStreamPublishRetryInitialBackoff
	}
	if cfg.JetStreamPublishRetryMaxBackoff > 0 {
		retry.MaxBackoff = cfg.JetStreamPublishRetryMaxBackoff
	}
	if cfg.JetStreamPublishClientRetryAttempts > 0 {
		retry.ClientRetryAttempts = cfg.JetStreamPublishClientRetryAttempts
	}
	if cfg.JetStreamPublishClientRetryWait > 0 {
		retry.ClientRetryWait = cfg.JetStreamPublishClientRetryWait
	}
	if cfg.JetStreamPublishAttemptTimeout > 0 {
		retry.AttemptTimeout = cfg.JetStreamPublishAttemptTimeout
	}
	if cfg.JetStreamPublishRetryMaxElapsed > 0 {
		retry.MaxElapsed = cfg.JetStreamPublishRetryMaxElapsed
	}
	if retry.InitialBackoff > retry.MaxBackoff {
		retry.InitialBackoff = retry.MaxBackoff
	}
	if retry.AttemptTimeout > retry.MaxElapsed {
		retry.AttemptTimeout = retry.MaxElapsed
	}
	return retry
}

func defaultPublishRetryConfig() publishRetryConfig {
	return publishRetryConfig{
		MaxAttempts:         publishRetryAttempts,
		InitialBackoff:      publishRetryInitialBackoff,
		MaxBackoff:          publishRetryMaxBackoff,
		ClientRetryAttempts: publishClientRetryAttempts,
		ClientRetryWait:     publishClientRetryWait,
		AttemptTimeout:      publishAttemptTimeout,
		MaxElapsed:          publishRetryMaxElapsed,
	}
}

func (l *Log) effectivePublishRetryConfig() publishRetryConfig {
	if l == nil {
		return defaultPublishRetryConfig()
	}
	retry := l.publishRetry
	if retry.MaxAttempts <= 0 {
		retry.MaxAttempts = publishRetryAttempts
	}
	if retry.InitialBackoff <= 0 {
		retry.InitialBackoff = publishRetryInitialBackoff
	}
	if retry.MaxBackoff <= 0 {
		retry.MaxBackoff = publishRetryMaxBackoff
	}
	if retry.ClientRetryAttempts <= 0 {
		retry.ClientRetryAttempts = publishClientRetryAttempts
	}
	if retry.ClientRetryWait <= 0 {
		retry.ClientRetryWait = publishClientRetryWait
	}
	if retry.AttemptTimeout <= 0 {
		retry.AttemptTimeout = publishAttemptTimeout
	}
	if retry.MaxElapsed <= 0 {
		retry.MaxElapsed = publishRetryMaxElapsed
	}
	return retry
}

// Close closes the underlying NATS connection.
func (l *Log) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	if err := l.conn.Drain(); err != nil {
		l.conn.Close()
		return fmt.Errorf("drain nats connection: %w", err)
	}
	return nil
}

func redactNATSURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "<redacted>"
	}
	parsed.User = nil
	return parsed.String()
}

// Ping verifies that JetStream is reachable.
func (l *Log) Ping(ctx context.Context) error {
	ctx, span := telemetry.Start(ctx, "jetstream.ping", jetstreamTelemetryAttrs("ping"))
	if l == nil || l.js == nil {
		err := errors.New("jetstream is not configured")
		jetstreamTelemetryError(ctx, span, "ping", err)
		return err
	}
	pingAttrs := telemetry.Attrs()
	accountStarted := time.Now()
	_, err := l.js.AccountInfo(ctx)
	pingAttrs = pingAttrs.WithField(telemetry.Field{Key: "messaging.jetstream.account_info.duration_ms", Value: time.Since(accountStarted).Milliseconds()})
	if err != nil {
		err = fmt.Errorf("jetstream account info: %w", err)
		jetstreamTelemetryError(ctx, span, "ping", err, pingAttrs)
		return err
	}
	if l.replay != nil {
		stream, err := l.replayStream(ctx)
		if err != nil {
			err = fmt.Errorf("jetstream stream readiness: %w", err)
			jetstreamTelemetryError(ctx, span, "ping", err, pingAttrs)
			return err
		}
		pingAttrs = pingAttrs.With(jetstreamStreamTelemetryAttrs(stream))
		if l.shouldRunCanary(time.Now().UTC()) {
			canaryAttrs, err := l.runCanary(ctx, stream)
			pingAttrs = pingAttrs.With(canaryAttrs)
			if err != nil {
				telemetry.Event(ctx, "jetstream.canary.failed", canaryAttrs.With(jetstreamErrorTelemetryAttrs("canary", err)))
				err = fmt.Errorf("jetstream canary: %w", err)
				jetstreamTelemetryError(ctx, span, "canary", err, pingAttrs)
				return err
			}
			l.markCanarySucceeded(time.Now().UTC())
			telemetry.Event(ctx, "jetstream.canary.completed", canaryAttrs)
		} else {
			pingAttrs = pingAttrs.With(telemetry.Attrs(
				telemetry.Field{Key: "messaging.jetstream.canary.throttled", Value: true},
				telemetry.Field{Key: "messaging.jetstream.canary.interval_ms", Value: jetstreamCanaryMinInterval.Milliseconds()},
			))
		}
	}
	jetstreamAnnotateMain(ctx, "ping", "completed", pingAttrs)
	telemetry.End(span, "completed", pingAttrs)
	return nil
}

// Append marshals and publishes an event envelope.
func (l *Log) Append(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	kind := ""
	if event != nil {
		kind = strings.TrimSpace(event.Kind)
	}
	ctx, span := telemetry.Start(ctx, "jetstream.append", jetstreamTelemetryAttrs("append").WithField(telemetry.Field{Key: "event.kind", Value: kind}))
	if l == nil || l.js == nil {
		err := errors.New("jetstream is not configured")
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	if event == nil {
		err := errors.New("event is required")
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	if err := validateEventKind(kind); err != nil {
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	subject, err := eventSubject(l.subjectPrefix, kind)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	envelope := proto.Clone(event).(*cerebrov1.EventEnvelope)
	envelope.Kind = kind
	payload, err := publishPayload(envelope)
	if err != nil {
		err = fmt.Errorf("marshal event: %w", err)
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	msg := nats.NewMsg(subject)
	msg.Data = payload
	if workflowevents.IsSharedEnvelopeEvent(envelope) {
		msg.Header = eventAttributesHeader(envelope.GetAttributes())
	}
	messageID := publishMessageID(envelope, payload)
	if messageID != "" {
		if msg.Header == nil {
			msg.Header = nats.Header{}
		}
		msg.Header.Set(nats.MsgIdHdr, messageID)
	}
	l.applyExpectedStream(msg)
	publishAttrs := func() telemetry.Attributes {
		return l.publishMessageAttrs(subject, len(payload), msg.Header.Get(nats.MsgIdHdr))
	}
	publishResult, err := l.publishMsg(ctx, msg, "append", publishAttrs)
	endAttrs := publishAttrs().With(publishResult.attrs())
	if err != nil {
		publishErr := fmt.Errorf("publish event: %w", err)
		recordJetStreamPublish(ctx, "append", subject, "failed", publishErr, publishResult)
		jetstreamTelemetryError(ctx, span, "append", publishErr, endAttrs)
		if publishResult.MaxExhausted {
			return &ports.AppendLogPublishExhaustedError{
				Operation:     "append",
				Subject:       subject,
				ErrorCategory: jetstreamErrorCategory(err),
				RetryCount:    publishResult.RetryCount,
				MaxAttempts:   publishResult.MaxAttempts,
				Err:           publishErr,
			}
		}
		return publishErr
	}
	recordJetStreamPublish(ctx, "append", subject, "completed", nil, publishResult)
	if publishResult.RetryCount > 0 {
		telemetry.IncrementMain(ctx, "messaging.jetstream.publish.recovered.count", 1)
		telemetry.Event(ctx, "jetstream.publish.recovered", endAttrs)
	}
	jetstreamAnnotateMain(ctx, "append", "completed", endAttrs)
	telemetry.End(span, "completed", endAttrs)
	return nil
}

// AppendBatch publishes a validated batch in order. It intentionally preserves
// the single-event append semantics so callers can retry safely using message ids.
func (l *Log) AppendBatch(ctx context.Context, events []*cerebrov1.EventEnvelope) error {
	for index, event := range events {
		if err := l.Append(ctx, event); err != nil {
			return fmt.Errorf("append batch event %d: %w", index, err)
		}
	}
	return nil
}

func (l *Log) publishMsg(ctx context.Context, msg *nats.Msg, operation string, eventAttrs func() telemetry.Attributes) (publishTelemetry, error) {
	retry := l.effectivePublishRetryConfig()
	result := publishTelemetry{
		Attempts:       0,
		MaxAttempts:    retry.MaxAttempts,
		RetryBudget:    retry.MaxElapsed,
		AttemptTimeout: retry.AttemptTimeout,
		MaxBackoff:     retry.MaxBackoff,
		ClientRetries:  retry.ClientRetryAttempts,
		ClientWait:     retry.ClientRetryWait,
	}
	backoff := retry.InitialBackoff
	started := time.Now()
	retryCtx, cancelRetry := context.WithTimeout(ctx, retry.MaxElapsed)
	defer cancelRetry()
	var err error
	for attempt := 1; attempt <= result.MaxAttempts; attempt++ {
		result.Attempts = attempt
		attemptCtx, cancel := context.WithTimeout(retryCtx, retry.AttemptTimeout)
		bulkheads, release, acquireErr := l.acquirePublishSlots(attemptCtx, msg.Subject)
		result.addBulkheads(bulkheads)
		if acquireErr != nil {
			cancel()
			err = acquireErr
			result.LastRetryable = retryablePublishError(err)
			if attempt == result.MaxAttempts || !result.LastRetryable || retryCtx.Err() != nil {
				result.Duration = time.Since(started)
				result.RetryExhausted = result.RetryCount > 0
				result.MaxExhausted = attempt == result.MaxAttempts
				if result.RetryExhausted {
					telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry_exhausted.count", 1)
					telemetry.Event(ctx, "jetstream.publish.retry_exhausted", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, err)))
				}
				return result, err
			}
			result.RetryCount++
			result.LastBackoff = backoff
			telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry.count", 1)
			telemetry.Event(ctx, "jetstream.publish.retry", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, err)).With(telemetry.Attrs(
				telemetry.Field{Key: "messaging.jetstream.publish.next_attempt", Value: attempt + 1},
				telemetry.Field{Key: "messaging.jetstream.publish.next_backoff_ms", Value: backoff.Milliseconds()},
			)))
			if waitErr := waitBeforePublishRetryFunc(retryCtx, backoff); waitErr != nil {
				result.Duration = time.Since(started)
				result.RetryExhausted = result.RetryCount > 0
				telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry_exhausted.count", 1)
				telemetry.Event(ctx, "jetstream.publish.retry_exhausted", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, waitErr)))
				return result, waitErr
			}
			backoff = minDuration(backoff*2, retry.MaxBackoff)
			continue
		}
		ack, publishErr := l.js.PublishMsg(
			attemptCtx,
			msg,
			jetstream.WithRetryAttempts(retry.ClientRetryAttempts),
			jetstream.WithRetryWait(retry.ClientRetryWait),
		)
		release()
		cancel()
		if publishErr == nil {
			result.Duration = time.Since(started)
			result.applyAck(ack)
			return result, nil
		}
		err = publishErr
		result.LastRetryable = retryablePublishError(err)
		if attempt == result.MaxAttempts || !result.LastRetryable || retryCtx.Err() != nil {
			result.Duration = time.Since(started)
			result.RetryExhausted = result.RetryCount > 0
			result.MaxExhausted = attempt == result.MaxAttempts
			if result.RetryCount > 0 {
				telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry_exhausted.count", 1)
				telemetry.Event(ctx, "jetstream.publish.retry_exhausted", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, err)))
			}
			return result, err
		}
		result.RetryCount++
		result.LastBackoff = backoff
		telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry.count", 1)
		telemetry.Event(ctx, "jetstream.publish.retry", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, err)).With(telemetry.Attrs(
			telemetry.Field{Key: "messaging.jetstream.publish.next_attempt", Value: attempt + 1},
			telemetry.Field{Key: "messaging.jetstream.publish.next_backoff_ms", Value: backoff.Milliseconds()},
		)))
		if waitErr := waitBeforePublishRetryFunc(retryCtx, backoff); waitErr != nil {
			result.Duration = time.Since(started)
			result.RetryExhausted = result.RetryCount > 0
			telemetry.IncrementMain(ctx, "messaging.jetstream.publish.retry_exhausted.count", 1)
			telemetry.Event(ctx, "jetstream.publish.retry_exhausted", eventAttrs().With(result.attrs()).With(jetstreamErrorTelemetryAttrs(operation, waitErr)))
			return result, waitErr
		}
		backoff = minDuration(backoff*2, retry.MaxBackoff)
	}
	result.Duration = time.Since(started)
	return result, err
}

func (l *Log) applyExpectedStream(msg *nats.Msg) {
	if l == nil || msg == nil || strings.TrimSpace(l.streamName) == "" {
		return
	}
	if msg.Header == nil {
		msg.Header = nats.Header{}
	}
	msg.Header.Set(jetstream.ExpectedStreamHeader, strings.TrimSpace(l.streamName))
}

func (l *Log) acquirePublishSlots(ctx context.Context, subject string) ([]publishBulkheadTelemetry, func(), error) {
	bulkheads := l.publishBulkheads(subject)
	if len(bulkheads) == 0 {
		return nil, func() {}, nil
	}
	acquired := make([]publishBulkheadTelemetry, 0, len(bulkheads))
	releases := make([]func(), 0, len(bulkheads))
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	for _, bulkhead := range bulkheads {
		wait, release, err := acquirePublishSlot(ctx, bulkhead.slots)
		acquired = append(acquired, publishBulkheadTelemetry{
			Scope: bulkhead.scope,
			Limit: cap(bulkhead.slots),
			Wait:  wait,
		})
		if err != nil {
			releaseAll()
			return acquired, func() {}, err
		}
		releases = append(releases, release)
	}
	return acquired, releaseAll, nil
}

type publishBulkhead struct {
	scope string
	slots chan struct{}
}

func (l *Log) publishBulkheads(subject string) []publishBulkhead {
	if l == nil {
		return nil
	}
	bulkheads := make([]publishBulkhead, 0, 2)
	if l.publishSlots != nil {
		bulkheads = append(bulkheads, publishBulkhead{
			scope: publishBulkheadScopeGlobal,
			slots: l.publishSlots,
		})
	}
	if l.findingSlots != nil && isFindingPublishSubject(subject) {
		bulkheads = append(bulkheads, publishBulkhead{
			scope: publishBulkheadScopeFindings,
			slots: l.findingSlots,
		})
	}
	return bulkheads
}

func acquirePublishSlot(ctx context.Context, slots chan struct{}) (time.Duration, func(), error) {
	if slots == nil {
		return 0, func() {}, nil
	}
	started := time.Now()
	select {
	case slots <- struct{}{}:
		return time.Since(started), func() {
			<-slots
		}, nil
	case <-ctx.Done():
		return time.Since(started), func() {}, ctx.Err()
	}
}

func isFindingPublishSubject(subject string) bool {
	normalized := strings.TrimSpace(subject)
	if normalized == securityevents.FindingsV1Prefix || strings.HasPrefix(normalized, securityevents.FindingsV1Prefix+".") {
		return true
	}
	for _, kind := range []string{
		workflowevents.EventKindFindingRecorded,
		workflowevents.EventKindFindingNoteAdded,
		workflowevents.EventKindFindingTicketLinked,
		workflowevents.EventKindFindingStatusChanged,
		workflowevents.EventKindFindingExternalRefLinked,
		workflowevents.EventKindFindingTombstoned,
	} {
		if normalized == kind || strings.HasSuffix(normalized, "."+kind) {
			return true
		}
	}
	return false
}

func publishMessageID(event *cerebrov1.EventEnvelope, payload []byte) string {
	if event != nil {
		if id := strings.TrimSpace(event.Id); id != "" {
			return id
		}
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *publishTelemetry) applyAck(ack *jetstream.PubAck) {
	if ack == nil {
		r.AckUnavailable = true
		return
	}
	r.AckStream = strings.TrimSpace(ack.Stream)
	r.AckSequence = ack.Sequence
	r.AckDuplicate = ack.Duplicate
}

func (r *publishTelemetry) addBulkheads(bulkheads []publishBulkheadTelemetry) {
	for _, bulkhead := range bulkheads {
		if bulkhead.Scope == "" || bulkhead.Limit <= 0 {
			continue
		}
		r.BulkheadWait += bulkhead.Wait
		if bulkhead.Scope == publishBulkheadScopeGlobal || r.BulkheadLimit == 0 {
			r.BulkheadLimit = bulkhead.Limit
		}
		if r.BulkheadEffectiveLimit == 0 || bulkhead.Limit < r.BulkheadEffectiveLimit {
			r.BulkheadEffectiveLimit = bulkhead.Limit
		}
		found := false
		for i := range r.Bulkheads {
			if r.Bulkheads[i].Scope == bulkhead.Scope {
				r.Bulkheads[i].Wait += bulkhead.Wait
				r.Bulkheads[i].Limit = bulkhead.Limit
				found = true
				break
			}
		}
		if !found {
			r.Bulkheads = append(r.Bulkheads, bulkhead)
		}
	}
}

func (r publishTelemetry) attrs() telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.publish.attempts", Value: r.Attempts},
		telemetry.Field{Key: "messaging.jetstream.publish.max_attempts", Value: r.MaxAttempts},
		telemetry.Field{Key: "messaging.jetstream.publish.retry_count", Value: r.RetryCount},
		telemetry.Field{Key: "messaging.jetstream.publish.retryable_last_error", Value: r.LastRetryable},
		telemetry.Field{Key: "messaging.jetstream.publish.retry_exhausted", Value: r.RetryExhausted},
		telemetry.Field{Key: "messaging.jetstream.publish.max_attempts_exhausted", Value: r.MaxExhausted},
		telemetry.Field{Key: "messaging.jetstream.publish.last_backoff_ms", Value: r.LastBackoff.Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.publish.duration_ms", Value: r.Duration.Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.publish.retry_budget_ms", Value: r.RetryBudget.Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.publish.attempt_timeout_ms", Value: r.AttemptTimeout.Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.publish.max_backoff_ms", Value: r.MaxBackoff.Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.publish.client_retry_attempts", Value: r.ClientRetries},
		telemetry.Field{Key: "messaging.jetstream.publish.client_retry_wait_ms", Value: r.ClientWait.Milliseconds()},
	)
	if r.BulkheadLimit > 0 {
		scopes := make([]string, 0, len(r.Bulkheads))
		for _, bulkhead := range r.Bulkheads {
			scopes = append(scopes, bulkhead.Scope)
		}
		attrs = attrs.With(telemetry.Attrs(
			telemetry.Field{Key: "messaging.jetstream.publish.bulkhead.enabled", Value: true},
			telemetry.Field{Key: "messaging.jetstream.publish.bulkhead.max_in_flight", Value: r.BulkheadLimit},
			telemetry.Field{Key: "messaging.jetstream.publish.bulkhead.effective_max_in_flight", Value: r.BulkheadEffectiveLimit},
			telemetry.Field{Key: "messaging.jetstream.publish.bulkhead.wait_ms", Value: r.BulkheadWait.Milliseconds()},
			telemetry.Field{Key: "messaging.jetstream.publish.bulkhead.scopes", Value: strings.Join(scopes, ",")},
		))
		for _, bulkhead := range r.Bulkheads {
			attrs = attrs.With(telemetry.Attrs(
				telemetry.Field{Key: "messaging.jetstream.publish.bulkhead." + bulkhead.Scope + ".max_in_flight", Value: bulkhead.Limit},
				telemetry.Field{Key: "messaging.jetstream.publish.bulkhead." + bulkhead.Scope + ".wait_ms", Value: bulkhead.Wait.Milliseconds()},
			))
		}
	}
	if r.AckUnavailable {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.ack.unavailable", Value: true})
	}
	if r.AckStream != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.ack.stream", Value: r.AckStream})
	}
	if r.AckSequence > 0 {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.ack.sequence", Value: r.AckSequence})
	}
	if r.AckStream != "" || r.AckSequence > 0 || r.AckDuplicate {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.ack.duplicate", Value: r.AckDuplicate})
	}
	return attrs
}

func retryablePublishError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		return apiErr.Code == 408 || apiErr.Code == 429 || apiErr.Code >= 500
	}
	text := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"no response",
		"timeout",
		"deadline exceeded",
		"temporarily unavailable",
		"connection",
		"reconnect",
		"broken pipe",
		"reset by peer",
	} {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

func recordJetStreamPublish(ctx context.Context, operation string, subject string, status string, err error, result publishTelemetry) {
	errorCategory := "none"
	if err != nil {
		errorCategory = jetstreamErrorCategory(err)
	}
	observability.RecordJetStreamPublish(ctx, observability.JetStreamPublishMetrics{
		Subject:              subject,
		Operation:            operation,
		Status:               status,
		ErrorCategory:        errorCategory,
		Duration:             result.Duration,
		RetryCount:           result.RetryCount,
		MaxAttemptsExhausted: result.MaxExhausted,
	})
}

func waitBeforePublishRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

// Replay returns the newest matching stored envelopes in append order.
func (l *Log) Replay(ctx context.Context, req ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	request := normalizeReplayRequest(req)
	ctx, span := telemetry.Start(ctx, "jetstream.replay", jetstreamTelemetryAttrs("replay").
		WithField(telemetry.Field{Key: "replay.limit", Value: normalizeReplayLimit(request.Limit)}).
		WithField(telemetry.Field{Key: "replay.kind_prefix_count", Value: len(replayKindPrefixes(request))}).
		WithField(telemetry.Field{Key: "replay.attribute_filter_count", Value: len(request.AttributeEquals)}).
		With(jetstreamReplayRequestAttrs(request)))
	if l == nil || l.replay == nil {
		err := errors.New("jetstream is not configured")
		jetstreamTelemetryError(ctx, span, "replay", err)
		return nil, err
	}
	if request.RuntimeID == "" && request.KindPrefix == "" && len(request.KindPrefixes) == 0 && request.TenantID == "" && len(request.AttributeEquals) == 0 {
		err := errors.New("at least one replay filter is required")
		jetstreamTelemetryError(ctx, span, "replay", err)
		return nil, err
	}
	stream, err := l.replayStream(ctx)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "replay", err)
		return nil, err
	}
	streamAttrs := jetstreamStreamTelemetryAttrs(stream)
	prefix, err := normalizeSubjectPrefix(l.subjectPrefix)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs)
		return nil, err
	}
	subjectPrefixes := replaySubjectPrefixes(prefix, request)
	limit := normalizeReplayLimit(request.Limit)
	candidateLimit := normalizeReplayCandidateLimit(limit)
	streamRef, err := l.replay.Stream(ctx, stream.Config.Name)
	if err != nil {
		err = fmt.Errorf("open replay stream %q: %w", stream.Config.Name, err)
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(jetstreamReplayScanAttrs(limit, candidateLimit, 0, 0, 0, 0, 0, 0, ctx)))
		return nil, err
	}
	started := time.Now()
	var candidates []replayCandidate
	var scan replayScanStats
	subjectFilters, useSubjectIndex, err := exactReplaySubjectFilters(prefix, request)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(jetstreamReplayScanAttrs(limit, candidateLimit, 0, 0, 0, 0, 0, 0, ctx)))
		return nil, err
	}
	if stream.State.LastSeq == 0 || stream.State.LastSeq < stream.State.FirstSeq {
		recordJetStreamReplayMetrics(ctx, replayScanStats{strategy: replayStrategyEmptyStream, subjectFilterCount: len(subjectFilters)}, "completed", "", time.Since(started), 0)
		endAttrs := streamAttrs.With(jetstreamReplayScanAttrs(limit, candidateLimit, 0, 0, 0, 0, 0, 0, ctx)).
			With(jetstreamReplayStrategyAttrs(replayStrategyEmptyStream, len(subjectFilters))).
			WithField(telemetry.Field{Key: "events_returned", Value: 0}).
			WithField(telemetry.Field{Key: "messaging.jetstream.replay.duration_ms", Value: time.Since(started).Milliseconds()})
		jetstreamAnnotateMain(ctx, "replay", "completed", endAttrs)
		telemetry.End(span, "completed", endAttrs)
		return nil, nil
	}
	resolved := false
	requireRuntimeIndex := request.RequireRuntimeIndex
	runtimeIndexEligible := runtimeIndexReplayEligible(request)
	if requireRuntimeIndex && !runtimeIndexEligible {
		scan = replayScanStats{strategy: replayStrategyRuntimeIndex, subjectFilterCount: len(subjectFilters)}
		err = fmt.Errorf("%w: ineligible replay request", errRuntimeReplayIndexRequired)
		recordJetStreamReplayMetrics(ctx, scan, "failed", jetstreamErrorCategory(err), time.Since(started), 0)
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(scan.attrs(limit, candidateLimit, ctx)))
		return nil, err
	}
	if requireRuntimeIndex && l.runtimeIndex == nil {
		scan = replayScanStats{strategy: replayStrategyRuntimeIndex, subjectFilterCount: len(subjectFilters)}
		err = fmt.Errorf("%w: not configured", errRuntimeReplayIndexRequired)
		recordJetStreamReplayMetrics(ctx, scan, "failed", jetstreamErrorCategory(err), time.Since(started), 0)
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(scan.attrs(limit, candidateLimit, ctx)))
		return nil, err
	}
	if l.runtimeIndex != nil && runtimeIndexEligible {
		indexed, indexScan, ok, indexErr := replayRuntimeIndexed(ctx, l.runtimeIndex, stream.Config.Name, stream.State, streamRef, subjectFilters, useSubjectIndex, subjectPrefixes, request, candidateLimit)
		if indexErr == nil && ok {
			candidates, scan, resolved = indexed, indexScan, true
		} else if requireRuntimeIndex {
			scan = indexScan
			if indexErr != nil {
				err = fmt.Errorf("%w: lookup: %w", errRuntimeReplayIndexRequired, indexErr)
			} else {
				err = fmt.Errorf("%w: unavailable", errRuntimeReplayIndexRequired)
			}
			recordJetStreamReplayMetrics(ctx, scan, "failed", jetstreamErrorCategory(err), time.Since(started), 0)
			jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(scan.attrs(limit, candidateLimit, ctx)))
			return nil, err
		}
	}
	if !resolved {
		if useSubjectIndex {
			candidates, scan, err = replaySubjectIndexed(ctx, stream.Config.Name, stream.State, streamRef, subjectFilters, request, candidateLimit)
		} else {
			scan.strategy = replayStrategyLegacyReverseScan
			candidates, scan, err = replayLegacyReverse(ctx, stream.Config.Name, stream.State, streamRef, subjectPrefixes, request, candidateLimit)
		}
	}
	if err != nil {
		recordJetStreamReplayMetrics(ctx, scan, "failed", jetstreamErrorCategory(err), time.Since(started), 0)
		jetstreamTelemetryError(ctx, span, "replay", err, streamAttrs.With(scan.attrs(limit, candidateLimit, ctx)))
		return nil, err
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return replayCandidateNewer(candidates[i], candidates[j])
	})
	if countGreaterThanUint32(len(candidates), limit) {
		candidates = candidates[:limit]
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].seq < candidates[j].seq
	})
	events := make([]*cerebrov1.EventEnvelope, 0, len(candidates))
	for _, candidate := range candidates {
		events = append(events, candidate.event)
	}
	recordJetStreamReplayMetrics(ctx, scan, "completed", "", time.Since(started), len(events))
	endAttrs := streamAttrs.With(scan.attrs(limit, candidateLimit, ctx)).
		WithField(telemetry.Field{Key: "events_returned", Value: len(events)}).
		WithField(telemetry.Field{Key: "messaging.jetstream.replay.duration_ms", Value: time.Since(started).Milliseconds()})
	jetstreamAnnotateMain(ctx, "replay", "completed", endAttrs)
	telemetry.End(span, "completed", endAttrs)
	return events, nil
}

type replayScanStats struct {
	scanned            uint64
	missing            uint64
	subjectMatched     uint64
	decoded            uint64
	matched            uint64
	sequence           uint64
	strategy           string
	subjectFilterCount int
}

func (s replayScanStats) attrs(limit uint32, candidateLimit uint32, ctx context.Context) telemetry.Attributes {
	strategy := strings.TrimSpace(s.strategy)
	if strategy == "" {
		strategy = replayStrategyLegacyReverseScan
	}
	return jetstreamReplayScanAttrs(limit, candidateLimit, s.scanned, s.missing, s.subjectMatched, s.decoded, s.matched, s.sequence, ctx).
		With(jetstreamReplayStrategyAttrs(strategy, s.subjectFilterCount))
}

func replayLegacyReverse(ctx context.Context, streamName string, state jetstream.StreamState, stream replayStream, subjectPrefixes []string, request ports.ReplayRequest, candidateLimit uint32) ([]replayCandidate, replayScanStats, error) {
	stats := replayScanStats{strategy: replayStrategyLegacyReverseScan}
	candidates := make([]replayCandidate, 0, candidateLimit)
	for seq := state.LastSeq; ; seq-- {
		stats.scanned++
		raw, err := stream.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				stats.missing++
				if seq == state.FirstSeq {
					break
				}
				continue
			}
			stats.sequence = seq
			return nil, stats, fmt.Errorf("get replay message %s:%d: %w", streamName, seq, err)
		}
		if raw != nil && replaySubjectMatchesAnyPrefix(raw.Subject, subjectPrefixes) {
			stats.subjectMatched++
			event, err := decodeReplayEvent(raw)
			if err != nil {
				stats.sequence = seq
				return nil, stats, fmt.Errorf("decode replay message %s:%d: %w", streamName, seq, err)
			}
			stats.decoded++
			if matchesReplayRequest(event, request) {
				stats.matched++
				candidates = appendNewestReplayCandidate(candidates, replayCandidate{event: event, seq: seq}, candidateLimit)
			}
		}
		if seq == state.FirstSeq {
			break
		}
	}
	return candidates, stats, nil
}

func replaySubjectIndexed(ctx context.Context, streamName string, state jetstream.StreamState, stream replayStream, subjects []string, request ports.ReplayRequest, candidateLimit uint32) ([]replayCandidate, replayScanStats, error) {
	stats := replayScanStats{strategy: replayStrategySubjectIndex, subjectFilterCount: len(subjects)}
	candidates := make([]replayCandidate, 0, candidateLimit)
	for _, subject := range subjects {
		for seq := state.FirstSeq; seq <= state.LastSeq; {
			raw, err := stream.GetNextMsgForSubject(ctx, seq, subject)
			if err != nil {
				if errors.Is(err, jetstream.ErrMsgNotFound) {
					stats.missing++
					break
				}
				stats.sequence = seq
				return nil, stats, fmt.Errorf("get replay message %s:%d subject %q: %w", streamName, seq, subject, err)
			}
			if raw == nil || raw.Sequence == 0 || raw.Sequence > state.LastSeq {
				stats.missing++
				break
			}
			if raw.Sequence < seq {
				stats.sequence = seq
				return nil, stats, fmt.Errorf("get replay message %s:%d subject %q returned older sequence %d", streamName, seq, subject, raw.Sequence)
			}
			stats.scanned++
			stats.subjectMatched++
			event, err := decodeReplayEvent(raw)
			if err != nil {
				stats.sequence = raw.Sequence
				return nil, stats, fmt.Errorf("decode replay message %s:%d: %w", streamName, raw.Sequence, err)
			}
			stats.decoded++
			if matchesReplayRequest(event, request) {
				stats.matched++
				candidates = appendNewestReplayCandidate(candidates, replayCandidate{event: event, seq: raw.Sequence}, candidateLimit)
			}
			if raw.Sequence == ^uint64(0) {
				break
			}
			seq = raw.Sequence + 1
		}
	}
	return candidates, stats, nil
}

func appendNewestReplayCandidate(candidates []replayCandidate, candidate replayCandidate, candidateLimit uint32) []replayCandidate {
	candidates = append(candidates, candidate)
	if countGreaterThanUint32(len(candidates), candidateLimit) {
		sort.SliceStable(candidates, func(i, j int) bool {
			return replayCandidateNewer(candidates[i], candidates[j])
		})
		candidates = candidates[:candidateLimit]
	}
	return candidates
}

// runtimeIndexReplayEligible reports whether a replay can be served from the
// per-runtime index without risking dropped matches. The index narrows only by
// runtime id and, in exact-kind mode, exact kinds. Any post-filter the index
// does not apply (non-exact kind prefixes, attribute-equals, or a tenant
// filter) could leave fewer than the requested limit of matches among the
// newest indexed sequences while older matches sit below the watermark, so such
// requests fall back to the subject/legacy strategies, which collect matched
// candidates directly.
func runtimeIndexReplayEligible(request ports.ReplayRequest) bool {
	if request.RuntimeID == "" {
		return false
	}
	if request.TenantID != "" || len(request.AttributeEquals) > 0 {
		return false
	}
	return request.ExactKindFilters || len(replayKindPrefixes(request)) == 0
}

// replayRuntimeIndexed resolves a runtime-scoped replay from the per-runtime
// index for the bulk of history, then always merges the un-indexed tail
// (watermark, LastSeq] directly from the stream so events appended after the
// asynchronous indexer's watermark are never missed (the sync-then-evaluate
// orchestration relies on this). It returns ok=false without error when the
// index is unpopulated so the caller falls back to the subject/legacy strategies.
func replayRuntimeIndexed(ctx context.Context, index ports.RuntimeReplayIndex, streamName string, state jetstream.StreamState, stream replayStream, subjectFilters []string, useSubjectIndex bool, subjectPrefixes []string, request ports.ReplayRequest, candidateLimit uint32) ([]replayCandidate, replayScanStats, bool, error) {
	stats := replayScanStats{strategy: replayStrategyRuntimeIndex, subjectFilterCount: len(subjectFilters)}
	var kinds []string
	if request.ExactKindFilters {
		kinds = replayKindPrefixes(request)
	}
	lookup, err := index.LookupRuntimeReplay(ctx, ports.RuntimeIndexQuery{
		RuntimeID: request.RuntimeID,
		Kinds:     kinds,
		Limit:     candidateLimit,
	})
	if err != nil {
		return nil, stats, false, err
	}
	if !lookup.Available {
		return nil, stats, false, nil
	}
	candidates := make([]replayCandidate, 0, candidateLimit)
	seen := make(map[uint64]struct{}, candidateLimit)
	for _, seq := range lookup.Sequences {
		raw, err := stream.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				stats.missing++
				continue
			}
			stats.sequence = seq
			return nil, stats, false, fmt.Errorf("get indexed replay message %s:%d: %w", streamName, seq, err)
		}
		if raw == nil {
			stats.missing++
			continue
		}
		stats.scanned++
		stats.subjectMatched++
		event, err := decodeReplayEvent(raw)
		if err != nil {
			stats.sequence = seq
			return nil, stats, false, fmt.Errorf("decode indexed replay message %s:%d: %w", streamName, seq, err)
		}
		stats.decoded++
		if !matchesReplayRequest(event, request) {
			continue
		}
		stats.matched++
		if _, ok := seen[seq]; ok {
			continue
		}
		seen[seq] = struct{}{}
		candidates = appendNewestReplayCandidate(candidates, replayCandidate{event: event, seq: seq}, candidateLimit)
	}
	if lookup.Watermark < state.LastSeq {
		tailState := jetstream.StreamState{FirstSeq: lookup.Watermark + 1, LastSeq: state.LastSeq}
		var (
			tail     []replayCandidate
			tailScan replayScanStats
			tailErr  error
		)
		if useSubjectIndex {
			tail, tailScan, tailErr = replaySubjectIndexed(ctx, streamName, tailState, stream, subjectFilters, request, candidateLimit)
		} else {
			tail, tailScan, tailErr = replayLegacyReverse(ctx, streamName, tailState, stream, subjectPrefixes, request, candidateLimit)
		}
		if tailErr != nil {
			return nil, stats, false, tailErr
		}
		stats.scanned += tailScan.scanned
		stats.missing += tailScan.missing
		stats.subjectMatched += tailScan.subjectMatched
		stats.decoded += tailScan.decoded
		stats.matched += tailScan.matched
		for _, candidate := range tail {
			if _, ok := seen[candidate.seq]; ok {
				continue
			}
			seen[candidate.seq] = struct{}{}
			candidates = appendNewestReplayCandidate(candidates, candidate, candidateLimit)
		}
	}
	return candidates, stats, true, nil
}

// ScanRuntimeIndex walks the stream forward from fromSeq, decoding up to batch
// messages into per-runtime index entries. It skips the purged prefix via the
// stream's FirstSeq and returns the new watermark (highest sequence examined),
// letting the population job advance incrementally and idempotently.
func (l *Log) ScanRuntimeIndex(ctx context.Context, fromSeq uint64, batch uint32) (ports.RuntimeIndexScan, error) {
	ctx, span := telemetry.Start(ctx, "jetstream.runtime_index_scan", jetstreamTelemetryAttrs("runtime_index_scan"))
	if l == nil || l.replay == nil {
		err := errors.New("jetstream is not configured")
		jetstreamTelemetryError(ctx, span, "runtime_index_scan", err)
		return ports.RuntimeIndexScan{}, err
	}
	if batch == 0 {
		batch = defaultRuntimeIndexScanBatch
	}
	if batch > maxRuntimeIndexScanBatch {
		batch = maxRuntimeIndexScanBatch
	}
	stream, err := l.replayStream(ctx)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "runtime_index_scan", err)
		return ports.RuntimeIndexScan{}, err
	}
	lower := fromSeq
	if first := stream.State.FirstSeq; first > 0 && lower+1 < first {
		lower = first - 1
	}
	last := stream.State.LastSeq
	if last == 0 || lower >= last {
		watermark := lower
		if watermark < fromSeq {
			watermark = fromSeq
		}
		telemetry.End(span, "completed", telemetry.Attrs())
		return ports.RuntimeIndexScan{Watermark: watermark, CaughtUp: true}, nil
	}
	streamRef, err := l.replay.Stream(ctx, stream.Config.Name)
	if err != nil {
		err = fmt.Errorf("open index scan stream %q: %w", stream.Config.Name, err)
		jetstreamTelemetryError(ctx, span, "runtime_index_scan", err)
		return ports.RuntimeIndexScan{}, err
	}
	end := lower + uint64(batch)
	if end > last {
		end = last
	}
	entries := make([]ports.RuntimeIndexEntry, 0, batch)
	for seq := lower + 1; seq <= end; seq++ {
		raw, err := streamRef.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			err = fmt.Errorf("get index scan message %s:%d: %w", stream.Config.Name, seq, err)
			jetstreamTelemetryError(ctx, span, "runtime_index_scan", err)
			return ports.RuntimeIndexScan{}, err
		}
		if raw == nil {
			continue
		}
		event, err := decodeReplayEvent(raw)
		if err != nil {
			err = fmt.Errorf("decode index scan message %s:%d: %w", stream.Config.Name, seq, err)
			jetstreamTelemetryError(ctx, span, "runtime_index_scan", err)
			return ports.RuntimeIndexScan{}, err
		}
		if entry, ok := runtimeIndexEntry(event, raw.Sequence); ok {
			entries = append(entries, entry)
		}
	}
	telemetry.End(span, "completed", telemetry.Attrs())
	return ports.RuntimeIndexScan{Entries: entries, Watermark: end, CaughtUp: end >= last}, nil
}

func runtimeIndexEntry(event *cerebrov1.EventEnvelope, seq uint64) (ports.RuntimeIndexEntry, bool) {
	if event == nil {
		return ports.RuntimeIndexEntry{}, false
	}
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		return ports.RuntimeIndexEntry{}, false
	}
	entry := ports.RuntimeIndexEntry{
		RuntimeID: runtimeID,
		Seq:       seq,
		TenantID:  strings.TrimSpace(event.GetTenantId()),
		Kind:      strings.TrimSpace(event.GetKind()),
	}
	if occurredAt, ok := replayEventTime(event); ok {
		entry.OccurredAt = occurredAt
	}
	return entry, true
}

func recordJetStreamReplayMetrics(ctx context.Context, scan replayScanStats, status string, errorCategory string, duration time.Duration, returned int) {
	observability.RecordJetStreamReplay(ctx, observability.JetStreamReplayMetrics{
		Strategy:             scan.strategy,
		Status:               status,
		ErrorCategory:        errorCategory,
		Duration:             duration,
		Scanned:              scan.scanned,
		Missing:              scan.missing,
		SubjectMatched:       scan.subjectMatched,
		Decoded:              scan.decoded,
		Matched:              scan.matched,
		Returned:             uint64(returned), // #nosec G115 -- returned is len(events), always non-negative.
		SubjectFilterPresent: scan.subjectFilterCount > 0,
	})
}

func (l *Log) shouldRunCanary(now time.Time) bool {
	l.canaryMu.Lock()
	defer l.canaryMu.Unlock()
	if l.lastCanary.IsZero() {
		return true
	}
	return now.Sub(l.lastCanary) >= jetstreamCanaryMinInterval
}

func (l *Log) markCanarySucceeded(now time.Time) {
	l.canaryMu.Lock()
	defer l.canaryMu.Unlock()
	if now.After(l.lastCanary) {
		l.lastCanary = now
	}
}

func (l *Log) runCanary(ctx context.Context, stream *jetstream.StreamInfo) (telemetry.Attributes, error) {
	started := time.Now()
	attrs := jetstreamStreamTelemetryAttrs(stream).With(telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.canary.enabled", Value: true},
		telemetry.Field{Key: "messaging.jetstream.canary.kind", Value: "publish_replay"},
		telemetry.Field{Key: "event.kind", Value: jetstreamCanaryKind},
	))
	finish := func(extra telemetry.Attributes) telemetry.Attributes {
		durationMs := time.Since(started).Milliseconds()
		return attrs.With(extra).With(telemetry.Attrs(
			telemetry.Field{Key: "messaging.jetstream.canary.duration_ms", Value: durationMs},
			telemetry.Field{Key: "canary_duration_ms", Value: durationMs},
		))
	}
	subject, err := eventSubject(l.subjectPrefix, jetstreamCanaryKind)
	if err != nil {
		return finish(telemetry.Attrs()), err
	}
	now := time.Now().UTC()
	event := &cerebrov1.EventEnvelope{
		Id:         fmt.Sprintf("jetstream-canary-%d", now.UnixNano()),
		Kind:       jetstreamCanaryKind,
		OccurredAt: timestamppb.New(now),
		Attributes: map[string]string{
			"canary":    "true",
			"component": "appendlog.jetstream",
		},
	}
	payload, err := publishPayload(event)
	if err != nil {
		return finish(telemetry.Attrs()), fmt.Errorf("marshal canary event: %w", err)
	}
	msg := nats.NewMsg(subject)
	msg.Data = payload
	msg.Header.Set(nats.MsgIdHdr, event.Id)
	l.applyExpectedStream(msg)
	publishAttrs := func() telemetry.Attributes {
		return l.publishMessageAttrs(subject, len(payload), event.Id).With(attrs)
	}
	publishResult, err := l.publishMsg(ctx, msg, "canary", publishAttrs)
	canaryAttrs := publishAttrs().With(publishResult.attrs()).With(telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.canary.publish.duration_ms", Value: publishResult.Duration.Milliseconds()},
	))
	if err != nil {
		recordJetStreamPublish(ctx, "canary", subject, "failed", err, publishResult)
		return finish(canaryAttrs), fmt.Errorf("publish canary event: %w", err)
	}
	if publishResult.AckSequence == 0 {
		return finish(canaryAttrs), errors.New("publish canary event: ack sequence unavailable")
	}
	recordJetStreamPublish(ctx, "canary", subject, "completed", nil, publishResult)
	streamName := strings.TrimSpace(publishResult.AckStream)
	if streamName == "" && stream != nil {
		streamName = strings.TrimSpace(stream.Config.Name)
	}
	if streamName == "" {
		return finish(canaryAttrs), errors.New("publish canary event: ack stream unavailable")
	}
	replayStarted := time.Now()
	streamRef, err := l.replay.Stream(ctx, streamName)
	if err != nil {
		return finish(canaryAttrs), fmt.Errorf("open canary replay stream %q: %w", streamName, err)
	}
	raw, err := streamRef.GetMsg(ctx, publishResult.AckSequence)
	if err != nil {
		return finish(canaryAttrs.WithField(telemetry.Field{Key: "messaging.jetstream.canary.replay.sequence", Value: publishResult.AckSequence})), fmt.Errorf("read canary message %s:%d: %w", streamName, publishResult.AckSequence, err)
	}
	replayed, err := decodeReplayEvent(raw)
	if err != nil {
		return finish(canaryAttrs.WithField(telemetry.Field{Key: "messaging.jetstream.canary.replay.sequence", Value: publishResult.AckSequence})), fmt.Errorf("decode canary message %s:%d: %w", streamName, publishResult.AckSequence, err)
	}
	if strings.TrimSpace(replayed.GetId()) != event.Id || strings.TrimSpace(replayed.GetKind()) != jetstreamCanaryKind {
		return finish(canaryAttrs.WithField(telemetry.Field{Key: "messaging.jetstream.canary.replay.sequence", Value: publishResult.AckSequence})), errors.New("canary replayed unexpected event")
	}
	return finish(canaryAttrs.With(telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.canary.replayed", Value: true},
		telemetry.Field{Key: "messaging.jetstream.canary.replay.duration_ms", Value: time.Since(replayStarted).Milliseconds()},
		telemetry.Field{Key: "messaging.jetstream.canary.replay.sequence", Value: publishResult.AckSequence},
	))), nil
}

func jetstreamTelemetryAttrs(operation string) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "appendlog.jetstream"},
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "messaging.system", Value: "nats"},
	)
}

func jetstreamPublishMessageAttrs(subject string, subjectPrefix string, payloadBytes int, messageID string) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "messaging.system", Value: "nats"},
		telemetry.Field{Key: "messaging.operation", Value: "publish"},
		telemetry.Field{Key: "messaging.destination.name", Value: strings.TrimSpace(subject)},
		telemetry.Field{Key: "messaging.destination.kind", Value: "topic"},
		telemetry.Field{Key: "messaging.jetstream.subject", Value: strings.TrimSpace(subject)},
		telemetry.Field{Key: "messaging.jetstream.subject_prefix", Value: strings.Trim(strings.TrimSpace(subjectPrefix), ".")},
		telemetry.Field{Key: "messaging.message.id.present", Value: strings.TrimSpace(messageID) != ""},
		telemetry.Field{Key: "payload_bytes", Value: payloadBytes},
	)
	if strings.TrimSpace(messageID) != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.message.id_hash", Value: shortHash(messageID)})
	}
	return attrs
}

func (l *Log) publishMessageAttrs(subject string, payloadBytes int, messageID string) telemetry.Attributes {
	subjectPrefix := ""
	streamName := ""
	if l != nil {
		subjectPrefix = l.subjectPrefix
		streamName = strings.TrimSpace(l.streamName)
	}
	attrs := jetstreamPublishMessageAttrs(subject, subjectPrefix, payloadBytes, messageID)
	if streamName != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.expected_stream", Value: streamName})
	}
	return attrs
}

func jetstreamStreamTelemetryAttrs(stream *jetstream.StreamInfo) telemetry.Attributes {
	attrs := telemetry.Attrs()
	if stream == nil {
		return attrs
	}
	attrs = attrs.With(telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.stream", Value: strings.TrimSpace(stream.Config.Name)},
		telemetry.Field{Key: "messaging.jetstream.stream.subject_count", Value: len(stream.Config.Subjects)},
		telemetry.Field{Key: "messaging.jetstream.stream.state.messages", Value: stream.State.Msgs},
		telemetry.Field{Key: "messaging.jetstream.stream.state.bytes", Value: stream.State.Bytes},
		telemetry.Field{Key: "messaging.jetstream.stream.state.first_sequence", Value: stream.State.FirstSeq},
		telemetry.Field{Key: "messaging.jetstream.stream.state.last_sequence", Value: stream.State.LastSeq},
		telemetry.Field{Key: "messaging.jetstream.stream.state.consumer_count", Value: stream.State.Consumers},
		telemetry.Field{Key: "messaging.jetstream.stream.state.deleted_count", Value: stream.State.NumDeleted},
		telemetry.Field{Key: "messaging.jetstream.stream.state.unique_subject_count", Value: stream.State.NumSubjects},
	))
	if stream.Cluster != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetry.Field{Key: "messaging.jetstream.cluster.name", Value: strings.TrimSpace(stream.Cluster.Name)},
			telemetry.Field{Key: "messaging.jetstream.cluster.leader", Value: strings.TrimSpace(stream.Cluster.Leader)},
			telemetry.Field{Key: "messaging.jetstream.cluster.replica_count", Value: len(stream.Cluster.Replicas)},
		))
	}
	return attrs
}

func jetstreamReplayRequestAttrs(request ports.ReplayRequest) telemetry.Attributes {
	kindPrefixes := replayKindPrefixes(request)
	filterKeys := make([]string, 0, len(request.AttributeEquals))
	for key := range request.AttributeEquals {
		filterKeys = append(filterKeys, strings.TrimSpace(key))
	}
	sort.Strings(filterKeys)
	return telemetry.Attrs(
		telemetry.Field{Key: "runtime_id", Value: request.RuntimeID},
		telemetry.Field{Key: "tenant_id", Value: request.TenantID},
		telemetry.Field{Key: "replay.kind_prefix", Value: request.KindPrefix},
		telemetry.Field{Key: "replay.kind_prefixes", Value: strings.Join(kindPrefixes, ",")},
		telemetry.Field{Key: "replay.attribute_filter_keys", Value: strings.Join(filterKeys, ",")},
		telemetry.Field{Key: "replay.require_runtime_index", Value: request.RequireRuntimeIndex},
	)
}

func jetstreamReplayScanAttrs(limit uint32, candidateLimit uint32, scanned uint64, missing uint64, subjectMatched uint64, decoded uint64, matched uint64, sequence uint64, ctx context.Context) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.replay.limit", Value: limit},
		telemetry.Field{Key: "messaging.jetstream.replay.candidate_limit", Value: candidateLimit},
		telemetry.Field{Key: "messaging.jetstream.replay.scanned_count", Value: scanned},
		telemetry.Field{Key: "messaging.jetstream.replay.missing_count", Value: missing},
		telemetry.Field{Key: "messaging.jetstream.replay.subject_matched_count", Value: subjectMatched},
		telemetry.Field{Key: "messaging.jetstream.replay.decoded_count", Value: decoded},
		telemetry.Field{Key: "messaging.jetstream.replay.matched_count", Value: matched},
		telemetry.Field{Key: "messaging.jetstream.replay.deadline_budget_ms", Value: contextDeadlineBudgetMs(ctx)},
		telemetry.Field{Key: "replay_scanned_count", Value: scanned},
		telemetry.Field{Key: "replay_matched_count", Value: matched},
	)
	if sequence > 0 {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.replay.sequence", Value: sequence})
	}
	return attrs
}

func jetstreamReplayStrategyAttrs(strategy string, subjectFilterCount int) telemetry.Attributes {
	strategy = strings.TrimSpace(strategy)
	if strategy == "" {
		strategy = replayStrategyLegacyReverseScan
	}
	return telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.replay.strategy", Value: strategy},
		telemetry.Field{Key: "messaging.jetstream.replay.subject_filter_count", Value: subjectFilterCount},
		telemetry.Field{Key: "messaging.jetstream.replay.subject_indexed", Value: strategy == replayStrategySubjectIndex},
		telemetry.Field{Key: "messaging.jetstream.replay.legacy_full_scan", Value: strategy == replayStrategyLegacyReverseScan},
	)
}

func contextDeadlineBudgetMs(ctx context.Context) int64 {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	remaining := time.Until(deadline).Milliseconds()
	if remaining < 0 {
		return 0
	}
	return remaining
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:8])
}

func jetstreamTelemetryError(ctx context.Context, span *telemetry.Span, operation string, err error, extra ...telemetry.Attributes) {
	attrs := jetstreamErrorTelemetryAttrs(operation, err)
	for _, item := range extra {
		attrs = attrs.With(item)
	}
	jetstreamAnnotateMain(ctx, operation, "failed", attrs)
	telemetry.CaptureError(ctx, "jetstream.error", err, telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "appendlog.jetstream"},
		telemetry.Field{Key: "operation", Value: operation},
	).With(attrs))
	telemetry.End(span, "failed", attrs)
}

func jetstreamErrorTelemetryAttrs(operation string, err error) telemetry.Attributes {
	attrs := telemetry.Attrs(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.error.category", Value: jetstreamErrorCategory(err)})
	if strings.TrimSpace(operation) == "append" || strings.TrimSpace(operation) == "canary" {
		attrs = attrs.WithField(telemetry.Field{Key: "messaging.jetstream.publish.retryable", Value: retryablePublishError(err)})
	}
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		attrs = attrs.With(telemetry.Attrs(
			telemetry.Field{Key: "nats.api.error.code", Value: apiErr.Code},
			telemetry.Field{Key: "nats.jetstream.error_code", Value: uint16(apiErr.ErrorCode)},
			telemetry.Field{Key: "nats.jetstream.error_description", Value: strings.TrimSpace(apiErr.Description)},
		))
	}
	return attrs
}

func jetstreamErrorCategory(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var apiErr *jetstream.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		switch {
		case apiErr.Code == 401 || apiErr.Code == 403:
			return "permission"
		case apiErr.Code == 404:
			return "not_found"
		case apiErr.Code == 408:
			return "timeout"
		case apiErr.Code == 429:
			return "rate_limited"
		case apiErr.Code >= 500:
			return "server"
		default:
			return "api"
		}
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "timeout") || strings.Contains(text, "deadline"):
		return "timeout"
	case strings.Contains(text, "no response"):
		return "no_response"
	case strings.Contains(text, "connection") || strings.Contains(text, "reconnect") || strings.Contains(text, "broken pipe") || strings.Contains(text, "reset by peer") || strings.Contains(text, "closed"):
		return "connection"
	case strings.Contains(text, "permission") || strings.Contains(text, "authorization") || strings.Contains(text, "authentication"):
		return "permission"
	case strings.Contains(text, "not found") || strings.Contains(text, "no replay stream"):
		return "not_found"
	default:
		return "unknown"
	}
}

func jetstreamAnnotateMain(ctx context.Context, operation string, status string, extra ...telemetry.Attributes) {
	operation = strings.TrimSpace(operation)
	status = strings.TrimSpace(status)
	telemetry.IncrementMain(ctx, "messaging.jetstream.operation.count", 1)
	if operation != "" {
		telemetry.IncrementMain(ctx, "messaging.jetstream."+operation+".count", 1)
	}
	if status == "failed" {
		telemetry.IncrementMain(ctx, "messaging.jetstream.error.count", 1)
		if operation != "" {
			telemetry.IncrementMain(ctx, "messaging.jetstream."+operation+".error.count", 1)
		}
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "messaging.jetstream.last_operation", Value: operation},
		telemetry.Field{Key: "messaging.jetstream.last_status", Value: status},
		telemetry.Field{Key: "messaging.system", Value: "nats"},
	)
	for _, item := range extra {
		attrs = attrs.With(item)
	}
	telemetry.AnnotateMain(ctx, attrs)
	telemetry.AnnotateMainDependency(ctx, "messaging.jetstream", "appendlog.jetstream", operation, status, attrs)
}

func countGreaterThanUint32(count int, limit uint32) bool {
	return uint64(count) > uint64(limit) // #nosec G115 -- count is derived from slice length and compared only after widening.
}

func replaySubjectPrefix(prefix string, kindPrefix string) string {
	normalized := strings.Trim(strings.TrimSpace(prefix), ".")
	kindPrefix = strings.Trim(strings.TrimSpace(kindPrefix), ".")
	if kindPrefix == "" {
		return normalized
	}
	if securityevents.IsCanonicalKind(kindPrefix) {
		return kindPrefix
	}
	return normalized + "." + kindPrefix
}

func replaySubjectPrefixes(prefix string, request ports.ReplayRequest) []string {
	kindPrefixes := replayKindPrefixes(request)
	if len(kindPrefixes) == 0 {
		return []string{replaySubjectPrefix(prefix, "")}
	}
	subjectPrefixes := make([]string, 0, len(kindPrefixes))
	for _, kindPrefix := range kindPrefixes {
		subjectPrefixes = append(subjectPrefixes, replaySubjectPrefix(prefix, kindPrefix))
	}
	return subjectPrefixes
}

func exactReplaySubjectFilters(prefix string, request ports.ReplayRequest) ([]string, bool, error) {
	if !request.ExactKindFilters {
		return nil, false, nil
	}
	kindPrefixes := replayKindPrefixes(request)
	if len(kindPrefixes) == 0 {
		return nil, false, nil
	}
	subjects := make([]string, 0, len(kindPrefixes))
	seen := map[string]struct{}{}
	for _, kindPrefix := range kindPrefixes {
		subject, err := eventSubject(prefix, kindPrefix)
		if err != nil {
			return nil, false, err
		}
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		subjects = append(subjects, subject)
	}
	sort.Strings(subjects)
	return subjects, len(subjects) > 0, nil
}

func replaySubjectMatchesPrefix(subject string, prefix string) bool {
	subject = strings.TrimSpace(subject)
	prefix = strings.TrimSpace(prefix)
	return subject == prefix || strings.HasPrefix(subject, prefix+".")
}

func replaySubjectMatchesAnyPrefix(subject string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if replaySubjectMatchesPrefix(subject, prefix) {
			return true
		}
	}
	return false
}

func publishPayload(event *cerebrov1.EventEnvelope) ([]byte, error) {
	if workflowevents.IsSharedEnvelopeEvent(event) {
		return event.GetPayload(), nil
	}
	return proto.Marshal(event)
}

func decodeReplayEvent(raw *jetstream.RawStreamMsg) (*cerebrov1.EventEnvelope, error) {
	event := &cerebrov1.EventEnvelope{}
	protoErr := proto.Unmarshal(raw.Data, event)
	if protoErr == nil && strings.TrimSpace(event.GetKind()) != "" {
		return event, nil
	}
	shared, sharedErr := workflowevents.DecodeSharedEnvelopeEvent(raw.Data, replayHeaderAttributes(raw.Header))
	if sharedErr == nil {
		return shared, nil
	}
	if protoErr != nil {
		return nil, protoErr
	}
	return nil, sharedErr
}

func eventAttributesHeader(attributes map[string]string) nats.Header {
	header := make(nats.Header, len(attributes))
	for key, value := range attributes {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" || isReservedNATSHeader(key) {
			continue
		}
		header[key] = []string{value}
	}
	return header
}

func replayHeaderAttributes(header nats.Header) map[string]string {
	attributes := make(map[string]string, len(header))
	for key, values := range header {
		if isReservedNATSHeader(key) || len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if strings.TrimSpace(key) == "" || value == "" {
			continue
		}
		attributes[key] = value
	}
	return attributes
}

func isReservedNATSHeader(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), "nats-")
}

type replayCandidate struct {
	event *cerebrov1.EventEnvelope
	seq   uint64
}

func replayCandidateNewer(left replayCandidate, right replayCandidate) bool {
	leftTime, leftHasTime := replayEventTime(left.event)
	rightTime, rightHasTime := replayEventTime(right.event)
	switch {
	case leftHasTime && rightHasTime && !leftTime.Equal(rightTime):
		return leftTime.After(rightTime)
	case leftHasTime != rightHasTime:
		return leftHasTime
	default:
		return left.seq > right.seq
	}
}

func replayEventTime(event *cerebrov1.EventEnvelope) (time.Time, bool) {
	if event == nil || event.GetOccurredAt() == nil {
		return time.Time{}, false
	}
	occurredAt := event.GetOccurredAt().AsTime().UTC()
	if occurredAt.IsZero() {
		return time.Time{}, false
	}
	return occurredAt, true
}

func normalizeReplayCandidateLimit(limit uint32) uint32 {
	if limit == 0 {
		limit = defaultReplayLimit
	}
	candidates := limit * 5
	if candidates < limit {
		return maxReplayCandidates
	}
	if candidates > maxReplayCandidates {
		return maxReplayCandidates
	}
	return candidates
}

func eventSubject(prefix string, kind string) (string, error) {
	normalizedPrefix, err := normalizeSubjectPrefix(prefix)
	if err != nil {
		return "", err
	}
	normalizedKind := strings.TrimSpace(kind)
	if err := validateEventKind(normalizedKind); err != nil {
		return "", err
	}
	if securityevents.IsCanonicalKind(normalizedKind) {
		return normalizedKind, nil
	}
	return normalizedPrefix + "." + normalizedKind, nil
}

func normalizeSubjectPrefix(prefix string) (string, error) {
	normalized := strings.TrimSpace(prefix)
	if normalized == "" {
		normalized = "events"
	}
	if err := validateSubjectTokens("subject prefix", normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

func normalizeStreamName(name string) (string, error) {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return "", nil
	}
	for _, r := range normalized {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("jetstream stream name must not contain whitespace or control characters")
		}
	}
	return normalized, nil
}

func validateEventKind(kind string) error {
	if strings.TrimSpace(kind) == "" {
		return errors.New("event kind is required")
	}
	return validateSubjectTokens("event kind", strings.TrimSpace(kind))
}

func validateSubjectTokens(label string, subject string) error {
	if subject == "" {
		return fmt.Errorf("%s is required", label)
	}
	for _, token := range strings.Split(subject, ".") {
		if token == "" {
			return fmt.Errorf("%s %q is not a valid NATS subject", label, subject)
		}
		for _, r := range token {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '*' || r == '>' {
				return fmt.Errorf("%s %q is not a valid NATS subject", label, subject)
			}
		}
	}
	return nil
}

func normalizeReplayLimit(limit uint32) uint32 {
	if limit == 0 {
		return defaultReplayLimit
	}
	if limit > maxReplayLimit {
		return maxReplayLimit
	}
	return limit
}

func normalizeReplayRequest(req ports.ReplayRequest) ports.ReplayRequest {
	normalized := ports.ReplayRequest{
		RuntimeID:           strings.TrimSpace(req.RuntimeID),
		KindPrefix:          strings.TrimSpace(req.KindPrefix),
		KindPrefixes:        normalizeReplayKindPrefixes(req.KindPrefixes),
		ExactKindFilters:    req.ExactKindFilters,
		RequireRuntimeIndex: req.RequireRuntimeIndex,
		TenantID:            strings.TrimSpace(req.TenantID),
		AttributeEquals:     make(map[string]string, len(req.AttributeEquals)),
		Limit:               req.Limit,
	}
	for key, value := range req.AttributeEquals {
		trimmedKey := strings.TrimSpace(key)
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" {
			continue
		}
		normalized.AttributeEquals[trimmedKey] = trimmedValue
	}
	return normalized
}

func normalizeReplayKindPrefixes(kindPrefixes []string) []string {
	normalized := make([]string, 0, len(kindPrefixes))
	seen := map[string]struct{}{}
	for _, kindPrefix := range kindPrefixes {
		kindPrefix = strings.TrimSpace(kindPrefix)
		if kindPrefix == "" {
			continue
		}
		if _, ok := seen[kindPrefix]; ok {
			continue
		}
		seen[kindPrefix] = struct{}{}
		normalized = append(normalized, kindPrefix)
	}
	return normalized
}

func replayKindPrefixes(req ports.ReplayRequest) []string {
	prefixes := make([]string, 0, 1+len(req.KindPrefixes))
	seen := map[string]struct{}{}
	add := func(kindPrefix string) {
		kindPrefix = strings.TrimSpace(kindPrefix)
		if kindPrefix == "" {
			return
		}
		if _, ok := seen[kindPrefix]; ok {
			return
		}
		seen[kindPrefix] = struct{}{}
		prefixes = append(prefixes, kindPrefix)
	}
	add(req.KindPrefix)
	for _, kindPrefix := range req.KindPrefixes {
		add(kindPrefix)
	}
	return prefixes
}

func matchesReplayRequest(event *cerebrov1.EventEnvelope, req ports.ReplayRequest) bool {
	if event == nil {
		return false
	}
	if req.RuntimeID != "" && strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]) != req.RuntimeID {
		return false
	}
	if kindPrefixes := replayKindPrefixes(req); len(kindPrefixes) > 0 {
		eventKind := strings.TrimSpace(event.GetKind())
		matched := false
		for _, kindPrefix := range kindPrefixes {
			if strings.HasPrefix(eventKind, kindPrefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if req.TenantID != "" && strings.TrimSpace(event.GetTenantId()) != req.TenantID {
		return false
	}
	for key, value := range req.AttributeEquals {
		if strings.TrimSpace(event.GetAttributes()[key]) != value {
			return false
		}
	}
	return true
}

func (l *Log) replayStream(ctx context.Context) (*jetstream.StreamInfo, error) {
	streams, err := l.replay.Streams(ctx)
	if err != nil {
		return nil, fmt.Errorf("list jetstream streams: %w", err)
	}
	prefix, err := normalizeSubjectPrefix(l.subjectPrefix)
	if err != nil {
		return nil, err
	}
	if configured := strings.TrimSpace(l.streamName); configured != "" {
		for _, stream := range streams {
			if stream == nil || strings.TrimSpace(stream.Config.Name) != configured {
				continue
			}
			if !streamAcceptsSubjectPrefix(stream, prefix) {
				return nil, fmt.Errorf("configured replay stream %q does not match subject prefix %q", configured, prefix)
			}
			return stream, nil
		}
		return nil, fmt.Errorf("configured replay stream %q was not found", configured)
	}
	var match *jetstream.StreamInfo
	for _, stream := range streams {
		if stream == nil || !streamAcceptsSubjectPrefix(stream, prefix) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple replay streams match subject prefix %q", prefix)
		}
		match = stream
	}
	if match == nil {
		return nil, fmt.Errorf("no replay stream matches subject prefix %q", prefix)
	}
	return match, nil
}

func streamAcceptsSubjectPrefix(stream *jetstream.StreamInfo, prefix string) bool {
	if stream == nil {
		return false
	}
	for _, pattern := range stream.Config.Subjects {
		if subjectPatternOverlapsPrefix(pattern, prefix) {
			return true
		}
	}
	return false
}

func subjectPatternOverlapsPrefix(pattern string, prefix string) bool {
	patternTokens := strings.Split(strings.TrimSpace(pattern), ".")
	prefixTokens := strings.Split(strings.TrimSpace(prefix), ".")
	for index, prefixToken := range prefixTokens {
		if index >= len(patternTokens) {
			return false
		}
		patternToken := patternTokens[index]
		if patternToken == ">" {
			return true
		}
		if patternToken != "*" && patternToken != prefixToken {
			return false
		}
	}
	return len(patternTokens) != len(prefixTokens)
}

func subjectMatches(pattern string, subject string) bool {
	patternTokens := strings.Split(strings.TrimSpace(pattern), ".")
	subjectTokens := strings.Split(strings.TrimSpace(subject), ".")
	for index, token := range patternTokens {
		if token == ">" {
			return index == len(patternTokens)-1 && index < len(subjectTokens)
		}
		if index >= len(subjectTokens) {
			return false
		}
		if token != "*" && token != subjectTokens[index] {
			return false
		}
	}
	return len(patternTokens) == len(subjectTokens)
}
