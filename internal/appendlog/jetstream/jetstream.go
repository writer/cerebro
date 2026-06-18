package jetstream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/telemetry"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	connectTimeout             = 5 * time.Second
	defaultReplayLimit         = 100
	maxReplayLimit             = 1000
	maxReplayCandidates        = 5000
	publishRetryAttempts       = 4
	publishRetryInitialBackoff = 50 * time.Millisecond
)

type publisher interface {
	AccountInfo(context.Context) (*jetstream.AccountInfo, error)
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

type replayManager interface {
	Streams(context.Context) ([]*jetstream.StreamInfo, error)
	Stream(context.Context, string) (replayStream, error)
}

type replayStream interface {
	GetMsg(context.Context, uint64, ...jetstream.GetMsgOpt) (*jetstream.RawStreamMsg, error)
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
	return streamRef, nil
}

// Log is the JetStream-backed append-log implementation.
type Log struct {
	conn          *nats.Conn
	js            publisher
	replay        replayManager
	subjectPrefix string
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
	return &Log{
		conn:          nc,
		js:            js,
		replay:        &jetStreamReplayManager{js: js},
		subjectPrefix: prefix,
	}, nil
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
	_, err := l.js.AccountInfo(ctx)
	if err != nil {
		err = fmt.Errorf("jetstream account info: %w", err)
		jetstreamTelemetryError(ctx, span, "ping", err)
		return err
	}
	if l.replay != nil {
		if _, err := l.replayStream(ctx); err != nil {
			err = fmt.Errorf("jetstream stream readiness: %w", err)
			jetstreamTelemetryError(ctx, span, "ping", err)
			return err
		}
	}
	telemetry.End(span, "completed", telemetry.Attrs())
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
	if event.Id != "" {
		msg.Header.Set(nats.MsgIdHdr, event.Id)
	}
	if err := l.publishMsg(ctx, msg); err != nil {
		err = fmt.Errorf("publish event: %w", err)
		jetstreamTelemetryError(ctx, span, "append", err)
		return err
	}
	telemetry.End(span, "completed", telemetry.Attrs(telemetry.Field{Key: "payload_bytes", Value: len(payload)}))
	return nil
}

func (l *Log) publishMsg(ctx context.Context, msg *nats.Msg) error {
	attempts := 1
	if msg.Header.Get(nats.MsgIdHdr) != "" {
		attempts = publishRetryAttempts
	}
	backoff := publishRetryInitialBackoff
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if _, err = l.js.PublishMsg(ctx, msg); err == nil {
			return nil
		}
		if attempt == attempts || !retryablePublishError(err) || ctx.Err() != nil {
			return err
		}
		if waitErr := waitBeforePublishRetry(ctx, backoff); waitErr != nil {
			return waitErr
		}
		backoff *= 2
	}
	return err
}

func retryablePublishError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"no response",
		"timeout",
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

// Replay returns the newest matching stored envelopes in append order.
func (l *Log) Replay(ctx context.Context, req ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	request := normalizeReplayRequest(req)
	ctx, span := telemetry.Start(ctx, "jetstream.replay", jetstreamTelemetryAttrs("replay").
		WithField(telemetry.Field{Key: "replay.limit", Value: normalizeReplayLimit(request.Limit)}).
		WithField(telemetry.Field{Key: "replay.kind_prefix_count", Value: len(replayKindPrefixes(request))}).
		WithField(telemetry.Field{Key: "replay.attribute_filter_count", Value: len(request.AttributeEquals)}))
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
	prefix, err := normalizeSubjectPrefix(l.subjectPrefix)
	if err != nil {
		jetstreamTelemetryError(ctx, span, "replay", err)
		return nil, err
	}
	subjectPrefixes := replaySubjectPrefixes(prefix, request)
	limit := normalizeReplayLimit(request.Limit)
	candidateLimit := normalizeReplayCandidateLimit(limit)
	streamRef, err := l.replay.Stream(ctx, stream.Config.Name)
	if err != nil {
		err = fmt.Errorf("open replay stream %q: %w", stream.Config.Name, err)
		jetstreamTelemetryError(ctx, span, "replay", err)
		return nil, err
	}
	candidates := make([]replayCandidate, 0, limit)
	if stream.State.LastSeq == 0 || stream.State.LastSeq < stream.State.FirstSeq {
		telemetry.End(span, "completed", telemetry.Attrs(telemetry.Field{Key: "events_returned", Value: 0}))
		return nil, nil
	}
	for seq := stream.State.LastSeq; ; seq-- {
		raw, err := streamRef.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				if seq == stream.State.FirstSeq {
					break
				}
				continue
			}
			err = fmt.Errorf("get replay message %s:%d: %w", stream.Config.Name, seq, err)
			jetstreamTelemetryError(ctx, span, "replay", err)
			return nil, err
		}
		if raw != nil && replaySubjectMatchesAnyPrefix(raw.Subject, subjectPrefixes) {
			event, err := decodeReplayEvent(raw)
			if err != nil {
				err = fmt.Errorf("decode replay message %s:%d: %w", stream.Config.Name, seq, err)
				jetstreamTelemetryError(ctx, span, "replay", err)
				return nil, err
			}
			if matchesReplayRequest(event, request) {
				candidates = append(candidates, replayCandidate{event: event, seq: seq})
				if countAtLeastUint32(len(candidates), candidateLimit) {
					break
				}
			}
		}
		if seq == stream.State.FirstSeq {
			break
		}
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
	telemetry.End(span, "completed", telemetry.Attrs(telemetry.Field{Key: "events_returned", Value: len(events)}))
	return events, nil
}

func jetstreamTelemetryAttrs(operation string) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "appendlog.jetstream"},
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "messaging.system", Value: "nats"},
	)
}

func jetstreamTelemetryError(ctx context.Context, span *telemetry.Span, operation string, err error) {
	attrs := telemetry.Attrs(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	telemetry.CaptureError(ctx, "jetstream.error", err, telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "appendlog.jetstream"},
		telemetry.Field{Key: "operation", Value: operation},
	))
	telemetry.End(span, "failed", attrs)
}

func countAtLeastUint32(count int, limit uint32) bool {
	return uint64(count) >= uint64(limit) // #nosec G115 -- count is derived from slice length and compared only after widening.
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
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		header[key] = []string{value}
	}
	return header
}

func replayHeaderAttributes(header nats.Header) map[string]string {
	attributes := make(map[string]string, len(header))
	for key, values := range header {
		if strings.EqualFold(key, nats.MsgIdHdr) || len(values) == 0 {
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
		RuntimeID:       strings.TrimSpace(req.RuntimeID),
		KindPrefix:      strings.TrimSpace(req.KindPrefix),
		KindPrefixes:    normalizeReplayKindPrefixes(req.KindPrefixes),
		TenantID:        strings.TrimSpace(req.TenantID),
		AttributeEquals: make(map[string]string, len(req.AttributeEquals)),
		Limit:           req.Limit,
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
