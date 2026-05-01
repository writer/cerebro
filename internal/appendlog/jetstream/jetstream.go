package jetstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

const (
	connectTimeout     = 5 * time.Second
	defaultReplayLimit = 100
	maxReplayLimit     = 1000
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
	nc, err := nats.Connect(
		url,
		nats.Name("cerebro"),
		nats.Timeout(connectTimeout),
		nats.RetryOnFailedConnect(false),
	)
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
	l.conn.Close()
	return nil
}

// Ping verifies that JetStream is reachable.
func (l *Log) Ping(ctx context.Context) error {
	if l == nil || l.js == nil {
		return errors.New("jetstream is not configured")
	}
	_, err := l.js.AccountInfo(ctx)
	if err != nil {
		return fmt.Errorf("jetstream account info: %w", err)
	}
	return nil
}

// Append marshals and publishes an event envelope.
func (l *Log) Append(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if l == nil || l.js == nil {
		return errors.New("jetstream is not configured")
	}
	if event == nil {
		return errors.New("event is required")
	}
	kind := strings.TrimSpace(event.Kind)
	if err := validateEventKind(kind); err != nil {
		return err
	}
	subject, err := eventSubject(l.subjectPrefix, kind)
	if err != nil {
		return err
	}
	envelope := proto.Clone(event).(*cerebrov1.EventEnvelope)
	envelope.Kind = kind
	payload, err := proto.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	msg := nats.NewMsg(subject)
	msg.Data = payload
	if event.Id != "" {
		msg.Header.Set(nats.MsgIdHdr, event.Id)
	}
	if _, err := l.js.PublishMsg(ctx, msg); err != nil {
		return fmt.Errorf("publish event: %w", err)
	}
	return nil
}

// Replay returns stored envelopes for one source runtime in append order.
func (l *Log) Replay(ctx context.Context, req ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	if l == nil || l.replay == nil {
		return nil, errors.New("jetstream is not configured")
	}
	request := normalizeReplayRequest(req)
	if request.RuntimeID == "" && request.KindPrefix == "" && request.TenantID == "" && len(request.AttributeEquals) == 0 {
		return nil, errors.New("at least one replay filter is required")
	}
	stream, err := l.replayStream(ctx)
	if err != nil {
		return nil, err
	}
	prefix, err := normalizeSubjectPrefix(l.subjectPrefix)
	if err != nil {
		return nil, err
	}
	limit := normalizeReplayLimit(request.Limit)
	streamRef, err := l.replay.Stream(ctx, stream.Config.Name)
	if err != nil {
		return nil, fmt.Errorf("open replay stream %q: %w", stream.Config.Name, err)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, limit)
	if stream.State.LastSeq == 0 || stream.State.LastSeq < stream.State.FirstSeq {
		return events, nil
	}
	for seq := stream.State.FirstSeq; seq <= stream.State.LastSeq; seq++ {
		raw, err := streamRef.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			return nil, fmt.Errorf("get replay message %s:%d: %w", stream.Config.Name, seq, err)
		}
		if raw == nil || !strings.HasPrefix(strings.TrimSpace(raw.Subject), prefix+".") {
			continue
		}
		event := &cerebrov1.EventEnvelope{}
		if err := proto.Unmarshal(raw.Data, event); err != nil {
			return nil, fmt.Errorf("decode replay message %s:%d: %w", stream.Config.Name, seq, err)
		}
		if !matchesReplayRequest(event, request) {
			continue
		}
		events = append(events, event)
		if uint32(len(events)) >= limit {
			break
		}
	}
	return events, nil
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

func matchesReplayRequest(event *cerebrov1.EventEnvelope, req ports.ReplayRequest) bool {
	if event == nil {
		return false
	}
	if req.RuntimeID != "" && strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]) != req.RuntimeID {
		return false
	}
	if req.KindPrefix != "" && !strings.HasPrefix(strings.TrimSpace(event.GetKind()), req.KindPrefix) {
		return false
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
