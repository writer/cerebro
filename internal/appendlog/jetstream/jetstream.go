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
	maxReplayScan      = 10000
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
	if strings.TrimSpace(cfg.JetStreamURL) == "" {
		return nil, errors.New("jetstream url is required")
	}
	nc, err := nats.Connect(
		cfg.JetStreamURL,
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
	prefix := strings.TrimSpace(cfg.JetStreamSubjectPrefix)
	if prefix == "" {
		prefix = "events"
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
	payload, err := proto.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	msg := nats.NewMsg(l.subjectPrefix + "." + kind)
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
	limit := normalizeReplayLimit(request.Limit)
	streamRef, err := l.replay.Stream(ctx, stream.Config.Name)
	if err != nil {
		return nil, fmt.Errorf("open replay stream %q: %w", stream.Config.Name, err)
	}
	events := make([]*cerebrov1.EventEnvelope, 0, limit)
	if stream.State.LastSeq == 0 || stream.State.LastSeq < stream.State.FirstSeq {
		return events, nil
	}
	var scanned uint32
	for seq := stream.State.FirstSeq; seq <= stream.State.LastSeq; seq++ {
		if scanned >= maxReplayScan {
			return nil, fmt.Errorf("replay scan exceeded %d messages while collecting %d events", maxReplayScan, limit)
		}
		scanned++
		raw, err := streamRef.GetMsg(ctx, seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			return nil, fmt.Errorf("get replay message %s:%d: %w", stream.Config.Name, seq, err)
		}
		if raw == nil || !strings.HasPrefix(strings.TrimSpace(raw.Subject), l.subjectPrefix+".") {
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

func validateEventKind(kind string) error {
	if kind == "" {
		return errors.New("event kind is required")
	}
	for _, token := range strings.Split(kind, ".") {
		if token == "" {
			return fmt.Errorf("event kind %q is not a valid NATS subject", kind)
		}
		for _, r := range token {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '*' || r == '>' {
				return fmt.Errorf("event kind %q is not a valid NATS subject", kind)
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
	probe := l.subjectPrefix + ".replay.probe"
	var match *jetstream.StreamInfo
	for _, stream := range streams {
		if stream == nil || !streamAcceptsSubject(stream, probe) {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("multiple replay streams match subject prefix %q", l.subjectPrefix)
		}
		match = stream
	}
	if match == nil {
		return nil, fmt.Errorf("no replay stream matches subject prefix %q", l.subjectPrefix)
	}
	return match, nil
}

func streamAcceptsSubject(stream *jetstream.StreamInfo, subject string) bool {
	if stream == nil {
		return false
	}
	for _, pattern := range stream.Config.Subjects {
		if subjectMatches(pattern, subject) {
			return true
		}
	}
	return false
}

func subjectMatches(pattern string, subject string) bool {
	patternTokens := strings.Split(strings.TrimSpace(pattern), ".")
	subjectTokens := strings.Split(strings.TrimSpace(subject), ".")
	for index, token := range patternTokens {
		switch token {
		case ">":
			return index == len(patternTokens)-1 && index < len(subjectTokens)
		case "*":
			if index >= len(subjectTokens) {
				return false
			}
		default:
			if index >= len(subjectTokens) || token != subjectTokens[index] {
				return false
			}
		}
	}
	return len(patternTokens) == len(subjectTokens)
}
