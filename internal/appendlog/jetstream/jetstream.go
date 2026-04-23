package jetstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

const connectTimeout = 5 * time.Second

type publisher interface {
	AccountInfo(context.Context) (*jetstream.AccountInfo, error)
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

type replayManager interface {
	Streams(context.Context) ([]*jetstream.StreamInfo, error)
	GetMsg(context.Context, string, uint64) (*jetstream.RawStreamMsg, error)
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

func (m *jetStreamReplayManager) GetMsg(ctx context.Context, stream string, seq uint64) (*jetstream.RawStreamMsg, error) {
	streamRef, err := m.js.Stream(ctx, stream)
	if err != nil {
		return nil, err
	}
	return streamRef.GetMsg(ctx, seq)
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
	if kind == "" {
		return errors.New("event kind is required")
	}
	if strings.ContainsRune(kind, ' ') {
		return fmt.Errorf("event kind %q is not a valid NATS subject token", kind)
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
	runtimeID := strings.TrimSpace(req.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("runtime id is required")
	}
	stream, err := l.replayStream(ctx)
	if err != nil {
		return nil, err
	}
	events := make([]*cerebrov1.EventEnvelope, 0)
	if stream.State.LastSeq == 0 || stream.State.LastSeq < stream.State.FirstSeq {
		return events, nil
	}
	for seq := stream.State.FirstSeq; seq <= stream.State.LastSeq; seq++ {
		raw, err := l.replay.GetMsg(ctx, stream.Config.Name, seq)
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
		if strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]) != runtimeID {
			continue
		}
		events = append(events, event)
		if req.Limit > 0 && uint32(len(events)) >= req.Limit {
			break
		}
	}
	return events, nil
}

func (l *Log) replayStream(ctx context.Context) (*jetstream.StreamInfo, error) {
	streams, err := l.replay.Streams(ctx)
	if err != nil {
		return nil, fmt.Errorf("list jetstream streams: %w", err)
	}
	probe := l.subjectPrefix + ".replay"
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
		if token == ">" {
			return true
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
