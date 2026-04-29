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
)

const connectTimeout = 5 * time.Second

type publisher interface {
	AccountInfo(context.Context) (*jetstream.AccountInfo, error)
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// Log is the JetStream-backed append-log implementation.
type Log struct {
	conn          *nats.Conn
	js            publisher
	subjectPrefix string
}

// Open dials JetStream and returns an append-log implementation.
func Open(cfg config.AppendLogConfig) (*Log, error) {
	url := strings.TrimSpace(cfg.JetStreamURL)
	if url == "" {
		return nil, errors.New("jetstream url is required")
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
	prefix := strings.TrimSpace(cfg.JetStreamSubjectPrefix)
	if prefix == "" {
		prefix = "events"
	}
	return &Log{
		conn:          nc,
		js:            js,
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
	if strings.ContainsAny(kind, " \t\r\n") {
		return fmt.Errorf("event kind %q is not a valid NATS subject token", kind)
	}
	publishEvent := proto.Clone(event).(*cerebrov1.EventEnvelope)
	publishEvent.Kind = kind
	payload, err := proto.Marshal(publishEvent)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	subject := l.subjectPrefix + "." + kind
	if strings.HasPrefix(subject, ".") || strings.HasSuffix(subject, ".") || strings.Contains(subject, "..") || strings.ContainsAny(subject, " \t\r\n") {
		return fmt.Errorf("publish subject %q is not a valid NATS subject", subject)
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
