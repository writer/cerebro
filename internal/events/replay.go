package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// ReplayConfig controls historical JetStream replay reads without mutating the
// live durable consumer position.
type ReplayConfig struct {
	URLs           []string
	Stream         string
	Subject        string
	BatchSize      int
	FetchTimeout   time.Duration
	ConnectTimeout time.Duration
	Limit          int
	FromSequence   uint64
	FromTime       *time.Time

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

	ContinueOnHandlerError bool
}

// ReplayEvent wraps one replayed stream message with sequence metadata.
type ReplayEvent struct {
	CloudEvent     CloudEvent
	Subject        string
	Stream         string
	StreamSequence uint64
	ConsumerSeq    uint64
	PublishedAt    time.Time
	RawPayload     []byte
}

// ReplayReport summarizes a bounded history replay run.
type ReplayReport struct {
	Stream              string    `json:"stream"`
	Subject             string    `json:"subject"`
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	StartSequence       uint64    `json:"start_sequence,omitempty"`
	UpperBoundSequence  uint64    `json:"upper_bound_sequence,omitempty"`
	LastStreamSequence  uint64    `json:"last_stream_sequence,omitempty"`
	MessagesFetched     int       `json:"messages_fetched"`
	EventsParsed        int       `json:"events_parsed"`
	EventsHandled       int       `json:"events_handled"`
	ParseErrors         int       `json:"parse_errors"`
	HandlerErrors       int       `json:"handler_errors"`
	LastHandlerError    string    `json:"last_handler_error,omitempty"`
	StoppedByUpperBound bool      `json:"stopped_by_upper_bound,omitempty"`
	StoppedByLimit      bool      `json:"stopped_by_limit,omitempty"`
}

type ReplayHandler func(context.Context, ReplayEvent) error

// ReplayJetStreamHistory replays a bounded historical window from JetStream
// using an ephemeral pull consumer so the live durable cursor is untouched.
func ReplayJetStreamHistory(ctx context.Context, cfg ReplayConfig, handler ReplayHandler) (ReplayReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config := cfg.withDefaults()
	if err := config.validate(); err != nil {
		return ReplayReport{}, err
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
		return ReplayReport{}, err
	}

	nc, err := nats.Connect(strings.Join(config.URLs, ","), natsOptions...)
	if err != nil {
		return ReplayReport{}, fmt.Errorf("connect replay reader to nats: %w", err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		return ReplayReport{}, fmt.Errorf("initialize replay jetstream context: %w", err)
	}

	info, err := js.StreamInfo(config.Stream)
	if err != nil {
		return ReplayReport{}, fmt.Errorf("lookup replay stream %s: %w", config.Stream, err)
	}

	report := ReplayReport{
		Stream:             config.Stream,
		Subject:            config.Subject,
		StartedAt:          time.Now().UTC(),
		UpperBoundSequence: info.State.LastSeq,
	}
	if report.UpperBoundSequence == 0 {
		report.CompletedAt = time.Now().UTC()
		return report, nil
	}

	subOpts := []nats.SubOpt{
		nats.BindStream(config.Stream),
		nats.AckExplicit(),
		nats.MaxAckPending(config.BatchSize * 2),
	}
	switch {
	case config.FromSequence > 0:
		report.StartSequence = config.FromSequence
		subOpts = append(subOpts, nats.StartSequence(config.FromSequence))
	case config.FromTime != nil && !config.FromTime.IsZero():
		at := config.FromTime.UTC()
		subOpts = append(subOpts, nats.StartTime(at))
	default:
		report.StartSequence = 1
		subOpts = append(subOpts, nats.DeliverAll())
	}

	sub, err := js.PullSubscribe(config.Subject, "", subOpts...)
	if err != nil {
		return report, fmt.Errorf("create replay pull subscription: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	stop := false
	for !stop {
		select {
		case <-ctx.Done():
			report.CompletedAt = time.Now().UTC()
			return report, ctx.Err()
		default:
		}

		msgs, err := sub.Fetch(config.BatchSize, nats.MaxWait(config.FetchTimeout))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				break
			}
			report.CompletedAt = time.Now().UTC()
			return report, fmt.Errorf("fetch replay batch: %w", err)
		}

		for _, msg := range msgs {
			meta, err := msg.Metadata()
			if err != nil || meta == nil {
				_ = msg.Ack()
				continue
			}
			seq := meta.Sequence.Stream
			if seq > report.UpperBoundSequence {
				report.StoppedByUpperBound = true
				_ = msg.Ack()
				stop = true
				break
			}

			report.MessagesFetched++
			report.LastStreamSequence = seq

			var evt CloudEvent
			if err := json.Unmarshal(msg.Data, &evt); err != nil {
				report.ParseErrors++
				_ = msg.Ack()
				if config.Limit > 0 && report.MessagesFetched >= config.Limit {
					report.StoppedByLimit = true
					stop = true
				}
				continue
			}
			report.EventsParsed++

			if handler != nil {
				replayEvent := ReplayEvent{
					CloudEvent:     evt,
					Subject:        msg.Subject,
					Stream:         config.Stream,
					StreamSequence: seq,
					ConsumerSeq:    meta.Sequence.Consumer,
					PublishedAt:    meta.Timestamp.UTC(),
					RawPayload:     append([]byte(nil), msg.Data...),
				}
				if err := handler(ctx, replayEvent); err != nil {
					report.HandlerErrors++
					report.LastHandlerError = err.Error()
					_ = msg.Ack()
					if !config.ContinueOnHandlerError {
						report.CompletedAt = time.Now().UTC()
						return report, fmt.Errorf("replay handler failed at stream sequence %d: %w", seq, err)
					}
				} else {
					report.EventsHandled++
					_ = msg.Ack()
				}
			} else {
				report.EventsHandled++
				_ = msg.Ack()
			}

			if config.Limit > 0 && report.MessagesFetched >= config.Limit {
				report.StoppedByLimit = true
				stop = true
				break
			}
		}
	}

	report.CompletedAt = time.Now().UTC()
	return report, nil
}

func (c ReplayConfig) withDefaults() ReplayConfig {
	cfg := c
	if len(cfg.URLs) == 0 {
		cfg.URLs = []string{defaultJetStreamURL}
	}
	if strings.TrimSpace(cfg.Stream) == "" {
		cfg.Stream = defaultConsumerStream
	}
	if strings.TrimSpace(cfg.Subject) == "" {
		cfg.Subject = defaultConsumerSubject
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultConsumerBatchSize
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = defaultConsumerFetchTimeout
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConsumerConnectWait
	}
	if strings.TrimSpace(cfg.AuthMode) == "" {
		cfg.AuthMode = defaultJetStreamAuthMode
	}
	return cfg
}

func (c ReplayConfig) validate() error {
	if len(c.URLs) == 0 {
		return errors.New("replay requires at least one URL")
	}
	if strings.TrimSpace(c.Stream) == "" {
		return errors.New("replay stream is required")
	}
	if strings.TrimSpace(c.Subject) == "" {
		return errors.New("replay subject is required")
	}
	if c.BatchSize <= 0 {
		return errors.New("replay batch size must be > 0")
	}
	if c.FetchTimeout <= 0 {
		return errors.New("replay fetch timeout must be > 0")
	}
	if c.Limit < 0 {
		return errors.New("replay limit must be >= 0")
	}
	if c.FromSequence > 0 && c.FromTime != nil && !c.FromTime.IsZero() {
		return errors.New("replay from_sequence and from_time are mutually exclusive")
	}
	return nil
}
