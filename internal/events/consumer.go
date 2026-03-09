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

	"github.com/nats-io/nats.go"
)

const (
	defaultConsumerStream       = "ENSEMBLE_TAP"
	defaultConsumerDurable      = "cerebro_graph_builder"
	defaultConsumerSubject      = "ensemble.tap.>"
	defaultConsumerBatchSize    = 50
	defaultConsumerAckWait      = 30 * time.Second
	defaultConsumerFetchTimeout = 2 * time.Second
	defaultConsumerConnectWait  = 5 * time.Second
)

type ConsumerConfig struct {
	URLs           []string
	Stream         string
	Subject        string
	Durable        string
	BatchSize      int
	AckWait        time.Duration
	FetchTimeout   time.Duration
	ConnectTimeout time.Duration
	MaxAckPending  int

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
	nc      *nats.Conn
	js      nats.JetStreamContext
	sub     *nats.Subscription

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
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
			var evt CloudEvent
			if err := json.Unmarshal(msg.Data, &evt); err != nil {
				c.logger.Warn("tap consumer dropped malformed cloud event", "error", err, "subject", msg.Subject)
				_ = msg.Ack()
				continue
			}
			if err := c.handler(runCtx, evt); err != nil {
				c.logger.Warn("tap consumer handler failed; message requeued", "error", err, "event_type", evt.Type)
				_ = msg.Nak()
				continue
			}
			_ = msg.Ack()
		}
	}
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
