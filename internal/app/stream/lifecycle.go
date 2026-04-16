package stream

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/health"
)

func (r *Runtime) InitTapGraphConsumer(ctx context.Context) {
	cfg := r.config()
	if r == nil || cfg == nil {
		return
	}
	if !r.graphWriterLeaseAllowsWrites() {
		if logger := r.logger(); logger != nil {
			logger.Info("deferring tap graph consumer until graph writer lease is acquired",
				"lease", cfg.GraphWriterLeaseName,
				"holder", r.graphWriterLeaseStatus().LeaseHolderID,
			)
		}
		return
	}
	r.StartTapGraphConsumer(ctx)
}

func (r *Runtime) StartTapGraphConsumer(ctx context.Context) {
	cfg := r.config()
	if r == nil || cfg == nil {
		return
	}
	if !cfg.NATSConsumerEnabled {
		return
	}
	if !r.graphWriterLeaseAllowsWrites() {
		return
	}
	r.consumerMu.Lock()
	defer r.consumerMu.Unlock()
	durable := r.TapGraphConsumerDurable()
	subjects := r.TapGraphConsumerSubjects()
	if r.tapGraphConsumerConfigMatchesLocked(durable, subjects) {
		return
	}
	if r.consumer != nil {
		if err := r.stopTapGraphConsumerLocked(ctx); err != nil {
			if logger := r.logger(); logger != nil {
				logger.Warn("failed to restart tap graph consumer with updated lease role", "error", err)
			}
			return
		}
	}
	if len(subjects) == 0 {
		return
	}
	handler := func(handlerCtx context.Context, evt events.CloudEvent) error {
		return r.handleTapGraphConsumerEvent(handlerCtx, evt)
	}

	created, err := events.NewJetStreamConsumer(events.ConsumerConfig{
		URLs:                  cfg.NATSJetStreamURLs,
		Stream:                cfg.NATSConsumerStream,
		Subjects:              subjects,
		Durable:               durable,
		BatchSize:             cfg.NATSConsumerBatchSize,
		AckWait:               cfg.NATSConsumerAckWait,
		FetchTimeout:          cfg.NATSConsumerFetchTimeout,
		InProgressInterval:    cfg.NATSConsumerInProgressInterval,
		DeadLetterPath:        cfg.NATSConsumerDeadLetterPath,
		DedupEnabled:          cfg.NATSConsumerDedupEnabled,
		DedupStateFile:        cfg.NATSConsumerDedupStateFile,
		DedupStore:            r.executionStoreForPath(cfg.NATSConsumerDedupStateFile),
		DedupTTL:              cfg.NATSConsumerDedupTTL,
		DedupMaxRecords:       cfg.NATSConsumerDedupMaxRecords,
		DropHealthLookback:    cfg.NATSConsumerDropHealthLookback,
		DropHealthThreshold:   cfg.NATSConsumerDropHealthThreshold,
		ConnectTimeout:        cfg.NATSJetStreamConnectTimeout,
		AuthMode:              cfg.NATSJetStreamAuthMode,
		Username:              cfg.NATSJetStreamUsername,
		Password:              cfg.NATSJetStreamPassword,
		NKeySeed:              cfg.NATSJetStreamNKeySeed,
		UserJWT:               cfg.NATSJetStreamUserJWT,
		TLSEnabled:            cfg.NATSJetStreamTLSEnabled,
		TLSCAFile:             cfg.NATSJetStreamTLSCAFile,
		TLSCertFile:           cfg.NATSJetStreamTLSCertFile,
		TLSKeyFile:            cfg.NATSJetStreamTLSKeyFile,
		TLSServerName:         cfg.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: cfg.NATSJetStreamTLSInsecure,
	}, r.logger(), handler)
	if err != nil {
		if logger := r.logger(); logger != nil {
			logger.Warn("failed to initialize tap graph consumer", "error", err)
		}
		return
	}
	r.consumer = created
	r.consumerDurable = durable
	r.consumerSubjects = append([]string(nil), subjects...)
	r.initEventCorrelationRefreshLoop(ctx)
	if registry := r.healthRegistry(); registry != nil {
		registry.Register("tap_consumer", func(_ context.Context) health.CheckResult {
			start := time.Now().UTC()
			snapshot := created.HealthSnapshot(start)
			status := health.StatusHealthy
			message := "consumer healthy"
			graphStaleness := snapshot.GraphStaleness
			if graphStaleness == 0 {
				if buildAt := r.graphBuildLastAt(); !buildAt.IsZero() {
					graphStaleness = time.Since(buildAt.UTC())
				}
			}
			if snapshot.Threshold > 0 && snapshot.RecentDropped >= snapshot.Threshold {
				status = health.StatusUnhealthy
				message = fmt.Sprintf("consumer dropped %d malformed events in last %s (threshold %d); last_reason=%s",
					snapshot.RecentDropped,
					snapshot.Lookback.String(),
					snapshot.Threshold,
					snapshot.LastDropReason,
				)
			} else if threshold := cfg.NATSConsumerGraphStalenessThreshold; threshold > 0 && graphStaleness > threshold {
				status = health.StatusUnhealthy
				message = fmt.Sprintf("graph staleness %s exceeds threshold %s", graphStaleness.Round(time.Second), threshold)
			} else if snapshot.ConsumerLag > 0 {
				message = fmt.Sprintf("consumer healthy; lag=%d lag_seconds=%s", snapshot.ConsumerLag, snapshot.ConsumerLagAge.Round(time.Second))
			}
			return health.CheckResult{
				Name:      "tap_consumer",
				Status:    status,
				Message:   message,
				Timestamp: start,
				Latency:   time.Since(start),
			}
		})
	}
	if logger := r.logger(); logger != nil {
		logger.Info("tap graph consumer enabled",
			"stream", cfg.NATSConsumerStream,
			"subjects", subjects,
			"durable", durable,
			"batch_size", cfg.NATSConsumerBatchSize,
			"dedupe_enabled", cfg.NATSConsumerDedupEnabled,
			"role", r.graphWriterLeaseStatus().Role,
		)
	}
}

func (r *Runtime) handleTapGraphConsumerEvent(ctx context.Context, evt events.CloudEvent) error {
	return r.HandleGraphCloudEvent(ctx, evt)
}

func (r *Runtime) StopTapGraphConsumer(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.consumerMu.Lock()
	defer r.consumerMu.Unlock()
	return r.stopTapGraphConsumerLocked(ctx)
}

func (r *Runtime) stopTapGraphConsumerLocked(ctx context.Context) error {
	if r == nil {
		return nil
	}
	consumer := r.consumer
	defer func() {
		r.consumer = nil
		r.consumerDurable = ""
		r.consumerSubjects = nil
	}()
	if consumer == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := consumer.Drain(ctx); err != nil {
		_ = consumer.Close()
		return err
	}
	return consumer.Close()
}

func (r *Runtime) TapGraphConsumerSubjects() []string {
	cfg := r.config()
	if r == nil || cfg == nil {
		return nil
	}
	return normalizeTapGraphConsumerSubjects(cfg.NATSConsumerSubjects)
}

func (r *Runtime) TapGraphConsumerDurable() string {
	cfg := r.config()
	if r == nil || cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.NATSConsumerDurable)
}

func (r *Runtime) tapGraphConsumerConfigMatchesLocked(durable string, subjects []string) bool {
	if r == nil || r.consumer == nil {
		return false
	}
	if r.consumerDurable != durable {
		return false
	}
	return tapGraphConsumerSubjectsEqual(r.consumerSubjects, subjects)
}

func normalizeTapGraphConsumerSubjects(subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(subjects))
	normalized := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			continue
		}
		if _, ok := seen[subject]; ok {
			continue
		}
		seen[subject] = struct{}{}
		normalized = append(normalized, subject)
	}
	return normalized
}

func tapGraphConsumerSubjectsEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for idx := range left {
		if left[idx] != right[idx] {
			return false
		}
	}
	return true
}
