package app

import (
	"context"
	"fmt"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/health"
)

func (a *App) initTapGraphConsumer(ctx context.Context) {
	if a == nil || a.Config == nil {
		return
	}
	if !a.graphWriterLeaseAllowsWrites() {
		if a.Logger != nil {
			a.Logger.Info("deferring tap graph consumer until graph writer lease is acquired",
				"lease", a.Config.GraphWriterLeaseName,
				"holder", a.GraphWriterLeaseStatusSnapshot().LeaseHolderID,
			)
		}
		return
	}
	a.startTapGraphConsumer(ctx)
}

func (a *App) startTapGraphConsumer(ctx context.Context) {
	if a == nil || a.Config == nil {
		return
	}
	if !a.Config.NATSConsumerEnabled {
		return
	}
	a.tapConsumerMu.Lock()
	defer a.tapConsumerMu.Unlock()
	if a.TapConsumer != nil {
		return
	}

	consumer, err := events.NewJetStreamConsumer(events.ConsumerConfig{
		URLs:                  a.Config.NATSJetStreamURLs,
		Stream:                a.Config.NATSConsumerStream,
		Subjects:              a.Config.NATSConsumerSubjects,
		Durable:               a.Config.NATSConsumerDurable,
		BatchSize:             a.Config.NATSConsumerBatchSize,
		AckWait:               a.Config.NATSConsumerAckWait,
		FetchTimeout:          a.Config.NATSConsumerFetchTimeout,
		InProgressInterval:    a.Config.NATSConsumerInProgressInterval,
		DeadLetterPath:        a.Config.NATSConsumerDeadLetterPath,
		DedupEnabled:          a.Config.NATSConsumerDedupEnabled,
		DedupStateFile:        a.Config.NATSConsumerDedupStateFile,
		DedupStore:            a.executionStoreForPath(a.Config.NATSConsumerDedupStateFile),
		DedupTTL:              a.Config.NATSConsumerDedupTTL,
		DedupMaxRecords:       a.Config.NATSConsumerDedupMaxRecords,
		DropHealthLookback:    a.Config.NATSConsumerDropHealthLookback,
		DropHealthThreshold:   a.Config.NATSConsumerDropHealthThreshold,
		ConnectTimeout:        a.Config.NATSJetStreamConnectTimeout,
		AuthMode:              a.Config.NATSJetStreamAuthMode,
		Username:              a.Config.NATSJetStreamUsername,
		Password:              a.Config.NATSJetStreamPassword,
		NKeySeed:              a.Config.NATSJetStreamNKeySeed,
		UserJWT:               a.Config.NATSJetStreamUserJWT,
		TLSEnabled:            a.Config.NATSJetStreamTLSEnabled,
		TLSCAFile:             a.Config.NATSJetStreamTLSCAFile,
		TLSCertFile:           a.Config.NATSJetStreamTLSCertFile,
		TLSKeyFile:            a.Config.NATSJetStreamTLSKeyFile,
		TLSServerName:         a.Config.NATSJetStreamTLSServerName,
		TLSInsecureSkipVerify: a.Config.NATSJetStreamTLSInsecure,
	}, a.Logger, a.handleGraphCloudEvent)
	if err != nil {
		a.Logger.Warn("failed to initialize tap graph consumer", "error", err)
		return
	}
	a.TapConsumer = consumer
	a.initEventCorrelationRefreshLoop(ctx)
	if a.Health != nil {
		a.Health.Register("tap_consumer", func(_ context.Context) health.CheckResult {
			start := time.Now().UTC()
			snapshot := consumer.HealthSnapshot(start)
			status := health.StatusHealthy
			message := "consumer healthy"
			graphStaleness := snapshot.GraphStaleness
			if graphStaleness == 0 {
				buildSnapshot := a.GraphBuildSnapshot()
				if !buildSnapshot.LastBuildAt.IsZero() {
					graphStaleness = time.Since(buildSnapshot.LastBuildAt.UTC())
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
			} else if threshold := a.Config.NATSConsumerGraphStalenessThreshold; threshold > 0 && graphStaleness > threshold {
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
	a.Logger.Info("tap graph consumer enabled",
		"stream", a.Config.NATSConsumerStream,
		"subjects", a.Config.NATSConsumerSubjects,
		"durable", a.Config.NATSConsumerDurable,
		"batch_size", a.Config.NATSConsumerBatchSize,
		"dedupe_enabled", a.Config.NATSConsumerDedupEnabled,
	)

	_ = ctx
}

func (a *App) stopTapGraphConsumer(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.tapConsumerMu.Lock()
	defer a.tapConsumerMu.Unlock()
	consumer := a.TapConsumer
	if consumer == nil {
		return nil
	}
	defer func() {
		a.TapConsumer = nil
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := consumer.Drain(ctx); err != nil {
		_ = consumer.Close()
		return err
	}
	return consumer.Close()
}
