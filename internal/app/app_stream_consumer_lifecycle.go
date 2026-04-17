package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/health"
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
	if !a.graphReadyClosed() {
		if a.Logger != nil {
			a.Logger.Info("deferring tap graph consumer until security graph is ready")
		}
		return
	}
	a.startTapGraphConsumer(ctx)
}

func (a *App) startTapGraphConsumer(ctx context.Context) {
	if a == nil || a.Config == nil {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}
	if !a.Config.NATSConsumerEnabled {
		return
	}
	if !a.graphWriterLeaseAllowsWrites() {
		return
	}
	if !a.graphReadyClosed() {
		return
	}
	a.tapConsumerMu.Lock()
	defer a.tapConsumerMu.Unlock()
	durable := a.tapGraphConsumerDurable()
	subjects := a.tapGraphConsumerSubjects()
	if a.tapGraphConsumerConfigMatchesLocked(durable, subjects) {
		return
	}
	if a.TapConsumer != nil {
		if err := a.stopTapGraphConsumerLocked(ctx); err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to restart tap graph consumer with updated lease role", "error", err)
			}
			return
		}
	}
	if len(subjects) == 0 {
		return
	}
	handler := func(handlerCtx context.Context, evt events.CloudEvent) error {
		return a.handleTapGraphConsumerEvent(handlerCtx, evt)
	}

	created, err := events.NewJetStreamConsumer(events.ConsumerConfig{
		URLs:                  a.Config.NATSJetStreamURLs,
		Stream:                a.Config.NATSConsumerStream,
		Subjects:              subjects,
		Durable:               durable,
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
	}, a.Logger, handler)
	if err != nil {
		a.Logger.Warn("failed to initialize tap graph consumer", "error", err)
		return
	}
	a.TapConsumer = created
	a.tapConsumerDurable = durable
	a.tapConsumerSubjects = append([]string(nil), subjects...)
	a.initEventCorrelationRefreshLoop(ctx)
	if a.Health != nil {
		a.Health.Register("tap_consumer", func(_ context.Context) health.CheckResult {
			start := time.Now().UTC()
			snapshot := created.HealthSnapshot(start)
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
		"subjects", subjects,
		"durable", durable,
		"batch_size", a.Config.NATSConsumerBatchSize,
		"dedupe_enabled", a.Config.NATSConsumerDedupEnabled,
		"role", a.GraphWriterLeaseStatusSnapshot().Role,
	)

	_ = ctx
}

func (a *App) handleTapGraphConsumerEvent(ctx context.Context, evt events.CloudEvent) error {
	return a.handleGraphCloudEvent(ctx, evt)
}

func (a *App) stopTapGraphConsumer(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.tapConsumerMu.Lock()
	defer a.tapConsumerMu.Unlock()
	return a.stopTapGraphConsumerLocked(ctx)
}

func (a *App) stopTapGraphConsumerLocked(ctx context.Context) error {
	if a == nil {
		return nil
	}
	consumer := a.TapConsumer
	defer func() {
		a.TapConsumer = nil
		a.tapConsumerDurable = ""
		a.tapConsumerSubjects = nil
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

func (a *App) tapGraphConsumerSubjects() []string {
	if a == nil || a.Config == nil {
		return nil
	}
	return normalizeTapGraphConsumerSubjects(a.Config.NATSConsumerSubjects)
}

func (a *App) tapGraphConsumerDurable() string {
	if a == nil || a.Config == nil {
		return ""
	}
	return strings.TrimSpace(a.Config.NATSConsumerDurable)
}

func (a *App) tapGraphConsumerConfigMatchesLocked(durable string, subjects []string) bool {
	if a == nil || a.TapConsumer == nil {
		return false
	}
	if a.tapConsumerDurable != durable {
		return false
	}
	return tapGraphConsumerSubjectsEqual(a.tapConsumerSubjects, subjects)
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
