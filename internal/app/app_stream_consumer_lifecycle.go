package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/health"
	"github.com/evalops/cerebro/internal/metrics"
)

var errTapGraphConsumerAuditMutationDeferred = errors.New("tap graph consumer follower replica deferred audit mutation event until writer lease is held")

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
	var consumer atomic.Pointer[events.Consumer]
	handler := func(handlerCtx context.Context, evt events.CloudEvent) error {
		currentConsumer := consumer.Load()
		err := a.handleTapGraphConsumerEvent(handlerCtx, evt)
		a.updateGraphReplicaLagMetric(currentConsumer)
		return err
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
	consumer.Store(created)
	a.TapConsumer = created
	a.tapConsumerDurable = durable
	a.tapConsumerSubjects = append([]string(nil), subjects...)
	a.updateGraphReplicaLagMetric(created)
	a.initEventCorrelationRefreshLoop(ctx)
	if a.Health != nil {
		a.Health.Register("tap_consumer", func(_ context.Context) health.CheckResult {
			start := time.Now().UTC()
			snapshot := created.HealthSnapshot(start)
			a.updateGraphReplicaLagMetric(created)
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
	if !a.graphWriterLeaseAllowsWrites() {
		if isAuditMutationEventType(cloudEventType(evt)) {
			return events.RetryWithDelay(errTapGraphConsumerAuditMutationDeferred, a.tapGraphAuditMutationRetryDelay())
		}
		ctx = withGraphReplicaReplay(ctx)
	}
	return a.handleGraphCloudEvent(ctx, evt)
}

func (a *App) tapGraphAuditMutationRetryDelay() time.Duration {
	if a == nil || a.Config == nil {
		return 0
	}
	if a.Config.GraphWriterLeaseHeartbeat > 0 {
		return a.Config.GraphWriterLeaseHeartbeat
	}
	return a.Config.NATSConsumerFetchTimeout
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
		metrics.SetGraphReplicaLagMutations(0)
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
	subjects := normalizeTapGraphConsumerSubjects(a.Config.NATSConsumerSubjects)
	if len(subjects) == 0 {
		return nil
	}
	if !a.Config.GraphWriterLeaseEnabled || a.graphWriterLeaseAllowsWrites() {
		return subjects
	}
	filtered := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if isFollowerTapGraphConsumerSubject(subject) {
			filtered = append(filtered, subject)
		}
	}
	return filtered
}

func (a *App) tapGraphConsumerDurable() string {
	if a == nil || a.Config == nil {
		return ""
	}
	base := strings.TrimSpace(a.Config.NATSConsumerDurable)
	if !a.Config.GraphWriterLeaseEnabled {
		return base
	}
	owner := strings.TrimSpace(a.Config.GraphWriterLeaseOwnerID)
	if host, _, ok := strings.Cut(owner, ":"); ok && strings.TrimSpace(host) != "" {
		owner = strings.TrimSpace(host)
	}
	owner = sanitizeJetStreamConsumerName(owner)
	if owner == "" {
		return base
	}
	if base == "" {
		return owner
	}
	return base + "_" + owner
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

func isFollowerTapGraphConsumerSubject(subject string) bool {
	subject = strings.ToLower(strings.TrimSpace(subject))
	return strings.HasPrefix(subject, "ensemble.tap.")
}

func sanitizeJetStreamConsumerName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func (a *App) updateGraphReplicaLagMetric(consumer *events.Consumer) {
	if consumer == nil {
		metrics.SetGraphReplicaLagMutations(0)
		return
	}
	if a == nil || a.Config == nil || !a.Config.GraphWriterLeaseEnabled || a.graphWriterLeaseAllowsWrites() {
		metrics.SetGraphReplicaLagMutations(0)
		return
	}
	metrics.SetGraphReplicaLagMutations(consumer.HealthSnapshot(time.Now().UTC()).ConsumerLag)
}
