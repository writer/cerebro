package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	// DefaultLeaseTTL bounds how long a single Sync call may hold a runtime
	// lease before the lease is considered abandoned and another caller
	// can acquire it. The orchestrator uses the same value when it leases
	// runtimes for its iteration; matching it here keeps cross-task
	// coordination behavior predictable when the API and the orchestrator
	// race for the same runtime.
	DefaultLeaseTTL = 30 * time.Minute

	// LeaseReleaseTimeout bounds the best-effort lease release on shutdown
	// paths so a slow database cannot block the caller indefinitely.
	LeaseReleaseTimeout = 5 * time.Second

	// LeaseRenewalMaxInterval keeps renewal attempts comfortably ahead of
	// the runtime lease TTL. Long-lived backfills can overlap scheduled or
	// verification tasks; renewing more often than TTL/2 narrows the window
	// where a delayed renewal lets another task acquire the runtime.
	LeaseRenewalMaxInterval = 5 * time.Minute
)

// ErrSyncInProgress is returned by SyncWithLease when the runtime is
// already leased by another worker (API task, orchestrator, or other API
// task). Callers should treat it as a soft conflict and retry after the
// holder finishes; HTTP and connect adapters map it to a 409/Aborted.
var ErrSyncInProgress = errors.New("source runtime sync is in progress")

// SyncWithLeaseOptions configures cross-task locking around Sync.
//
// LeaseStore is the durable lease coordinator. When nil, SyncWithLease
// falls back to plain Sync so callers that are statically single-task
// (CLI, single-replica deployments) keep working without changes.
type SyncWithLeaseOptions struct {
	LeaseStore ports.SourceRuntimeLeaseStore
	LeaseOwner string
	LeaseTTL   time.Duration
}

// SyncWithLease wraps Sync with a durable, renewable runtime lease so the
// cursor advance is safe when several API replicas (or the API and the
// orchestrator) try to sync the same runtime concurrently.
//
// Behavior:
//
//   - Acquire fails fast with ErrSyncInProgress when another holder has a
//     valid lease; the caller decides whether to retry.
//   - A background goroutine renews the lease every TTL/2 so a long pull
//     (paginated GitHub backfill, slow projection) does not lose the
//     lease mid-stream. Renewal failure cancels the Sync context so the
//     work stops promptly and the cursor is not advanced after another
//     task has taken over.
//   - Release runs on a detached timeout-bounded context so it still
//     happens when the parent context is already cancelled.
func (s *Service) SyncWithLease(ctx context.Context, req *cerebrov1.SyncSourceRuntimeRequest, opts SyncWithLeaseOptions) (_ *cerebrov1.SyncSourceRuntimeResponse, err error) {
	runtimeID := strings.TrimSpace(req.GetId())
	ttl := opts.LeaseTTL
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	attrs := syncWithLeaseTelemetryAttrs(req, opts.LeaseStore != nil, ttl)
	ctx, span := telemetry.Start(ctx, "source_runtime.sync_with_lease", attrs)
	status := "completed"
	errorKind := ""
	defer func() {
		if err != nil {
			status = syncWithLeaseTelemetryStatus(err)
			if errorKind == "" {
				errorKind = syncWithLeaseTelemetryErrorKind(err)
			}
			attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: errorKind})
			telemetry.IncrementMain(ctx, "source_runtime.lease.error.count", 1)
		}
		telemetry.IncrementMain(ctx, "source_runtime.lease.count", 1)
		telemetry.AnnotateMain(ctx, attrs.WithField(telemetry.Field{Key: "source_runtime.lease.status", Value: status}))
		telemetry.End(span, status, attrs)
	}()
	if s == nil {
		return nil, ErrRuntimeUnavailable
	}
	if opts.LeaseStore == nil {
		return s.Sync(ctx, req)
	}
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	owner := strings.TrimSpace(opts.LeaseOwner)
	if owner == "" {
		owner = DefaultAPILeaseOwner()
	}
	acquired, err := opts.LeaseStore.AcquireSourceRuntimeLease(ctx, runtimeID, owner, ttl)
	if err != nil {
		errorKind = "lease_acquire_failed"
		attrs = attrs.WithField(telemetry.Field{Key: "lease_acquired", Value: false})
		return nil, fmt.Errorf("acquire source runtime lease %q: %w", runtimeID, err)
	}
	attrs = attrs.WithField(telemetry.Field{Key: "lease_acquired", Value: acquired})
	if !acquired {
		if s.store != nil {
			if _, lookupErr := s.lookupRuntime(ctx, runtimeID); lookupErr != nil {
				return nil, lookupErr
			}
		}
		attrs = attrs.WithField(telemetry.Field{Key: "lease_conflict", Value: true})
		return nil, fmt.Errorf("%w: %s", ErrSyncInProgress, runtimeID)
	}
	syncCtx, cancelSync := context.WithCancel(ctx)
	stopRenewal := startLeaseRenewal(syncCtx, opts.LeaseStore, runtimeID, owner, ttl, cancelSync)
	response, syncErr := s.Sync(syncCtx, req)
	cancelSync()
	renewalErr := stopRenewal()
	releaseErr := releaseLease(ctx, opts.LeaseStore, runtimeID, owner)
	if syncErr != nil {
		return nil, syncErr
	}
	if renewalErr != nil {
		errorKind = "lease_renew_failed"
		return nil, fmt.Errorf("renew source runtime lease %q: %w", runtimeID, renewalErr)
	}
	if releaseErr != nil {
		errorKind = "lease_release_failed"
		return nil, fmt.Errorf("release source runtime lease %q: %w", runtimeID, releaseErr)
	}
	return response, nil
}

func syncWithLeaseTelemetryAttrs(req *cerebrov1.SyncSourceRuntimeRequest, leaseStorePresent bool, ttl time.Duration) telemetry.Attributes {
	return telemetry.Attrs(
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(req.GetId())},
		telemetry.Field{Key: "page_limit", Value: req.GetPageLimit()},
		telemetry.Field{Key: "lease_store_present", Value: leaseStorePresent},
		telemetry.Field{Key: "lease_ttl_seconds", Value: int64(ttl.Seconds())},
	)
}

func syncWithLeaseTelemetryStatus(err error) string {
	if errors.Is(err, ErrSyncInProgress) {
		return "conflict"
	}
	return "failed"
}

func syncWithLeaseTelemetryErrorKind(err error) string {
	switch {
	case errors.Is(err, ErrSyncInProgress):
		return "sync_in_progress"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, ErrRuntimeUnavailable):
		return "runtime_unavailable"
	case errors.Is(err, ports.ErrSourceRuntimeNotFound):
		return "runtime_not_found"
	default:
		return "sync_failed"
	}
}

// DefaultAPILeaseOwner returns an owner identifier suitable for the API
// service. The pid+nanos suffix keeps owners unique across both replicas
// on the same host (rare in ECS, common in local dev) and across rapid
// restarts.
func DefaultAPILeaseOwner() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("cerebro-api:%s:%d:%d", hostname, os.Getpid(), time.Now().UnixNano())
}

func startLeaseRenewal(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtimeID string, owner string, ttl time.Duration, cancelWork context.CancelFunc) func() error {
	if cancelWork == nil {
		cancelWork = func() {}
	}
	renewCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	interval := LeaseRenewalInterval(ttl)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				renewed, err := store.RenewSourceRuntimeLease(renewCtx, runtimeID, owner, ttl)
				if err != nil {
					cancelWork()
					done <- err
					return
				}
				if !renewed {
					cancelWork()
					done <- fmt.Errorf("source runtime lease lost: %s", runtimeID)
					return
				}
			}
		}
	}()
	return func() error {
		cancel()
		return <-done
	}
}

func LeaseRenewalInterval(ttl time.Duration) time.Duration {
	interval := ttl / 2
	if interval <= 0 {
		return ttl
	}
	if LeaseRenewalMaxInterval > 0 && interval > LeaseRenewalMaxInterval {
		return LeaseRenewalMaxInterval
	}
	return interval
}

func releaseLease(parent context.Context, store ports.SourceRuntimeLeaseStore, runtimeID string, owner string) error {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), LeaseReleaseTimeout)
	defer cancel()
	return store.ReleaseSourceRuntimeLease(releaseCtx, runtimeID, owner)
}
