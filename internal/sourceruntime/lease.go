package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/panicsafe"
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
// LeaseStore is the durable lease coordinator. SyncWithLease fails closed when
// it is absent or cannot return the acquired lease's durable generation.
type SyncWithLeaseOptions struct {
	LeaseStore ports.SourceRuntimeLeaseStore
	LeaseOwner string
	LeaseTTL   time.Duration
}

type sourceRuntimeLeaseFenceContextKey struct{}

type sourceRuntimeLeaseAuthority struct {
	fence     ports.SourceRuntimeLeaseFence
	runtimeID string
	reader    ports.SourceRuntimeLeaseFenceReader
}

func sourceRuntimeLeaseFenceFromContext(ctx context.Context) (ports.SourceRuntimeLeaseFence, bool) {
	authority, ok := ctx.Value(sourceRuntimeLeaseFenceContextKey{}).(sourceRuntimeLeaseAuthority)
	fence := authority.fence
	return fence, ok && strings.TrimSpace(fence.Owner) != "" && fence.Generation > 0 && !fence.ExpiresAt.IsZero()
}

// currentSourceRuntimeLeaseFence refreshes the durable expiry before each Rust
// source page while preserving the generation acquired for this execution.
// Package-local tests may bind an immutable fence directly; production callers
// bind through WithCurrentSourceRuntimeLeaseFence and always carry a reader.
func currentSourceRuntimeLeaseFence(ctx context.Context, runtimeID string) (ports.SourceRuntimeLeaseFence, error) {
	authority, ok := ctx.Value(sourceRuntimeLeaseFenceContextKey{}).(sourceRuntimeLeaseAuthority)
	bound := authority.fence
	if !ok || strings.TrimSpace(bound.Owner) == "" || bound.Generation == 0 || bound.ExpiresAt.IsZero() {
		return ports.SourceRuntimeLeaseFence{}, fmt.Errorf("%w: source worker requires a current durable lease fence", ErrRuntimeUnavailable)
	}
	runtimeID = strings.TrimSpace(runtimeID)
	if authority.reader == nil {
		if !bound.ExpiresAt.After(time.Now().UTC()) {
			return ports.SourceRuntimeLeaseFence{}, fmt.Errorf("%w: source runtime lease fence %q is not current", ports.ErrSourceRuntimeLeaseLost, runtimeID)
		}
		return bound, nil
	}
	if strings.TrimSpace(authority.runtimeID) != runtimeID {
		return ports.SourceRuntimeLeaseFence{}, fmt.Errorf("%w: source runtime lease fence does not match runtime %q", ports.ErrSourceRuntimeLeaseLost, runtimeID)
	}
	fence, err := authority.reader.ReadSourceRuntimeLeaseFence(ctx, runtimeID, bound.Owner)
	if err != nil {
		return ports.SourceRuntimeLeaseFence{}, fmt.Errorf("refresh source runtime lease fence %q: %w", runtimeID, err)
	}
	fence.Owner = strings.TrimSpace(fence.Owner)
	fence.ExpiresAt = fence.ExpiresAt.UTC()
	if fence.Owner != bound.Owner || fence.Generation != bound.Generation || !fence.ExpiresAt.After(time.Now().UTC()) {
		return ports.SourceRuntimeLeaseFence{}, fmt.Errorf("%w: source runtime lease fence %q changed generation or expired", ports.ErrSourceRuntimeLeaseLost, runtimeID)
	}
	return fence, nil
}

// WithCurrentSourceRuntimeLeaseFence binds the durable owner/generation snapshot
// for an already acquired lease to source-runtime work. Callers that acquire a
// lease outside SyncWithLease, such as the orchestrator, must use the returned
// context before invoking Sync so credential-free source execution can reject
// stale workers and fenced page commits can use the same generation.
func WithCurrentSourceRuntimeLeaseFence(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtimeID string, owner string) (context.Context, error) {
	if store == nil {
		return ctx, fmt.Errorf("%w: durable source runtime lease store is unavailable", ErrRuntimeUnavailable)
	}
	reader, ok := store.(ports.SourceRuntimeLeaseFenceReader)
	if !ok {
		return ctx, fmt.Errorf("%w: durable source runtime lease fence reader is unavailable", ErrRuntimeUnavailable)
	}
	runtimeID = strings.TrimSpace(runtimeID)
	owner = strings.TrimSpace(owner)
	fence, err := reader.ReadSourceRuntimeLeaseFence(ctx, runtimeID, owner)
	if err != nil {
		return ctx, fmt.Errorf("read source runtime lease fence %q: %w", runtimeID, err)
	}
	fence.Owner = strings.TrimSpace(fence.Owner)
	fence.ExpiresAt = fence.ExpiresAt.UTC()
	if fence.Owner != owner || fence.Generation == 0 || !fence.ExpiresAt.After(time.Now().UTC()) {
		return ctx, fmt.Errorf("%w: source runtime lease fence %q is not current", ports.ErrSourceRuntimeLeaseLost, runtimeID)
	}
	return context.WithValue(ctx, sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{
		fence:     fence,
		runtimeID: runtimeID,
		reader:    reader,
	}), nil
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
		telemetry.AnnotateMainPhase(ctx, "source_runtime.sync_with_lease", status, attrs)
		telemetry.End(span, status, attrs)
	}()
	if s == nil {
		return nil, ErrRuntimeUnavailable
	}
	if opts.LeaseStore == nil {
		return nil, fmt.Errorf("%w: durable source runtime lease store is unavailable", ErrRuntimeUnavailable)
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
	syncCtx, fenceErr := WithCurrentSourceRuntimeLeaseFence(syncCtx, opts.LeaseStore, runtimeID, owner)
	if fenceErr != nil {
		cancelSync()
		_ = releaseLease(ctx, opts.LeaseStore, runtimeID, owner)
		return nil, fenceErr
	}
	stopRenewal := startLeaseRenewal(syncCtx, opts.LeaseStore, runtimeID, owner, ttl, cancelSync)
	response, syncErr := s.Sync(syncCtx, req)
	cancelSync()
	renewalErr := stopRenewal()
	releaseErr := releaseLease(ctx, opts.LeaseStore, runtimeID, owner)
	if errors.Is(renewalErr, ports.ErrSourceRuntimeLeaseLost) {
		return nil, fmt.Errorf("renew source runtime lease %q: %w", runtimeID, renewalErr)
	}
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
	if errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		return "lease_lost"
	}
	if errors.Is(err, ErrSyncInProgress) {
		return "conflict"
	}
	return "failed"
}

func syncWithLeaseTelemetryErrorKind(err error) string {
	switch {
	case errors.Is(err, ports.ErrSourceRuntimeLeaseLost):
		return "lease_lost"
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
	panicsafe.Go(renewCtx, "source_runtime.lease_renewal", func() {
		defer close(done)
		defer func() {
			select {
			case done <- panicsafe.ErrTaskPanicked:
			default:
			}
		}()
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
					done <- fmt.Errorf("%w: %s", ports.ErrSourceRuntimeLeaseLost, runtimeID)
					return
				}
			}
		}
	})
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

// AcquireRenewableLease acquires one source-runtime lease and returns a
// cancellable work context plus an idempotent release function. The work
// context is cancelled if renewal fails or ownership is lost.
func AcquireRenewableLease(ctx context.Context, store ports.SourceRuntimeLeaseStore, runtimeID string, owner string, ttl time.Duration) (context.Context, func() error, bool, error) {
	noop := func() error { return nil }
	if store == nil {
		return ctx, noop, false, nil
	}
	runtimeID = strings.TrimSpace(runtimeID)
	owner = strings.TrimSpace(owner)
	if runtimeID == "" {
		return ctx, noop, false, errors.New("source runtime id is required")
	}
	if owner == "" {
		return ctx, noop, false, errors.New("source runtime lease owner is required")
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	acquired, err := store.AcquireSourceRuntimeLease(ctx, runtimeID, owner, ttl)
	if err != nil || !acquired {
		return ctx, noop, acquired, err
	}
	workCtx, cancelWork := context.WithCancel(ctx)
	renewCtx, cancelRenew := context.WithCancel(ctx)
	done := make(chan error, 1)
	panicsafe.Go(renewCtx, "source_runtime.lease_renewal", func() {
		defer close(done)
		defer func() {
			select {
			case done <- panicsafe.ErrTaskPanicked:
			default:
			}
		}()
		ticker := time.NewTicker(LeaseRenewalInterval(ttl))
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				renewed, renewErr := store.RenewSourceRuntimeLease(renewCtx, runtimeID, owner, ttl)
				if renewErr != nil {
					if renewCtx.Err() != nil {
						done <- nil
						return
					}
					cancelWork()
					done <- renewErr
					return
				}
				if !renewed {
					if renewCtx.Err() != nil {
						done <- nil
						return
					}
					cancelWork()
					done <- fmt.Errorf("%w: %s", ports.ErrSourceRuntimeLeaseLost, runtimeID)
					return
				}
			}
		}
	})
	var (
		releaseOnce sync.Once
		releaseErr  error
	)
	return workCtx, func() error {
		releaseOnce.Do(func() {
			cancelRenew()
			renewalErr := <-done
			cancelWork()
			releaseErr = errors.Join(renewalErr, releaseLease(ctx, store, runtimeID, owner))
		})
		return releaseErr
	}, true, nil
}

func releaseLease(parent context.Context, store ports.SourceRuntimeLeaseStore, runtimeID string, owner string) error {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), LeaseReleaseTimeout)
	defer cancel()
	return store.ReleaseSourceRuntimeLease(releaseCtx, runtimeID, owner)
}
