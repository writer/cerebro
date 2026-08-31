package sourceruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/panicsafe"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/telemetry"
)

type leaseEvent struct {
	verb     string
	owner    string
	acquired bool
}

type stubLeaseStore struct {
	mu sync.Mutex

	heldBy        string
	holdUntil     time.Time
	generation    uint64
	rejectNext    bool
	rejectRenewal bool
	renewPanic    bool

	renewStarted       chan struct{}
	renewStartOnce     sync.Once
	renewWaitForCancel bool

	acquireErr error
	renewErr   error
	releaseErr error

	events []leaseEvent
}

type fencedStubLeaseStore struct {
	*stubLeaseStore
	fence ports.SourceRuntimeLeaseFence
	err   error
	reads int

	errAfterReads int
}

type leaseStoreWithoutFenceReader struct {
	store *stubLeaseStore
}

type renewalBlockingSource struct{}

type coordinatedFailureSource struct {
	err         error
	readRelease <-chan struct{}
	readStarted chan struct{}
}

func (renewalBlockingSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "renewal_blocking"}
}

func (renewalBlockingSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (renewalBlockingSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (renewalBlockingSource) Read(ctx context.Context, _ sourcecdk.Config, _ *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	<-ctx.Done()
	return sourcecdk.Pull{}, ctx.Err()
}

func (s coordinatedFailureSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "coordinated_failure"}
}

func (coordinatedFailureSource) Check(context.Context, sourcecdk.Config) error {
	return nil
}

func (coordinatedFailureSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}

func (s coordinatedFailureSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	close(s.readStarted)
	<-s.readRelease
	return sourcecdk.Pull{}, s.err
}

func (s *leaseStoreWithoutFenceReader) AcquireSourceRuntimeLease(ctx context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	return s.store.AcquireSourceRuntimeLease(ctx, runtimeID, owner, ttl)
}

func (s *leaseStoreWithoutFenceReader) RenewSourceRuntimeLease(ctx context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	return s.store.RenewSourceRuntimeLease(ctx, runtimeID, owner, ttl)
}

func (s *leaseStoreWithoutFenceReader) ReleaseSourceRuntimeLease(ctx context.Context, runtimeID string, owner string) error {
	return s.store.ReleaseSourceRuntimeLease(ctx, runtimeID, owner)
}

func (s *fencedStubLeaseStore) ReadSourceRuntimeLeaseFence(_ context.Context, runtimeID string, owner string) (ports.SourceRuntimeLeaseFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil && (s.errAfterReads == 0 || s.reads > s.errAfterReads) {
		return ports.SourceRuntimeLeaseFence{}, s.err
	}
	if strings.TrimSpace(runtimeID) == "" || strings.TrimSpace(owner) == "" {
		return ports.SourceRuntimeLeaseFence{}, errors.New("runtime ID and owner are required")
	}
	return s.fence, nil
}

func (s *fencedStubLeaseStore) setFence(fence ports.SourceRuntimeLeaseFence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fence = fence
}

func (s *fencedStubLeaseStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

func (s *stubLeaseStore) AcquireSourceRuntimeLease(_ context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acquireErr != nil {
		return false, s.acquireErr
	}
	if s.rejectNext {
		s.rejectNext = false
		s.events = append(s.events, leaseEvent{verb: "acquire", owner: owner, acquired: false})
		return false, nil
	}
	now := time.Now()
	if s.heldBy != "" && s.heldBy != owner && s.holdUntil.After(now) {
		s.events = append(s.events, leaseEvent{verb: "acquire", owner: owner, acquired: false})
		return false, nil
	}
	if s.heldBy != owner || !s.holdUntil.After(now) || s.generation == 0 {
		s.generation++
	}
	s.heldBy = owner
	s.holdUntil = now.Add(ttl)
	_ = runtimeID
	s.events = append(s.events, leaseEvent{verb: "acquire", owner: owner, acquired: true})
	return true, nil
}

func (s *stubLeaseStore) RenewSourceRuntimeLease(ctx context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	if s.renewStarted != nil {
		s.renewStartOnce.Do(func() { close(s.renewStarted) })
	}
	if s.renewWaitForCancel {
		<-ctx.Done()
	}
	if s.renewPanic {
		panic("lease renewal store panic")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewErr != nil {
		return false, s.renewErr
	}
	if s.rejectRenewal {
		s.events = append(s.events, leaseEvent{verb: "renew", owner: owner, acquired: false})
		return false, nil
	}
	if s.heldBy != owner {
		s.events = append(s.events, leaseEvent{verb: "renew", owner: owner, acquired: false})
		return false, nil
	}
	s.holdUntil = time.Now().Add(ttl)
	_ = runtimeID
	s.events = append(s.events, leaseEvent{verb: "renew", owner: owner, acquired: true})
	return true, nil
}

func (s *stubLeaseStore) ReleaseSourceRuntimeLease(_ context.Context, runtimeID string, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.releaseErr != nil {
		return s.releaseErr
	}
	if s.heldBy == owner {
		s.heldBy = ""
	}
	_ = runtimeID
	s.events = append(s.events, leaseEvent{verb: "release", owner: owner, acquired: true})
	return nil
}

func (s *stubLeaseStore) ReadSourceRuntimeLeaseFence(_ context.Context, runtimeID string, owner string) (ports.SourceRuntimeLeaseFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(runtimeID) == "" || strings.TrimSpace(owner) == "" {
		return ports.SourceRuntimeLeaseFence{}, errors.New("runtime ID and owner are required")
	}
	if s.heldBy != owner || s.generation == 0 || !s.holdUntil.After(time.Now()) {
		return ports.SourceRuntimeLeaseFence{}, ports.ErrSourceRuntimeLeaseLost
	}
	return ports.SourceRuntimeLeaseFence{Owner: owner, Generation: s.generation, ExpiresAt: s.holdUntil}, nil
}

func (s *stubLeaseStore) snapshotEvents() []leaseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]leaseEvent, len(s.events))
	copy(out, s.events)
	return out
}

func leaseProgressProbeService(t *testing.T) (*Service, *runtimeStore) {
	t.Helper()
	registry, err := sourcecdk.NewRegistry(emptyPageSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	store := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "empty_page", TenantId: "tenant-a"},
	}}
	return New(registry, store, &appendLog{}, nil), store
}

func assertLeaseAcquiredAndReleased(t *testing.T, events []leaseEvent) {
	t.Helper()
	if len(events) < 2 || events[0].verb != "acquire" || !events[0].acquired || events[len(events)-1].verb != "release" {
		t.Fatalf("lease events = %#v, want successful acquire followed by release", events)
	}
}

func TestSyncWithLeaseRejectsMissingLeaseStoreBeforeProgressAdvances(t *testing.T) {
	service, store := leaseProgressProbeService(t)
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ErrRuntimeUnavailable)
	}
	if store.putCount != 0 {
		t.Fatalf("runtime progress writes = %d, want 0", store.putCount)
	}
}

func TestWithCurrentSourceRuntimeLeaseFenceBindsDurableFence(t *testing.T) {
	fence := ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 7, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	store := &fencedStubLeaseStore{stubLeaseStore: &stubLeaseStore{}, fence: fence}

	ctx, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if err != nil {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v", err)
	}
	got, ok := sourceRuntimeLeaseFenceFromContext(ctx)
	if !ok {
		t.Fatal("sourceRuntimeLeaseFenceFromContext() = false, want true")
	}
	if got != fence {
		t.Fatalf("lease fence = %#v, want %#v", got, fence)
	}
}

func TestCurrentSourceRuntimeLeaseFenceRefreshesRenewedExpiry(t *testing.T) {
	initial := ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 7, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	store := &fencedStubLeaseStore{stubLeaseStore: &stubLeaseStore{}, fence: initial}
	ctx, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if err != nil {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v", err)
	}

	renewed := ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 7, ExpiresAt: initial.ExpiresAt.Add(time.Minute)}
	store.setFence(renewed)
	got, err := currentSourceRuntimeLeaseFence(ctx, "runtime-a")
	if err != nil {
		t.Fatalf("currentSourceRuntimeLeaseFence() error = %v", err)
	}
	if got != renewed {
		t.Fatalf("current fence = %#v, want renewed fence %#v", got, renewed)
	}
	if gotReads := store.readCount(); gotReads != 2 {
		t.Fatalf("fence reads = %d, want initial bind plus page refresh", gotReads)
	}
}

func TestCurrentSourceRuntimeLeaseFenceRejectsGenerationChange(t *testing.T) {
	initial := ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 7, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	store := &fencedStubLeaseStore{stubLeaseStore: &stubLeaseStore{}, fence: initial}
	ctx, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if err != nil {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v", err)
	}

	store.setFence(ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 8, ExpiresAt: initial.ExpiresAt.Add(time.Minute)})
	_, err = currentSourceRuntimeLeaseFence(ctx, "runtime-a")
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("currentSourceRuntimeLeaseFence() error = %v, want %v", err, ports.ErrSourceRuntimeLeaseLost)
	}
}

func TestCurrentSourceRuntimeLeaseFenceClassifiesReaderUncertaintyAsLeaseLoss(t *testing.T) {
	initial := ports.SourceRuntimeLeaseFence{Owner: "owner-a", Generation: 7, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	want := errors.New("fence store unavailable")
	store := &fencedStubLeaseStore{
		stubLeaseStore: &stubLeaseStore{},
		fence:          initial,
		err:            want,
		errAfterReads:  1,
	}
	ctx, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if err != nil {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v", err)
	}

	_, err = currentSourceRuntimeLeaseFence(ctx, "runtime-a")
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, want) {
		t.Fatalf("currentSourceRuntimeLeaseFence() error = %v, want lease loss preserving %v", err, want)
	}
}

func TestWithCurrentSourceRuntimeLeaseFencePreservesReaderFailure(t *testing.T) {
	want := errors.New("fence unavailable")
	store := &fencedStubLeaseStore{stubLeaseStore: &stubLeaseStore{}, err: want}

	_, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if !errors.Is(err, want) {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v, want %v", err, want)
	}
}

func TestWithCurrentSourceRuntimeLeaseFenceRejectsMissingReader(t *testing.T) {
	store := &leaseStoreWithoutFenceReader{store: &stubLeaseStore{}}

	_, err := WithCurrentSourceRuntimeLeaseFence(context.Background(), store, "runtime-a", "owner-a")
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("WithCurrentSourceRuntimeLeaseFence() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestSyncWithLeaseRejectsMissingFenceReaderBeforeProgressAdvances(t *testing.T) {
	service, runtimeStore := leaseProgressProbeService(t)
	inner := &stubLeaseStore{}
	store := &leaseStoreWithoutFenceReader{store: inner}

	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
		LeaseStore: store,
		LeaseOwner: "owner-a",
	})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("SyncWithLease() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime progress writes = %d, want 0", runtimeStore.putCount)
	}
	assertLeaseAcquiredAndReleased(t, inner.snapshotEvents())
}

func TestSyncWithLeaseRejectsStaleFenceBeforeProgressAdvances(t *testing.T) {
	service, runtimeStore := leaseProgressProbeService(t)
	inner := &stubLeaseStore{}
	store := &fencedStubLeaseStore{
		stubLeaseStore: inner,
		fence: ports.SourceRuntimeLeaseFence{
			Owner:      "owner-a",
			Generation: 1,
			ExpiresAt:  time.Now().Add(-time.Minute),
		},
	}

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
			LeaseStore: store,
			LeaseOwner: "owner-a",
		})
		if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
			t.Fatalf("SyncWithLease() error = %v, want %v", err, ports.ErrSourceRuntimeLeaseLost)
		}
	})
	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync_with_lease")
	if got := payload["status"]; got != "lease_lost" {
		t.Fatalf("telemetry status = %#v, want lease_lost; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "lease_lost" {
		t.Fatalf("telemetry error_kind = %#v, want lease_lost; payload=%#v", got, payload)
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime progress writes = %d, want 0", runtimeStore.putCount)
	}
	assertLeaseAcquiredAndReleased(t, inner.snapshotEvents())
}

func TestSyncWithLeaseSuppressesFailureWriteWhenFenceRefreshIsUncertain(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "tailscale"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {
			Id: "runtime-a", SourceId: "tailscale", TenantId: "tenant-a",
			Config: map[string]string{"family": "user"},
		},
	}}
	service := New(registry, runtimeStore, &appendLog{}, nil)
	service.sourceWorker = &runtimePlanWorker{}
	want := errors.New("fence store unavailable")
	leaseStore := &fencedStubLeaseStore{
		stubLeaseStore: &stubLeaseStore{},
		fence: ports.SourceRuntimeLeaseFence{
			Owner: "owner-a", Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Minute),
		},
		err:           want,
		errAfterReads: 1,
	}

	_, err = service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
		LeaseStore: leaseStore,
		LeaseOwner: "owner-a",
	})
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, want) {
		t.Fatalf("SyncWithLease() error = %v, want lease loss preserving %v", err, want)
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime failure writes after fence refresh uncertainty = %d, want 0", runtimeStore.putCount)
	}
}

func TestSyncWithLeaseRejectsMissingRuntimeID(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{}
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{}, SyncWithLeaseOptions{LeaseStore: store})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestSyncWithLeaseReturnsErrSyncInProgressWhenNotAcquired(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{rejectNext: true}
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{LeaseStore: store})
	if !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ErrSyncInProgress)
	}
	events := store.snapshotEvents()
	if len(events) != 1 || events[0].verb != "acquire" || events[0].acquired {
		t.Fatalf("SyncWithLease() events = %#v, want one rejected acquire", events)
	}
}

func TestSyncWithLeaseEmitsTelemetryWhenLeaseConflict(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{rejectNext: true}
	owner := "owner-should-not-be-logged"

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{
			Id:        "runtime-a",
			PageLimit: 7,
		}, SyncWithLeaseOptions{
			LeaseStore: store,
			LeaseOwner: owner,
			LeaseTTL:   time.Minute,
		})
		if !errors.Is(err, ErrSyncInProgress) {
			t.Fatalf("SyncWithLease() err = %v, want ErrSyncInProgress", err)
		}
	})

	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync_with_lease")
	for key, want := range map[string]any{
		"kind":                "span_end",
		"name":                "source_runtime.sync_with_lease",
		"status":              "conflict",
		"runtime_id":          "runtime-a",
		"page_limit":          float64(7),
		"lease_store_present": true,
		"lease_ttl_seconds":   float64(60),
		"lease_acquired":      false,
		"lease_conflict":      true,
		"error_kind":          "sync_in_progress",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["duration_ms"].(float64); !ok {
		t.Fatalf("telemetry duration_ms = %#v, want number; payload=%#v", payload["duration_ms"], payload)
	}
	if strings.Contains(stderr, owner) {
		t.Fatalf("SyncWithLease telemetry leaked lease owner %q in %s", owner, stderr)
	}
}

func TestSyncWithLeaseTelemetryRecordsAcquiredFailure(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{}

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{LeaseStore: store})
		if !errors.Is(err, ErrRuntimeUnavailable) {
			t.Fatalf("SyncWithLease() err = %v, want ErrRuntimeUnavailable", err)
		}
	})

	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync_with_lease")
	for key, want := range map[string]any{
		"name":           "source_runtime.sync_with_lease",
		"status":         "failed",
		"runtime_id":     "runtime-a",
		"lease_acquired": true,
		"error_kind":     "runtime_unavailable",
	} {
		if got := payload[key]; got != want {
			t.Fatalf("telemetry %s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestSyncWithLeasePreservesNotFoundWhenAcquireRejectsMissingRuntime(t *testing.T) {
	service := New(nil, &runtimeStore{}, nil, nil)
	store := &stubLeaseStore{rejectNext: true}
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "missing-runtime"}, SyncWithLeaseOptions{LeaseStore: store})
	if !errors.Is(err, ports.ErrSourceRuntimeNotFound) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ports.ErrSourceRuntimeNotFound)
	}
}

func TestSyncWithLeaseAcquiresAndReleasesAroundSync(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{}
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{LeaseStore: store})
	// The inner Sync should fail with ErrRuntimeUnavailable because the
	// service has no store/appendlog, but the lease must still be acquired
	// and released around it; that is what this test asserts.
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ErrRuntimeUnavailable)
	}
	events := store.snapshotEvents()
	if len(events) < 2 {
		t.Fatalf("SyncWithLease() events = %#v, want at least acquire and release", events)
	}
	if events[0].verb != "acquire" || !events[0].acquired {
		t.Fatalf("first event = %#v, want successful acquire", events[0])
	}
	last := events[len(events)-1]
	if last.verb != "release" {
		t.Fatalf("last event = %#v, want release", last)
	}
}

func TestSyncWithLeaseRefusesSecondHolderWhileLeased(t *testing.T) {
	service := New(nil, nil, nil, nil)
	store := &stubLeaseStore{
		heldBy:    "holder-a",
		holdUntil: time.Now().Add(time.Minute),
	}
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
		LeaseStore: store,
		LeaseOwner: "holder-b",
	})
	if !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("SyncWithLease() err = %v, want ErrSyncInProgress", err)
	}
	events := store.snapshotEvents()
	for _, ev := range events {
		if ev.verb == "release" {
			t.Fatalf("SyncWithLease() released a lease it never acquired: %#v", events)
		}
	}
}

func TestStartLeaseRenewalStopsWhenSyncContextCancels(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	store := &stubLeaseStore{renewErr: errors.New("renew should not run after sync stops")}
	stopRenewal := startLeaseRenewal(parent, store, "runtime-a", "owner-a", time.Hour, func(error) {})

	cancel()

	if err := stopRenewal(); err != nil {
		t.Fatalf("stopRenewal() err = %v, want nil", err)
	}
}

func TestStartLeaseRenewalClassifiesLostOwnership(t *testing.T) {
	cancelled := make(chan struct{})
	var cancelOnce sync.Once
	store := &stubLeaseStore{}
	stopRenewal := startLeaseRenewal(context.Background(), store, "runtime-a", "owner-a", 10*time.Millisecond, func(error) {
		cancelOnce.Do(func() { close(cancelled) })
	})

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("lost lease did not cancel source-runtime work")
	}
	if err := stopRenewal(); !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("stopRenewal() error = %v, want %v", err, ports.ErrSourceRuntimeLeaseLost)
	}
}

func TestSyncWithLeasePreservesRenewalOwnershipLoss(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(renewalBlockingSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "renewal_blocking", TenantId: "tenant-a"},
	}}
	service := New(registry, runtimeStore, &appendLog{}, nil)
	leaseStore := &stubLeaseStore{rejectRenewal: true}

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
			LeaseStore: leaseStore,
			LeaseOwner: "owner-a",
			LeaseTTL:   30 * time.Millisecond,
		})
		if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
			t.Fatalf("SyncWithLease() error = %v, want %v", err, ports.ErrSourceRuntimeLeaseLost)
		}
	})
	payload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync_with_lease")
	if got := payload["status"]; got != "lease_lost" {
		t.Fatalf("telemetry status = %#v, want lease_lost; payload=%#v", got, payload)
	}
	if got := payload["error_kind"]; got != "lease_lost" {
		t.Fatalf("telemetry error_kind = %#v, want lease_lost; payload=%#v", got, payload)
	}
	syncPayload := sourceRuntimeTelemetryPayload(t, stderr, "source_runtime.sync")
	if got := syncPayload["status"]; got != "lease_lost" {
		t.Fatalf("inner sync telemetry status = %#v, want lease_lost; payload=%#v", got, syncPayload)
	}
	if got := syncPayload["error_kind"]; got != "lease_lost" {
		t.Fatalf("inner sync telemetry error_kind = %#v, want lease_lost; payload=%#v", got, syncPayload)
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime failure writes after renewal ownership loss = %d, want 0", runtimeStore.putCount)
	}
}

func TestSyncWithLeaseSuppressesFailureWriteWhenRenewalAuthorityIsUncertain(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(renewalBlockingSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "renewal_blocking", TenantId: "tenant-a"},
	}}
	service := New(registry, runtimeStore, &appendLog{}, nil)
	renewErr := errors.New("lease store unavailable")
	leaseStore := &stubLeaseStore{renewErr: renewErr}

	stderr := captureSourceRuntimeStderr(t, func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
			LeaseStore: leaseStore,
			LeaseOwner: "owner-a",
			LeaseTTL:   30 * time.Millisecond,
		})
		if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, renewErr) {
			t.Fatalf("SyncWithLease() error = %v, want lease loss preserving %v", err, renewErr)
		}
	})
	for _, operation := range []string{"source_runtime.sync_with_lease", "source_runtime.sync"} {
		payload := sourceRuntimeTelemetryPayload(t, stderr, operation)
		if got := payload["status"]; got != "lease_lost" {
			t.Fatalf("%s telemetry status = %#v, want lease_lost; payload=%#v", operation, got, payload)
		}
		if got := payload["error_kind"]; got != "lease_lost" {
			t.Fatalf("%s telemetry error_kind = %#v, want lease_lost; payload=%#v", operation, got, payload)
		}
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime failure writes after ambiguous renewal failure = %d, want 0", runtimeStore.putCount)
	}
}

func TestSyncWithLeaseSuppressesFailureWriteWhenSourceAndRenewalFailConcurrently(t *testing.T) {
	sourceErr := errors.New("source read failed")
	renewErr := errors.New("lease store unavailable")
	readStarted := make(chan struct{})
	readRelease := make(chan struct{})
	registry, err := sourcecdk.NewRegistry(coordinatedFailureSource{
		err: sourceErr, readStarted: readStarted, readRelease: readRelease,
	})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "coordinated_failure", TenantId: "tenant-a"},
	}}
	service := New(registry, runtimeStore, &appendLog{}, nil)
	renewStarted := make(chan struct{})
	leaseStore := &stubLeaseStore{
		renewErr: renewErr, renewStarted: renewStarted, renewWaitForCancel: true,
	}
	result := make(chan error, 1)
	go func() {
		_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
			LeaseStore: leaseStore,
			LeaseOwner: "owner-a",
			LeaseTTL:   10 * time.Millisecond,
		})
		result <- err
	}()

	select {
	case <-readStarted:
	case <-time.After(time.Second):
		t.Fatal("source read did not start")
	}
	select {
	case <-renewStarted:
	case <-time.After(time.Second):
		t.Fatal("lease renewal did not start")
	}
	close(readRelease)
	select {
	case err := <-result:
		if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, renewErr) {
			t.Fatalf("SyncWithLease() error = %v, want lease loss preserving %v", err, renewErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SyncWithLease() did not finish after concurrent source and renewal failures")
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime failure writes after concurrent source and renewal failures = %d, want 0", runtimeStore.putCount)
	}
}

func TestSyncWithLeaseFailsClosedWhenRenewalTaskPanics(t *testing.T) {
	registry, err := sourcecdk.NewRegistry(renewalBlockingSource{})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtimeStore := &runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
		"runtime-a": {Id: "runtime-a", SourceId: "renewal_blocking", TenantId: "tenant-a"},
	}}
	service := New(registry, runtimeStore, &appendLog{}, nil)
	leaseStore := &stubLeaseStore{renewPanic: true}

	_, err = service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{
		LeaseStore: leaseStore,
		LeaseOwner: "owner-a",
		LeaseTTL:   10 * time.Millisecond,
	})
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, panicsafe.ErrTaskPanicked) {
		t.Fatalf("SyncWithLease() error = %v, want lease loss preserving renewal panic", err)
	}
	if runtimeStore.putCount != 0 {
		t.Fatalf("runtime failure writes after renewal panic = %d, want 0", runtimeStore.putCount)
	}
}

func TestLeaseRenewalIntervalCapsLongTTL(t *testing.T) {
	if got := LeaseRenewalInterval(time.Minute); got != 30*time.Second {
		t.Fatalf("LeaseRenewalInterval(1m) = %s, want 30s", got)
	}
	if got := LeaseRenewalInterval(DefaultLeaseTTL); got != LeaseRenewalMaxInterval {
		t.Fatalf("LeaseRenewalInterval(default) = %s, want %s", got, LeaseRenewalMaxInterval)
	}
}

func TestAcquireRenewableLeaseReturnsConflictWithoutRelease(t *testing.T) {
	store := &stubLeaseStore{rejectNext: true}
	workCtx, release, acquired, err := AcquireRenewableLease(context.Background(), store, "runtime-a", "owner-a", time.Minute)
	if err != nil || acquired || workCtx == nil {
		t.Fatalf("AcquireRenewableLease() = (%v, %t, %v), want context, false, nil", workCtx, acquired, err)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v, want nil", err)
	}
	events := store.snapshotEvents()
	if len(events) != 1 || events[0].verb != "acquire" || events[0].acquired {
		t.Fatalf("events = %#v, want one rejected acquire and no release", events)
	}
}

func TestAcquireRenewableLeaseCancelsWorkAndReleasesAfterRenewalFailure(t *testing.T) {
	renewErr := errors.New("renew failed")
	store := &stubLeaseStore{renewErr: renewErr}
	workCtx, release, acquired, err := AcquireRenewableLease(context.Background(), store, "runtime-a", "owner-a", 30*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("AcquireRenewableLease() = (%t, %v), want true, nil", acquired, err)
	}
	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("renewal failure did not cancel the work context")
	}
	if cause := context.Cause(workCtx); !errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(cause, renewErr) {
		t.Fatalf("renewal failure cause = %v, want lease loss preserving %v", cause, renewErr)
	}
	if err := release(); !errors.Is(err, renewErr) || !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("release() error = %v, want lease loss preserving %v", err, renewErr)
	}
	if err := release(); !errors.Is(err, renewErr) || !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("second release() error = %v, want stable lease loss preserving %v", err, renewErr)
	}
	events := store.snapshotEvents()
	if len(events) < 2 || events[0].verb != "acquire" || events[len(events)-1].verb != "release" {
		t.Fatalf("events = %#v, want acquire followed by release", events)
	}
}

func TestAcquireRenewableLeaseShutdownClassifiesInFlightRenewalResult(t *testing.T) {
	genuineErr := errors.New("lease store unavailable")
	for _, test := range []struct {
		name          string
		renewErr      error
		wantLeaseLost bool
	}{
		{name: "cancellation from stop", renewErr: context.Canceled},
		{name: "genuine store failure", renewErr: genuineErr, wantLeaseLost: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			renewStarted := make(chan struct{})
			store := &stubLeaseStore{
				renewErr: test.renewErr, renewStarted: renewStarted, renewWaitForCancel: true,
			}
			workCtx, release, acquired, err := AcquireRenewableLease(context.Background(), store, "runtime-a", "owner-a", 10*time.Millisecond)
			if err != nil || !acquired {
				t.Fatalf("AcquireRenewableLease() = (%t, %v), want true, nil", acquired, err)
			}
			select {
			case <-renewStarted:
			case <-time.After(time.Second):
				t.Fatal("lease renewal did not start")
			}
			err = release()
			if test.wantLeaseLost {
				if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, genuineErr) {
					t.Fatalf("release() error = %v, want lease loss preserving %v", err, genuineErr)
				}
				if cause := context.Cause(workCtx); !errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) {
					t.Fatalf("work cancellation cause = %v, want lease loss", cause)
				}
			} else if err != nil {
				t.Fatalf("release() error = %v, want nil for stop cancellation", err)
			}
		})
	}
}

func TestAcquireRenewableLeaseFailsClosedWhenRenewalTaskPanics(t *testing.T) {
	store := &stubLeaseStore{renewPanic: true}
	workCtx, release, acquired, err := AcquireRenewableLease(context.Background(), store, "runtime-a", "owner-a", 10*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("AcquireRenewableLease() = (%t, %v), want true, nil", acquired, err)
	}
	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("renewal panic did not cancel work")
	}
	if cause := context.Cause(workCtx); !errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(cause, panicsafe.ErrTaskPanicked) {
		t.Fatalf("work cancellation cause = %v, want lease loss preserving renewal panic", cause)
	}
	if err := release(); !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) || !errors.Is(err, panicsafe.ErrTaskPanicked) {
		t.Fatalf("release() error = %v, want lease loss preserving renewal panic", err)
	}
}

func TestAcquireRenewableLeaseClassifiesLostOwnership(t *testing.T) {
	store := &stubLeaseStore{}
	workCtx, release, acquired, err := AcquireRenewableLease(context.Background(), store, "runtime-a", "owner-a", 30*time.Millisecond)
	if err != nil || !acquired {
		t.Fatalf("AcquireRenewableLease() = (%t, %v), want true, nil", acquired, err)
	}
	store.mu.Lock()
	store.heldBy = "successor"
	store.mu.Unlock()

	select {
	case <-workCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("lost lease did not cancel renewable work")
	}
	if cause := context.Cause(workCtx); !errors.Is(cause, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("renewable work cancellation cause = %v, want %v", cause, ports.ErrSourceRuntimeLeaseLost)
	}
	if err := release(); !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("release() error = %v, want %v", err, ports.ErrSourceRuntimeLeaseLost)
	}
}

func TestSyncWithLeaseSerializesConcurrentCallers(t *testing.T) {
	store := &stubLeaseStore{}
	service := New(nil, nil, nil, nil)
	var (
		successCount  atomic.Int64
		conflictCount atomic.Int64
		wg            sync.WaitGroup
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-shared"}, SyncWithLeaseOptions{
				LeaseStore: store,
				LeaseOwner: defaultOwnerFromIndex(i),
				LeaseTTL:   time.Second,
			})
			switch {
			case errors.Is(err, ErrSyncInProgress):
				conflictCount.Add(1)
			case errors.Is(err, ErrRuntimeUnavailable):
				// inner Sync stub is unavailable; success path from the lease
				// perspective.
				successCount.Add(1)
			default:
				t.Errorf("unexpected SyncWithLease err = %v", err)
			}
		}(i)
	}
	wg.Wait()
	if successCount.Load()+conflictCount.Load() != 8 {
		t.Fatalf("success=%d conflict=%d, want sum=8", successCount.Load(), conflictCount.Load())
	}
	if successCount.Load() == 0 {
		t.Fatalf("no caller acquired the lease in 8 concurrent attempts; events=%#v", store.snapshotEvents())
	}
}

func defaultOwnerFromIndex(i int) string {
	return "owner-" + time.Now().Format("150405.000000") + ":" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	negative := false
	if i < 0 {
		negative = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func captureSourceRuntimeStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stderr: %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
	}()
	fn()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := telemetry.FlushWideEvents(ctx); err != nil {
		t.Fatalf("flush telemetry: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(payload)
}

func sourceRuntimeTelemetryPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "span_end" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry span_end %q not found in stderr: %s", name, stderr)
	return nil
}

func sourceRuntimeTelemetryEventPayload(t *testing.T, stderr string, name string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(lines[i]), &payload); err != nil {
			t.Fatalf("unmarshal telemetry payload %q: %v", lines[i], err)
		}
		if payload["kind"] == "event" && payload["name"] == name {
			return payload
		}
	}
	t.Fatalf("telemetry event %q not found in stderr: %s", name, stderr)
	return nil
}
