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
	"github.com/writer/cerebro/internal/ports"
)

type leaseEvent struct {
	verb     string
	owner    string
	acquired bool
}

type stubLeaseStore struct {
	mu sync.Mutex

	heldBy     string
	holdUntil  time.Time
	rejectNext bool

	acquireErr error
	renewErr   error
	releaseErr error

	events []leaseEvent
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
	s.heldBy = owner
	s.holdUntil = now.Add(ttl)
	_ = runtimeID
	s.events = append(s.events, leaseEvent{verb: "acquire", owner: owner, acquired: true})
	return true, nil
}

func (s *stubLeaseStore) RenewSourceRuntimeLease(_ context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewErr != nil {
		return false, s.renewErr
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

func (s *stubLeaseStore) snapshotEvents() []leaseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]leaseEvent, len(s.events))
	copy(out, s.events)
	return out
}

func TestSyncWithLeaseFallsThroughWhenLeaseStoreIsNil(t *testing.T) {
	service := New(nil, nil, nil, nil)
	_, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: "runtime-a"}, SyncWithLeaseOptions{})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("SyncWithLease() err = %v, want %v", err, ErrRuntimeUnavailable)
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
	stopRenewal := startLeaseRenewal(parent, store, "runtime-a", "owner-a", time.Hour, func() {})

	cancel()

	if err := stopRenewal(); err != nil {
		t.Fatalf("stopRenewal() err = %v, want nil", err)
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
	if err := release(); !errors.Is(err, renewErr) {
		t.Fatalf("release() error = %v, want renewal error %v", err, renewErr)
	}
	if err := release(); !errors.Is(err, renewErr) {
		t.Fatalf("second release() error = %v, want stable renewal error %v", err, renewErr)
	}
	events := store.snapshotEvents()
	if len(events) < 2 || events[0].verb != "acquire" || events[len(events)-1].verb != "release" {
		t.Fatalf("events = %#v, want acquire followed by release", events)
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
