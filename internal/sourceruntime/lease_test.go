package sourceruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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
