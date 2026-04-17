package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/health"
	integrationtest "github.com/writer/cerebro/internal/testutil/integration"
	"github.com/writer/cerebro/internal/webhooks"
)

type scriptedGraphWriterLeaseResult struct {
	snapshot graphWriterLeaseSnapshot
	writer   bool
	err      error
}

type scriptedGraphWriterLeaseStore struct {
	mu         sync.Mutex
	tryAcquire []scriptedGraphWriterLeaseResult
	renew      []scriptedGraphWriterLeaseResult
	current    graphWriterLeaseSnapshot
	currentErr error
	closeCalls int
}

func (s *scriptedGraphWriterLeaseStore) TryAcquire(_ context.Context, _, _ string, _ time.Duration, _ time.Time) (graphWriterLeaseSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tryAcquire) == 0 {
		return s.current, false, nil
	}
	result := s.tryAcquire[0]
	s.tryAcquire = s.tryAcquire[1:]
	s.current = result.snapshot
	return result.snapshot, result.writer, result.err
}

func (s *scriptedGraphWriterLeaseStore) Renew(_ context.Context, _, _ string, _ time.Duration, _ time.Time) (graphWriterLeaseSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.renew) == 0 {
		return s.current, false, nil
	}
	result := s.renew[0]
	s.renew = s.renew[1:]
	s.current = result.snapshot
	return result.snapshot, result.writer, result.err
}

func (s *scriptedGraphWriterLeaseStore) Current(_ context.Context, _ string, _ time.Time) (graphWriterLeaseSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.currentErr
}

func (s *scriptedGraphWriterLeaseStore) Release(_ context.Context, _, _ string) error {
	return nil
}

func (s *scriptedGraphWriterLeaseStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCalls++
	return nil
}

func TestGraphWriterLeaseManagerStopAfterFailedSync(t *testing.T) {
	store := &scriptedGraphWriterLeaseStore{
		tryAcquire: []scriptedGraphWriterLeaseResult{{err: errors.New("sync failed")}},
	}
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})

	if err := manager.sync(context.Background()); err == nil {
		t.Fatal("expected sync to fail")
		return
	}

	done := make(chan struct{})
	go func() {
		_ = manager.stop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manager.stop() timed out after failed sync")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closeCalls != 1 {
		t.Fatalf("Close() calls = %d, want 1", store.closeCalls)
	}
}

func TestMutateSecurityGraphRequiresWriterLease(t *testing.T) {
	store := newInMemoryGraphWriterLeaseStore()
	now := time.Now().UTC()
	if _, acquired, err := store.TryAcquire(context.Background(), "security_graph_writer", "other", time.Minute, now); err != nil || !acquired {
		t.Fatalf("seed lease = acquired %v err %v", acquired, err)
	}
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})
	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("sync() error = %v", err)
	}

	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
		},
		graphWriterLease: manager,
	}
	application.setSecurityGraph(graph.New())

	_, err := application.MutateSecurityGraph(context.Background(), func(g *graph.Graph) error {
		g.AddNode(&graph.Node{ID: "service:test", Kind: graph.NodeKindService})
		return nil
	})
	if !errors.Is(err, cerrors.ErrForbidden) {
		t.Fatalf("MutateSecurityGraph() error = %v, want forbidden", err)
	}
}

func TestMutateSecurityGraphSucceedsWithWriterLease(t *testing.T) {
	store := newInMemoryGraphWriterLeaseStore()
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})
	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("sync() error = %v", err)
	}

	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
		},
		graphWriterLease: manager,
	}
	application.setSecurityGraph(graph.New())

	mutated, err := application.MutateSecurityGraph(context.Background(), func(g *graph.Graph) error {
		g.AddNode(&graph.Node{ID: "service:test", Kind: graph.NodeKindService})
		return nil
	})
	if err != nil {
		t.Fatalf("MutateSecurityGraph() error = %v", err)
	}
	if _, ok := mutated.GetNode("service:test"); !ok {
		t.Fatal("expected mutated graph to contain new node")
	}
}

func TestInitTapGraphConsumerDefersWithoutWriterLease(t *testing.T) {
	store := newInMemoryGraphWriterLeaseStore()
	now := time.Now().UTC()
	if _, acquired, err := store.TryAcquire(context.Background(), "security_graph_writer", "other", time.Minute, now); err != nil || !acquired {
		t.Fatalf("seed lease = acquired %v err %v", acquired, err)
	}
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})
	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("sync() error = %v", err)
	}

	var logs bytes.Buffer
	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
			NATSConsumerEnabled:     true,
		},
		Logger:           slog.New(slog.NewTextHandler(&logs, nil)),
		graphWriterLease: manager,
	}

	application.initTapGraphConsumer(context.Background())
	if application.currentTapConsumer() != nil {
		t.Fatal("expected tap consumer initialization to defer without writer lease")
	}
	if got := logs.String(); !strings.Contains(got, "deferring tap graph consumer until graph writer lease is acquired") {
		t.Fatalf("initTapGraphConsumer() log = %q, want accurate deferral message", got)
	}
	if strings.Contains(logs.String(), "starting tap graph consumer in follower replica mode") {
		t.Fatalf("initTapGraphConsumer() log = %q, should not claim the follower consumer started", logs.String())
	}
}

func TestHandleGraphWriterLeaseAcquiredPersistsWarmGraphAndEmitsEvents(t *testing.T) {
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    t.TempDir(),
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("NewGraphPersistenceStore() error = %v", err)
	}

	publisher := &captureEventPublisher{}
	hooks := webhooks.NewServiceForTesting()
	hooks.SetEventPublisher(publisher)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	warm := graph.New()
	warm.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})
	warm.SetMetadata(graph.Metadata{
		BuiltAt:       time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
		NodeCount:     warm.NodeCount(),
		EdgeCount:     warm.EdgeCount(),
		BuildDuration: 1500 * time.Millisecond,
	})

	application := &App{
		Config: &Config{
			GraphSchemaValidationMode: string(graph.SchemaValidationEnforce),
		},
		Logger:               logger,
		Webhooks:             hooks,
		GraphSnapshots:       store,
		SecurityGraphBuilder: builders.NewBuilder(nil, logger),
		graphReady:           make(chan struct{}),
	}
	application.setSecurityGraph(warm)
	close(application.graphReady)

	application.handleGraphWriterLeaseAcquired(context.Background())

	done := make(chan struct{})
	go func() {
		application.graphWriterLeaseTransitionWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for graph writer promotion")
	}

	promoted := application.CurrentSecurityGraph()
	if promoted == warm {
		t.Fatal("expected warm graph promotion to clone the live graph before activation")
	}
	if got := warm.SchemaValidationMode(); got != graph.SchemaValidationWarn {
		t.Fatalf("warm graph schema validation mode = %q, want %q", got, graph.SchemaValidationWarn)
	}
	if got := promoted.SchemaValidationMode(); got != graph.SchemaValidationEnforce {
		t.Fatalf("promoted graph schema validation mode = %q, want %q", got, graph.SchemaValidationEnforce)
	}

	records, err := store.ListGraphSnapshotRecords()
	if err != nil {
		t.Fatalf("ListGraphSnapshotRecords() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one persisted snapshot after warm promotion, got %d", len(records))
	}

	events := publisher.all()
	if len(events) != 2 {
		t.Fatalf("expected two emitted events after warm promotion, got %d", len(events))
	}
	if events[0].Type != webhooks.EventGraphRebuilt {
		t.Fatalf("expected first event type %q, got %q", webhooks.EventGraphRebuilt, events[0].Type)
	}
	if events[1].Type != webhooks.EventGraphMutated {
		t.Fatalf("expected second event type %q, got %q", webhooks.EventGraphMutated, events[1].Type)
	}
}

func TestPromoteOrRebuildSecurityGraphUnlocksOnPanic(t *testing.T) {
	warm := graph.New()
	warm.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "payments"})

	application := &App{
		Config: &Config{
			WorkloadScanStateFile: string([]byte{0}),
		},
	}
	application.setSecurityGraph(warm)

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected promoteOrRebuildSecurityGraph() to panic")
			return
		}
		if !application.graphUpdateMu.TryLock() {
			t.Fatal("expected graphUpdateMu to be unlocked after panic")
		}
		application.graphUpdateMu.Unlock()
	}()

	_ = application.promoteOrRebuildSecurityGraph(context.Background())
}

func TestPromoteOrRebuildSecurityGraphPromotesPersistedSnapshot(t *testing.T) {
	persisted := graph.New()
	persisted.AddNode(&graph.Node{ID: "service:persisted", Kind: graph.NodeKindService, Name: "persisted"})
	persisted.BuildIndex()

	application := &App{
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		GraphSnapshots: mustPersistToolGraph(t, persisted),
	}

	if err := application.promoteOrRebuildSecurityGraph(context.Background()); err != nil {
		t.Fatalf("promoteOrRebuildSecurityGraph() error = %v", err)
	}

	current := application.CurrentSecurityGraph()
	if current == nil {
		t.Fatal("expected promoted graph from persisted snapshot")
		return
	}
	if _, ok := current.GetNode("service:persisted"); !ok {
		t.Fatal("expected persisted node after promotion")
	}
}

func TestTapGraphConsumerDurableUsesConfiguredName(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseOwnerID: "replica-host:4321",
			NATSConsumerDurable:     "cerebro_graph_builder",
		},
	}

	if got := application.tapGraphConsumerDurable(); got != "cerebro_graph_builder" {
		t.Fatalf("tapGraphConsumerDurable() = %q, want cerebro_graph_builder", got)
	}
}

func TestTapGraphConsumerSubjectsNormalizeConfiguredSources(t *testing.T) {
	application := &App{
		Config: &Config{
			NATSConsumerSubjects: []string{
				" ensemble.tap.> ",
				"aws.cloudtrail.>",
				"ensemble.tap.>",
			},
		},
	}

	got := application.tapGraphConsumerSubjects()
	want := []string{"ensemble.tap.>", "aws.cloudtrail.>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tapGraphConsumerSubjects() = %#v, want %#v", got, want)
	}
}

func TestTapGraphConsumerSubjectsRetainConfiguredSourcesForWriters(t *testing.T) {
	application := &App{
		Config: &Config{
			NATSConsumerSubjects: []string{
				"ensemble.tap.>",
				"aws.cloudtrail.>",
			},
		},
	}

	got := application.tapGraphConsumerSubjects()
	want := []string{"ensemble.tap.>", "aws.cloudtrail.>"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tapGraphConsumerSubjects() = %#v, want %#v", got, want)
	}
}

func TestHandleGraphWriterLeaseLostLogsConsumerStopUntilReacquired(t *testing.T) {
	var logs bytes.Buffer
	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
			NATSConsumerEnabled:     true,
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	application.handleGraphWriterLeaseLost(context.Background())

	if got := logs.String(); !strings.Contains(got, "tap graph consumer stopped until the lease is reacquired") {
		t.Fatalf("handleGraphWriterLeaseLost() log = %q, want stop-until-reacquired message", got)
	}
}

func TestNATSGraphWriterLeaseStoreAcquireRenewAndFailover(t *testing.T) {
	natsURL := integrationtest.StartJetStreamServer(t)
	cfgA := &Config{
		NATSJetStreamEnabled:        true,
		NATSJetStreamURLs:           []string{natsURL},
		NATSJetStreamConnectTimeout: 5 * time.Second,
		NATSJetStreamAuthMode:       "none",
		GraphWriterLeaseBucket:      "CEREBRO_GRAPH_LEASES_TEST",
		GraphWriterLeaseName:        "security_graph_writer",
		GraphWriterLeaseOwnerID:     "writer-a",
	}
	cfgB := &Config{
		NATSJetStreamEnabled:        true,
		NATSJetStreamURLs:           []string{natsURL},
		NATSJetStreamConnectTimeout: 5 * time.Second,
		NATSJetStreamAuthMode:       "none",
		GraphWriterLeaseBucket:      "CEREBRO_GRAPH_LEASES_TEST",
		GraphWriterLeaseName:        "security_graph_writer",
		GraphWriterLeaseOwnerID:     "writer-b",
	}
	storeA, err := newNATSGraphWriterLeaseStore(cfgA)
	if err != nil {
		t.Fatalf("newNATSGraphWriterLeaseStore(cfgA) error = %v", err)
	}
	defer func() { _ = storeA.Close() }()
	storeB, err := newNATSGraphWriterLeaseStore(cfgB)
	if err != nil {
		t.Fatalf("newNATSGraphWriterLeaseStore(cfgB) error = %v", err)
	}
	defer func() { _ = storeB.Close() }()

	now := time.Date(2026, time.March, 18, 0, 0, 0, 0, time.UTC)
	leaseA, acquired, err := storeA.TryAcquire(context.Background(), cfgA.GraphWriterLeaseName, cfgA.GraphWriterLeaseOwnerID, 15*time.Second, now)
	if err != nil || !acquired {
		t.Fatalf("storeA.TryAcquire() acquired %v err %v", acquired, err)
	}
	if leaseA.OwnerID != cfgA.GraphWriterLeaseOwnerID {
		t.Fatalf("leaseA owner = %q, want %q", leaseA.OwnerID, cfgA.GraphWriterLeaseOwnerID)
	}

	leaseB, acquired, err := storeB.TryAcquire(context.Background(), cfgB.GraphWriterLeaseName, cfgB.GraphWriterLeaseOwnerID, 15*time.Second, now)
	if err != nil {
		t.Fatalf("storeB.TryAcquire() error = %v", err)
	}
	if acquired {
		t.Fatal("expected second owner acquisition to fail while first lease is active")
	}
	if leaseB.OwnerID != cfgA.GraphWriterLeaseOwnerID {
		t.Fatalf("leaseB owner = %q, want %q", leaseB.OwnerID, cfgA.GraphWriterLeaseOwnerID)
	}

	renewed, acquired, err := storeA.Renew(context.Background(), cfgA.GraphWriterLeaseName, cfgA.GraphWriterLeaseOwnerID, 15*time.Second, now.Add(5*time.Second))
	if err != nil || !acquired {
		t.Fatalf("storeA.Renew() acquired %v err %v", acquired, err)
	}
	if !renewed.LeaseUntil.After(now.Add(15 * time.Second)) {
		t.Fatalf("renewed lease_until = %s, want after %s", renewed.LeaseUntil, now.Add(15*time.Second))
	}

	failedOver, acquired, err := storeB.TryAcquire(context.Background(), cfgB.GraphWriterLeaseName, cfgB.GraphWriterLeaseOwnerID, 15*time.Second, now.Add(30*time.Second))
	if err != nil || !acquired {
		t.Fatalf("storeB.TryAcquire(failover) acquired %v err %v", acquired, err)
	}
	if failedOver.OwnerID != cfgB.GraphWriterLeaseOwnerID {
		t.Fatalf("failedOver owner = %q, want %q", failedOver.OwnerID, cfgB.GraphWriterLeaseOwnerID)
	}
}

func TestNATSGraphWriterLeaseStoreReleaseUsesRevisionGuard(t *testing.T) {
	natsURL := integrationtest.StartJetStreamServer(t)
	cfgA := &Config{
		NATSJetStreamEnabled:        true,
		NATSJetStreamURLs:           []string{natsURL},
		NATSJetStreamConnectTimeout: 5 * time.Second,
		NATSJetStreamAuthMode:       "none",
		GraphWriterLeaseBucket:      "CEREBRO_GRAPH_LEASES_RELEASE_GUARD",
		GraphWriterLeaseName:        "security_graph_writer",
		GraphWriterLeaseOwnerID:     "writer-a",
	}
	cfgB := &Config{
		NATSJetStreamEnabled:        true,
		NATSJetStreamURLs:           []string{natsURL},
		NATSJetStreamConnectTimeout: 5 * time.Second,
		NATSJetStreamAuthMode:       "none",
		GraphWriterLeaseBucket:      "CEREBRO_GRAPH_LEASES_RELEASE_GUARD",
		GraphWriterLeaseName:        "security_graph_writer",
		GraphWriterLeaseOwnerID:     "writer-b",
	}
	storeA, err := newNATSGraphWriterLeaseStore(cfgA)
	if err != nil {
		t.Fatalf("newNATSGraphWriterLeaseStore(cfgA) error = %v", err)
	}
	defer func() { _ = storeA.Close() }()
	storeB, err := newNATSGraphWriterLeaseStore(cfgB)
	if err != nil {
		t.Fatalf("newNATSGraphWriterLeaseStore(cfgB) error = %v", err)
	}
	defer func() { _ = storeB.Close() }()

	now := time.Date(2026, time.March, 18, 0, 10, 0, 0, time.UTC)
	if _, acquired, err := storeA.TryAcquire(context.Background(), cfgA.GraphWriterLeaseName, cfgA.GraphWriterLeaseOwnerID, 5*time.Second, now); err != nil || !acquired {
		t.Fatalf("storeA.TryAcquire() acquired %v err %v", acquired, err)
	}

	natsGraphWriterLeaseReleaseBeforeDeleteHook = func() {
		if _, acquired, err := storeB.TryAcquire(context.Background(), cfgB.GraphWriterLeaseName, cfgB.GraphWriterLeaseOwnerID, 5*time.Second, now.Add(10*time.Second)); err != nil || !acquired {
			t.Fatalf("storeB.TryAcquire() during release acquired %v err %v", acquired, err)
		}
	}
	defer func() {
		natsGraphWriterLeaseReleaseBeforeDeleteHook = nil
	}()

	if err := storeA.Release(context.Background(), cfgA.GraphWriterLeaseName, cfgA.GraphWriterLeaseOwnerID); err != nil {
		t.Fatalf("storeA.Release() error = %v", err)
	}

	current, err := storeB.Current(context.Background(), cfgB.GraphWriterLeaseName, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("storeB.Current() error = %v", err)
	}
	if current.OwnerID != cfgB.GraphWriterLeaseOwnerID {
		t.Fatalf("current owner = %q, want %q", current.OwnerID, cfgB.GraphWriterLeaseOwnerID)
	}
}

func TestGraphWriterLeaseHealthCheckHidesRemoteHolderIdentity(t *testing.T) {
	store := newInMemoryGraphWriterLeaseStore()
	now := time.Now().UTC()
	if _, acquired, err := store.TryAcquire(context.Background(), "security_graph_writer", "remote-host:1234", time.Minute, now); err != nil || !acquired {
		t.Fatalf("seed lease = acquired %v err %v", acquired, err)
	}
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})
	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("sync() error = %v", err)
	}

	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
		},
		graphWriterLease: manager,
	}

	result := application.graphWriterLeaseHealthCheck()(context.Background())
	if result.Message != "graph writer lease held remotely" {
		t.Fatalf("health message = %q, want generic remote-holder message", result.Message)
	}
	if strings.Contains(result.Message, "remote-host:1234") {
		t.Fatalf("health message leaked lease holder identity: %q", result.Message)
	}
}

func TestGraphWriterLeaseHealthCheckHidesRawLeaseErrors(t *testing.T) {
	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
		},
		graphWriterLease: &graphWriterLeaseManager{
			status: GraphWriterLeaseStatus{
				Enabled:   true,
				Role:      GraphWriterRoleFollower,
				LastError: "nats://internal-broker:4222 bucket CEREBRO_GRAPH_LEASES auth failed",
			},
		},
	}

	result := application.graphWriterLeaseHealthCheck()(context.Background())
	if result.Status != health.StatusDegraded {
		t.Fatalf("health status = %q, want degraded", result.Status)
	}
	if result.Message != "graph writer lease unavailable" {
		t.Fatalf("health message = %q, want generic lease-unavailable message", result.Message)
	}
	if strings.Contains(result.Message, "internal-broker") || strings.Contains(result.Message, "CEREBRO_GRAPH_LEASES") {
		t.Fatalf("health message leaked raw lease error: %q", result.Message)
	}
}

func TestGraphWriterLeaseManagerSerializesTransitionCallbacks(t *testing.T) {
	store := &scriptedGraphWriterLeaseStore{
		tryAcquire: []scriptedGraphWriterLeaseResult{
			{
				snapshot: graphWriterLeaseSnapshot{
					Name:       "security_graph_writer",
					OwnerID:    "self",
					LeaseUntil: time.Now().UTC().Add(time.Minute),
				},
				writer: true,
			},
			{
				snapshot: graphWriterLeaseSnapshot{
					Name:       "security_graph_writer",
					OwnerID:    "self",
					LeaseUntil: time.Now().UTC().Add(time.Minute),
				},
				writer: true,
			},
		},
		renew: []scriptedGraphWriterLeaseResult{
			{
				snapshot: graphWriterLeaseSnapshot{
					Name:       "security_graph_writer",
					OwnerID:    "other",
					LeaseUntil: time.Now().UTC().Add(time.Minute),
				},
				writer: false,
			},
		},
	}

	callbacks := make(chan string, 3)
	releaseLose := make(chan struct{})
	var (
		acquireCount int
		acquireMu    sync.Mutex
		releaseOnce  sync.Once
	)
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{
		onAcquire: func(context.Context) {
			acquireMu.Lock()
			acquireCount++
			acquireMu.Unlock()
			callbacks <- "acquire"
		},
		onLose: func(context.Context) {
			callbacks <- "lose"
			<-releaseLose
		},
	})
	defer func() {
		releaseOnce.Do(func() { close(releaseLose) })
		_ = manager.stop(context.Background())
	}()

	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("initial sync() error = %v", err)
	}
	if got := <-callbacks; got != "acquire" {
		t.Fatalf("first callback = %q, want acquire", got)
	}

	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("loss sync() error = %v", err)
	}
	if got := <-callbacks; got != "lose" {
		t.Fatalf("second callback = %q, want lose", got)
	}

	reacquireDone := make(chan error, 1)
	go func() {
		reacquireDone <- manager.sync(context.Background())
	}()

	reacquireReturned := false
	select {
	case got := <-callbacks:
		t.Fatalf("reacquire callback %q ran before delayed lose completed", got)
	case err := <-reacquireDone:
		if err != nil {
			t.Fatalf("reacquire sync() error = %v", err)
		}
		reacquireReturned = true
	case <-time.After(100 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseLose) })

	if !reacquireReturned {
		select {
		case err := <-reacquireDone:
			if err != nil {
				t.Fatalf("reacquire sync() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for reacquire sync")
		}
	}

	select {
	case got := <-callbacks:
		if got != "acquire" {
			t.Fatalf("final callback = %q, want acquire", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reacquire callback")
	}

	acquireMu.Lock()
	defer acquireMu.Unlock()
	if acquireCount != 2 {
		t.Fatalf("acquire callback count = %d, want 2", acquireCount)
	}
}

func TestCloseWaitsForGraphWriterLeaseTransitionWork(t *testing.T) {
	application := &App{}
	application.graphWriterLeaseTransitionWG.Add(1)

	done := make(chan error, 1)
	go func() {
		done <- application.Close()
	}()

	select {
	case err := <-done:
		t.Fatalf("Close() returned before transition work finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	application.graphWriterLeaseTransitionWG.Done()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Close() to finish")
	}
}

func TestRequireGraphWriterLeaseHidesRemoteHolderIdentity(t *testing.T) {
	store := newInMemoryGraphWriterLeaseStore()
	now := time.Now().UTC()
	if _, acquired, err := store.TryAcquire(context.Background(), "security_graph_writer", "remote-host:1234", time.Minute, now); err != nil || !acquired {
		t.Fatalf("seed lease = acquired %v err %v", acquired, err)
	}
	manager := newGraphWriterLeaseManager(slog.Default(), store, "security_graph_writer", "self", time.Minute, 5*time.Second, graphWriterLeaseCallbacks{})
	if err := manager.sync(context.Background()); err != nil {
		t.Fatalf("sync() error = %v", err)
	}

	application := &App{
		Config: &Config{
			GraphWriterLeaseEnabled: true,
			GraphWriterLeaseName:    "security_graph_writer",
			GraphWriterLeaseOwnerID: "self",
		},
		graphWriterLease: manager,
	}

	err := application.requireGraphWriterLease("mutate security graph")
	if !errors.Is(err, cerrors.ErrForbidden) {
		t.Fatalf("requireGraphWriterLease() error = %v, want forbidden", err)
	}
	if strings.Contains(err.Error(), "remote-host:1234") {
		t.Fatalf("requireGraphWriterLease() leaked lease holder identity: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "graph writer lease not held by this process") {
		t.Fatalf("requireGraphWriterLease() = %q, want generic denial text", err.Error())
	}
}
