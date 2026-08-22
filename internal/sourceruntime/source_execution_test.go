package sourceruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

type fencedLedgerRuntimeStore struct {
	*ledgerRuntimeStore
	mu         sync.Mutex
	generation uint64
	owner      string
	expiresAt  time.Time
}

func (s *fencedLedgerRuntimeStore) AcquireSourceRuntimeLease(_ context.Context, _ string, owner string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
	s.owner = owner
	s.expiresAt = time.Now().UTC().Add(ttl)
	return true, nil
}

func (s *fencedLedgerRuntimeStore) RenewSourceRuntimeLease(_ context.Context, _ string, owner string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != owner {
		return false, nil
	}
	s.expiresAt = time.Now().UTC().Add(ttl)
	return true, nil
}

func (s *fencedLedgerRuntimeStore) ReleaseSourceRuntimeLease(_ context.Context, _ string, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == owner {
		s.owner = ""
	}
	return nil
}

func (s *fencedLedgerRuntimeStore) ReadSourceRuntimeLeaseFence(_ context.Context, _ string, owner string) (ports.SourceRuntimeLeaseFence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner != owner || s.generation == 0 {
		return ports.SourceRuntimeLeaseFence{}, errors.New("lease fence is not owned")
	}
	return ports.SourceRuntimeLeaseFence{Owner: owner, Generation: s.generation, ExpiresAt: s.expiresAt}, nil
}

func (s *fencedLedgerRuntimeStore) CommitSourceRuntimePageFenced(ctx context.Context, attemptID string, runtime *cerebrov1.SourceRuntime, fence ports.SourceRuntimeLeaseFence) error {
	s.mu.Lock()
	valid := s.owner == fence.Owner && s.generation == fence.Generation && s.expiresAt.After(time.Now().UTC())
	s.mu.Unlock()
	if !valid {
		return ports.ErrSourceRuntimeLeaseLost
	}
	return s.ledgerRuntimeStore.CommitSourceRuntimePage(ctx, attemptID, runtime)
}

func (s *fencedLedgerRuntimeStore) MarkSourceRuntimePageProjected(_ context.Context, _ string, _ ports.SourceRuntimePageProjection) error {
	s.calls = append(s.calls, "projected")
	return nil
}

type scriptedSourceExecutionHost struct {
	inputs       []sourceworker.ExecutionInput
	afterExecute func()
}

func (h *scriptedSourceExecutionHost) Execute(_ context.Context, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
	h.inputs = append(h.inputs, input)
	observedAt := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC).Add(time.Duration(input.Scope.LeaseGeneration) * time.Millisecond)
	scope := input.Scope
	scope.ObservedAtUnixMillis = observedAt.UnixMilli()
	request := &cerebrov1.SourceWorkerHTTPRequestV1{
		PlanId: input.Plan.GetPlanId(), Method: "GET", Url: "https://graph.microsoft.com/v1.0/policies/authorizationPolicy",
		Accept: "application/json", MaxResponseBytes: input.Plan.GetMaxResponseBytes(), PlanDigestSha256: input.Plan.GetPlanDigestSha256(),
	}
	intent, err := sourceworker.CanonicalRequestIntentDigest(input.Plan, scope, request)
	if err != nil {
		return nil, err
	}
	receipt := sourceworker.SafeReceipt{
		PlanDigestSHA256: input.Plan.GetPlanDigestSha256(), TenantID: scope.TenantID, RuntimeID: scope.RuntimeID,
		LogicalPageID: scope.LogicalPageID, RequestIntentDigest: intent,
		RuntimeGeneration: scope.RuntimeGeneration, LeaseGeneration: scope.LeaseGeneration,
		CredentialOperation: "test-operation", StatusCode: 200, ResponseBytes: 2,
		ResponseSHA256:       "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		ObservedAtUnixMillis: observedAt.UnixMilli(),
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy",
		OccurredAtUnixMillis: observedAt.UnixMilli(), PayloadJson: []byte(`{"id":"authorizationPolicy"}`),
		Attributes: map[string]string{
			"family": "authorization_policy", "resource_id": "authorizationPolicy",
			"resource_name": "authorizationPolicy", "resource_provider": "azure", "resource_type": "authorization_policy",
		},
	}
	result := &cerebrov1.SourceWorkerDecodeResultV1{
		PlanId: input.Plan.GetPlanId(), PlanDigestSha256: input.Plan.GetPlanDigestSha256(),
		LogicalPageId: scope.LogicalPageID, RequestIntentDigest: intent, Records: []*cerebrov1.SourceWorkerRecordV1{record},
		TenantId: scope.TenantID, RuntimeId: scope.RuntimeID, RuntimeGeneration: scope.RuntimeGeneration,
		LeaseGeneration: scope.LeaseGeneration, ObservedAtUnixMillis: observedAt.UnixMilli(),
	}
	result.ResultDigestSha256, err = sourceworker.CanonicalResultDigest(result, receipt)
	if err != nil {
		return nil, err
	}
	if h.afterExecute != nil {
		h.afterExecute()
	}
	return &sourceworker.ExecutionOutput{Result: result, Receipt: receipt}, nil
}

func TestSourceExecutionServiceRejectsStaleLeaseBeforeAppend(t *testing.T) {
	source := admissionTestSource{id: "azure", contracts: []sourcecdk.EventContract{{
		Kind: "azure.authorization_policy", SchemaRef: "azure/authorization_policy/v1",
		RequiredAttributes:    []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"},
		RequiredPayloadFields: []string{"id"},
	}}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-stale-policy", SourceId: "azure", TenantId: "tenant-a", Config: map[string]string{
		"family": "authorization_policy", "token": "env:CEREBRO_SOURCE_AZURE_TOKEN",
	}}
	store := &fencedLedgerRuntimeStore{ledgerRuntimeStore: &ledgerRuntimeStore{runtimeStore: runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}}}}
	appendLog := &idempotentExecutionAppendLog{}
	projector := &idempotentExecutionProjector{}
	host := &scriptedSourceExecutionHost{}
	host.afterExecute = func() {
		store.mu.Lock()
		store.generation++
		store.owner = "successor"
		store.expiresAt = time.Now().UTC().Add(time.Minute)
		store.mu.Unlock()
	}
	service := New(registry, store, appendLog, projector).WithConfigResolver(func(_ context.Context, _ string, values map[string]string) (map[string]string, error) {
		resolved := sourceconfig.WithRuntimeContext(values, values[sourceconfig.RuntimeTenantIDKey], values[sourceconfig.RuntimeIDKey])
		resolved["token"] = "resolved-test-token"
		return resolved, nil
	})
	service.sourceHostFactory = func(sourceworker.CredentialRedeemer) sourceExecutionHost { return host }

	_, err = service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId()}, SyncWithLeaseOptions{
		LeaseStore: store, LeaseOwner: "worker-a", LeaseTTL: time.Minute,
	})
	if !errors.Is(err, ports.ErrSourceRuntimeLeaseLost) {
		t.Fatalf("SyncWithLease() error = %v, want lease lost", err)
	}
	stored, getErr := store.GetSourceRuntime(context.Background(), runtime.GetId())
	if getErr != nil {
		t.Fatal(getErr)
	}
	if len(appendLog.events) != 0 || len(projector.events) != 0 || stored.GetCheckpoint() != nil {
		t.Fatalf("stale generation mutated durable state: appended=%d projected=%d checkpoint=%v", len(appendLog.events), len(projector.events), stored.GetCheckpoint())
	}
}

type idempotentExecutionAppendLog struct {
	events map[string]*cerebrov1.EventEnvelope
	fail   bool
}

func (l *idempotentExecutionAppendLog) Ping(context.Context) error { return nil }
func (l *idempotentExecutionAppendLog) Append(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	return l.AppendBatch(ctx, []*cerebrov1.EventEnvelope{event})
}
func (l *idempotentExecutionAppendLog) AppendBatch(_ context.Context, events []*cerebrov1.EventEnvelope) error {
	if l.fail {
		return errors.New("append unavailable")
	}
	if l.events == nil {
		l.events = map[string]*cerebrov1.EventEnvelope{}
	}
	for _, event := range events {
		l.events[event.GetTenantId()+"\x00"+event.GetId()] = event
	}
	return nil
}

type idempotentExecutionProjector struct {
	events map[string]*cerebrov1.EventEnvelope
}

func (p *idempotentExecutionProjector) Project(_ context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if p.events == nil {
		p.events = map[string]*cerebrov1.EventEnvelope{}
	}
	key := event.GetTenantId() + "\x00" + event.GetId()
	_, existed := p.events[key]
	p.events[key] = event
	if existed {
		return ports.ProjectionResult{}, nil
	}
	return ports.ProjectionResult{EntitiesProjected: 1}, nil
}

func TestSourceExecutionServiceFencesAppendProjectionCheckpointAndRestart(t *testing.T) {
	source := admissionTestSource{id: "azure", contracts: []sourcecdk.EventContract{{
		Kind: "azure.authorization_policy", SchemaRef: "azure/authorization_policy/v1",
		RequiredAttributes:    []string{"family", "resource_id", "resource_name", "resource_provider", "resource_type"},
		RequiredPayloadFields: []string{"id"},
	}}}
	registry, err := sourcecdk.NewRegistry(source)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-azure-policy", SourceId: "azure", TenantId: "tenant-a", Config: map[string]string{
		"family": "authorization_policy", "token": "env:CEREBRO_SOURCE_AZURE_TOKEN",
	}}
	store := &fencedLedgerRuntimeStore{ledgerRuntimeStore: &ledgerRuntimeStore{runtimeStore: runtimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}}}}
	appendLog := &idempotentExecutionAppendLog{fail: true}
	projector := &idempotentExecutionProjector{}
	host := &scriptedSourceExecutionHost{}
	service := New(registry, store, appendLog, projector).WithConfigResolver(func(_ context.Context, _ string, values map[string]string) (map[string]string, error) {
		resolved := sourceconfig.WithRuntimeContext(values, values[sourceconfig.RuntimeTenantIDKey], values[sourceconfig.RuntimeIDKey])
		resolved["token"] = "resolved-test-token"
		return resolved, nil
	})
	service.sourceHostFactory = func(sourceworker.CredentialRedeemer) sourceExecutionHost { return host }
	opts := SyncWithLeaseOptions{LeaseStore: store, LeaseOwner: "worker-a", LeaseTTL: time.Minute}

	if _, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId()}, opts); err == nil {
		t.Fatal("SyncWithLease() append failure = nil")
	}
	stored, err := store.GetSourceRuntime(context.Background(), runtime.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if stored.GetCheckpoint() != nil || len(projector.events) != 0 {
		t.Fatalf("failed append advanced durable state: checkpoint=%v projections=%d", stored.GetCheckpoint(), len(projector.events))
	}

	appendLog.fail = false
	first, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetEventsAppended() != 1 || first.GetEntitiesProjected() != 1 || first.GetRuntime().GetCheckpoint().GetCursorOpaque() == "" {
		t.Fatalf("first committed sync = %#v", first)
	}
	second, err := service.SyncWithLease(context.Background(), &cerebrov1.SyncSourceRuntimeRequest{Id: runtime.GetId()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.GetEventsAppended() != 1 || len(appendLog.events) != 1 || len(projector.events) != 1 {
		t.Fatalf("restart duplicated durable identity: response=%#v appended=%d projected=%d", second, len(appendLog.events), len(projector.events))
	}
	if len(host.inputs) != 3 || host.inputs[0].Scope.TenantID != "tenant-a" || host.inputs[1].Scope.LeaseGeneration == host.inputs[2].Scope.LeaseGeneration {
		t.Fatalf("host fences = %#v", host.inputs)
	}
	if host.inputs[1].Scope.LogicalPageID != host.inputs[2].Scope.LogicalPageID {
		t.Fatalf("restart logical page changed: first=%q second=%q", host.inputs[1].Scope.LogicalPageID, host.inputs[2].Scope.LogicalPageID)
	}
	if _, ok := projector.events["tenant-a\x00azure-authorization-policy-authorizationPolicy"]; !ok {
		t.Fatal("authenticated tenant-scoped projected object is missing")
	}
}
