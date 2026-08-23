package sourceruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func TestPutTailscaleRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeTailscaleProbe{}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "tailscale-user-runtime", SourceId: "tailscale", TenantId: "tenant-1",
		Config: map[string]string{"family": "user", "tailnet": "example.com", "token": sourceconfig.CredentialReferenceValue("tailscale", "token")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.publicConfig["tailnet"] != "example.com" || worker.publicConfig["family"] != "user" || worker.publicConfig["token"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestTailscaleRuntimeFailsClosedWithoutRustWorker(t *testing.T) {
	legacy := &runtimeTailscaleProbe{}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry, &runtimeStore{}, nil, nil)
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "tailscale-device-runtime", SourceId: "tailscale", TenantId: "tenant-1",
		Config: map[string]string{"tailnet": "example.com", "token": sourceconfig.CredentialReferenceValue("tailscale", "token")},
	}})
	if !errors.Is(err, ErrRuntimeUnavailable) || legacy.checkCalls != 0 {
		t.Fatalf("Put() error = %v, Go Check calls = %d", err, legacy.checkCalls)
	}
}

func TestUnknownTailscaleFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeTailscaleProbe{}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "tailscale-future-runtime", SourceId: "tailscale", TenantId: "tenant-1",
		Config: map[string]string{"family": "future-family", "tailnet": "example.com", "token": sourceconfig.CredentialReferenceValue("tailscale", "token")},
	}
	if _, err := service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: runtime}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Put() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("Go Check calls = %d", legacy.checkCalls)
	}

	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "future-family", "tailnet": "example.com", "token": "host-only-secret",
	})
	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 {
		t.Fatalf("Go Read calls = %d", legacy.readCalls)
	}
}

func TestCompatibilitySourceFallsBackBeforeRustLeaseAndCredentialValidation(t *testing.T) {
	legacy := &runtimeCompatibilityProbe{sourceID: "gcp"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "gcp-audit-runtime", SourceId: "gcp", TenantId: "tenant-1",
		Config: map[string]string{"family": "audit", "project_id": "project-1"},
	}
	resolved := sourcecdk.NewConfig(runtime.GetConfig())

	if _, executedByRust, err := service.readSourcePull(context.Background(), runtime, legacy, resolved, nil, nil, 1); err != nil {
		t.Fatalf("readSourcePull() error = %v", err)
	} else if executedByRust {
		t.Fatal("readSourcePull() reported Rust execution for a compatibility family")
	}
	if legacy.readCalls != 1 || worker.compileCalls != 1 {
		t.Fatalf("execution calls = Go %d, Rust compile %d", legacy.readCalls, worker.compileCalls)
	}
}

type runtimeTailscaleProbe struct{ checkCalls, readCalls int }

func (*runtimeTailscaleProbe) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: "tailscale"}
}
func (s *runtimeTailscaleProbe) Check(context.Context, sourcecdk.Config) error {
	s.checkCalls++
	return nil
}
func (*runtimeTailscaleProbe) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}
func (s *runtimeTailscaleProbe) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readCalls++
	return sourcecdk.Pull{}, nil
}

type runtimeCompatibilityProbe struct {
	sourceID  string
	readCalls int
}

func (s *runtimeCompatibilityProbe) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.sourceID}
}
func (*runtimeCompatibilityProbe) Check(context.Context, sourcecdk.Config) error { return nil }
func (*runtimeCompatibilityProbe) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}
func (s *runtimeCompatibilityProbe) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readCalls++
	return sourcecdk.Pull{}, nil
}

type runtimePlanWorker struct {
	compileCalls int
	planCalls    int
	publicConfig map[string]string
	compileErr   error
}

func (w *runtimePlanWorker) Compile(_ context.Context, request sourceworker.SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	w.compileCalls++
	if w.compileErr != nil {
		return nil, w.compileErr
	}
	return &cerebrov1.SourceExecutionPlanV1{SourceId: request.SourceID, FamilyId: request.FamilyID}, nil
}
func (*runtimePlanWorker) Context(_ context.Context, request sourceworker.ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	return &cerebrov1.SourceWorkerExecutionContextV1{
		TenantId: request.TenantID, RuntimeId: request.RuntimeID, LogicalPageId: "page-1",
		RuntimeGeneration: request.RuntimeGeneration, LeaseGeneration: request.LeaseGeneration,
		ObservedAtUnixMillis: request.ObservedAtUnixMillis,
	}, nil
}
func (w *runtimePlanWorker) PlanV2(_ context.Context, envelope *cerebrov1.SourceWorkerPlanEnvelopeV2) (*cerebrov1.SourceWorkerHTTPExecutionV2, error) {
	w.planCalls++
	w.publicConfig = envelope.GetMetadata().GetPublicConfig()
	return &cerebrov1.SourceWorkerHTTPExecutionV2{}, nil
}
func (*runtimePlanWorker) DecodeV2(context.Context, *cerebrov1.SourceWorkerDecodeEnvelopeV2) (*cerebrov1.SourceWorkerDecodeOutputV2, error) {
	return nil, errors.New("unexpected DecodeV2 call")
}
func (*runtimePlanWorker) SealPage(context.Context, sourceworker.PageProgramRequest) (*sourceworker.PageProgram, error) {
	return nil, errors.New("unexpected SealPage call")
}
