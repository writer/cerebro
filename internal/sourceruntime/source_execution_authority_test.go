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
	legacy := &runtimeAuthorityProbe{sourceID: "tailscale"}
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
	legacy := &runtimeAuthorityProbe{sourceID: "tailscale"}
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
	legacy := &runtimeAuthorityProbe{sourceID: "tailscale"}
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

func TestNonTailscaleRuntimeUsesGoCompatibilityBeforeRustCredentialChecks(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "gcp"}
	service := &Service{sourceWorker: &runtimePlanWorker{}}
	runtime := &cerebrov1.SourceRuntime{Id: "gcp-runtime", SourceId: "gcp", TenantId: "tenant-1"}

	if _, rustPage, err := service.readSourcePull(context.Background(), runtime, legacy, sourcecdk.NewConfig(nil), nil, nil, 1); err != nil {
		t.Fatalf("readSourcePull() error = %v", err)
	} else if rustPage {
		t.Fatal("readSourcePull() reported a Rust page for a Go-authoritative source")
	}
	if legacy.readCalls != 1 {
		t.Fatalf("Go Read calls = %d, want 1", legacy.readCalls)
	}
}

func TestAzureAuthorizationPolicyValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "azure"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "azure-authorization-policy-runtime", SourceId: "azure", TenantId: "tenant-1",
		Config: map[string]string{"family": "authorization_policy", "graph_token": sourceconfig.CredentialReferenceValue("azure", "graph_token")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "azure" || worker.selection.FamilyID != "authorization_policy" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
}

func TestAzureAuthorizationPolicyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "azure"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "azure-authorization-policy-runtime", SourceId: "azure", TenantId: "tenant-1",
		Config: map[string]string{"family": "authorization_policy", "graph_token": sourceconfig.CredentialReferenceValue("azure", "graph_token")},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{"family": "authorization_policy", "graph_token": "host-only-secret"})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "azure" || worker.selection.FamilyID != "authorization_policy" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestOtherAzureFamilyRemainsGoCompatible(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "azure"}
	service := &Service{sourceWorker: &runtimePlanWorker{}}
	runtime := &cerebrov1.SourceRuntime{Id: "azure-user-runtime", SourceId: "azure", TenantId: "tenant-1"}
	config := sourcecdk.NewConfig(map[string]string{"family": "user"})

	if _, rustPage, err := service.readSourcePull(context.Background(), runtime, legacy, config, nil, nil, 1); err != nil {
		t.Fatalf("readSourcePull() error = %v", err)
	} else if rustPage {
		t.Fatal("readSourcePull() reported a Rust page for a Go-authoritative Azure family")
	}
	if legacy.readCalls != 1 {
		t.Fatalf("Go Read calls = %d, want 1", legacy.readCalls)
	}
}

func TestPutTwilioAccountsRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "twilio-accounts-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "accounts", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "accounts" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "accounts" || worker.publicConfig["username"] != "" || worker.publicConfig["password"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestTwilioAccountsNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "twilio-accounts-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "accounts", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "accounts", "username": "AC123", "password": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "accounts" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutTwilioAuditEventsRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "twilio-audit-events-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "audit_events", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "audit_events" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "audit_events" || worker.publicConfig["username"] != "" || worker.publicConfig["password"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestTwilioAuditEventsNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "twilio-audit-events-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "audit_events", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "audit_events", "username": "AC123", "password": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "audit_events" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestTwilioKeysRemainsGoCompatible(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	service := &Service{sourceWorker: &runtimePlanWorker{}}
	runtime := &cerebrov1.SourceRuntime{Id: "twilio-keys-runtime", SourceId: "twilio", TenantId: "tenant-1"}
	config := sourcecdk.NewConfig(map[string]string{"family": "keys"})

	if _, rustPage, err := service.readSourcePull(context.Background(), runtime, legacy, config, nil, nil, 1); err != nil {
		t.Fatalf("readSourcePull() error = %v", err)
	} else if rustPage {
		t.Fatal("readSourcePull() reported a Rust page for a Go-authoritative Twilio family")
	}
	if legacy.readCalls != 1 {
		t.Fatalf("Go Read calls = %d, want 1", legacy.readCalls)
	}
}

func TestPutSentinelOneAgentRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "sentinelone"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "sentinelone-agent-runtime", SourceId: "sentinelone", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "agent", "base_url": "https://sentinelone.example.test",
			"token": sourceconfig.CredentialReferenceValue("sentinelone", "token"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "sentinelone" || worker.selection.FamilyID != "agent" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["base_url"] != "https://sentinelone.example.test" || worker.publicConfig["family"] != "agent" || worker.publicConfig["token"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestSentinelOneAgentNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "sentinelone"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "sentinelone-agent-runtime", SourceId: "sentinelone", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "agent", "base_url": "https://sentinelone.example.test",
			"token": sourceconfig.CredentialReferenceValue("sentinelone", "token"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "agent", "base_url": "https://sentinelone.example.test", "token": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "sentinelone" || worker.selection.FamilyID != "agent" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestOtherSentinelOneFamilyRemainsGoCompatible(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "sentinelone"}
	service := &Service{sourceWorker: &runtimePlanWorker{}}
	runtime := &cerebrov1.SourceRuntime{Id: "sentinelone-threat-runtime", SourceId: "sentinelone", TenantId: "tenant-1"}
	config := sourcecdk.NewConfig(map[string]string{"family": "threat"})

	if _, rustPage, err := service.readSourcePull(context.Background(), runtime, legacy, config, nil, nil, 1); err != nil {
		t.Fatalf("readSourcePull() error = %v", err)
	} else if rustPage {
		t.Fatal("readSourcePull() reported a Rust page for a Go-authoritative SentinelOne family")
	}
	if legacy.readCalls != 1 {
		t.Fatalf("Go Read calls = %d, want 1", legacy.readCalls)
	}
}

func TestPutJumpCloudFamiliesValidateWithRustWithoutCallingGoCheck(t *testing.T) {
	families := []string{"users", "groups", "systems", "applications", "system_groups", "group_members", "audit_events"}
	for _, family := range families {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "jumpcloud"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			worker := &runtimePlanWorker{}
			service := New(registry, &runtimeStore{}, nil, nil)
			service.sourceWorker = worker
			config := map[string]string{
				"family": family, "api_key": sourceconfig.CredentialReferenceValue("jumpcloud", "api_key"),
			}
			if family == "group_members" {
				config["group_ids"] = "group-1,group-2"
			}
			_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
				Id: "jumpcloud-" + family + "-runtime", SourceId: "jumpcloud", TenantId: "tenant-1", Config: config,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if legacy.checkCalls != 0 || worker.planCalls != 1 {
				t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
			}
			if worker.selection.SourceID != "jumpcloud" || worker.selection.FamilyID != family {
				t.Fatalf("Rust selection = %#v", worker.selection)
			}
			if worker.publicConfig["api_key"] != "" || worker.publicConfig["family"] != family {
				t.Fatalf("Rust public config = %#v", worker.publicConfig)
			}
		})
	}
}

func TestUnknownJumpCloudFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "jumpcloud"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "jumpcloud-future-runtime", SourceId: "jumpcloud", TenantId: "tenant-1",
		Config: map[string]string{"family": "future-family", "api_key": sourceconfig.CredentialReferenceValue("jumpcloud", "api_key")},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{"family": "future-family", "api_key": "host-only-value"})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "jumpcloud" || worker.selection.FamilyID != "future-family" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

type runtimeAuthorityProbe struct {
	sourceID              string
	checkCalls, readCalls int
}

func (s *runtimeAuthorityProbe) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.sourceID}
}
func (s *runtimeAuthorityProbe) Check(context.Context, sourcecdk.Config) error {
	s.checkCalls++
	return nil
}
func (*runtimeAuthorityProbe) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	return nil, nil
}
func (s *runtimeAuthorityProbe) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readCalls++
	return sourcecdk.Pull{}, nil
}

type runtimePlanWorker struct {
	planCalls    int
	publicConfig map[string]string
	compileErr   error
	selection    sourceworker.SelectionRequest
}

func (w *runtimePlanWorker) Compile(_ context.Context, request sourceworker.SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	w.selection = request
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
