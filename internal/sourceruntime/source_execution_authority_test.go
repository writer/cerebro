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

func TestPutAnthropicRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "anthropic"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "anthropic-user-runtime", SourceId: "anthropic", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "user", "auth_model": "api_key", "per_page": "100",
			"api_key": sourceconfig.CredentialReferenceValue("anthropic", "api_key"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "anthropic" || worker.selection.FamilyID != "user" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "user" || worker.publicConfig["auth_model"] != "api_key" || worker.publicConfig["per_page"] != "100" || worker.publicConfig["api_key"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestAnthropicRuntimeNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "anthropic"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "anthropic-user-runtime", SourceId: "anthropic", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "user", "auth_model": "api_key",
			"api_key": sourceconfig.CredentialReferenceValue("anthropic", "api_key"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "user", "auth_model": "api_key", "api_key": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "anthropic" || worker.selection.FamilyID != "user" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutOpenAIRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "openai"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "openai-user-runtime", SourceId: "openai", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "user", "per_page": "100",
			"api_key": sourceconfig.CredentialReferenceValue("openai", "api_key"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "openai" || worker.selection.FamilyID != "user" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "user" || worker.publicConfig["per_page"] != "100" || worker.publicConfig["api_key"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestOpenAIRuntimeNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "openai"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "openai-user-runtime", SourceId: "openai", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "user", "api_key": sourceconfig.CredentialReferenceValue("openai", "api_key"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{"family": "user", "api_key": "host-only-secret"})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "openai" || worker.selection.FamilyID != "user" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
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

func TestPutDiscordAuthoritativeFamiliesValidateWithRustWithoutCallingGoCheck(t *testing.T) {
	for _, family := range []string{"audit_log", "member", "role", "permission"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "discord"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			worker := &runtimePlanWorker{}
			service := New(registry, &runtimeStore{}, nil, nil)
			service.sourceWorker = worker
			_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
				Id: "discord-" + family + "-runtime", SourceId: "discord", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "guild_id": "100000000000000000", "application_id": "200000000000000000", "per_page": "100",
					"api_token": sourceconfig.CredentialReferenceValue("discord", "api_token"),
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if legacy.checkCalls != 0 || worker.planCalls != 1 {
				t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
			}
			if worker.selection.SourceID != "discord" || worker.selection.FamilyID != family {
				t.Fatalf("Rust selection = %#v", worker.selection)
			}
			if worker.publicConfig["family"] != family || worker.publicConfig["guild_id"] != "100000000000000000" || worker.publicConfig["application_id"] != "200000000000000000" || worker.publicConfig["per_page"] != "100" || worker.publicConfig["api_token"] != "" {
				t.Fatalf("Rust public config = %#v", worker.publicConfig)
			}
		})
	}
}

func TestDiscordAuthoritativeFamiliesNeverFallBackToGo(t *testing.T) {
	for _, family := range []string{"audit_log", "member", "role", "permission"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "discord"}
			worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
			service := &Service{sourceWorker: worker}
			runtime := &cerebrov1.SourceRuntime{
				Id: "discord-" + family + "-runtime", SourceId: "discord", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "guild_id": "100000000000000000", "application_id": "200000000000000000", "per_page": "100",
					"api_token": sourceconfig.CredentialReferenceValue("discord", "api_token"),
				},
			}
			ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
				Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
			}})
			resolved := sourcecdk.NewConfig(map[string]string{
				"family": family, "guild_id": "100000000000000000", "application_id": "200000000000000000", "per_page": "100", "api_token": "host-only-secret",
			})

			if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
				t.Fatalf("readSourcePull() error = %v", err)
			}
			if legacy.readCalls != 0 || worker.selection.SourceID != "discord" || worker.selection.FamilyID != family {
				t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
			}
		})
	}
}

func TestUnknownDiscordFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "discord"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "discord-future-runtime", SourceId: "discord", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "future-family", "guild_id": "100000000000000000", "application_id": "200000000000000000",
			"api_token": sourceconfig.CredentialReferenceValue("discord", "api_token"),
		},
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
		"family": "future-family", "guild_id": "100000000000000000", "application_id": "200000000000000000", "api_token": "host-only-secret",
	})
	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "discord" || worker.selection.FamilyID != "future-family" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutPagerDutyAuthoritativeFamiliesValidateWithRustWithoutCallingGoCheck(t *testing.T) {
	for _, family := range []string{"user", "team", "service", "schedule", "escalation_policy", "integration", "vendor"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "pagerduty"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			worker := &runtimePlanWorker{}
			service := New(registry, &runtimeStore{}, nil, nil)
			service.sourceWorker = worker
			config := map[string]string{
				"family": family, "per_page": "100",
				"token": sourceconfig.CredentialReferenceValue("pagerduty", "token"),
			}
			if family == "integration" {
				config["service_ids"] = "PS1,PS2"
			}
			_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
				Id: "pagerduty-" + family + "-runtime", SourceId: "pagerduty", TenantId: "tenant-1", Config: config,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if legacy.checkCalls != 0 || worker.planCalls != 1 {
				t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
			}
			if worker.selection.SourceID != "pagerduty" || worker.selection.FamilyID != family {
				t.Fatalf("Rust selection = %#v", worker.selection)
			}
			if worker.publicConfig["family"] != family || worker.publicConfig["per_page"] != "100" || worker.publicConfig["token"] != "" || (family == "integration" && worker.publicConfig["service_ids"] != "PS1,PS2") {
				t.Fatalf("Rust public config = %#v", worker.publicConfig)
			}
		})
	}
}

func TestPagerDutyAuthoritativeFamiliesNeverFallBackToGo(t *testing.T) {
	for _, family := range []string{"user", "team", "service", "schedule", "escalation_policy", "integration", "vendor"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "pagerduty"}
			worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
			service := &Service{sourceWorker: worker}
			config := map[string]string{
				"family": family, "per_page": "100",
				"token": sourceconfig.CredentialReferenceValue("pagerduty", "token"),
			}
			resolvedConfig := map[string]string{"family": family, "per_page": "100", "token": "host-only-secret"}
			if family == "integration" {
				config["service_ids"] = "PS1,PS2"
				resolvedConfig["service_ids"] = "PS1,PS2"
			}
			runtime := &cerebrov1.SourceRuntime{
				Id: "pagerduty-" + family + "-runtime", SourceId: "pagerduty", TenantId: "tenant-1", Config: config,
			}
			ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
				Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
			}})
			resolved := sourcecdk.NewConfig(resolvedConfig)

			if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
				t.Fatalf("readSourcePull() error = %v", err)
			}
			if legacy.readCalls != 0 || worker.selection.SourceID != "pagerduty" || worker.selection.FamilyID != family {
				t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
			}
		})
	}
}

func TestUnknownPagerDutyFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "pagerduty"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "pagerduty-future-runtime", SourceId: "pagerduty", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "future-family", "token": sourceconfig.CredentialReferenceValue("pagerduty", "token"),
		},
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
	resolved := sourcecdk.NewConfig(map[string]string{"family": "future-family", "token": "host-only-secret"})
	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "pagerduty" || worker.selection.FamilyID != "future-family" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutAsanaAuthoritativeFamiliesValidateWithRustWithoutCallingGoCheck(t *testing.T) {
	for _, family := range []string{"users", "projects", "audit_events"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "asana"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			worker := &runtimePlanWorker{}
			service := New(registry, &runtimeStore{}, nil, nil)
			service.sourceWorker = worker
			_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
				Id: "asana-" + family + "-runtime", SourceId: "asana", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "workspace_gid": "workspace-1", "page_size": "100",
					"token": sourceconfig.CredentialReferenceValue("asana", "token"),
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if legacy.checkCalls != 0 || worker.planCalls != 1 {
				t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
			}
			if worker.selection.SourceID != "asana" || worker.selection.FamilyID != family {
				t.Fatalf("Rust selection = %#v", worker.selection)
			}
			if worker.publicConfig["family"] != family || worker.publicConfig["workspace_gid"] != "workspace-1" || worker.publicConfig["page_size"] != "100" || worker.publicConfig["token"] != "" {
				t.Fatalf("Rust public config = %#v", worker.publicConfig)
			}
		})
	}
}

func TestAsanaAuthoritativeFamiliesNeverFallBackToGo(t *testing.T) {
	for _, family := range []string{"users", "projects", "audit_events"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "asana"}
			worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
			service := &Service{sourceWorker: worker}
			runtime := &cerebrov1.SourceRuntime{
				Id: "asana-" + family + "-runtime", SourceId: "asana", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "workspace_gid": "workspace-1", "page_size": "100",
					"token": sourceconfig.CredentialReferenceValue("asana", "token"),
				},
			}
			ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
				Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
			}})
			resolved := sourcecdk.NewConfig(map[string]string{
				"family": family, "workspace_gid": "workspace-1", "page_size": "100", "token": "host-only-secret",
			})

			if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
				t.Fatalf("readSourcePull() error = %v", err)
			}
			if legacy.readCalls != 0 || worker.selection.SourceID != "asana" || worker.selection.FamilyID != family {
				t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
			}
		})
	}
}

func TestUnknownAsanaFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "asana"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "asana-future-runtime", SourceId: "asana", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "future-family", "workspace_gid": "workspace-1",
			"token": sourceconfig.CredentialReferenceValue("asana", "token"),
		},
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
		"family": "future-family", "workspace_gid": "workspace-1", "token": "host-only-secret",
	})
	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "asana" || worker.selection.FamilyID != "future-family" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutDigitalOceanAuthoritativeFamiliesValidateWithRustWithoutCallingGoCheck(t *testing.T) {
	for _, family := range []string{"droplets", "vpcs", "firewalls"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "digitalocean"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			worker := &runtimePlanWorker{}
			service := New(registry, &runtimeStore{}, nil, nil)
			service.sourceWorker = worker
			_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
				Id: "digitalocean-" + family + "-runtime", SourceId: "digitalocean", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "per_page": "100",
					"token": sourceconfig.CredentialReferenceValue("digitalocean", "token"),
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if legacy.checkCalls != 0 || worker.planCalls != 1 {
				t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
			}
			if worker.selection.SourceID != "digitalocean" || worker.selection.FamilyID != family {
				t.Fatalf("Rust selection = %#v", worker.selection)
			}
			if worker.publicConfig["family"] != family || worker.publicConfig["per_page"] != "100" || worker.publicConfig["token"] != "" {
				t.Fatalf("Rust public config = %#v", worker.publicConfig)
			}
		})
	}
}

func TestDigitalOceanAuthoritativeFamiliesNeverFallBackToGo(t *testing.T) {
	for _, family := range []string{"droplets", "vpcs", "firewalls"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "digitalocean"}
			worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
			service := &Service{sourceWorker: worker}
			runtime := &cerebrov1.SourceRuntime{
				Id: "digitalocean-" + family + "-runtime", SourceId: "digitalocean", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "per_page": "100",
					"token": sourceconfig.CredentialReferenceValue("digitalocean", "token"),
				},
			}
			ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
				Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
			}})
			resolved := sourcecdk.NewConfig(map[string]string{
				"family": family, "per_page": "100", "token": "host-only-secret",
			})

			if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
				t.Fatalf("readSourcePull() error = %v", err)
			}
			if legacy.readCalls != 0 || worker.selection.SourceID != "digitalocean" || worker.selection.FamilyID != family {
				t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
			}
		})
	}
}

func TestUnknownDigitalOceanFamilyNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "digitalocean"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	runtime := &cerebrov1.SourceRuntime{
		Id: "digitalocean-future-runtime", SourceId: "digitalocean", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "future-family", "per_page": "100",
			"token": sourceconfig.CredentialReferenceValue("digitalocean", "token"),
		},
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
		"family": "future-family", "per_page": "100", "token": "host-only-secret",
	})
	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "digitalocean" || worker.selection.FamilyID != "future-family" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestPutLinodeIssueRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "linode"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "linode-issue-runtime", SourceId: "linode", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "issue", "page_size": "100",
			"token": sourceconfig.CredentialReferenceValue("linode", "token"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "linode" || worker.selection.FamilyID != "issue" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "issue" || worker.publicConfig["page_size"] != "100" || worker.publicConfig["token"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestLinodeIssueNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "linode"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "linode-issue-runtime", SourceId: "linode", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "issue", "page_size": "100",
			"token": sourceconfig.CredentialReferenceValue("linode", "token"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "issue", "page_size": "100", "token": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "linode" || worker.selection.FamilyID != "issue" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
	}
}

func TestOtherLinodeFamiliesRemainGoCompatible(t *testing.T) {
	for _, family := range []string{"event", "credential", "user", "future-family"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "linode"}
			service := &Service{sourceWorker: &runtimePlanWorker{}}
			runtime := &cerebrov1.SourceRuntime{Id: "linode-" + family + "-runtime", SourceId: "linode", TenantId: "tenant-1"}
			config := sourcecdk.NewConfig(map[string]string{"family": family})

			if _, rustPage, err := service.readSourcePull(context.Background(), runtime, legacy, config, nil, nil, 1); err != nil {
				t.Fatalf("readSourcePull() error = %v", err)
			} else if rustPage {
				t.Fatal("readSourcePull() reported a Rust page for a Go-authoritative Linode family")
			}
			if legacy.readCalls != 1 {
				t.Fatalf("Go Read calls = %d, want 1", legacy.readCalls)
			}
		})
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

func TestPutTwilioKeysRuntimeValidatesWithRustWithoutCallingGoCheck(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	worker := &runtimePlanWorker{}
	service := New(registry, &runtimeStore{}, nil, nil)
	service.sourceWorker = worker
	_, err = service.Put(context.Background(), &cerebrov1.PutSourceRuntimeRequest{Runtime: &cerebrov1.SourceRuntime{
		Id: "twilio-keys-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "keys", "account_sid": "AC123", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 0 || worker.planCalls != 1 {
		t.Fatalf("validation calls = Go %d, Rust %d", legacy.checkCalls, worker.planCalls)
	}
	if worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "keys" {
		t.Fatalf("Rust selection = %#v", worker.selection)
	}
	if worker.publicConfig["family"] != "keys" || worker.publicConfig["account_sid"] != "AC123" || worker.publicConfig["username"] != "" || worker.publicConfig["password"] != "" {
		t.Fatalf("Rust public config = %#v", worker.publicConfig)
	}
}

func TestTwilioKeysNeverFallsBackToGoAuthority(t *testing.T) {
	legacy := &runtimeAuthorityProbe{sourceID: "twilio"}
	worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
	service := &Service{sourceWorker: worker}
	runtime := &cerebrov1.SourceRuntime{
		Id: "twilio-keys-runtime", SourceId: "twilio", TenantId: "tenant-1",
		Config: map[string]string{
			"family": "keys", "account_sid": "AC123", "username": "AC123",
			"password": sourceconfig.CredentialReferenceValue("twilio", "password"),
		},
	}
	ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
		Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
	}})
	resolved := sourcecdk.NewConfig(map[string]string{
		"family": "keys", "account_sid": "AC123", "username": "AC123", "password": "host-only-secret",
	})

	if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("readSourcePull() error = %v", err)
	}
	if legacy.readCalls != 0 || worker.selection.SourceID != "twilio" || worker.selection.FamilyID != "keys" {
		t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
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

func TestPromotedSentinelOneNonAgentFamiliesNeverFallBackToGoAuthority(t *testing.T) {
	for _, family := range []string{"activity", "application", "exclusion", "group", "site", "threat"} {
		t.Run(family, func(t *testing.T) {
			legacy := &runtimeAuthorityProbe{sourceID: "sentinelone"}
			worker := &runtimePlanWorker{compileErr: sourceworker.ErrWorkerUnsupported}
			service := &Service{sourceWorker: worker}
			runtime := &cerebrov1.SourceRuntime{
				Id: "sentinelone-" + family + "-runtime", SourceId: "sentinelone", TenantId: "tenant-1",
				Config: map[string]string{
					"family": family, "base_url": "https://sentinelone.example.test",
					"token": sourceconfig.CredentialReferenceValue("sentinelone", "token"),
				},
			}
			ctx := context.WithValue(context.Background(), sourceRuntimeLeaseFenceContextKey{}, sourceRuntimeLeaseAuthority{fence: ports.SourceRuntimeLeaseFence{
				Owner: "owner-1", Generation: 1, ExpiresAt: time.Now().Add(time.Minute),
			}})
			resolved := sourcecdk.NewConfig(map[string]string{
				"family": family, "base_url": "https://sentinelone.example.test", "token": "host-only-secret",
			})

			if _, _, err := service.readSourcePull(ctx, runtime, legacy, resolved, nil, nil, 1); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
				t.Fatalf("readSourcePull() error = %v", err)
			}
			if legacy.readCalls != 0 || worker.selection.SourceID != "sentinelone" || worker.selection.FamilyID != family {
				t.Fatalf("authority calls = Go %d, Rust selection %#v", legacy.readCalls, worker.selection)
			}
		})
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
