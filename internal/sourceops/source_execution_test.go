package sourceops

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func TestRustSourceFamilyPreviewAuthorityIsExact(t *testing.T) {
	for name, test := range map[string]struct {
		source, family, wantFamily string
		wantAuthoritative          bool
	}{
		"Azure authorization policy": {"azure", "authorization_policy", "authorization_policy", true},
		"other Azure family":         {"azure", "user", "user", false},
		"Tailscale default":          {"tailscale", "", "device", true},
		"JumpCloud default":          {"jumpcloud", "", "users", true},
		"JumpCloud family":           {"jumpcloud", "group_members", "group_members", true},
		"unknown JumpCloud family":   {"jumpcloud", "future-family", "future-family", true},
		"SentinelOne threat":         {"sentinelone", "threat", "threat", true},
		"SentinelOne application":    {"sentinelone", "application", "application", true},
		"unknown SentinelOne family": {"sentinelone", "future-family", "future-family", false},
		"compatibility source":       {"gcp", "audit", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			family, authoritative := rustSourceFamily(test.source, map[string]string{"family": test.family})
			if family != test.wantFamily || authoritative != test.wantAuthoritative {
				t.Fatalf("rustSourceFamily() = (%q, %v), want (%q, %v)", family, authoritative, test.wantFamily, test.wantAuthoritative)
			}
		})
	}
}

func TestSentinelOneCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-sentinelone-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"activity", "agent", "application", "exclusion", "group", "site", "threat"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "sentinelone"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			service := New(registry)
			service.sourceWorker = previewWorkerStub{}
			calls := 0
			service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, reference string, credential []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
				calls++
				if reference != previewCredentialReference || string(credential) != credentialFixture {
					t.Fatal("SentinelOne credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "sentinelone" || input.FamilyID != family {
					t.Fatalf("Rust selection = %s.%s", input.SourceID, input.FamilyID)
				}
				return sentinelOnePreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tenant_id": "tenant-1", "token": credentialFixture, "base_url": "https://sentinelone.example.test"}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "sentinelone", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "sentinelone", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "sentinelone", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "sentinelone" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestJumpCloudCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-jumpcloud-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"users", "groups", "systems", "applications", "system_groups", "group_members", "audit_events"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "jumpcloud"}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			service := New(registry)
			service.sourceWorker = previewWorkerStub{}
			calls := 0
			service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, reference string, credential []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
				calls++
				if reference != previewCredentialReference || string(credential) != credentialFixture {
					t.Fatal("JumpCloud credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["api_key"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "jumpcloud" || input.FamilyID != family {
					t.Fatalf("Rust selection = %s.%s", input.SourceID, input.FamilyID)
				}
				return jumpCloudPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tenant_id": "tenant-1", "api_key": credentialFixture}
			if family == "group_members" {
				config["group_ids"] = "group-1,group-2"
			}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "jumpcloud", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "jumpcloud", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			providerID := family + "-1"
			if family == "audit_events" {
				providerID = sourcecdk.StableExternalID("event-1", "event")
			}
			wantURN, urnErr := sourcecdk.URNFor("tenant-1", "jumpcloud_"+family, providerID)
			if family == "group_members" {
				wantURN, urnErr = sourcecdk.URNForEscaped("tenant-1", "jumpcloud_group_members", "group-1", family+"-1")
			}
			if urnErr != nil || discovered.GetUrns()[0] != wantURN.String() {
				t.Fatalf("Discover() URN = %q, want %q, %v", discovered.GetUrns()[0], wantURN.String(), urnErr)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "jumpcloud", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "jumpcloud" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestUnknownJumpCloudFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "jumpcloud"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := map[string]string{"family": "future-family", "tenant_id": "tenant-1", "api_key": "host-only-secret"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "jumpcloud", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("legacy check calls = %d", legacy.checkCalls)
	}
}

func TestJumpCloudPreviewCredentialAliases(t *testing.T) {
	for name, test := range map[string]struct {
		config map[string]string
		want   string
	}{
		"api key":   {map[string]string{"api_key": "api-key", "token": "fallback"}, "api-key"},
		"api token": {map[string]string{"api_token": "api-token", "token": "fallback"}, "api-token"},
		"token":     {map[string]string{"token": "token"}, "token"},
		"missing":   {map[string]string{"graph_token": "wrong-provider"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := previewCredential("jumpcloud", test.config); got != test.want {
				t.Fatalf("previewCredential() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTailscaleCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	for _, family := range []string{"device", "grant", "group", "service", "tag", "tailnet", "user"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{}
			registry, err := sourcecdk.NewRegistry(legacy)
			if err != nil {
				t.Fatal(err)
			}
			service := New(registry)
			service.sourceWorker = previewWorkerStub{}
			calls := 0
			service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, reference string, credential []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
				calls++
				if reference != previewCredentialReference || string(credential) != "host-only-secret" {
					t.Fatal("credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), "host-only-secret") || input.Scope.PublicConfig["token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				return previewOutput(family, "", family+"-1", input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tailnet": "example.com", "tenant_id": "tenant-1", "token": "host-only-secret"}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "tailscale", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "tailscale", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "tailscale", Config: config})
			if err != nil {
				t.Fatal(err)
			}
			if read.GetNextCursor() != nil || len(read.GetEvents()) != 1 || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("terminal Read() = %#v", read)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestTailscaleReadPersistsTerminalRestartWithoutContinuingCurrentRun(t *testing.T) {
	for _, family := range []string{"device", "grant", "group", "service", "tag", "tailnet", "user"} {
		t.Run(family, func(t *testing.T) {
			service := tailscaleAuthorityService(t)
			var inputs []sourceworker.ExecutionInput
			service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, _ string, _ []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
				inputs = append(inputs, input)
				return previewOutput(family, "", family+"-terminal", max(input.Scope.PriorTerminalWatermarkUnixMillis, 1_725_000_000_000)), nil
			}
			config := tailscalePreviewConfig(family)
			first, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "tailscale", Config: config})
			if err != nil {
				t.Fatal(err)
			}
			if first.GetNextCursor() != nil {
				t.Fatalf("terminal page scheduled another page: %#v", first.GetNextCursor())
			}
			second, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
				SourceId: "tailscale", Config: config, Cursor: &cerebrov1.SourceCursor{Opaque: first.GetCheckpoint().GetCursorOpaque()},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(inputs) != 2 || inputs[1].Scope.PriorCursor != "" || inputs[1].Scope.PriorTerminalWatermarkUnixMillis != 1_725_000_000_000 {
				t.Fatalf("restart input = %#v", inputs)
			}
			if second.GetNextCursor() != nil {
				t.Fatal("restarted terminal page scheduled another page")
			}
		})
	}
}

func TestTailscaleReadContinuesOnlyForProviderCursorAndFailsClosed(t *testing.T) {
	service := tailscaleAuthorityService(t)
	var inputs []sourceworker.ExecutionInput
	service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, _ string, _ []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		inputs = append(inputs, input)
		return previewOutput("device", "provider-page-2", "provider-page-2", 1_725_000_000_000), nil
	}
	response, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "tailscale", Config: tailscalePreviewConfig("device")})
	if err != nil || response.GetNextCursor().GetOpaque() != "provider-page-2" {
		t.Fatalf("Read() continuation = %#v, %v", response, err)
	}
	_, err = service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
		SourceId: "tailscale", Config: tailscalePreviewConfig("device"), Cursor: &cerebrov1.SourceCursor{Opaque: response.GetCheckpoint().GetCursorOpaque()},
	})
	if err != nil || len(inputs) != 2 || inputs[1].Scope.PriorCursor != "provider-page-2" {
		t.Fatalf("continuation restart inputs = %#v, %v", inputs, err)
	}

	for name, cursor := range map[string]string{
		"malformed": `{"version":1`,
		"cross family": `{"version":1,"source":"tailscale","family":"user","mode":"rust_provider_checkpoint",` +
			`"resumable_checkpoint":true,"token":"user-1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{
				SourceId: "tailscale", Config: tailscalePreviewConfig("device"), Cursor: &cerebrov1.SourceCursor{Opaque: cursor},
			})
			if sourcecdk.SourceErrorKind(err) != sourcecdk.ErrorKindDecode || !errors.Is(err, sourceworker.ErrWorkerContract) {
				t.Fatalf("Read() error = %v, want typed fail-closed cursor error", err)
			}
		})
	}
}

func TestRustDiscoveryReadsEveryPageAndDeduplicatesURNs(t *testing.T) {
	service := tailscaleAuthorityService(t)
	var inputs []sourceworker.ExecutionInput
	service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, _ string, _ []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		inputs = append(inputs, input)
		if len(inputs) == 1 {
			return previewOutput("device", "provider-page-2", "provider-page-2", 1_725_000_000_000), nil
		}
		return previewOutput("device", "", "device-terminal", 1_725_000_001_000), nil
	}
	urns, err := service.discoverRustSource(context.Background(), "tailscale", "device", tailscalePreviewConfig("device"))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 || inputs[1].Scope.PriorCursor != "provider-page-2" {
		t.Fatalf("discovery inputs = %#v", inputs)
	}
	if len(urns) != 1 || urns[0].String() != "urn:cerebro:tenant-1:tailscale_device:device-1" {
		t.Fatalf("deduplicated URNs = %#v", urns)
	}
}

func TestRustDiscoveryRejectsRepeatedContinuation(t *testing.T) {
	service := tailscaleAuthorityService(t)
	service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, _ string, _ []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return previewOutput("device", "provider-page-2", "provider-page-2", input.Scope.PriorTerminalWatermarkUnixMillis), nil
	}
	_, err := service.discoverRustSource(context.Background(), "tailscale", "device", tailscalePreviewConfig("device"))
	if !errors.Is(err, sourceworker.ErrWorkerContract) {
		t.Fatalf("discoverRustSource() error = %v", err)
	}
}

func TestUnknownTailscaleFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := tailscalePreviewConfig("future-family")
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "tailscale", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if _, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "tailscale", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Discover() error = %v", err)
	}
	if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "tailscale", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Read() error = %v", err)
	}
	if legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
		t.Fatalf("legacy calls = check/discover/read %d/%d/%d", legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
	}
}

func TestTailscaleSourceExecutionFailuresRemainTyped(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		kind sourcecdk.ErrorKind
	}{
		"authentication": {sourceworker.ErrProviderAuthentication, sourcecdk.ErrorKindAuth},
		"permission":     {sourceworker.ErrProviderPermission, sourcecdk.ErrorKindPermission},
		"rate limit":     {sourceworker.ErrProviderRateLimited, sourcecdk.ErrorKindRateLimited},
		"timeout":        {sourceworker.ErrProviderTimeout, sourcecdk.ErrorKindTransient},
		"contract":       {sourceworker.ErrWorkerContract, sourcecdk.ErrorKindDecode},
	} {
		t.Run(name, func(t *testing.T) {
			service := tailscaleAuthorityService(t)
			service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
				return nil, test.err
			}
			_, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "tailscale", Config: tailscalePreviewConfig("user")})
			if !errors.Is(err, test.err) || sourcecdk.SourceErrorKind(err) != test.kind {
				t.Fatalf("Read() error = %v, want %v / %s", err, test.err, test.kind)
			}
		})
	}
}

func TestAzureAuthorizationPolicyCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const graphCredentialFixture = "host-only-graph-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	legacy := &authorityProbeSource{sourceID: "azure"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	calls := 0
	service.runSourceExecution = func(_ context.Context, _ sourceworker.Worker, reference string, credential []byte, _ time.Time, input sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		calls++
		if reference != previewCredentialReference || string(credential) != graphCredentialFixture {
			t.Fatal("Azure graph credential was not confined to the trusted runner boundary")
		}
		encoded, marshalErr := json.Marshal(input)
		if marshalErr != nil || strings.Contains(string(encoded), graphCredentialFixture) || input.Scope.PublicConfig["graph_token"] != "" {
			t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
		}
		if input.SourceID != "azure" || input.FamilyID != "authorization_policy" {
			t.Fatalf("Rust selection = %s.%s", input.SourceID, input.FamilyID)
		}
		return azureAuthorizationPolicyPreviewOutput(input.Scope.PriorTerminalWatermarkUnixMillis), nil
	}
	config := map[string]string{
		"family": "authorization_policy", "tenant_id": "tenant-1", "graph_token": graphCredentialFixture,
	}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "azure", Config: config}); err != nil {
		t.Fatal(err)
	}
	discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "azure", Config: config})
	if err != nil || len(discovered.GetUrns()) != 1 || discovered.GetUrns()[0] != "urn:cerebro:tenant-1:azure_authorization_policy:authorizationPolicy" {
		t.Fatalf("Discover() = %#v, %v", discovered, err)
	}
	read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "azure", Config: config})
	if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "azure" {
		t.Fatalf("Read() = %#v, %v", read, err)
	}
	if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
		t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
	}
}

func TestOtherAzureFamilyRemainsOnGoPreview(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "azure"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		t.Fatal("Rust preview executed for a Go-compatible Azure family")
		return nil, nil
	}
	config := map[string]string{"family": "user"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "azure", Config: config}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "azure", Config: config}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "azure", Config: config}); err != nil {
		t.Fatal(err)
	}
	if legacy.checkCalls != 1 || legacy.discoverCalls != 1 || legacy.readCalls != 1 {
		t.Fatalf("Go calls = check/discover/read %d/%d/%d", legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
	}
}

type authorityProbeSource struct {
	sourceID                             string
	checkCalls, discoverCalls, readCalls int
}

func (s *authorityProbeSource) Spec() *cerebrov1.SourceSpec {
	if s.sourceID == "" {
		return &cerebrov1.SourceSpec{Id: "tailscale"}
	}
	return &cerebrov1.SourceSpec{Id: s.sourceID}
}
func (s *authorityProbeSource) Check(context.Context, sourcecdk.Config) error {
	s.checkCalls++
	return nil
}
func (s *authorityProbeSource) Discover(context.Context, sourcecdk.Config) ([]sourcecdk.URN, error) {
	s.discoverCalls++
	return nil, nil
}
func (s *authorityProbeSource) Read(context.Context, sourcecdk.Config, *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	s.readCalls++
	return sourcecdk.Pull{}, nil
}

type previewWorkerStub struct{}

func (previewWorkerStub) Compile(context.Context, sourceworker.SelectionRequest) (*cerebrov1.SourceExecutionPlanV1, error) {
	return nil, errors.New("unexpected Compile call")
}
func (previewWorkerStub) Context(context.Context, sourceworker.ContextRequest) (*cerebrov1.SourceWorkerExecutionContextV1, error) {
	return nil, errors.New("unexpected Context call")
}
func (previewWorkerStub) PlanV2(context.Context, *cerebrov1.SourceWorkerPlanEnvelopeV2) (*cerebrov1.SourceWorkerHTTPExecutionV2, error) {
	return nil, errors.New("unexpected PlanV2 call")
}
func (previewWorkerStub) DecodeV2(context.Context, *cerebrov1.SourceWorkerDecodeEnvelopeV2) (*cerebrov1.SourceWorkerDecodeOutputV2, error) {
	return nil, errors.New("unexpected DecodeV2 call")
}
func (previewWorkerStub) SealPage(context.Context, sourceworker.PageProgramRequest) (*sourceworker.PageProgram, error) {
	return nil, errors.New("unexpected SealPage call")
}

func tailscaleAuthorityService(t *testing.T) *Service {
	t.Helper()
	registry, err := sourcecdk.NewRegistry(&authorityProbeSource{})
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	return service
}

func tailscalePreviewConfig(family string) map[string]string {
	return map[string]string{"family": family, "tailnet": "example.com", "tenant_id": "tenant-1", "token": "host-only-secret"}
}

func previewOutput(family, nextCursor, checkpointCursor string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	plan := &cerebrov1.SourceExecutionPlanV1{SourceId: "tailscale", FamilyId: family, EventKind: "tailscale." + family, SchemaRef: "tailscale/" + family + "/v1"}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: family + "-1", EventId: "tailscale-tenant-1-" + family + "-1", OccurredAtUnixMillis: watermark,
		Attributes:  map[string]string{"tenant_id": "tenant-1", "family": family, "resource_urn": "urn:cerebro:tenant-1:tailscale_" + family + ":" + family + "-1"},
		PayloadJson: []byte(`{"id":"` + family + `-1"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{NextCursor: nextCursor, ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: checkpointCursor, CheckpointWatermarkUnixMillis: watermark},
	}
}

func azureAuthorizationPolicyPreviewOutput(priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "azure", FamilyId: "authorization_policy", EventKind: "azure.authorization_policy", SchemaRef: "azure/authorization_policy/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "authorizationPolicy", EventId: "azure-authorization-policy-authorizationPolicy", OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"family": "authorization_policy", "resource_id": "authorizationPolicy", "resource_name": "authorizationPolicy",
			"resource_provider": "azure", "resource_type": "authorization_policy",
		},
		PayloadJson: []byte(`{"id":"authorizationPolicy"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: "authorizationPolicy", CheckpointWatermarkUnixMillis: watermark},
	}
}

func jumpCloudPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := family + "-1"
	if family == "audit_events" {
		providerID = "event-1"
	}
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "jumpcloud", FamilyId: family, EventKind: "jumpcloud." + family, SchemaRef: "jumpcloud/" + family + "/v1",
	}
	attributes := map[string]string{
		"family": family, "provider": "jumpcloud", "source_event_id": providerID,
		"resource_id": providerID, "resource_type": family,
	}
	if family == "users" || family == "systems" || family == "applications" {
		attributes["resource_urn"] = "urn:cerebro:tenant-1:jumpcloud_" + family + ":" + family + "-1"
	}
	if family == "group_members" {
		attributes["group_id"] = "group-1"
		attributes["member_id"] = family + "-1"
		attributes["member_user_id"] = family + "-1"
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "jumpcloud-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes:  attributes,
		PayloadJson: []byte(`{"id":"` + family + `-1"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: family + "-1", CheckpointWatermarkUnixMillis: watermark},
	}
}

func sentinelOnePreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := family + "-1"
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "sentinelone", FamilyId: family, EventKind: "sentinelone." + family, SchemaRef: "sentinelone/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "sentinelone-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"family": family, "resource_id": providerID,
			"resource_urn": "urn:cerebro:tenant-1:sentinelone_" + family + ":" + providerID,
		},
		PayloadJson: []byte(`{"id":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
	}
}
