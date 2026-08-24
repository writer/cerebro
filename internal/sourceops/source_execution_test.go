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
