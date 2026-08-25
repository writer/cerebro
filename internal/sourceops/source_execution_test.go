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
		"Azure authorization policy":  {"azure", "authorization_policy", "authorization_policy", true},
		"other Azure family":          {"azure", "user", "user", false},
		"Anthropic default":           {"anthropic", "", "user", true},
		"Anthropic user":              {"anthropic", "user", "user", true},
		"Anthropic compliance":        {"anthropic", "compliance_activity", "compliance_activity", true},
		"unknown Anthropic family":    {"anthropic", "future-family", "future-family", true},
		"OpenAI default":              {"openai", "", "user", true},
		"OpenAI user":                 {"openai", "user", "user", true},
		"OpenAI project API key":      {"openai", "project_api_key", "project_api_key", true},
		"unknown OpenAI family":       {"openai", "future-family", "future-family", true},
		"DeepSeek default":            {"deepseek", "", "model_catalog", true},
		"DeepSeek model catalog":      {"deepseek", "model_catalog", "model_catalog", true},
		"DeepSeek account balances":   {"deepseek", "account_balances", "account_balances", true},
		"unknown DeepSeek family":     {"deepseek", "future-family", "future-family", true},
		"Azure OpenAI default":        {"azure_openai", "", "deployments", true},
		"Cohere default":              {"cohere", "", "model_catalog", true},
		"Gemini default":              {"google_gemini", "", "model_catalog", true},
		"Vertex default":              {"google_vertex_ai", "", "models", true},
		"Groq default":                {"groq", "", "model_catalog", true},
		"Hugging Face default":        {"huggingface", "", "organization_members", true},
		"Mistral default":             {"mistral", "", "workspaces", true},
		"Perplexity default":          {"perplexity", "", "api_groups", true},
		"AWS Bedrock default":         {"aws_bedrock", "", "foundation_models", true},
		"Langfuse default":            {"langfuse", "", "project", true},
		"unknown portable AI family":  {"mistral", "future-family", "future-family", true},
		"Asana default":               {"asana", "", "users", true},
		"Asana users":                 {"asana", "users", "users", true},
		"Asana projects":              {"asana", "projects", "projects", true},
		"Asana audit events":          {"asana", "audit_events", "audit_events", true},
		"unknown Asana family":        {"asana", "future-family", "future-family", true},
		"DigitalOcean default":        {"digitalocean", "", "droplets", true},
		"DigitalOcean droplets":       {"digitalocean", "droplets", "droplets", true},
		"DigitalOcean VPCs":           {"digitalocean", "vpcs", "vpcs", true},
		"DigitalOcean firewalls":      {"digitalocean", "firewalls", "firewalls", true},
		"unknown DigitalOcean family": {"digitalocean", "future-family", "future-family", true},
		"Discord default":             {"discord", "", "audit_log", true},
		"Discord audit log":           {"discord", "audit_log", "audit_log", true},
		"Discord member":              {"discord", "member", "member", true},
		"Discord role":                {"discord", "role", "role", true},
		"Discord permission":          {"discord", "permission", "permission", true},
		"unknown Discord family":      {"discord", "future-family", "future-family", true},
		"Tailscale default":           {"tailscale", "", "device", true},
		"JumpCloud default":           {"jumpcloud", "", "users", true},
		"JumpCloud family":            {"jumpcloud", "group_members", "group_members", true},
		"unknown JumpCloud family":    {"jumpcloud", "future-family", "future-family", true},
		"Linode default":              {"linode", "", "issue", true},
		"Linode issue":                {"linode", "issue", "issue", true},
		"other Linode family":         {"linode", "event", "event", false},
		"unknown Linode family":       {"linode", "future-family", "future-family", false},
		"PagerDuty default":           {"pagerduty", "", "user", true},
		"PagerDuty user":              {"pagerduty", "user", "user", true},
		"PagerDuty team":              {"pagerduty", "team", "team", true},
		"PagerDuty integration":       {"pagerduty", "integration", "integration", true},
		"unknown PagerDuty family":    {"pagerduty", "future-family", "future-family", true},
		"SentinelOne threat":          {"sentinelone", "threat", "threat", true},
		"SentinelOne application":     {"sentinelone", "application", "application", true},
		"unknown SentinelOne family":  {"sentinelone", "future-family", "future-family", false},
		"compatibility source":        {"gcp", "audit", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			family, authoritative := rustSourceFamily(test.source, map[string]string{"family": test.family})
			if family != test.wantFamily || authoritative != test.wantAuthoritative {
				t.Fatalf("rustSourceFamily() = (%q, %v), want (%q, %v)", family, authoritative, test.wantFamily, test.wantAuthoritative)
			}
		})
	}
}

func TestAsanaCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-asana-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"users", "projects", "audit_events"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "asana"}
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
					t.Fatal("Asana credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "asana" || input.FamilyID != family || input.Scope.PublicConfig["workspace_gid"] != "workspace-1" || input.Scope.PublicConfig["page_size"] != "100" {
					t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
				}
				return asanaPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{
				"family": family, "tenant_id": "tenant-1", "token": credentialFixture,
				"workspace_gid": "workspace-1", "page_size": "100",
			}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "asana", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "asana", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "asana", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "asana" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestAnthropicCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-anthropic-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"user", "compliance_activity"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "anthropic"}
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
					t.Fatal("Anthropic credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["api_key"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "anthropic" || input.FamilyID != family || input.Scope.PublicConfig["auth_model"] != "api_key" || input.Scope.PublicConfig["per_page"] != "100" {
					t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
				}
				return anthropicPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{
				"family": family, "tenant_id": "tenant-1", "api_key": credentialFixture,
				"auth_model": "api_key", "per_page": "100",
			}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "anthropic", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "anthropic", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 || !strings.Contains(discovered.GetUrns()[0], ":anthropic_"+family+":") {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "anthropic", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "anthropic" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestOpenAICheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-openai-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	legacy := &authorityProbeSource{sourceID: "openai"}
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
			t.Fatal("OpenAI credential was not confined to the trusted runner boundary")
		}
		encoded, marshalErr := json.Marshal(input)
		if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["api_key"] != "" {
			t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
		}
		if input.SourceID != "openai" || input.FamilyID != "user" || input.Scope.PublicConfig["per_page"] != "100" {
			t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
		}
		return openAIPreviewOutput(input.Scope.PriorTerminalWatermarkUnixMillis), nil
	}
	config := map[string]string{
		"family": "user", "tenant_id": "tenant-1", "api_key": credentialFixture, "per_page": "100",
	}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "openai", Config: config}); err != nil {
		t.Fatal(err)
	}
	discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "openai", Config: config})
	if err != nil || len(discovered.GetUrns()) != 1 || !strings.Contains(discovered.GetUrns()[0], ":openai_user:") {
		t.Fatalf("Discover() = %#v, %v", discovered, err)
	}
	read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "openai", Config: config})
	if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "openai" || read.GetCheckpoint().GetCursorOpaque() == "" {
		t.Fatalf("Read() = %#v, %v", read, err)
	}
	if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
		t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
	}
}

func TestDeepSeekCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-deepseek-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"model_catalog", "account_balances"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "deepseek"}
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
					t.Fatal("DeepSeek credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["api_key"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "deepseek" || input.FamilyID != family {
					t.Fatalf("Rust selection = %s.%s", input.SourceID, input.FamilyID)
				}
				return deepSeekPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tenant_id": "tenant-1", "api_key": credentialFixture}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "deepseek", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "deepseek", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 || !strings.Contains(discovered.GetUrns()[0], ":deepseek_"+family+":") {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "deepseek", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "deepseek" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestUnknownAsanaFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "asana"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := map[string]string{"family": "future-family", "tenant_id": "tenant-1", "token": "host-only-secret", "workspace_gid": "workspace-1"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "asana", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("legacy check calls = %d", legacy.checkCalls)
	}
}

func TestDiscordCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-discord-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"audit_log", "member", "role", "permission"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "discord"}
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
					t.Fatal("Discord credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["api_token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "discord" || input.FamilyID != family || input.Scope.PublicConfig["guild_id"] != "100000000000000000" || input.Scope.PublicConfig["application_id"] != "200000000000000000" || input.Scope.PublicConfig["per_page"] != "100" {
					t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
				}
				return discordPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{
				"family": family, "tenant_id": "tenant-1", "api_token": credentialFixture,
				"guild_id": "100000000000000000", "application_id": "200000000000000000", "per_page": "100",
			}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "discord", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "discord", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "discord", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "discord" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestUnknownDiscordFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "discord"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := map[string]string{
		"family": "future-family", "tenant_id": "tenant-1", "api_token": "host-only-secret",
		"guild_id": "100000000000000000", "application_id": "200000000000000000",
	}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "discord", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("legacy check calls = %d", legacy.checkCalls)
	}
}

func TestPagerDutyCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-pagerduty-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"user", "team", "service", "schedule", "escalation_policy", "integration", "vendor"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "pagerduty"}
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
					t.Fatal("PagerDuty credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "pagerduty" || input.FamilyID != family || input.Scope.PublicConfig["per_page"] != "100" {
					t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
				}
				if family == "integration" && input.Scope.PublicConfig["service_ids"] != "PS1,PS2" {
					t.Fatalf("integration service scope = %#v", input.Scope.PublicConfig)
				}
				return pagerDutyPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tenant_id": "tenant-1", "token": credentialFixture, "per_page": "100"}
			if family == "integration" {
				config["service_ids"] = "PS1,PS2"
			}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "pagerduty", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "pagerduty", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "pagerduty", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "pagerduty" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestUnknownPagerDutyFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "pagerduty"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := map[string]string{"family": "future-family", "tenant_id": "tenant-1", "token": "host-only-secret"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "pagerduty", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("legacy check calls = %d", legacy.checkCalls)
	}
}

func TestDigitalOceanCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-digitalocean-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	for _, family := range []string{"droplets", "vpcs", "firewalls"} {
		t.Run(family, func(t *testing.T) {
			legacy := &authorityProbeSource{sourceID: "digitalocean"}
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
					t.Fatal("DigitalOcean credential was not confined to the trusted runner boundary")
				}
				encoded, marshalErr := json.Marshal(input)
				if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["token"] != "" {
					t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
				}
				if input.SourceID != "digitalocean" || input.FamilyID != family {
					t.Fatalf("Rust selection = %s.%s", input.SourceID, input.FamilyID)
				}
				return digitalOceanPreviewOutput(family, input.Scope.PriorTerminalWatermarkUnixMillis), nil
			}
			config := map[string]string{"family": family, "tenant_id": "tenant-1", "token": credentialFixture, "per_page": "50"}
			if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "digitalocean", Config: config}); err != nil {
				t.Fatal(err)
			}
			discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "digitalocean", Config: config})
			if err != nil || len(discovered.GetUrns()) != 1 {
				t.Fatalf("Discover() = %#v, %v", discovered, err)
			}
			read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "digitalocean", Config: config})
			if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "digitalocean" || read.GetCheckpoint().GetCursorOpaque() == "" {
				t.Fatalf("Read() = %#v, %v", read, err)
			}
			if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
				t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
			}
		})
	}
}

func TestUnknownDigitalOceanFamilyFailsClosedWithoutLegacyCalls(t *testing.T) {
	legacy := &authorityProbeSource{sourceID: "digitalocean"}
	registry, err := sourcecdk.NewRegistry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	service := New(registry)
	service.sourceWorker = previewWorkerStub{}
	service.runSourceExecution = func(context.Context, sourceworker.Worker, string, []byte, time.Time, sourceworker.ExecutionInput) (*sourceworker.ExecutionOutput, error) {
		return nil, sourceworker.ErrWorkerUnsupported
	}
	config := map[string]string{"family": "future-family", "tenant_id": "tenant-1", "token": "host-only-secret"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "digitalocean", Config: config}); !errors.Is(err, sourceworker.ErrWorkerUnsupported) {
		t.Fatalf("Check() error = %v", err)
	}
	if legacy.checkCalls != 0 {
		t.Fatalf("legacy check calls = %d", legacy.checkCalls)
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

func TestLinodeIssueCheckDiscoverAndReadUseOnlyClosedRustAuthority(t *testing.T) {
	const credentialFixture = "host-only-linode-secret" // #nosec G101 -- synthetic boundary-test sentinel, not credential material.
	legacy := &authorityProbeSource{sourceID: "linode"}
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
			t.Fatal("Linode credential was not confined to the trusted runner boundary")
		}
		encoded, marshalErr := json.Marshal(input)
		if marshalErr != nil || strings.Contains(string(encoded), credentialFixture) || input.Scope.PublicConfig["token"] != "" {
			t.Fatalf("credential crossed the worker protocol: %s, %v", encoded, marshalErr)
		}
		if input.SourceID != "linode" || input.FamilyID != "issue" || input.Scope.PublicConfig["page_size"] != "100" {
			t.Fatalf("Rust selection = %s.%s, public config = %#v", input.SourceID, input.FamilyID, input.Scope.PublicConfig)
		}
		return linodeIssuePreviewOutput(input.Scope.PriorTerminalWatermarkUnixMillis), nil
	}
	config := map[string]string{"family": "issue", "tenant_id": "tenant-1", "token": credentialFixture, "page_size": "100"}
	if _, err := service.Check(context.Background(), &cerebrov1.CheckSourceRequest{SourceId: "linode", Config: config}); err != nil {
		t.Fatal(err)
	}
	discovered, err := service.Discover(context.Background(), &cerebrov1.DiscoverSourceRequest{SourceId: "linode", Config: config})
	if err != nil || len(discovered.GetUrns()) != 1 || discovered.GetUrns()[0] != "urn:cerebro:tenant-1:linode_issue:823" {
		t.Fatalf("Discover() = %#v, %v", discovered, err)
	}
	read, err := service.Read(context.Background(), &cerebrov1.ReadSourceRequest{SourceId: "linode", Config: config})
	if err != nil || len(read.GetEvents()) != 1 || read.GetEvents()[0].GetSourceId() != "linode" || read.GetCheckpoint().GetCursorOpaque() == "" {
		t.Fatalf("Read() = %#v, %v", read, err)
	}
	if calls != 3 || legacy.checkCalls != 0 || legacy.discoverCalls != 0 || legacy.readCalls != 0 {
		t.Fatalf("calls = Rust %d, Go check/discover/read %d/%d/%d", calls, legacy.checkCalls, legacy.discoverCalls, legacy.readCalls)
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

func TestAnthropicPreviewCredentialAliases(t *testing.T) {
	for name, test := range map[string]struct {
		config map[string]string
		want   string
	}{
		"token precedence": {map[string]string{"token": "token", "api_key": "fallback"}, "token"},
		"api token":        {map[string]string{"api_token": "api-token", "api_key": "fallback"}, "api-token"},
		"api key":          {map[string]string{"api_key": "api-key"}, "api-key"},
		"access token":     {map[string]string{"access_token": "access-token"}, "access-token"},
		"missing":          {map[string]string{"graph_token": "wrong-provider"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := previewCredential("anthropic", test.config); got != test.want {
				t.Fatalf("previewCredential() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOpenAIPreviewCredentialAliases(t *testing.T) {
	for name, test := range map[string]struct {
		config map[string]string
		want   string
	}{
		"token precedence": {map[string]string{"token": "token", "api_key": "fallback"}, "token"},
		"api token":        {map[string]string{"api_token": "api-token", "api_key": "fallback"}, "api-token"},
		"api key":          {map[string]string{"api_key": "api-key"}, "api-key"},
		"access token":     {map[string]string{"access_token": "access-token"}, "access-token"},
		"missing":          {map[string]string{"graph_token": "wrong-provider"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := previewCredential("openai", test.config); got != test.want {
				t.Fatalf("previewCredential() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDeepSeekPreviewCredentialAliases(t *testing.T) {
	for name, test := range map[string]struct {
		config map[string]string
		want   string
	}{
		"token precedence": {map[string]string{"token": "token", "api_key": "fallback"}, "token"},
		"api token":        {map[string]string{"api_token": "api-token", "api_key": "fallback"}, "api-token"},
		"api key":          {map[string]string{"api_key": "api-key"}, "api-key"},
		"access token":     {map[string]string{"access_token": "access-token"}, "access-token"},
		"missing":          {map[string]string{"graph_token": "wrong-provider"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := previewCredential("deepseek", test.config); got != test.want {
				t.Fatalf("previewCredential() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPortableAIPreviewCredentialAliasesStayInsideTheTrustedRunner(t *testing.T) {
	for _, sourceID := range []string{"azure_openai", "cohere", "google_gemini", "google_vertex_ai", "groq", "huggingface", "mistral", "perplexity"} {
		t.Run(sourceID, func(t *testing.T) {
			if got := previewCredential(sourceID, map[string]string{"api_key": "api-key", "token": "token"}); got != "token" {
				t.Fatalf("previewCredential() = %q, want token precedence", got)
			}
			if got := previewCredential(sourceID, map[string]string{"api_key": "api-key"}); got != "api-key" {
				t.Fatalf("previewCredential() = %q, want api-key compatibility", got)
			}
		})
	}
}

func TestSpecialAIPreviewCredentialsStayInsideTheTrustedRunner(t *testing.T) {
	aws := previewCredential("aws_bedrock", map[string]string{"access_key": "AKIDEXAMPLE", "secret_key": "synthetic-secret"}) // #nosec G101 -- synthetic fixture.
	if aws != sourceworker.EncodeAWSHostCredential("AKIDEXAMPLE", "synthetic-secret") {
		t.Fatal("AWS preview credential was not encoded for the trusted host")
	}
	langfuse := previewCredential("langfuse", map[string]string{"public_key": "pk-example", "secret_key": "synthetic-secret"}) // #nosec G101 -- synthetic fixture.
	if langfuse != "cGstZXhhbXBsZTpzeW50aGV0aWMtc2VjcmV0" {
		t.Fatal("Langfuse preview credential was not encoded for Basic auth inside the trusted host")
	}
	if previewCredential("aws_bedrock", map[string]string{"access_key": "AKIDEXAMPLE"}) != "" || previewCredential("langfuse", map[string]string{"public_key": "pk-example"}) != "" {
		t.Fatal("incomplete compound credentials must fail closed")
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

func asanaPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := family + "-1"
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "asana", FamilyId: family, EventKind: "asana." + family, SchemaRef: "asana/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "asana-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"tenant_id": "tenant-1", "source_event_id": providerID,
			"resource_id": providerID, "resource_type": strings.TrimSuffix(family, "s"),
			"resource_urn": "urn:cerebro:tenant-1:asana_" + family + ":" + providerID,
		},
		PayloadJson: []byte(`{"gid":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
	}
}

func anthropicPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := family + "-1"
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "anthropic", FamilyId: family, EventKind: "anthropic." + family, SchemaRef: "anthropic/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "anthropic-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"external_id": providerID, "family": family, "provider": "anthropic", "source_provider": "anthropic",
		},
		PayloadJson: []byte(`{"id":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
	}
}

func openAIPreviewOutput(priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "openai", FamilyId: "user", EventKind: "openai.user", SchemaRef: "openai/user/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "user-1", EventId: "openai-tenant-1-user-1", OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"external_id": "user-1", "family": "user", "provider": "openai", "source_provider": "openai",
		},
		PayloadJson: []byte(`{"id":"user-1"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: "user-1", CheckpointWatermarkUnixMillis: watermark},
	}
}

func deepSeekPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := family + "-1"
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "deepseek", FamilyId: family, EventKind: "deepseek." + family, SchemaRef: "deepseek/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "deepseek-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"tenant_id": "tenant-1", "external_id": providerID, "family": family,
			"provider": "deepseek", "source_provider": "deepseek", "resource_id": providerID,
			"resource_type": family, "resource_urn": "urn:cerebro:tenant-1:deepseek_" + family + ":" + providerID,
		},
		PayloadJson: []byte(`{"id":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointWatermarkUnixMillis: watermark},
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

func digitalOceanPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := map[string]string{"droplets": "3164444", "vpcs": "vpc-1111", "firewalls": "fw-2222"}[family]
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "digitalocean", FamilyId: family, EventKind: "digitalocean." + family, SchemaRef: "digitalocean/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "digitalocean-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"tenant_id": "tenant-1", "source_event_id": providerID, "resource_id": providerID,
			"resource_type": strings.TrimSuffix(family, "s"),
			"resource_urn":  "urn:cerebro:tenant-1:digitalocean_" + family + ":" + providerID,
		},
		PayloadJson: []byte(`{"id":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
	}
}

func discordPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := map[string]string{
		"audit_log": "100000000000000001", "member": "100000000000000002",
		"role": "100000000000000003", "permission": "100000000000000004",
	}[family]
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "discord", FamilyId: family, EventKind: "discord." + family, SchemaRef: "discord/" + family + "/v1",
	}
	attributes := map[string]string{
		"tenant_id": "tenant-1", "source_event_id": providerID,
		"resource_id": providerID, "resource_type": family,
		"resource_urn": "urn:cerebro:tenant-1:discord_" + family + ":" + providerID,
	}
	switch family {
	case "audit_log":
		attributes["event_type"] = "10"
	case "member":
		attributes["user_id"] = providerID
	case "role":
		attributes["group_id"] = providerID
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "discord-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: attributes, PayloadJson: []byte(`{"id":"` + providerID + `","avatar":""}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
	}
}

func pagerDutyPreviewOutput(family string, priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	providerID := "P" + strings.ToUpper(strings.ReplaceAll(family, "_", "")) + "1"
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "pagerduty", FamilyId: family, EventKind: "pagerduty." + family, SchemaRef: "pagerduty/" + family + "/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: providerID, EventId: "pagerduty-tenant-1-" + providerID, OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"tenant_id": "tenant-1", "external_id": providerID, "source_event_id": providerID,
			"resource_id": providerID, "resource_type": family,
			"resource_urn": "urn:cerebro:tenant-1:pagerduty_" + family + ":" + providerID,
		},
		PayloadJson: []byte(`{"id":"` + providerID + `"}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: providerID, CheckpointWatermarkUnixMillis: watermark},
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

func linodeIssuePreviewOutput(priorWatermark int64) *sourceworker.ExecutionOutput {
	watermark := max(priorWatermark, 1_725_000_000_000)
	plan := &cerebrov1.SourceExecutionPlanV1{
		SourceId: "linode", FamilyId: "issue", EventKind: "linode.issue", SchemaRef: "linode/issue/v1",
	}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "823", EventId: "linode-tenant-1-c9ca572ccbf1-issue-823", OccurredAtUnixMillis: watermark,
		Attributes: map[string]string{
			"tenant_id": "tenant-1", "source_event_id": "823", "finding_id": "823",
			"resource_urn": "urn:cerebro:tenant-1:linode_issue:823", "severity": "medium", "status": "open",
		},
		PayloadJson: []byte(`{"id":823}`),
	}
	return &sourceworker.ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{ResultDigestSha256: "result-digest"},
		Program: &sourceworker.PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: "823", CheckpointWatermarkUnixMillis: watermark},
	}
}
