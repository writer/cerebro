package sourceworker

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestPullSeparatesTerminalCheckpointFromSameRunContinuation(t *testing.T) {
	terminal := tailscaleOutput("", "user-1", 1_725_000_000_000)
	pull, err := PullFromExecutionOutput(terminal, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if pull.NextCursor != nil {
		t.Fatalf("terminal NextCursor = %#v, want nil", pull.NextCursor)
	}
	providerCursor, watermark, err := ProviderResume(
		&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.GetCursorOpaque()}, "tailscale", "user",
	)
	if err != nil {
		t.Fatal(err)
	}
	if providerCursor != "" || watermark != 1_725_000_000_000 {
		t.Fatalf("restart = (%q, %d), want no provider cursor and terminal watermark", providerCursor, watermark)
	}
	terminalEnvelope, ok := sourcecdk.DecodeCursorEnvelope(pull.Checkpoint.GetCursorOpaque())
	if !ok || terminalEnvelope.Token != "" || len(terminalEnvelope.BoundaryIDs) != 1 || terminalEnvelope.BoundaryIDs[0] != "user-1" {
		t.Fatalf("terminal checkpoint envelope = %#v, %v", terminalEnvelope, ok)
	}

	nonterminal := tailscaleOutput("page-2", "page-2", 1_725_000_001_000)
	pull, err = PullFromExecutionOutput(nonterminal, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if pull.NextCursor.GetOpaque() != "page-2" {
		t.Fatalf("nonterminal NextCursor = %q, want page-2", pull.NextCursor.GetOpaque())
	}
	providerCursor, _, err = ProviderResume(
		&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.GetCursorOpaque()}, "tailscale", "user",
	)
	if err != nil || providerCursor != "page-2" {
		t.Fatalf("nonterminal checkpoint = %q, %v", providerCursor, err)
	}
	continuationEnvelope, ok := sourcecdk.DecodeCursorEnvelope(pull.Checkpoint.GetCursorOpaque())
	if !ok || continuationEnvelope.Token != "page-2" || len(continuationEnvelope.BoundaryIDs) != 0 {
		t.Fatalf("continuation checkpoint envelope = %#v, %v", continuationEnvelope, ok)
	}
}

func TestProviderResumeFailsClosedForMalformedAndCrossFamilyCheckpoints(t *testing.T) {
	for name, cursor := range map[string]string{
		"malformed":    `{"version":1`,
		"cross family": `{"version":1,"source":"tailscale","family":"device","mode":"rust_provider_checkpoint","resumable_checkpoint":true,"token":"device-1"}`,
		"cross source": `{"version":1,"source":"other","family":"user","mode":"rust_provider_checkpoint","resumable_checkpoint":true,"token":"user-1"}`,
		"mixed continuation and boundary": `{"version":1,"source":"tailscale","family":"user","mode":"rust_provider_checkpoint",` +
			`"resumable_checkpoint":true,"token":"page-2","boundary_ids":["user-1"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := ProviderResume(&cerebrov1.SourceCursor{Opaque: cursor}, "tailscale", "user")
			if !errors.Is(err, ErrWorkerContract) {
				t.Fatalf("ProviderResume() error = %v, want ErrWorkerContract", err)
			}
		})
	}
}

func TestPublicExecutionConfigNeverCarriesCredentialMaterial(t *testing.T) {
	public := PublicExecutionConfig(map[string]string{
		"account_sid": " AC123 ", "family": "user", "tailnet": "example.com", "base_url": "https://api.tailscale.com/api/v2",
		"site_id": "site-1", "agent_id": "agent-1", "since": "2026-01-01T00:00:00Z", "until": "2026-02-01T00:00:00Z", "activity_type": "27",
		"page_size": " 100 ", "workspace_gid": " workspace-1 ", "service_id": " PS1 ", "service_ids": " PS1,PS2 ",
		"application_id": " app-1 ", "guild_id": " guild-1 ",
		"token": "secret-token", "graph_token": "secret-graph-token", "tenant_id": "tenant-1",
	})
	if len(public) != 15 || public["account_sid"] != "AC123" || public["site_id"] != "site-1" || public["agent_id"] != "agent-1" || public["application_id"] != "app-1" || public["guild_id"] != "guild-1" || public["since"] == "" || public["until"] == "" || public["activity_type"] != "27" || public["page_size"] != "100" || public["workspace_gid"] != "workspace-1" || public["service_id"] != "PS1" || public["service_ids"] != "PS1,PS2" || public["token"] != "" || public["api_token"] != "" || public["graph_token"] != "" || public["tenant_id"] != "" {
		t.Fatalf("public config leaked private fields: %#v", public)
	}
}

func TestAnthropicPublicExecutionConfigCarriesSelectorsWithoutCredentialMaterial(t *testing.T) {
	public := PublicExecutionConfigForSource("anthropic", map[string]string{
		"family": " usage_report_message ", "auth_model": " bearer_token ",
		"organization_uuid": " org-1 ", "workspace_id": " workspace-1 ",
		"api_key_ids": " key-1,key-2 ", "models": " model-1,model-2 ",
		"api_key": "must-not-cross", "token": "must-not-cross-either",
	})
	if public["family"] != "usage_report_message" || public["auth_model"] != "bearer_token" || public["organization_uuid"] != "org-1" || public["workspace_id"] != "workspace-1" || public["admin_key_ids"] != "key-1,key-2" || public["models"] != "model-1,model-2" {
		t.Fatalf("Anthropic public config lost declared selectors: %#v", public)
	}
	if public["api_key"] != "" || public["token"] != "" || public["api_key_ids"] != "" {
		t.Fatalf("Anthropic public config leaked credential-shaped fields: %#v", public)
	}
}

func TestOpenAIPublicExecutionConfigCarriesSelectorsWithoutCredentialMaterial(t *testing.T) {
	public := PublicExecutionConfigForSource("openai", map[string]string{
		"family": " usage_completion ", "project_id": " project-1 ",
		"user_id": " user-1 ", "api_key_ids": " key-1,key-2 ", "models": " model-1,model-2 ",
		"api_key": "must-not-cross", "token": "must-not-cross-either",
	})
	if public["family"] != "usage_completion" || public["project_id"] != "project-1" || public["user_id"] != "user-1" || public["admin_key_ids"] != "key-1,key-2" || public["models"] != "model-1,model-2" {
		t.Fatalf("OpenAI public config lost declared selectors: %#v", public)
	}
	if public["api_key"] != "" || public["token"] != "" || public["api_key_ids"] != "" {
		t.Fatalf("OpenAI public config leaked credential-shaped fields: %#v", public)
	}
}

func TestPortableAIPublicExecutionConfigCarriesOnlyProviderSelectors(t *testing.T) {
	azure := PublicExecutionConfigForSource("azure_openai", map[string]string{
		"family": " deployments ", "subscription_id": " sub-1 ", "resource_group": " rg-ai ",
		"account_name": " acct-openai ", "location": " westus ", "api_key": "must-not-cross",
	})
	if azure["subscription_id"] != "sub-1" || azure["resource_group"] != "rg-ai" || azure["account_name"] != "acct-openai" || azure["location"] != "westus" || azure["api_key"] != "" {
		t.Fatalf("Azure OpenAI public config = %#v", azure)
	}
	vertex := PublicExecutionConfigForSource("google_vertex_ai", map[string]string{
		"project_id": " project-1 ", "location": " us-central1 ", "token": "must-not-cross",
	})
	if vertex["project_id"] != "project-1" || vertex["location"] != "us-central1" || vertex["token"] != "" {
		t.Fatalf("Vertex public config = %#v", vertex)
	}
	huggingface := PublicExecutionConfigForSource("huggingface", map[string]string{
		"organization": " writer ", "token": "must-not-cross",
	})
	if huggingface["organization"] != "writer" || huggingface["token"] != "" {
		t.Fatalf("Hugging Face public config = %#v", huggingface)
	}
}

func TestRustAuthoritativeFamilyIsAnExactClosedAllowlist(t *testing.T) {
	for name, test := range map[string]struct {
		source, family, wantFamily string
		wantAuthoritative          bool
	}{
		"Azure authorization policy":  {" azure ", " authorization_policy ", "authorization_policy", true},
		"other Azure family":          {"azure", "user", "user", false},
		"Anthropic default":           {" anthropic ", "", "user", true},
		"Anthropic user":              {"anthropic", " user ", "user", true},
		"Anthropic compliance":        {"anthropic", "compliance_activity", "compliance_activity", true},
		"unknown Anthropic family":    {"anthropic", "future-family", "future-family", true},
		"OpenAI default":              {" openai ", "", "user", true},
		"OpenAI user":                 {"openai", " user ", "user", true},
		"OpenAI project API key":      {"openai", "project_api_key", "project_api_key", true},
		"unknown OpenAI family":       {"openai", "future-family", "future-family", true},
		"DeepSeek default":            {" deepseek ", "", "model_catalog", true},
		"DeepSeek model catalog":      {"deepseek", " model_catalog ", "model_catalog", true},
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
		"unknown portable AI family":  {"google_gemini", "future-family", "future-family", true},
		"Asana default":               {" asana ", "", "users", true},
		"Asana users":                 {"asana", " users ", "users", true},
		"Asana projects":              {"asana", "projects", "projects", true},
		"Asana audit events":          {"asana", "audit_events", "audit_events", true},
		"unknown Asana family":        {"asana", "future-family", "future-family", true},
		"DigitalOcean default":        {" digitalocean ", "", "droplets", true},
		"DigitalOcean droplets":       {"digitalocean", " droplets ", "droplets", true},
		"DigitalOcean VPCs":           {"digitalocean", " vpcs ", "vpcs", true},
		"DigitalOcean firewalls":      {"digitalocean", "firewalls", "firewalls", true},
		"unknown DigitalOcean family": {"digitalocean", "future-family", "future-family", true},
		"Discord default":             {" discord ", "", "audit_log", true},
		"Discord audit log":           {"discord", " audit_log ", "audit_log", true},
		"Discord member":              {"discord", "member", "member", true},
		"Discord role":                {"discord", "role", "role", true},
		"Discord permission":          {"discord", "permission", "permission", true},
		"unknown Discord family":      {"discord", "future-family", "future-family", true},
		"JumpCloud default":           {"jumpcloud", "", "users", true},
		"JumpCloud family":            {"jumpcloud", "group_members", "group_members", true},
		"unknown JumpCloud family":    {"jumpcloud", "future-family", "future-family", true},
		"Linode default":              {" linode ", "", "issue", true},
		"Linode issue":                {"linode", " issue ", "issue", true},
		"other Linode family":         {"linode", "event", "event", false},
		"unknown Linode family":       {"linode", "future-family", "future-family", false},
		"PagerDuty default":           {" pagerduty ", "", "user", true},
		"PagerDuty user":              {"pagerduty", " user ", "user", true},
		"PagerDuty team":              {"pagerduty", "team", "team", true},
		"PagerDuty integration":       {"pagerduty", "integration", "integration", true},
		"unknown PagerDuty family":    {"pagerduty", "future-family", "future-family", true},
		"SentinelOne agent":           {" sentinelone ", " agent ", "agent", true},
		"SentinelOne activity":        {"sentinelone", "activity", "activity", true},
		"SentinelOne exclusion":       {"sentinelone", "exclusion", "exclusion", true},
		"SentinelOne group":           {"sentinelone", "group", "group", true},
		"SentinelOne site":            {"sentinelone", "site", "site", true},
		"SentinelOne default":         {"sentinelone", "", "", false},
		"SentinelOne threat":          {"sentinelone", "threat", "threat", true},
		"SentinelOne application":     {"sentinelone", "application", "application", true},
		"Tailscale default":           {"tailscale", "", "device", true},
		"unknown Tailscale family":    {"tailscale", "future-family", "future-family", true},
		"Twilio accounts":             {"twilio", "accounts", "accounts", true},
		"Twilio audit events":         {"twilio", "audit_events", "audit_events", true},
		"Twilio keys":                 {"twilio", "keys", "keys", true},
		"unknown Twilio family":       {"twilio", "future-family", "future-family", false},
		"compatibility source":        {"gcp", "audit", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			family, authoritative := RustAuthoritativeFamily(test.source, test.family)
			if family != test.wantFamily || authoritative != test.wantAuthoritative {
				t.Fatalf("RustAuthoritativeFamily() = (%q, %v), want (%q, %v)", family, authoritative, test.wantFamily, test.wantAuthoritative)
			}
		})
	}
}

func TestCredentialBindingUsesOnlyTheSelectedProviderAliases(t *testing.T) {
	for name, test := range map[string]struct {
		source                      string
		references, resolved        map[string]string
		wantReference, wantResolved string
	}{
		"Azure graph token": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "azure", references: map[string]string{"graph_token": "credential:azure:graph", "token": "credential:azure:fallback"},
			resolved: map[string]string{"graph_token": "resolved-graph", "token": "resolved-fallback"}, wantReference: "credential:azure:graph", wantResolved: "resolved-graph",
		},
		"Discord bot token": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "discord", references: map[string]string{"api_token": "credential:discord:bot-token", "token": "credential:discord:fallback"},
			resolved:      map[string]string{"api_token": "resolved-bot-token", "token": "resolved-fallback"}, // #nosec G101 -- synthetic resolved-value fixture.
			wantReference: "credential:discord:bot-token", wantResolved: "resolved-bot-token",
		},
		"Discord api key compatibility": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "discord", references: map[string]string{"api_key": "credential:discord:api-key"},
			resolved: map[string]string{"api_key": "resolved-api-key"}, wantReference: "credential:discord:api-key", wantResolved: "resolved-api-key",
		},
		"JumpCloud api key": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "jumpcloud", references: map[string]string{"api_key": "credential:jumpcloud:api-key", "token": "credential:jumpcloud:fallback"},
			resolved: map[string]string{"api_key": "resolved-api-key", "token": "resolved-fallback"}, wantReference: "credential:jumpcloud:api-key", wantResolved: "resolved-api-key",
		},
		"Anthropic token precedence": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "anthropic", references: map[string]string{"token": "credential:anthropic:token", "api_key": "credential:anthropic:api-key"},
			resolved: map[string]string{"token": "resolved-token", "api_key": "resolved-api-key"}, wantReference: "credential:anthropic:token", wantResolved: "resolved-token",
		},
		"Anthropic api key": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "anthropic", references: map[string]string{"api_key": "credential:anthropic:api-key"},
			resolved: map[string]string{"api_key": "resolved-api-key"}, wantReference: "credential:anthropic:api-key", wantResolved: "resolved-api-key",
		},
		"OpenAI api key": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "openai", references: map[string]string{"api_key": "credential:openai:api-key"},
			resolved: map[string]string{"api_key": "resolved-api-key"}, wantReference: "credential:openai:api-key", wantResolved: "resolved-api-key",
		},
		"DeepSeek api key": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "deepseek", references: map[string]string{"api_key": "credential:deepseek:api-key"},
			resolved: map[string]string{"api_key": "resolved-api-key"}, wantReference: "credential:deepseek:api-key", wantResolved: "resolved-api-key",
		},
		"Gemini api key": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "google_gemini", references: map[string]string{"api_key": "credential:gemini:api-key"},
			resolved: map[string]string{"api_key": "resolved-api-key"}, wantReference: "credential:gemini:api-key", wantResolved: "resolved-api-key",
		},
		"AWS Bedrock compound host credential": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "aws_bedrock", references: map[string]string{"access_key": "credential:aws:access", "secret_key": "credential:aws:secret"},
			resolved: map[string]string{"access_key": "AKIDEXAMPLE", "secret_key": "synthetic-secret"}, wantReference: "credential:aws:secret", wantResolved: EncodeAWSHostCredential("AKIDEXAMPLE", "synthetic-secret"),
		},
		"Langfuse basic host credential": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "langfuse", references: map[string]string{"public_key": "credential:langfuse:public", "secret_key": "credential:langfuse:secret"},
			resolved: map[string]string{"public_key": "pk-example", "secret_key": "synthetic-secret"}, wantReference: "credential:langfuse:secret", wantResolved: "cGstZXhhbXBsZTpzeW50aGV0aWMtc2VjcmV0",
		},
		"Twilio basic credentials": {
			// #nosec G101 -- synthetic credential-reference and resolved-value fixtures.
			source: "twilio", references: map[string]string{"username": "AC123", "password": "credential:twilio:password"},
			resolved: map[string]string{"username": "AC123", "password": "synthetic-password"}, wantReference: "credential:twilio:password", wantResolved: "QUMxMjM6c3ludGhldGljLXBhc3N3b3Jk",
		},
		"aliases cannot cross": {
			source: "jumpcloud", references: map[string]string{"api_key": "credential:jumpcloud:api-key"},
			resolved: map[string]string{"token": "resolved-different-alias"}, wantReference: "credential:jumpcloud:api-key", wantResolved: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			reference, resolved := CredentialBinding(test.source, test.references, test.resolved)
			if reference != test.wantReference || resolved != test.wantResolved {
				t.Fatalf("CredentialBinding() = (%q, %q), want (%q, %q)", reference, resolved, test.wantReference, test.wantResolved)
			}
		})
	}
}

func TestTrustedHostCredentialReferenceMatchesGoogleWorkspaceAuthMode(t *testing.T) {
	for name, test := range map[string]struct {
		references map[string]string
		resolved   map[string]string
		want       string
	}{
		"static token": {
			references: map[string]string{"token": "credential:google-workspace:token"}, // #nosec G101 -- opaque reference fixture.
			resolved:   map[string]string{"token": "static-token"},
			want:       "credential:google-workspace:token",
		},
		"delegated service account private key": {
			references: map[string]string{"private_key": "env:GOOGLE_WORKSPACE_PRIVATE_KEY"},
			resolved: map[string]string{
				"service_account_email": "service-account@example.com",
				"private_key":           "private-key-material",
				"delegated_admin_email": "admin@example.com",
			},
			want: "env:GOOGLE_WORKSPACE_PRIVATE_KEY",
		},
		"service account alias": {
			references: map[string]string{"service_account_private_key": "env:GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY"},
			resolved: map[string]string{
				"service_account_email":       "service-account@example.com",
				"service_account_private_key": "private-key-material",
				"subject_email":               "admin@example.com",
			},
			want: "env:GOOGLE_WORKSPACE_SERVICE_ACCOUNT_PRIVATE_KEY",
		},
		"OAuth refresh token": {
			references: map[string]string{"refresh_token": "credential:google-workspace:refresh-token"}, // #nosec G101 -- opaque reference fixture.
			resolved: map[string]string{
				"client_id": "client-id", "client_secret": "client-secret", "refresh_token": "refresh-token",
			},
			want: "credential:google-workspace:refresh-token",
		},
		"incomplete mode fails closed": {
			references: map[string]string{"private_key": "env:GOOGLE_WORKSPACE_PRIVATE_KEY"},
			resolved:   map[string]string{"private_key": "private-key-material"},
		},
		"other providers cannot use adapter": {
			references: map[string]string{"token": "credential:other:token"}, // #nosec G101 -- opaque reference fixture.
			resolved:   map[string]string{"token": "token"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			sourceID := "google_workspace"
			if name == "other providers cannot use adapter" {
				sourceID = "other"
			}
			if got := TrustedHostCredentialReference(sourceID, test.references, test.resolved); got != test.want {
				t.Fatalf("TrustedHostCredentialReference() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAzureAuthorizationPolicyPersistsARestartableRustCheckpoint(t *testing.T) {
	output := tailscaleOutput("", "authorizationPolicy", 1_725_000_000_000)
	output.Plan.SourceId = "azure"
	output.Plan.FamilyId = "authorization_policy"
	pull, err := PullFromExecutionOutput(output, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	providerCursor, watermark, err := ProviderResume(
		&cerebrov1.SourceCursor{Opaque: pull.Checkpoint.GetCursorOpaque()}, "azure", "authorization_policy",
	)
	if err != nil {
		t.Fatal(err)
	}
	if providerCursor != "" || watermark != 1_725_000_000_000 {
		t.Fatalf("restart = (%q, %d), want no provider cursor and terminal watermark", providerCursor, watermark)
	}
}

func tailscaleOutput(nextCursor, checkpointCursor string, watermark int64) *ExecutionOutput {
	plan := &cerebrov1.SourceExecutionPlanV1{SourceId: "tailscale", FamilyId: "user", EventKind: "tailscale.user", SchemaRef: "tailscale/user/v1"}
	record := &cerebrov1.SourceWorkerRecordV1{
		ProviderId: "user-1", EventId: "tailscale-tenant-1-user-user-1", OccurredAtUnixMillis: watermark,
		Attributes:  map[string]string{"tenant_id": "tenant-1", "family": "user", "resource_urn": "urn:cerebro:tenant-1:tailscale_user:user-1"},
		PayloadJson: []byte(`{"id":"user-1"}`),
	}
	return &ExecutionOutput{
		Plan: plan, Result: &cerebrov1.SourceWorkerDecodeResultV1{NextCursor: nextCursor, ResultDigestSha256: "digest"},
		Program: &PageProgram{TransitionDigest: "transition", AdmittedRecords: []*cerebrov1.SourceWorkerRecordV1{record}, CheckpointCursor: checkpointCursor, CheckpointWatermarkUnixMillis: watermark},
	}
}
