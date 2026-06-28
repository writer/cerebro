package connectorcatalog

import "testing"

func TestAIGovernanceProvidersAreGenerateable(t *testing.T) {
	analysis, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v; issues = %#v", err, analysis.Issues)
	}
	entries := map[string]Entry{}
	for _, entry := range analysis.Entries {
		entries[entry.Definition.SourceID] = entry
	}
	expected := map[string][]string{
		"anthropic":             {"api_keys", "model_catalog", "organization_invites", "organization_members", "workspaces"},
		"aws_bedrock":           {"custom_models", "foundation_models", "guardrails", "model_customization_jobs", "provisioned_model_throughputs"},
		"azure_openai":          {"deployments", "model_catalog", "private_endpoint_connections", "rai_blocklists", "rai_policies"},
		"cerebras":              {"api_keys", "model_deployments", "projects", "usage_reports"},
		"cloudflare_workers_ai": {"ai_gateways", "gateway_evaluations", "gateway_logs", "gateway_provider_configs", "model_catalog", "vectorize_indexes"},
		"cohere":                {"connectors", "datasets", "fine_tuned_models", "model_catalog"},
		"databricks":            {"audit_events", "assets", "model_serving_endpoints", "vulnerabilities"},
		"deepseek":              {"account_balances", "model_catalog"},
		"elevenlabs":            {"auth_connections", "model_catalog", "service_account_api_keys", "service_accounts", "voices", "webhooks"},
		"fireworks_ai":          {"audit_logs", "billing_metrics", "model_deployments", "service_accounts"},
		"google_gemini":         {"batch_jobs", "cached_contents", "files", "model_catalog", "tuned_models"},
		"google_vertex_ai":      {"batch_prediction_jobs", "custom_jobs", "endpoints", "indexes", "models", "reasoning_engines"},
		"groq":                  {"batch_jobs", "files", "fine_tuning_jobs", "model_catalog"},
		"huggingface":           {"audit_logs", "organization_members", "repositories", "resource_groups"},
		"ibm_watsonx_ai":        {"custom_models", "deployments", "foundation_model_specs", "foundation_model_tasks", "training_jobs"},
		"microsoft_foundry":     {"agents", "connections", "datasets", "evaluations", "indexes"},
		"mistral":               {"api_keys", "audit_logs", "usage_reports", "workspaces"},
		"openrouter":            {"api_keys", "organization_members", "provider_keys", "usage_reports"},
		"perplexity":            {"api_groups", "api_keys", "team_members", "usage_reports"},
		"pinecone":              {"backups", "collections", "indexes", "restore_jobs"},
		"qdrant_cloud":          {"account_members", "accounts", "backup_restores", "backup_schedules", "backups", "clusters", "database_api_keys", "roles"},
		"replicate":             {"collections", "deployments", "models", "predictions"},
		"snowflake":             {"assets", "audit_events", "cortex_search_services", "vulnerabilities"},
		"stability_ai":          {"account", "account_balance", "engines"},
		"together_ai":           {"api_keys", "fine_tuning_jobs", "projects", "usage_reports"},
		"xai":                   {"api_keys", "audit_logs", "model_access", "usage_reports"},
	}
	directProviders := map[string]struct{}{
		"cerebras":     {},
		"fireworks_ai": {},
		"huggingface":  {},
		"mistral":      {},
		"openrouter":   {},
		"perplexity":   {},
		"together_ai":  {},
		"xai":          {},
	}
	for sourceID, families := range expected {
		entry, ok := entries[sourceID]
		if !ok {
			t.Fatalf("source %q is missing from connector catalog", sourceID)
		}
		if entry.Status != StatusGenerateable || !entry.Generateable {
			t.Fatalf("source %q status = %q generateable = %v, want %q true; sourcegen_error=%q", sourceID, entry.Status, entry.Generateable, StatusGenerateable, entry.SourcegenError)
		}
		have := map[string]struct{}{}
		for _, family := range entry.ResourceFamilyIDs {
			have[family] = struct{}{}
		}
		for _, family := range families {
			if _, ok := have[family]; !ok {
				t.Fatalf("source %q missing family %q; have %v", sourceID, family, entry.ResourceFamilyIDs)
			}
		}
		if _, ok := directProviders[sourceID]; ok {
			for _, family := range entry.Definition.ResourceFamilies {
				if sourceID == "huggingface" && family.ID == "repositories" {
					if family.Pagination == nil || family.Pagination.Type != "link" || family.Pagination.CursorParam != "cursor" || family.Pagination.LinkHeader != "Link" || family.Pagination.PageSizeParam != "limit" {
						t.Fatalf("huggingface repositories pagination = %#v, want link pagination", family.Pagination)
					}
					continue
				}
				if family.Pagination == nil || family.Pagination.Type != "none" || !family.Pagination.DisablePageSize {
					t.Fatalf("source %q family %q pagination = %#v, want none with disabled page size", sourceID, family.ID, family.Pagination)
				}
			}
		}
	}
	huggingFace := entries["huggingface"]
	repositories := catalogFamily(t, huggingFace.Definition.ResourceFamilies, "repositories")
	if repositories.Path != "/models" {
		t.Fatalf("huggingface repositories path = %q, want /models", repositories.Path)
	}
	if got := repositories.ConfigQuery["author"]; got != "organization" {
		t.Fatalf("huggingface repositories author config query = %q, want organization", got)
	}
	anthropic := entries["anthropic"]
	if anthropic.Definition.Auth.TokenHeader != "x-api-key" {
		t.Fatalf("anthropic token header = %q, want x-api-key", anthropic.Definition.Auth.TokenHeader)
	}
	if got := anthropic.Definition.Transport.Headers["anthropic-version"]; got != "2023-06-01" {
		t.Fatalf("anthropic version header = %q, want 2023-06-01", got)
	}
	azureOpenAI := entries["azure_openai"]
	deployments := catalogFamily(t, azureOpenAI.Definition.ResourceFamilies, "deployments")
	if got := deployments.StaticQuery["api-version"]; got != "2024-10-01" {
		t.Fatalf("azure_openai deployments api-version = %q, want 2024-10-01", got)
	}
	for _, familyID := range []string{"deployments", "model_catalog", "rai_policies", "rai_blocklists", "private_endpoint_connections"} {
		family := catalogFamily(t, azureOpenAI.Definition.ResourceFamilies, familyID)
		if family.Pagination == nil || family.Pagination.Type != "next_url" || family.Pagination.NextURLJSONPath != "$.nextLink" || !family.Pagination.DisablePageSize {
			t.Fatalf("azure_openai %s pagination = %#v, want nextLink next_url pagination", familyID, family.Pagination)
		}
	}
	cloudflareAI := entries["cloudflare_workers_ai"]
	cloudflareModels := catalogFamily(t, cloudflareAI.Definition.ResourceFamilies, "model_catalog")
	if got := cloudflareModels.StaticQuery["format"]; got != "openrouter" {
		t.Fatalf("cloudflare_workers_ai model_catalog format query = %q, want openrouter", got)
	}
	if cloudflareModels.RecordSelector != "$.data[*]" {
		t.Fatalf("cloudflare_workers_ai model_catalog selector = %q, want OpenRouter-format data selector", cloudflareModels.RecordSelector)
	}
	for _, familyID := range []string{"model_catalog", "ai_gateways", "gateway_provider_configs", "gateway_evaluations", "gateway_logs"} {
		family := catalogFamily(t, cloudflareAI.Definition.ResourceFamilies, familyID)
		if family.Pagination == nil || family.Pagination.Type != "page" || family.Pagination.PageParam != "page" || family.Pagination.PageSizeParam != "per_page" || family.Pagination.StartPage != 1 {
			t.Fatalf("cloudflare_workers_ai %s pagination = %#v, want page/per_page pagination", familyID, family.Pagination)
		}
	}
	gatewayProviderConfigs := catalogFamily(t, cloudflareAI.Definition.ResourceFamilies, "gateway_provider_configs")
	if gatewayProviderConfigs.Path != "/accounts/${config.account_id}/ai-gateway/gateways/${config.gateway_id}/provider_configs" {
		t.Fatalf("cloudflare_workers_ai gateway_provider_configs path = %q, want gateway-scoped provider configs path", gatewayProviderConfigs.Path)
	}
	elevenLabs := entries["elevenlabs"]
	if elevenLabs.Definition.Auth.TokenHeader != "xi-api-key" {
		t.Fatalf("elevenlabs token header = %q, want xi-api-key", elevenLabs.Definition.Auth.TokenHeader)
	}
	elevenLabsVoices := catalogFamily(t, elevenLabs.Definition.ResourceFamilies, "voices")
	if elevenLabsVoices.Pagination == nil || elevenLabsVoices.Pagination.CursorParam != "next_page_token" || elevenLabsVoices.Pagination.CursorJSONPath != "$.next_page_token" || elevenLabsVoices.Pagination.HasMoreKey != "has_more" {
		t.Fatalf("elevenlabs voices pagination = %#v, want next_page_token cursor with has_more", elevenLabsVoices.Pagination)
	}
	serviceAccounts := catalogFamily(t, elevenLabs.Definition.ResourceFamilies, "service_accounts")
	if serviceAccounts.RecordSelector != "$.service-accounts[*]" {
		t.Fatalf("elevenlabs service_accounts selector = %q, want service-accounts list selector", serviceAccounts.RecordSelector)
	}
	serviceAccountAPIKeys := catalogFamily(t, elevenLabs.Definition.ResourceFamilies, "service_account_api_keys")
	if serviceAccountAPIKeys.Path != "/v1/service-accounts/${config.service_account_user_id}/api-keys" || serviceAccountAPIKeys.RecordSelector != "$.api-keys[*]" {
		t.Fatalf("elevenlabs service_account_api_keys path=%q selector=%q, want scoped API key list", serviceAccountAPIKeys.Path, serviceAccountAPIKeys.RecordSelector)
	}
	googleGemini := entries["google_gemini"]
	if googleGemini.Definition.Auth.TokenHeader != "x-goog-api-key" {
		t.Fatalf("google_gemini token header = %q, want x-goog-api-key", googleGemini.Definition.Auth.TokenHeader)
	}
	geminiFiles := catalogFamily(t, googleGemini.Definition.ResourceFamilies, "files")
	if geminiFiles.Pagination == nil || geminiFiles.Pagination.CursorParam != "pageToken" || geminiFiles.Pagination.CursorJSONPath != "$.nextPageToken" {
		t.Fatalf("google_gemini files pagination = %#v, want pageToken cursor", geminiFiles.Pagination)
	}
	ibmWatsonx := entries["ibm_watsonx_ai"]
	modelSpecs := catalogFamily(t, ibmWatsonx.Definition.ResourceFamilies, "foundation_model_specs")
	if got := modelSpecs.StaticQuery["version"]; got != "2024-03-14" {
		t.Fatalf("ibm_watsonx_ai foundation model specs version = %q, want 2024-03-14", got)
	}
	customModels := catalogFamily(t, ibmWatsonx.Definition.ResourceFamilies, "custom_models")
	if customModels.ConfigQuery["project_id"] != "project_id" || len(customModels.ConfigQuery) != 1 {
		t.Fatalf("ibm_watsonx_ai custom_models config query = %#v, want project_id only", customModels.ConfigQuery)
	}
	microsoftFoundry := entries["microsoft_foundry"]
	if microsoftFoundry.Definition.Auth.TokenHeader != "api-key" {
		t.Fatalf("microsoft_foundry token header = %q, want api-key", microsoftFoundry.Definition.Auth.TokenHeader)
	}
	agents := catalogFamily(t, microsoftFoundry.Definition.ResourceFamilies, "agents")
	if got := agents.StaticQuery["api-version"]; got != "v1" {
		t.Fatalf("microsoft_foundry agents api-version = %q, want v1", got)
	}
	pinecone := entries["pinecone"]
	if pinecone.Definition.Auth.TokenHeader != "Api-Key" {
		t.Fatalf("pinecone token header = %q, want Api-Key", pinecone.Definition.Auth.TokenHeader)
	}
	if got := pinecone.Definition.Transport.Headers["X-Pinecone-Api-Version"]; got != "2025-10" {
		t.Fatalf("pinecone API version header = %q, want 2025-10", got)
	}
	for _, familyID := range []string{"backups", "restore_jobs"} {
		family := catalogFamily(t, pinecone.Definition.ResourceFamilies, familyID)
		if family.Pagination == nil || family.Pagination.CursorParam != "paginationToken" || family.Pagination.CursorJSONPath != "$.pagination.next" || family.Pagination.PageSizeParam != "limit" {
			t.Fatalf("pinecone %s pagination = %#v, want paginationToken cursor", familyID, family.Pagination)
		}
	}
	qdrant := entries["qdrant_cloud"]
	if qdrant.Definition.Auth.TokenHeader != "Authorization" || qdrant.Definition.Auth.TokenScheme != "apikey" {
		t.Fatalf("qdrant_cloud auth header=%q scheme=%q, want Authorization apikey", qdrant.Definition.Auth.TokenHeader, qdrant.Definition.Auth.TokenScheme)
	}
	qdrantClusters := catalogFamily(t, qdrant.Definition.ResourceFamilies, "clusters")
	if qdrantClusters.Pagination == nil || qdrantClusters.Pagination.CursorParam != "page_token" || qdrantClusters.Pagination.CursorJSONPath != "$.next_page_token" || qdrantClusters.Pagination.PageSizeParam != "page_size" {
		t.Fatalf("qdrant_cloud clusters pagination = %#v, want page_token cursor", qdrantClusters.Pagination)
	}
	qdrantKeys := catalogFamily(t, qdrant.Definition.ResourceFamilies, "database_api_keys")
	if qdrantKeys.ConfigQuery["cluster_id"] != "cluster_id" {
		t.Fatalf("qdrant_cloud database_api_keys config query = %#v, want cluster_id filter", qdrantKeys.ConfigQuery)
	}
	stability := entries["stability_ai"]
	for _, familyID := range []string{"account", "account_balance"} {
		if family := catalogFamily(t, stability.Definition.ResourceFamilies, familyID); !family.Singleton {
			t.Fatalf("stability_ai family %q singleton = false, want true", familyID)
		}
	}
	for _, test := range []struct {
		sourceID string
		field    string
		required bool
	}{
		{sourceID: "aws_bedrock", field: "region", required: true},
		{sourceID: "aws_bedrock", field: "service", required: true},
		{sourceID: "azure_openai", field: "subscription_id", required: true},
		{sourceID: "azure_openai", field: "resource_group", required: true},
		{sourceID: "azure_openai", field: "account_name", required: true},
		{sourceID: "azure_openai", field: "location", required: true},
		{sourceID: "cloudflare_workers_ai", field: "account_id", required: true},
		{sourceID: "cloudflare_workers_ai", field: "gateway_id", required: true},
		{sourceID: "databricks", field: "workspace_url", required: true},
		{sourceID: "elevenlabs", field: "service_account_user_id", required: true},
		{sourceID: "google_vertex_ai", field: "project_id", required: true},
		{sourceID: "google_vertex_ai", field: "location", required: true},
		{sourceID: "ibm_watsonx_ai", field: "region", required: true},
		{sourceID: "ibm_watsonx_ai", field: "project_id", required: true},
		{sourceID: "microsoft_foundry", field: "endpoint", required: true},
		{sourceID: "microsoft_foundry", field: "project_name", required: true},
		{sourceID: "qdrant_cloud", field: "account_id", required: true},
		{sourceID: "qdrant_cloud", field: "cluster_id"},
		{sourceID: "snowflake", field: "account", required: true},
	} {
		fields := map[string]bool{}
		for _, field := range entries[test.sourceID].Definition.ConfigFields {
			fields[field.Key] = field.Required
		}
		required, ok := fields[test.field]
		if !ok {
			t.Fatalf("source %q missing config field %q", test.sourceID, test.field)
		}
		if required != test.required {
			t.Fatalf("source %q config field %q required = %v, want %v", test.sourceID, test.field, required, test.required)
		}
	}
}
