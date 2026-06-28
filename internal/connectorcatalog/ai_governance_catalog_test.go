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
		"anthropic":         {"api_keys", "model_catalog", "organization_invites", "organization_members", "workspaces"},
		"aws_bedrock":       {"custom_models", "foundation_models", "guardrails", "model_customization_jobs", "provisioned_model_throughputs"},
		"azure_openai":      {"deployments", "model_catalog", "private_endpoint_connections", "rai_blocklists", "rai_policies"},
		"cerebras":          {"api_keys", "model_deployments", "projects", "usage_reports"},
		"cohere":            {"connectors", "datasets", "fine_tuned_models", "model_catalog"},
		"databricks":        {"audit_events", "assets", "model_serving_endpoints", "vulnerabilities"},
		"deepseek":          {"account_balances", "model_catalog"},
		"fireworks_ai":      {"audit_logs", "billing_metrics", "model_deployments", "service_accounts"},
		"google_gemini":     {"batch_jobs", "cached_contents", "files", "model_catalog", "tuned_models"},
		"google_vertex_ai":  {"batch_prediction_jobs", "custom_jobs", "endpoints", "indexes", "models", "reasoning_engines"},
		"groq":              {"batch_jobs", "files", "fine_tuning_jobs", "model_catalog"},
		"huggingface":       {"audit_logs", "organization_members", "repositories", "resource_groups"},
		"ibm_watsonx_ai":    {"custom_models", "deployments", "foundation_model_specs", "foundation_model_tasks", "training_jobs"},
		"microsoft_foundry": {"agents", "connections", "datasets", "evaluations", "indexes"},
		"mistral":           {"api_keys", "audit_logs", "usage_reports", "workspaces"},
		"openrouter":        {"api_keys", "organization_members", "provider_keys", "usage_reports"},
		"perplexity":        {"api_groups", "api_keys", "team_members", "usage_reports"},
		"replicate":         {"collections", "deployments", "models", "predictions"},
		"snowflake":         {"assets", "audit_events", "cortex_search_services", "vulnerabilities"},
		"stability_ai":      {"account", "account_balance", "engines"},
		"together_ai":       {"api_keys", "fine_tuning_jobs", "projects", "usage_reports"},
		"xai":               {"api_keys", "audit_logs", "model_access", "usage_reports"},
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
	stability := entries["stability_ai"]
	for _, familyID := range []string{"account", "account_balance"} {
		if family := catalogFamily(t, stability.Definition.ResourceFamilies, familyID); !family.Singleton {
			t.Fatalf("stability_ai family %q singleton = false, want true", familyID)
		}
	}
	for _, test := range []struct {
		sourceID string
		field    string
	}{
		{sourceID: "aws_bedrock", field: "region"},
		{sourceID: "aws_bedrock", field: "service"},
		{sourceID: "azure_openai", field: "subscription_id"},
		{sourceID: "azure_openai", field: "resource_group"},
		{sourceID: "azure_openai", field: "account_name"},
		{sourceID: "azure_openai", field: "location"},
		{sourceID: "databricks", field: "workspace_url"},
		{sourceID: "google_vertex_ai", field: "project_id"},
		{sourceID: "google_vertex_ai", field: "location"},
		{sourceID: "ibm_watsonx_ai", field: "region"},
		{sourceID: "ibm_watsonx_ai", field: "project_id"},
		{sourceID: "microsoft_foundry", field: "endpoint"},
		{sourceID: "microsoft_foundry", field: "project_name"},
		{sourceID: "snowflake", field: "account"},
	} {
		fields := map[string]struct{}{}
		for _, field := range entries[test.sourceID].Definition.ConfigFields {
			fields[field.Key] = struct{}{}
		}
		if _, ok := fields[test.field]; !ok {
			t.Fatalf("source %q missing config field %q", test.sourceID, test.field)
		}
	}
}
