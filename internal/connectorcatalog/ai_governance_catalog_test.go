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
		"cerebras":     {"api_keys", "model_deployments", "projects", "usage_reports"},
		"databricks":   {"audit_events", "assets", "model_serving_endpoints", "vulnerabilities"},
		"fireworks_ai": {"audit_logs", "billing_metrics", "model_deployments", "service_accounts"},
		"huggingface":  {"audit_logs", "organization_members", "repositories", "resource_groups"},
		"mistral":      {"api_keys", "audit_logs", "usage_reports", "workspaces"},
		"openrouter":   {"api_keys", "organization_members", "provider_keys", "usage_reports"},
		"perplexity":   {"api_groups", "api_keys", "team_members", "usage_reports"},
		"snowflake":    {"assets", "audit_events", "cortex_search_services", "vulnerabilities"},
		"together_ai":  {"api_keys", "fine_tuning_jobs", "projects", "usage_reports"},
		"xai":          {"api_keys", "audit_logs", "model_access", "usage_reports"},
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
}
