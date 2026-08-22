package langchain_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/sources/catalogruntime"
	"gopkg.in/yaml.v3"
)

func TestCatalogDeclaresLangSmithFamilyContracts(t *testing.T) {
	entry := langChainEntry(t)
	if entry.Definition.Auth.Model != "api_key" || entry.Definition.Auth.TokenHeader != "X-API-Key" || entry.Definition.Auth.TokenScheme != "" {
		t.Fatalf("default auth = %#v, want unschemed X-API-Key", entry.Definition.Auth)
	}
	if !hasConfigField(entry.Definition.ConfigFields, "auth_model") {
		t.Fatal("auth_model config field is missing")
	}
	want := map[string]struct {
		method string
		path   string
	}{
		"organization":        {"GET", "/api/v1/orgs/current"},
		"workspace":           {"GET", "/api/v1/workspaces"},
		"organization_member": {"GET", "/api/v1/orgs/current/members"},
		"workspace_member":    {"GET", "/api/v1/workspaces/current/members"},
		"role":                {"GET", "/api/v1/orgs/current/roles"},
		"api_key":             {"GET", "/api/v1/orgs/current/service-keys"},
		"service_account":     {"GET", "/api/v1/service-accounts"},
		"project":             {"GET", "/api/v1/sessions"},
		"run":                 {"POST", "/api/v1/runs/query"},
		"feedback":            {"GET", "/api/v1/feedback"},
		"dataset":             {"GET", "/api/v1/datasets"},
		"usage_limit":         {"GET", "/api/v1/usage-limits"},
		"audit_log":           {"GET", "/api/v1/audit-logs"},
	}
	if len(entry.Definition.ResourceFamilies) != len(want) {
		t.Fatalf("family count = %d, want %d", len(entry.Definition.ResourceFamilies), len(want))
	}
	for _, family := range entry.Definition.ResourceFamilies {
		contract, ok := want[family.ID]
		if !ok {
			t.Fatalf("unexpected family %q", family.ID)
		}
		method := family.Method
		if method == "" {
			method = "GET"
		}
		if method != contract.method || family.Path != contract.path {
			t.Fatalf("%s request = %s %s, want %s %s", family.ID, method, family.Path, contract.method, contract.path)
		}
	}
}

func TestCatalogDeclaresLangSmithScopePaginationAndQueryMappings(t *testing.T) {
	entry := langChainEntry(t)
	families := familyMap(entry.Definition.ResourceFamilies)
	organization := families["organization"]
	if !organization.Singleton || organization.Pagination == nil || !organization.Pagination.DisablePageSize {
		t.Fatalf("organization singleton contract = %#v", organization)
	}
	for _, id := range []string{"workspace_member", "project", "run", "feedback", "dataset", "usage_limit", "audit_log"} {
		family := families[id]
		if family.Config == nil || family.Config.ConfigHeaders["X-Organization-Id"] != "organization_id" || family.Config.ConfigHeaders["X-Tenant-Id"] != "workspace_id" {
			t.Fatalf("%s scope headers = %#v", id, family.Config)
		}
		if family.Config.ConfigAttributes["organization_id"] != "organization_id" || family.Config.ConfigAttributes["workspace_id"] != "workspace_id" {
			t.Fatalf("%s scope attributes = %#v", id, family.Config.ConfigAttributes)
		}
	}
	for _, id := range []string{"project", "feedback", "dataset"} {
		pagination := families[id].Pagination
		if pagination == nil || pagination.Type != "offset" || pagination.OffsetParam != "offset" || pagination.LimitParam != "limit" || !pagination.InjectFirstPage || pagination.StartPage != 0 {
			t.Fatalf("%s pagination = %#v", id, pagination)
		}
	}
	if got := families["project"].Config.ConfigQuery; !reflect.DeepEqual(got, map[string]string{"filter": "filter", "include_stats": "include_stats", "name": "name", "name_contains": "name_contains"}) {
		t.Fatalf("project query mapping = %#v", got)
	}
	if got := families["feedback"].Config.ConfigQuery; !reflect.DeepEqual(got, map[string]string{"feedback_source": "feedback_source", "key": "key", "run": "run_id"}) {
		t.Fatalf("feedback query mapping = %#v", got)
	}
	if got := families["dataset"].Config.ConfigQuery; !reflect.DeepEqual(got, map[string]string{"name": "name", "name_contains": "name_contains"}) {
		t.Fatalf("dataset query mapping = %#v", got)
	}
	run := families["run"]
	if run.Pagination == nil || run.Pagination.Type != "cursor" || run.Pagination.CursorParam != "cursor" || run.Pagination.CursorJSONPath != "$.cursors.next" || !run.Pagination.CursorInJSONBody {
		t.Fatalf("run pagination = %#v", run.Pagination)
	}
	audit := families["audit_log"]
	if audit.Pagination == nil || audit.Pagination.Type != "cursor" || audit.Pagination.CursorJSONPath != "$.cursor" || audit.Pagination.CursorInJSONBody {
		t.Fatalf("audit pagination = %#v", audit.Pagination)
	}
}

func TestCatalogDeclaresSelectableAuthAndRunJSONBodyMappings(t *testing.T) {
	payload, err := os.ReadFile("../../internal/connectorcatalog/catalog/ai-governance/langchain.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Entries []struct {
			Definition struct {
				Auth struct {
					ConfigurableModels []string `yaml:"configurable_models"`
					ModelConfigKey     string   `yaml:"model_config_key"`
				} `yaml:"auth"`
				ResourceFamilies []struct {
					ID   string `yaml:"id"`
					Read struct {
						ConfigJSONBody map[string]string `yaml:"config_json_body"`
					} `yaml:"read"`
				} `yaml:"resource_families"`
			} `yaml:"definition"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(payload, &file); err != nil {
		t.Fatal(err)
	}
	auth := file.Entries[0].Definition.Auth
	if !reflect.DeepEqual(auth.ConfigurableModels, []string{"api_key", "bearer_token"}) || auth.ModelConfigKey != "auth_model" {
		t.Fatalf("selectable auth = %#v", auth)
	}
	for _, family := range file.Entries[0].Definition.ResourceFamilies {
		if family.ID != "run" {
			continue
		}
		want := map[string]string{"project": "project", "session": "session", "start_time": "start_time", "end_time": "end_time", "run_type": "run_type", "filter": "filter"}
		if !reflect.DeepEqual(family.Read.ConfigJSONBody, want) {
			t.Fatalf("run JSON-body mapping = %#v, want %#v", family.Read.ConfigJSONBody, want)
		}
		return
	}
	t.Fatal("run family not found")
}

func TestLangSmithThirteenFamilyFixtureCorpus(t *testing.T) {
	entry := langChainEntry(t)
	paths, err := filepath.Glob("testdata/read_*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 13 {
		t.Fatalf("fixture count = %d, want 13", len(paths))
	}
	wantFamilies := make([]string, 0, len(entry.Definition.ResourceFamilies))
	for _, family := range entry.Definition.ResourceFamilies {
		wantFamilies = append(wantFamilies, family.ID)
	}
	sort.Strings(wantFamilies)
	gotFamilies := make([]string, 0, len(paths))
	for _, path := range paths {
		familyID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "read_"), ".json")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result, err := catalogruntime.ReadDefinitionFixture(context.Background(), entry.Definition, familyID, body)
		if err != nil {
			t.Fatalf("ReadDefinitionFixture(%s) error = %v", familyID, err)
		}
		if result.EventCount != 1 || len(result.EventKinds) != 1 || result.EventKinds[0] != "langchain."+familyID {
			t.Fatalf("%s fixture result = %#v", familyID, result)
		}
		gotFamilies = append(gotFamilies, familyID)
	}
	sort.Strings(gotFamilies)
	if !reflect.DeepEqual(gotFamilies, wantFamilies) {
		t.Fatalf("fixture families = %#v, want %#v", gotFamilies, wantFamilies)
	}
}

func langChainEntry(t *testing.T) connectorcatalog.Entry {
	t.Helper()
	entry, found, err := connectorcatalog.BuiltinEntry("langchain")
	if err != nil {
		t.Fatalf("BuiltinEntry(langchain) error = %v", err)
	}
	if !found || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
		t.Fatalf("langchain catalog entry = found %t, verdict %q", found, entry.Report.Verdict)
	}
	return entry
}

func familyMap(families []connectordefinitions.ResourceFamily) map[string]connectordefinitions.ResourceFamily {
	out := make(map[string]connectordefinitions.ResourceFamily, len(families))
	for _, family := range families {
		out[family.ID] = family
	}
	return out
}

func hasConfigField(fields []connectordefinitions.Field, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return true
		}
	}
	return false
}
