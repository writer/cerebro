package catalogruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestConjurCatalogRuntimeAuthority(t *testing.T) {
	entry := supportedCatalogEntry(t, "conjur")
	definition := entry.Definition
	if definition.Auth.Model != "basic" || definition.Auth.TokenHeader != "Authorization" || definition.Auth.TokenScheme != "Basic" {
		t.Fatalf("auth = %#v, want Basic Authorization contract", definition.Auth)
	}
	if definition.Transport == nil || definition.Transport.Verification == nil {
		t.Fatal("transport verification is required")
	}
	verification := definition.Transport.Verification
	if verification.Path != "/resources" || verification.ConfigPath != "health_path" {
		t.Fatalf("verification = %#v, want /resources with health_path override", verification)
	}
	wantPaths := map[string]string{
		"authenticator": "/authenticators",
		"resource":      "/resources",
		"resource_2":    "/resources/${config.account}",
		"resource_3":    "/resources/${config.account}/${config.kind}",
	}
	if len(definition.ResourceFamilies) != len(wantPaths) {
		t.Fatalf("family count = %d, want %d", len(definition.ResourceFamilies), len(wantPaths))
	}
	for _, family := range definition.ResourceFamilies {
		if family.Path != wantPaths[family.ID] {
			t.Fatalf("%s path = %q, want %q", family.ID, family.Path, wantPaths[family.ID])
		}
		if family.ID == "authenticator" {
			if family.ListKey != "configured" || family.Read == nil || !family.Read.DisablePageSize {
				t.Fatalf("authenticator read contract = %#v", family)
			}
			continue
		}
		if family.Read == nil || family.Read.MapRecords["data.key_info"] != "resource" {
			t.Fatalf("%s map-record contract = %#v", family.ID, family.Read)
		}
		pagination := family.Pagination
		if pagination == nil || pagination.Type != "offset" || !pagination.InjectFirstPage || pagination.OffsetParam != "offset" || pagination.LimitParam != "limit" {
			t.Fatalf("%s pagination = %#v", family.ID, pagination)
		}
	}
}

func TestConjurCatalogRuntimeBasicVariantsAndNestedMap(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "conjur", "testdata", "provider_resource_key_info.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantPair := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:fixture-password"))
	for _, test := range []struct {
		name        string
		credentials map[string]string
		wantHeader  string
	}{
		{name: "username_password", credentials: map[string]string{"username": "alice", "password": "fixture-password"}, wantHeader: wantPair},
		{name: "precomputed_basic", credentials: map[string]string{"token": "fixture-basic-token"}, wantHeader: "Basic fixture-basic-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.RequestURI())
				if got := r.Header.Get("Authorization"); got != test.wantHeader {
					t.Errorf("Authorization = %q, want %q", got, test.wantHeader)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(fixture)
			}))
			defer server.Close()
			entry := supportedCatalogEntry(t, "conjur")
			source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{
				"account": "myorg", "base_url": server.URL, "family": "resource_3", "health_path": "/resources/myorg/variable", "kind": "variable", "tenant_id": "tenant",
			}
			for key, value := range test.credentials {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(paths) != 2 || !strings.HasPrefix(paths[1], "/resources/myorg/variable?") || !strings.Contains(paths[1], "offset=0") || !strings.Contains(paths[1], "limit=100") {
				t.Fatalf("request paths = %#v", paths)
			}
			if len(pull.Events) != 2 {
				t.Fatalf("event count = %d, want 2", len(pull.Events))
			}
			ids := []string{pull.Events[0].Attributes["resource_id"], pull.Events[1].Attributes["resource_id"]}
			sort.Strings(ids)
			wantIDs := []string{"myorg:variable:apps/api/password", "myorg:variable:apps/web/password"}
			if !reflect.DeepEqual(ids, wantIDs) {
				t.Fatalf("resource IDs = %#v, want %#v", ids, wantIDs)
			}
			for _, event := range pull.Events {
				if event.Kind != "conjur.resource_3" || event.SchemaRef != "conjur/resource_3/v1" || event.Attributes["resource_name"] == "" || event.Attributes["resource_type"] != "resource" {
					t.Fatalf("event contract = %#v", event)
				}
			}
		})
	}
}

func TestLangSmithCatalogRuntimeAuthority(t *testing.T) {
	definition := supportedCatalogEntry(t, "langchain").Definition
	if definition.Auth.Model != "api_key" || definition.Auth.TokenHeader != "X-API-Key" || definition.Auth.TokenScheme != "" {
		t.Fatalf("default auth = %#v, want unschemed X-API-Key", definition.Auth)
	}
	if !reflect.DeepEqual(definition.Auth.ConfigurableModels, []string{"api_key", "bearer_token"}) || definition.Auth.ModelConfigKey != "auth_model" {
		t.Fatalf("selectable auth = %#v", definition.Auth)
	}
	wantPaths := map[string]string{
		"organization": "/api/v1/orgs/current", "workspace": "/api/v1/workspaces", "organization_member": "/api/v1/orgs/current/members",
		"workspace_member": "/api/v1/workspaces/current/members", "role": "/api/v1/orgs/current/roles", "api_key": "/api/v1/orgs/current/service-keys",
		"service_account": "/api/v1/service-accounts", "project": "/api/v1/sessions", "run": "/api/v1/runs/query", "feedback": "/api/v1/feedback",
		"dataset": "/api/v1/datasets", "usage_limit": "/api/v1/usage-limits", "audit_log": "/api/v1/audit-logs",
	}
	families := definitionFamilyMap(definition.ResourceFamilies)
	if len(families) != 13 {
		t.Fatalf("family count = %d, want 13", len(families))
	}
	for id, path := range wantPaths {
		if families[id].Path != path {
			t.Fatalf("%s path = %q, want %q", id, families[id].Path, path)
		}
	}
	if !families["organization"].Singleton || !families["organization"].Pagination.DisablePageSize {
		t.Fatalf("organization singleton = %#v", families["organization"])
	}
	for _, id := range []string{"workspace_member", "project", "run", "feedback", "dataset", "usage_limit", "audit_log"} {
		config := families[id].Config
		if config == nil || config.ConfigHeaders["X-Organization-Id"] != "organization_id" || config.ConfigHeaders["X-Tenant-Id"] != "workspace_id" || config.ConfigAttributes["organization_id"] != "organization_id" || config.ConfigAttributes["workspace_id"] != "workspace_id" {
			t.Fatalf("%s scope = %#v", id, config)
		}
	}
	for _, id := range []string{"project", "feedback", "dataset"} {
		pagination := families[id].Pagination
		if pagination == nil || pagination.Type != "offset" || pagination.OffsetParam != "offset" || pagination.LimitParam != "limit" || !pagination.InjectFirstPage || pagination.StartPage != 0 {
			t.Fatalf("%s pagination = %#v", id, pagination)
		}
	}
	run := families["run"]
	if run.Method != http.MethodPost || run.Read == nil || !reflect.DeepEqual(run.Read.ConfigJSONBody, map[string]string{"project": "project", "session": "session", "start_time": "start_time", "end_time": "end_time", "run_type": "run_type", "filter": "filter"}) {
		t.Fatalf("run body contract = %#v", run)
	}
	if run.Pagination == nil || run.Pagination.Type != "cursor" || run.Pagination.CursorParam != "cursor" || run.Pagination.CursorJSONPath != "$.cursors.next" || !run.Pagination.CursorInJSONBody {
		t.Fatalf("run pagination = %#v", run.Pagination)
	}
	audit := families["audit_log"]
	if audit.Pagination == nil || audit.Pagination.Type != "cursor" || audit.Pagination.CursorJSONPath != "$.cursor" || audit.Pagination.CursorInJSONBody {
		t.Fatalf("audit pagination = %#v", audit.Pagination)
	}
}

func TestLangSmithCatalogRuntimeAuthHeadersBodyAndCursor(t *testing.T) {
	entry := supportedCatalogEntry(t, "langchain")
	for _, test := range []struct {
		name       string
		authModel  string
		wantHeader string
	}{
		{name: "api_key", authModel: "api_key", wantHeader: "X-API-Key:fixture-secret"},
		{name: "bearer", authModel: "bearer_token", wantHeader: "Authorization:Bearer fixture-secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				parts := strings.SplitN(test.wantHeader, ":", 2)
				if got := r.Header.Get(parts[0]); got != parts[1] {
					t.Errorf("%s = %q, want %q", parts[0], got, parts[1])
				}
				if r.Header.Get("X-Organization-Id") != "org-1" || r.Header.Get("X-Tenant-Id") != "workspace-1" {
					t.Errorf("scope headers = %#v", r.Header)
				}
				if r.URL.Query().Get("offset") != "0" || r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("name_contains") != "security" {
					t.Errorf("project query = %q", r.URL.RawQuery)
				}
				_, _ = w.Write([]byte(`[]`))
			}))
			defer server.Close()
			source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"api_key": "fixture-secret", "auth_model": test.authModel, "base_url": server.URL, "family": "project", "name_contains": "security", "organization_id": "org-1", "tenant_id": "tenant", "workspace_id": "workspace-1",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			t.Errorf("request = %s %s", r.Method, r.URL.RequestURI())
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["cursor"] != "cursor-2" || body["project"] != "project-1" || body["filter"] != "eq(status,success)" || body["limit"] != float64(100) {
			t.Errorf("run body = %#v", body)
		}
		if _, ok := body["select"].([]any); !ok {
			t.Errorf("run select = %#v", body["select"])
		}
		_, _ = w.Write([]byte(`{"runs":[{"id":"run-2","name":"Run 2"}],"cursors":{"next":null}}`))
	}))
	defer server.Close()
	source, err := NewDefinitionWithValidationOptions(entry.Definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatal(err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"api_key": "fixture-secret", "base_url": server.URL, "family": "run", "filter": "eq(status,success)", "organization_id": "org-1", "project": "project-1", "tenant_id": "tenant", "workspace_id": "workspace-1",
	}), &cerebrov1.SourceCursor{Opaque: "cursor-2"})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].Kind != "langchain.run" || pull.NextCursor != nil {
		t.Fatalf("run pull = %#v", pull)
	}
}

func TestLangSmithCatalogRuntimeThirteenFamilyFixtureCorpus(t *testing.T) {
	definition := supportedCatalogEntry(t, "langchain").Definition
	fixtureDirectory := filepath.Join("..", "..", "langchain", "testdata")
	fixtureRoot, err := os.OpenRoot(fixtureDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = fixtureRoot.Close()
	})
	paths, err := filepath.Glob(filepath.Join(fixtureDirectory, "read_*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 13 {
		t.Fatalf("fixture count = %d, want 13", len(paths))
	}
	wantFamilies := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		wantFamilies = append(wantFamilies, family.ID)
	}
	sort.Strings(wantFamilies)
	gotFamilies := make([]string, 0, len(paths))
	for _, path := range paths {
		familyID := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "read_"), ".json")
		body, err := fixtureRoot.ReadFile(filepath.Base(path))
		if err != nil {
			t.Fatal(err)
		}
		result, err := ReadDefinitionFixture(context.Background(), definition, familyID, body)
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

func TestDopplerCatalogContractIsCredentialFree(t *testing.T) {
	definition := supportedCatalogEntry(t, "doppler").Definition
	if definition.Auth.Model != "bearer_token" || definition.Auth.TokenHeader != "Authorization" || definition.Auth.TokenScheme != "Bearer" {
		t.Fatalf("auth = %#v, want Bearer Authorization contract", definition.Auth)
	}
	if definition.Transport == nil || definition.Transport.Verification == nil {
		t.Fatal("transport verification is required")
	}
	verification := definition.Transport.Verification
	if verification.Path != "/v3/workplace" || verification.ConfigPath != "health_path" {
		t.Fatalf("verification = %#v, want /v3/workplace with health_path override", verification)
	}
	wantPaths := map[string]string{
		"secrets": "/v3/workplace/secrets", "projects": "/v3/workplace/projects", "audit_events": "/v3/workplace/logs",
	}
	families := definitionFamilyMap(definition.ResourceFamilies)
	if len(families) != len(wantPaths) {
		t.Fatalf("family count = %d, want %d", len(families), len(wantPaths))
	}
	for id, path := range wantPaths {
		family := families[id]
		if family.Path != path {
			t.Fatalf("%s path = %q, want %q", id, family.Path, path)
		}
		pagination := family.Pagination
		if pagination == nil || pagination.Type != "cursor" || pagination.CursorParam != "cursor" || pagination.PageSizeParam != "limit" || pagination.PageSize != 100 || pagination.CursorJSONPath != "$.next_cursor" {
			t.Fatalf("%s pagination = %#v", id, pagination)
		}
		if !family.Event.ExactAttributes || (family.Config != nil && len(family.Config.ConfigAttributes) != 0) {
			t.Fatalf("%s event/config contract = %#v / %#v", id, family.Event, family.Config)
		}
	}
	if got := families["secrets"].Event.Attributes["project_id"]; got != "project.id|project_id|project" {
		t.Fatalf("secret project mapping = %q", got)
	}
	audit := families["audit_events"].Event.Attributes
	for key, want := range map[string]string{
		"actor_id": "actor_id|actor.id|actorId|user_id|user.id", "actor_name": "actor_name|actor.name|user.name",
		"resource_id": "resource_id|target_id|target.id|resource.id|object_id", "event_type": "event_type|event_name|action|type",
	} {
		if audit[key] != want {
			t.Fatalf("audit %s mapping = %q, want %q", key, audit[key], want)
		}
	}
}

func TestVaultCatalogRuntimeAuthority(t *testing.T) {
	definition := supportedCatalogEntry(t, "hashicorp_vault").Definition
	if definition.Auth.Model != "api_key" || definition.Auth.TokenHeader != "X-Vault-Token" || definition.Auth.TokenScheme != "" {
		t.Fatalf("auth = %#v, want unschemed X-Vault-Token", definition.Auth)
	}
	if definition.Transport == nil || definition.Transport.BaseURL != "https://${config.vault_addr}" || definition.Transport.Verification == nil {
		t.Fatalf("transport = %#v", definition.Transport)
	}
	if definition.Transport.Verification.Path != "/v1/sys/health" || definition.Transport.Verification.ConfigPath != "health_path" {
		t.Fatalf("verification = %#v", definition.Transport.Verification)
	}
	families := definitionFamilyMap(definition.ResourceFamilies)
	wantPaths := map[string]string{"users": "/v1/identity/entity/id", "secrets": "/v1/sys/mounts", "audit_events": "/v1/sys/audit"}
	for id, path := range wantPaths {
		family := families[id]
		if family.Path != path || family.Read == nil || !family.Read.DisablePageSize || !family.Event.ExactAttributes {
			t.Fatalf("%s family = %#v", id, family)
		}
	}
	users := families["users"]
	if users.Config.StaticQuery["list"] != "true" || users.Read.MapRecords["data.key_info"] != "entity" || users.UpdatedAtField != "entity.last_update_time|entity.creation_time" || users.Event.Attributes["login"] != "entity.metadata.login|entity.name" {
		t.Fatalf("users contract = %#v", users)
	}
	secrets := families["secrets"]
	if secrets.Read.MapRecords["data"] != "mount" || secrets.Event.Attributes["vault_id"] != "mount.accessor|id" || secrets.Event.StaticAttributes["secret_status"] != "enabled" {
		t.Fatalf("secrets contract = %#v", secrets)
	}
	audit := families["audit_events"]
	if audit.Read.MapRecords["data"] != "audit_device" || audit.Event.StaticAttributes["actor_id"] != "vault" || audit.Event.StaticAttributes["event_type"] != "vault.audit_device.enabled" {
		t.Fatalf("audit contract = %#v", audit)
	}
}

func TestVaultCatalogRuntimeTokenOriginNestedMapAndFinalStatic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "fixture-token" {
			t.Errorf("X-Vault-Token = %q, want fixture-token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ready":
			_, _ = w.Write([]byte(`{"ready":true}`))
		case "/v1/identity/entity/id":
			if r.URL.Query().Get("list") != "true" || r.URL.Query().Has("limit") {
				t.Errorf("users query = %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"data":{"key_info":{"user-b":{"name":"Bob","creation_time":"2026-08-19T00:00:00Z","last_update_time":"2026-08-20T00:00:00Z","metadata":{"login":"bob","email":"bob@example.com","status":"active"},"resource_type":"provider-user"},"user-a":{"name":"Alice","creation_time":"2026-08-18T00:00:00Z","metadata":{"login":"alice","email":"alice@example.com","status":"active"},"resource_type":"provider-user"}}}}`))
		case "/v1/sys/mounts":
			_, _ = w.Write([]byte(`{"data":{"secret/":{"accessor":"kv_123","type":"kv","resource_type":"provider-secret","secret_status":"disabled"}}}`))
		case "/v1/sys/audit":
			_, _ = w.Write([]byte(`{"data":{"file/":{"type":"file","actor_id":"provider-actor","event_type":"provider.event","resource_type":"provider-audit"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := NewDefinitionWithValidationOptions(supportedCatalogEntry(t, "hashicorp_vault").Definition, ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatal(err)
	}
	config := func(family string) sourcecdk.Config {
		return sourcecdk.NewConfig(map[string]string{
			"base_url": server.URL, "family": family, "health_path": "/ready", "tenant_id": "tenant-1", "token": "fixture-token",
		})
	}
	if err := source.Check(context.Background(), config("users")); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	users, err := source.Read(context.Background(), config("users"), nil)
	if err != nil {
		t.Fatalf("Read(users) error = %v", err)
	}
	if len(users.Events) != 2 || users.NextCursor != nil || users.Events[0].Attributes["user_id"] != "user-a" || users.Events[1].Attributes["user_id"] != "user-b" {
		t.Fatalf("users deterministic map records = %#v", users)
	}
	if users.Events[0].Attributes["login"] != "alice" || users.Events[0].Attributes["resource_type"] != "vault_identity_entity" || users.Events[1].OccurredAt.AsTime().UTC().Format("2006-01-02T15:04:05Z") != "2026-08-20T00:00:00Z" {
		t.Fatalf("users mappings = %#v", users.Events)
	}
	secrets, err := source.Read(context.Background(), config("secrets"), nil)
	if err != nil {
		t.Fatalf("Read(secrets) error = %v", err)
	}
	if len(secrets.Events) != 1 || secrets.Events[0].Attributes["vault_id"] != "kv_123" || secrets.Events[0].Attributes["resource_type"] != "vault_secret_engine" || secrets.Events[0].Attributes["secret_status"] != "enabled" {
		t.Fatalf("secrets mappings = %#v", secrets)
	}
	audit, err := source.Read(context.Background(), config("audit_events"), nil)
	if err != nil {
		t.Fatalf("Read(audit_events) error = %v", err)
	}
	if len(audit.Events) != 1 || audit.Events[0].Attributes["actor_id"] != "vault" || audit.Events[0].Attributes["event_type"] != "vault.audit_device.enabled" || audit.Events[0].Attributes["resource_type"] != "vault_audit_device" {
		t.Fatalf("audit mappings = %#v", audit)
	}
}

func supportedCatalogEntry(t *testing.T, sourceID string) connectorcatalog.Entry {
	t.Helper()
	entry, found, err := connectorcatalog.BuiltinEntry(sourceID)
	if err != nil {
		t.Fatalf("BuiltinEntry(%s) error = %v", sourceID, err)
	}
	if !found || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
		t.Fatalf("%s catalog entry = found %t, verdict %q", sourceID, found, entry.Report.Verdict)
	}
	return entry
}

func definitionFamilyMap(families []connectordefinitions.ResourceFamily) map[string]connectordefinitions.ResourceFamily {
	out := make(map[string]connectordefinitions.ResourceFamily, len(families))
	for _, family := range families {
		out[family.ID] = family
	}
	return out
}
