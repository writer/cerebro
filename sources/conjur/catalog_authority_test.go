package conjur_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/catalogruntime"
	"gopkg.in/yaml.v3"
)

func TestCatalogDeclaresConjurRequestContract(t *testing.T) {
	entry := conjurEntry(t)
	definition := entry.Definition
	if definition.Auth.Model != "basic" || definition.Auth.TokenHeader != "Authorization" || definition.Auth.TokenScheme != "Basic" {
		t.Fatalf("auth = %#v, want Basic Authorization contract", definition.Auth)
	}
	if definition.Transport == nil || definition.Transport.Verification == nil {
		t.Fatal("transport verification is required")
	}
	if got := definition.Transport.Verification.Path; got != "/resources" {
		t.Fatalf("verification path = %q, want /resources", got)
	}
	wantPaths := map[string]string{
		"authenticator": "/authenticators",
		"resource":      "/resources",
		"resource_2":    "/resources/${config.account}",
		"resource_3":    "/resources/${config.account}/${config.kind}",
	}
	for _, family := range definition.ResourceFamilies {
		want, ok := wantPaths[family.ID]
		if !ok {
			t.Fatalf("unexpected family %q", family.ID)
		}
		if family.Path != want {
			t.Fatalf("%s path = %q, want %q", family.ID, family.Path, want)
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
		if family.Pagination == nil || family.Pagination.Type != "offset" || !family.Pagination.InjectFirstPage || family.Pagination.OffsetParam != "offset" || family.Pagination.LimitParam != "limit" {
			t.Fatalf("%s pagination contract = %#v", family.ID, family.Pagination)
		}
		delete(wantPaths, family.ID)
	}
	if len(definition.ResourceFamilies) != 4 {
		t.Fatalf("family count = %d, want 4", len(definition.ResourceFamilies))
	}
}

func TestCatalogDeclaresConfigurableConjurHealthPath(t *testing.T) {
	payload, err := os.ReadFile("../../internal/connectorcatalog/catalog/identity-access-secrets/conjur.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Entries []struct {
			Definition struct {
				Transport struct {
					Verification struct {
						ConfigPath string `yaml:"config_path"`
						Path       string `yaml:"path"`
					} `yaml:"verification"`
				} `yaml:"transport"`
			} `yaml:"definition"`
		} `yaml:"entries"`
	}
	if err := yaml.Unmarshal(payload, &file); err != nil {
		t.Fatal(err)
	}
	verification := file.Entries[0].Definition.Transport.Verification
	if verification.Path != "/resources" || verification.ConfigPath != "health_path" {
		t.Fatalf("verification contract = %#v", verification)
	}
}

func TestCatalogRuntimeConjurBasicAuthVariantsAndHealth(t *testing.T) {
	entry := conjurEntry(t)
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
				paths = append(paths, r.URL.EscapedPath())
				if got := r.Header.Get("Authorization"); got != test.wantHeader {
					t.Errorf("Authorization = %q, want %q", got, test.wantHeader)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":{"key_info":{"myorg:variable:apps/api/password":{"annotations":"API password"}}}}`))
			}))
			defer server.Close()
			source, err := catalogruntime.NewDefinitionWithValidationOptions(entry.Definition, catalogruntime.ValidationOptions{AllowLoopbackBaseURL: true})
			if err != nil {
				t.Fatalf("NewDefinitionWithValidationOptions() error = %v", err)
			}
			values := map[string]string{"base_url": server.URL, "family": "resource", "tenant_id": "tenant"}
			for key, value := range test.credentials {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !reflect.DeepEqual(paths, []string{"/resources"}) {
				t.Fatalf("health paths = %#v, want [/resources]", paths)
			}
		})
	}
}

func TestCatalogRuntimeConjurNestedKeyInfoMapRecords(t *testing.T) {
	body, err := os.ReadFile("testdata/provider_resource_key_info.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/resources/myorg/variable" {
			t.Errorf("path = %q, want /resources/myorg/variable", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	entry := conjurEntry(t)
	source, err := catalogruntime.NewDefinitionWithValidationOptions(entry.Definition, catalogruntime.ValidationOptions{AllowLoopbackBaseURL: true})
	if err != nil {
		t.Fatalf("NewDefinitionWithValidationOptions() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account": "myorg", "base_url": server.URL, "family": "resource_3", "kind": "variable", "tenant_id": "tenant", "token": "fixture-basic-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
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
		if event.Kind != "conjur.resource_3" || event.SchemaRef != "conjur/resource_3/v1" {
			t.Fatalf("event contract = %q/%q", event.Kind, event.SchemaRef)
		}
		if event.Attributes["resource_name"] == "" || event.Attributes["resource_type"] != "resource" {
			t.Fatalf("event attributes = %#v", event.Attributes)
		}
	}
}

func conjurEntry(t *testing.T) connectorcatalog.Entry {
	t.Helper()
	entry, found, err := connectorcatalog.BuiltinEntry("conjur")
	if err != nil {
		t.Fatalf("BuiltinEntry(conjur) error = %v", err)
	}
	if !found || entry.Report.Verdict != connectordefinitions.SupportVerdictSupported {
		t.Fatalf("conjur catalog entry = found %t, verdict %q", found, entry.Report.Verdict)
	}
	return entry
}
