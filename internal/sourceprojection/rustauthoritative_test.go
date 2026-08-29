package sourceprojection

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
)

// Every catalog-declared event kind of a Rust-authoritative source must fail
// closed in Go. Before the retirement table this was enforced by one checked-in
// stub file per source, so a kind a stub happened to miss (backstage.system)
// silently kept a live generic catalog-runtime projector.
func TestRustAuthoritativeSourcesFailClosedForEveryCatalogKind(t *testing.T) {
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v", err)
	}
	registry := BuiltinRegistry()
	checked := 0
	for _, entry := range catalog.Entries {
		sourceID := strings.TrimSpace(entry.Definition.SourceID)
		if !rustAuthoritativeSource(sourceID) {
			continue
		}
		for _, resource := range entry.Definition.ResourceFamilies {
			kind := catalogRuntimeEventKind(sourceID, resource)
			if kind == "" {
				continue
			}
			checked++
			entities, links, err := registry.Project(&cerebrov1.EventEnvelope{
				Kind:     kind,
				SourceId: sourceID,
				TenantId: "tenant-a",
			})
			if !errors.Is(err, errRustProjectionRequired) {
				t.Errorf("Project(%q) error = %v, want errRustProjectionRequired", kind, err)
				continue
			}
			if entities != nil || links != nil {
				t.Errorf("Project(%q) produced entities=%d links=%d, want none", kind, len(entities), len(links))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Rust-authoritative catalog kinds were checked")
	}
	t.Logf("checked %d kinds across %d Rust-authoritative sources", checked, len(rustAuthoritativeKinds))
}

// backstage.system is declared by the Backstage catalog but never had a stub,
// so it kept a live projector after Backstage moved to Rust authority.
func TestRetiredSourceKindWithoutStubFailsClosed(t *testing.T) {
	_, _, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Kind:     "backstage.system",
		SourceId: "backstage",
		TenantId: "tenant-a",
	})
	if !errors.Is(err, errRustProjectionRequired) {
		t.Fatalf("Project(backstage.system) error = %v, want errRustProjectionRequired", err)
	}
}

// Kinds a retired source once registered statically are not always declared as
// catalog resource families (sailpoint_identitynow.segments and 27 others), so
// per-kind registration alone would let them fall through to a silent no-op
// rather than an error once the stub files are gone.
func TestRetiredSourceKindOutsideCatalogFamiliesFailsClosed(t *testing.T) {
	for _, tc := range []struct{ sourceID, kind string }{
		{"sailpoint_identitynow", "sailpoint_identitynow.segments"},
		{"onelogin", "onelogin.user_apps"},
		{"fivetran", "fivetran.audit_events"},
		{"beezup", "beezup.rule"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			_, _, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
				Kind:     tc.kind,
				SourceId: tc.sourceID,
				TenantId: "tenant-a",
			})
			if !errors.Is(err, errRustProjectionRequired) {
				t.Fatalf("Project(%q) error = %v, want errRustProjectionRequired", tc.kind, err)
			}
		})
	}
}

// A replayed event without a source ID still resolves through its kind prefix.
func TestRetiredSourceFailsClosedWithoutSourceID(t *testing.T) {
	_, _, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Kind:     "deepseek.model_catalog",
		TenantId: "tenant-a",
	})
	if !errors.Is(err, errRustProjectionRequired) {
		t.Fatalf("Project(deepseek.model_catalog) error = %v, want errRustProjectionRequired", err)
	}
}

// Go still owns every source outside the table.
func TestNonRetiredSourceStillProjectsInGo(t *testing.T) {
	if rustAuthoritativeSource("trivy") {
		t.Fatal("trivy is not Rust-authoritative")
	}
	_, _, err := BuiltinRegistry().Project(&cerebrov1.EventEnvelope{
		Kind:     "trivy.image_package",
		SourceId: "trivy",
		TenantId: "tenant-a",
	})
	if errors.Is(err, errRustProjectionRequired) {
		t.Fatalf("Project(trivy.image_package) unexpectedly refused: %v", err)
	}
}

// The table is the retirement contract: every listed source must exist in the
// connector catalog, so a typo cannot silently retire nothing.
func TestRustAuthoritativeSourcesExistInCatalog(t *testing.T) {
	catalog, err := connectorcatalog.BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v", err)
	}
	known := make(map[string]struct{}, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		known[strings.TrimSpace(entry.Definition.SourceID)] = struct{}{}
	}
	for sourceID := range rustAuthoritativeKinds {
		if _, ok := known[sourceID]; !ok {
			t.Errorf("rustAuthoritativeKinds[%q] is not a catalog source", sourceID)
		}
	}
}

// The table must list every kind a retired source declares. catalogcheck reads
// Registry.Kinds and fails on an emitted kind with no projector, so a catalog
// that gains a kind without a table entry has to fail here first.
func TestRustAuthoritativeKindsMatchSourceCatalogs(t *testing.T) {
	for sourceID, kinds := range rustAuthoritativeKinds {
		listed := make(map[string]struct{}, len(kinds))
		for _, kind := range kinds {
			listed[kind] = struct{}{}
		}
		path := filepath.Join("..", "..", "sources", sourceID, "catalog.yaml")
		raw, err := os.ReadFile(path) // #nosec G304 -- repository source catalog path built from the table key.
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		var catalog struct {
			EmittedKinds []string `yaml:"emitted_kinds"`
		}
		if err := yaml.Unmarshal(raw, &catalog); err != nil {
			t.Errorf("parse %s: %v", path, err)
			continue
		}
		for _, kind := range catalog.EmittedKinds {
			if _, ok := listed[kind]; !ok {
				t.Errorf("%s emits %q but rustAuthoritativeKinds[%q] does not list it", path, kind, sourceID)
			}
		}
	}
}
