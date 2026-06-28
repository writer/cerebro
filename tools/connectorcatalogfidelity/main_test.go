package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

func TestRunDetectsAndWritesFidelityUpdates(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	if err := os.MkdirAll(catalogDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	path := filepath.Join(catalogDir, "example.yaml")
	if err := os.WriteFile(path, []byte(`
entries:
- classifier_output: supported
  definition:
    id: builtin-example
    tenant_id: builtin_catalog
    source_id: example_saas
    display_name: Example SaaS
    description: Collects users.
    auth:
      model: bearer_token
      credential_fields:
      - key: token
        label: Bearer token
        secret: true
        reference_only: true
        required: true
    transport:
      base_url: https://api.example.com
      verification:
        path: /v1/me
        expect_status: [200]
    resource_families:
    - id: users
      label: Users
      path: /v1/users
      method: GET
      record_selector: $.data[*]
      id_field: id
      name_field: name
      event:
        kind: example_saas.users
        schema_ref: example_saas/users/v1
      projection:
        template: identity_user
      coverage:
      - type: entity_family
        support: partial
        evidence_types: [source_snapshot]
        control_domains: [asset_inventory]
      pagination:
        type: cursor
        cursor_param: cursor
        cursor_json_path: $.next_cursor
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	checkReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(check) error = %v", err)
	}
	if checkReport.ChangedEntries != 1 || checkReport.ChangedFiles != 1 {
		t.Fatalf("check report = %+v, want one changed entry and file", checkReport)
	}

	writeReport, err := run(options{root: root, write: true})
	if err != nil {
		t.Fatalf("run(write) error = %v", err)
	}
	if writeReport.ChangedEntries != 1 {
		t.Fatalf("write changed entries = %d, want 1", writeReport.ChangedEntries)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, want := range []string{"urn_kind: example_saas_users", "required_payload_fields:", "user_id: id", "display_name: name"} {
		if !strings.Contains(string(updated), want) {
			t.Fatalf("updated file missing %q:\n%s", want, updated)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("file mode = %#o, want 0644", got)
	}

	cleanReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(clean check) error = %v", err)
	}
	if cleanReport.ChangedEntries != 0 {
		t.Fatalf("clean changed entries = %d, want 0; report = %+v", cleanReport.ChangedEntries, cleanReport)
	}
}

func TestRenderCatalogEntriesKeepsUnsupportedClassifierOutput(t *testing.T) {
	entries, err := decodeCatalogEntries("example.yaml", []byte(`
classifier_output: extension_required
definition:
  id: builtin-example
  tenant_id: builtin_catalog
  source_id: example_saas
  display_name: Example SaaS
  auth:
    model: api_key
  resource_families:
  - id: users
    path: /v1/users
    id_field: id
`))
	if err != nil {
		t.Fatalf("decodeCatalogEntries() error = %v", err)
	}
	payload, err := renderCatalogEntries(entries)
	if err != nil {
		t.Fatalf("renderCatalogEntries() error = %v", err)
	}
	if !strings.Contains(string(payload), "classifier_output: extension_required") {
		t.Fatalf("rendered payload did not keep classifier output:\n%s", payload)
	}
}

func TestRunSplitsRootMultiEntryCatalogFile(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	if err := os.MkdirAll(catalogDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	path := filepath.Join(catalogDir, "ai-governance.yaml")
	if err := os.WriteFile(path, []byte(`
entries:
- classifier_output: supported
  definition:
    id: builtin-anthropic
    tenant_id: builtin_catalog
    source_id: anthropic
    display_name: Anthropic
    description: Collects model catalog records from Anthropic and projects them into the graph for inventory, access review, audit, risk, and operational context.
    auth:
      model: api_key
    resource_families:
    - id: models
      path: /v1/models
      id_field: id
      event:
        kind: anthropic.models
        schema_ref: anthropic/models/v1
        urn_kind: anthropic_models
        required_payload_fields: [id]
      projection:
        template: asset
        fields:
          resource_id: id
          resource_name: display_name
- classifier_output: supported
  definition:
    id: builtin-cohere
    tenant_id: builtin_catalog
    source_id: cohere
    display_name: Cohere
    description: Collects model catalog records from Cohere and projects them into the graph for inventory, access review, audit, risk, and operational context.
    auth:
      model: api_key
    resource_families:
    - id: models
      path: /v1/models
      id_field: id
      event:
        kind: cohere.models
        schema_ref: cohere/models/v1
        urn_kind: cohere_models
        required_payload_fields: [id]
      projection:
        template: asset
        fields:
          resource_id: id
          resource_name: display_name
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	checkReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(check) error = %v", err)
	}
	if checkReport.ChangedEntries != 2 {
		t.Fatalf("changed entries = %d, want two layout changes", checkReport.ChangedEntries)
	}

	if _, err := run(options{root: root, write: true}); err != nil {
		t.Fatalf("run(write) error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("source multi-entry file stat err = %v, want not exist", err)
	}
	for _, rel := range []string{"ai-governance/anthropic.yaml", "ai-governance/cohere.yaml"} {
		if _, err := os.Stat(filepath.Join(catalogDir, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("split target %s stat error = %v", rel, err)
		}
	}
	cleanReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(clean check) error = %v", err)
	}
	if cleanReport.ChangedEntries != 0 {
		t.Fatalf("clean changed entries = %d, want 0", cleanReport.ChangedEntries)
	}
}

func TestRunSplitsSubdirMultiEntryCatalogFileKeepsSourceNamedEntry(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	sourceDir := filepath.Join(catalogDir, "business-data-grc")
	if err := os.MkdirAll(sourceDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	path := filepath.Join(sourceDir, "foo.yaml")
	if err := os.WriteFile(path, []byte(`
entries:
- classifier_output: supported
  definition:
    id: builtin-foo
    tenant_id: builtin_catalog
    source_id: foo
    display_name: Foo
    description: Collects users from Foo and projects them into the graph for inventory, access review, audit, risk, and operational context.
    auth:
      model: api_key
    transport:
      base_url: https://api.foo.example
      verification:
        path: /v1/me
        expect_status: [200]
    resource_families:
    - id: users
      path: /v1/users
      method: GET
      record_selector: $.data[*]
      id_field: id
      name_field: name
      event:
        kind: foo.users
        schema_ref: foo/users/v1
        urn_kind: foo_users
        required_payload_fields: [id]
      projection:
        template: identity_user
        fields:
          user_id: id
          display_name: name
      coverage:
      - type: entity_family
        support: partial
        evidence_types: [source_snapshot]
        control_domains: [asset_inventory]
      pagination:
        type: cursor
        cursor_param: cursor
        cursor_json_path: $.next_cursor
- classifier_output: supported
  definition:
    id: builtin-bar
    tenant_id: builtin_catalog
    source_id: bar
    display_name: Bar
    description: Collects users from Bar and projects them into the graph for inventory, access review, audit, risk, and operational context.
    auth:
      model: api_key
    transport:
      base_url: https://api.bar.example
      verification:
        path: /v1/me
        expect_status: [200]
    resource_families:
    - id: users
      path: /v1/users
      method: GET
      record_selector: $.data[*]
      id_field: id
      name_field: name
      event:
        kind: bar.users
        schema_ref: bar/users/v1
        urn_kind: bar_users
        required_payload_fields: [id]
      projection:
        template: identity_user
        fields:
          user_id: id
          display_name: name
      coverage:
      - type: entity_family
        support: partial
        evidence_types: [source_snapshot]
        control_domains: [asset_inventory]
      pagination:
        type: cursor
        cursor_param: cursor
        cursor_json_path: $.next_cursor
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := run(options{root: root, write: true}); err != nil {
		t.Fatalf("run(write) error = %v", err)
	}
	fooPayload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(foo) error = %v", err)
	}
	if !strings.Contains(string(fooPayload), "source_id: foo") {
		t.Fatalf("foo source file missing source_id foo:\n%s", fooPayload)
	}
	if strings.Contains(string(fooPayload), "source_id: bar") {
		t.Fatalf("foo source file still contains bar entry:\n%s", fooPayload)
	}
	barPath := filepath.Join(sourceDir, "bar.yaml")
	barPayload, err := os.ReadFile(barPath)
	if err != nil {
		t.Fatalf("ReadFile(bar) error = %v", err)
	}
	if !strings.Contains(string(barPayload), "source_id: bar") {
		t.Fatalf("bar source file missing source_id bar:\n%s", barPayload)
	}
	cleanReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(clean check) error = %v", err)
	}
	if cleanReport.ChangedEntries != 0 {
		t.Fatalf("clean changed entries = %d, want 0", cleanReport.ChangedEntries)
	}
}

func TestRunDetectsMissingURNKindWhenProjectionFieldsExist(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "internal", "connectorcatalog", "catalog")
	if err := os.MkdirAll(catalogDir, 0o750); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	path := filepath.Join(catalogDir, "semgrep.yaml")
	if err := os.WriteFile(path, []byte(`
entries:
- classifier_output: supported
  definition:
    id: builtin-semgrep
    tenant_id: builtin_catalog
    source_id: semgrep
    display_name: Semgrep
    description: Collects assets and findings from Semgrep and projects them into the graph for inventory, access review, audit, risk, and operational context.
    auth:
      model: bearer_token
    resource_families:
    - id: assets
      path: /v1/assets
      id_field: id
      event:
        kind: semgrep.assets
        schema_ref: semgrep/assets/v1
        required_payload_fields: [id]
      projection:
        template: asset
        fields:
          resource_id: id
          resource_name: name
`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	entries, err := decodeCatalogEntries(path, payload)
	if err != nil {
		t.Fatalf("decodeCatalogEntries() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Definition.SourceID != "semgrep" || len(entries[0].Definition.ResourceFamilies) != 1 {
		t.Fatalf("decoded entries = %#v", entries)
	}
	hardened, changes := connectorcatalog.HardenDefinitionFidelity(entries[0].Definition)
	if len(changes) == 0 {
		t.Fatalf("hardener changes = 0 for decoded definition: %#v", entries[0].Definition.ResourceFamilies[0].Event)
	}
	if definitionsEqual(entries[0].Definition, hardened) {
		t.Fatalf("definitionsEqual returned true after hardening; hardened event = %#v", hardened.ResourceFamilies[0].Event)
	}
	processed, err := processFile(root, path)
	if err != nil {
		t.Fatalf("processFile() error = %v", err)
	}
	if processed.report.ChangedEntries != 1 {
		t.Fatalf("processFile changed entries = %d, want 1; report = %+v", processed.report.ChangedEntries, processed.report)
	}

	checkReport, err := run(options{root: root})
	if err != nil {
		t.Fatalf("run(check) error = %v", err)
	}
	if checkReport.ChangedEntries != 1 {
		t.Fatalf("changed entries = %d, want missing urn_kind drift", checkReport.ChangedEntries)
	}
	if _, err := run(options{root: root, write: true}); err != nil {
		t.Fatalf("run(write) error = %v", err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(updated), "urn_kind: semgrep_assets") {
		t.Fatalf("updated file missing urn kind:\n%s", updated)
	}
}
