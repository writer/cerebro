package sourcecdk

import "testing"

func TestLoadCatalog(t *testing.T) {
	spec, err := LoadCatalog([]byte(`
id: github
name: GitHub
description: GitHub audit source
emitted_kinds:
  - github.audit
  - github.pull_request
`))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if spec.Id != "github" {
		t.Fatalf("Id = %q, want %q", spec.Id, "github")
	}
	if len(spec.EmittedKinds) != 2 {
		t.Fatalf("len(EmittedKinds) = %d, want 2", len(spec.EmittedKinds))
	}
}

func TestLoadCatalogRejectsMissingID(t *testing.T) {
	if _, err := LoadCatalog([]byte("name: GitHub\n")); err == nil {
		t.Fatal("LoadCatalog() error = nil, want non-nil")
	}
}

func TestLoadCatalogRejectsDuplicateEmittedKinds(t *testing.T) {
	if _, err := LoadCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.audit
  - github.audit
`)); err == nil {
		t.Fatal("LoadCatalog() error = nil, want duplicate emitted kind error")
	}
}

func TestLoadCatalogValidatesKindLifecycle(t *testing.T) {
	spec, err := LoadCatalog([]byte(`
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.secret_scanning
    status: planned
`))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if len(spec.EmittedKinds) != 1 || spec.EmittedKinds[0] != "github.audit" {
		t.Fatalf("EmittedKinds = %#v, want active emitted kind only", spec.EmittedKinds)
	}
}

func TestLoadSourceCatalogParsesEventContracts(t *testing.T) {
	catalog, err := LoadSourceCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.audit
event_contracts:
  - kind: github.audit
    schema_ref: github/audit/v1
    required_attributes:
      - org
    required_payload_fields:
      - action
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if catalog.Spec.GetId() != "github" {
		t.Fatalf("Spec.Id = %q, want github", catalog.Spec.GetId())
	}
	if len(catalog.EventContracts) != 1 {
		t.Fatalf("len(EventContracts) = %d, want 1", len(catalog.EventContracts))
	}
	if got := catalog.EventContracts[0].SchemaRef; got != "github/audit/v1" {
		t.Fatalf("EventContracts[0].SchemaRef = %q, want github/audit/v1", got)
	}
}

func TestLoadCatalogRejectsInvalidLifecycleStatus(t *testing.T) {
	if _, err := LoadCatalog([]byte(`
id: github
name: GitHub
kind_lifecycle:
  - kind: github.secret_scanning
    status: maybe
`)); err == nil {
		t.Fatal("LoadCatalog() error = nil, want invalid lifecycle status error")
	}
}
