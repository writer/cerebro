package sourcecdk

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

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

func TestNewRegistryPreservesCatalogEventContracts(t *testing.T) {
	_, err := LoadSourceCatalog([]byte(`
id: contract_source
name: Contract Source
emitted_kinds:
  - contract_source.event
event_contracts:
  - kind: contract_source.event
    schema_ref: contract_source/event/v1
    required_attributes:
      - required_attribute
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	registry, err := NewRegistry(catalogTestSource{id: "contract_source"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registered, ok := registry.Get("contract_source")
	if !ok {
		t.Fatal("registry missing contract_source")
	}
	provider, ok := registered.(EventContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement EventContractProvider")
	}
	if got := provider.EventContracts(); len(got) != 1 || got[0].Kind != "contract_source.event" {
		t.Fatalf("EventContracts() = %#v, want contract_source.event", got)
	}
}

type catalogTestSource struct {
	id string
}

func (s catalogTestSource) Spec() *cerebrov1.SourceSpec {
	return &cerebrov1.SourceSpec{Id: s.id, Name: "Catalog Test Source"}
}

func (catalogTestSource) Check(context.Context, Config) error {
	return nil
}

func (catalogTestSource) Discover(context.Context, Config) ([]URN, error) {
	return nil, nil
}

func (catalogTestSource) Read(context.Context, Config, *cerebrov1.SourceCursor) (Pull, error) {
	return Pull{}, nil
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
