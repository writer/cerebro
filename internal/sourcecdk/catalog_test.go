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

func TestLoadSourceCatalogParsesCoverageContract(t *testing.T) {
	catalog, err := LoadSourceCatalog([]byte(`
id: okta
name: Okta
emitted_kinds:
  - okta.audit
coverage_contract:
  owner_domain: identity
  authority_domain: okta
  dimensions:
    - id: users
      type: entity_family
      title: Users
      families: [user]
      support: supported
      high_value: true
    - id: remediation
      type: remediation_state
      title: Remediation lifecycle
      support: unsupported
      known_unsupported_fields: [app remediation state]
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if catalog.CoverageContract == nil {
		t.Fatal("CoverageContract = nil, want parsed contract")
	}
	if catalog.CoverageContract.SourceID != "okta" || catalog.CoverageContract.AuthorityDomain != "okta" {
		t.Fatalf("CoverageContract = %#v", catalog.CoverageContract)
	}
	if len(catalog.CoverageContract.Dimensions) != 2 {
		t.Fatalf("len(Dimensions) = %d, want 2", len(catalog.CoverageContract.Dimensions))
	}
	if got := catalog.CoverageContract.Dimensions[1].Support; got != CoverageSupportUnsupported {
		t.Fatalf("Dimensions[1].Support = %q, want unsupported", got)
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

func TestNewRegistryPreservesCatalogCoverageContracts(t *testing.T) {
	_, err := LoadSourceCatalog([]byte(`
id: coverage_source
name: Coverage Source
emitted_kinds:
  - coverage_source.user
coverage_contract:
  owner_domain: identity
  dimensions:
    - id: users
      type: entity_family
      title: Users
      families: [user]
      support: supported
      high_value: true
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	registry, err := NewRegistry(catalogTestSource{id: "coverage_source"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registered, ok := registry.Get("coverage_source")
	if !ok {
		t.Fatal("registry missing coverage_source")
	}
	provider, ok := registered.(CoverageContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement CoverageContractProvider")
	}
	if got := provider.CoverageContract(); got.SourceID != "coverage_source" || len(got.Dimensions) != 1 {
		t.Fatalf("CoverageContract() = %#v, want coverage_source contract", got)
	}
	contracts := registry.CoverageContracts()
	if len(contracts) != 1 || contracts[0].SourceID != "coverage_source" {
		t.Fatalf("CoverageContracts() = %#v, want coverage_source", contracts)
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

func TestLoadCatalogRejectsInvalidCoverageContract(t *testing.T) {
	if _, err := LoadCatalog([]byte(`
id: okta
name: Okta
coverage_contract:
  dimensions:
    - id: users
      type: entity_family
      title: Users
      support: maybe
`)); err == nil {
		t.Fatal("LoadCatalog() error = nil, want invalid coverage support error")
	}
}
