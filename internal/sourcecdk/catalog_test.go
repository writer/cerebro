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
	catalog, err := LoadSourceCatalog([]byte(`
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.audit
    status: active
  - kind: github.secret_scanning
    status: planned
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	spec := catalog.Spec
	if len(spec.EmittedKinds) != 1 || spec.EmittedKinds[0] != "github.audit" {
		t.Fatalf("EmittedKinds = %#v, want active emitted kind only", spec.EmittedKinds)
	}
	if catalog.LifecycleContract == nil || len(catalog.LifecycleContract.Kinds) != 2 {
		t.Fatalf("LifecycleContract = %#v, want two lifecycle entries", catalog.LifecycleContract)
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
      evidence_types: [identity_configuration]
      control_domains: [identity_access]
      control_refs:
        - framework_name: SOC 2
          control_id: CC6.1
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
	users := catalog.CoverageContract.Dimensions[0]
	if len(users.EvidenceTypes) != 1 || users.EvidenceTypes[0] != "identity_configuration" {
		t.Fatalf("users evidence types = %#v, want identity_configuration", users.EvidenceTypes)
	}
	if len(users.ControlDomains) != 1 || users.ControlDomains[0] != "identity_access" {
		t.Fatalf("users control domains = %#v, want identity_access", users.ControlDomains)
	}
	if len(users.ControlRefs) != 1 || users.ControlRefs[0].FrameworkName != "SOC 2" || users.ControlRefs[0].ControlID != "CC6.1" {
		t.Fatalf("users control refs = %#v, want SOC 2 CC6.1", users.ControlRefs)
	}
	remediation := catalog.CoverageContract.Dimensions[1]
	if len(remediation.EvidenceTypes) != 1 || remediation.EvidenceTypes[0] != "remediation_state" {
		t.Fatalf("remediation evidence types = %#v, want default remediation_state", remediation.EvidenceTypes)
	}
}

func TestLoadSourceCatalogParsesProviderAPIProof(t *testing.T) {
	catalog, err := LoadSourceCatalog([]byte(`
id: catalog_provider_api_test
name: Catalog Provider API Test
emitted_kinds:
  - catalog_provider_api_test.user
runtime_families:
  - users
  - audit_events
provider_api:
  status: verified
  basis: declared
  verified_at: 2026-07-03T00:00:00Z
  transport: rest
  auth: oauth_client_credentials
  auth_mechanics: oauth2_client_credentials_bearer
  base_url: https://example.test/api
  spec_url: https://example.test/openapi.json
  spec_kind: openapi
  references:
    - https://example.test/docs
  auth_evidence:
    - https://example.test/auth
  scope_evidence:
    - https://example.test/scopes
  families:
    - id: users
      method: get
      path: /users
    - id: audit_events
      method: GET
      path: /logs
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if catalog.ProviderAPI == nil {
		t.Fatal("ProviderAPI = nil, want parsed provider API proof")
	}
	if catalog.ProviderAPI.Families[0].Method != "GET" {
		t.Fatalf("ProviderAPI family method = %q, want GET", catalog.ProviderAPI.Families[0].Method)
	}
	if len(catalog.RuntimeFamilies) != 2 || catalog.RuntimeFamilies[0] != "audit_events" || catalog.RuntimeFamilies[1] != "users" {
		t.Fatalf("RuntimeFamilies = %#v, want sorted audit_events/users", catalog.RuntimeFamilies)
	}
	api, runtimeFamilies, ok := CatalogProviderAPIForSource("catalog_provider_api_test")
	if !ok {
		t.Fatal("CatalogProviderAPIForSource() ok = false, want registered provider API proof")
	}
	if api.Status != "verified" || api.SpecURL != "https://example.test/openapi.json" {
		t.Fatalf("registered provider API = %#v", api)
	}
	if len(runtimeFamilies) != 2 || runtimeFamilies[0] != "audit_events" || runtimeFamilies[1] != "users" {
		t.Fatalf("registered runtime families = %#v, want sorted audit_events/users", runtimeFamilies)
	}
	api.References[0] = "mutated"
	api, _, ok = CatalogProviderAPIForSource("catalog_provider_api_test")
	if !ok || api.References[0] != "https://example.test/docs" {
		t.Fatalf("registered provider API clone = %#v, ok=%v", api, ok)
	}
}

func TestLoadSourceCatalogParsesFamilyFreshnessProbe(t *testing.T) {
	catalog, err := LoadSourceCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.code.repository
families:
  - id: repository
    incremental: watermark
    freshness_probe:
      supported: true
      canary_kind: newest_updated_resource
      confidence: heuristic
      reconciliation_interval: 24h
      max_skip_duration: 6h
      max_consecutive_skips: 3
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if len(catalog.Families) != 1 {
		t.Fatalf("len(Families) = %d, want 1", len(catalog.Families))
	}
	family := catalog.Families[0]
	if family.ID != "repository" || family.Incremental != "watermark" {
		t.Fatalf("family = %#v, want repository/watermark", family)
	}
	if family.FreshnessProbe == nil {
		t.Fatal("FreshnessProbe = nil, want parsed probe")
	}
	if got := family.FreshnessProbe.Confidence; got != CanaryConfidenceHeuristic {
		t.Fatalf("probe confidence = %q, want heuristic", got)
	}
	if got := family.FreshnessProbe.MaxConsecutiveSkips; got != 3 {
		t.Fatalf("max skips = %d, want 3", got)
	}
}

func TestLoadSourceCatalogRejectsInvalidFreshnessProbe(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
	}{
		{
			name: "confidence",
			body: `
families:
  - id: repository
    freshness_probe:
      supported: true
      canary_kind: newest_updated_resource
      confidence: maybe
`,
		},
		{
			name: "duration",
			body: `
families:
  - id: repository
    freshness_probe:
      supported: true
      canary_kind: newest_updated_resource
      confidence: heuristic
      max_skip_duration: soon
`,
		},
		{
			name: "missing kind",
			body: `
families:
  - id: repository
    freshness_probe:
      supported: true
      confidence: heuristic
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadSourceCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.code.repository
` + tt.body)); err == nil {
				t.Fatal("LoadSourceCatalog() error = nil, want invalid freshness probe error")
			}
		})
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

func TestNewRegistryPreservesCatalogLifecycleContracts(t *testing.T) {
	_, err := LoadSourceCatalog([]byte(`
id: lifecycle_source
name: Lifecycle Source
emitted_kinds:
  - lifecycle_source.event
kind_lifecycle:
  - kind: lifecycle_source.event
    status: active
  - kind: lifecycle_source.old_event
    status: deprecated
    replacement: lifecycle_source.event
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	registry, err := NewRegistry(catalogTestSource{id: "lifecycle_source"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registered, ok := registry.Get("lifecycle_source")
	if !ok {
		t.Fatal("registry missing lifecycle_source")
	}
	provider, ok := registered.(LifecycleContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement LifecycleContractProvider")
	}
	contract := provider.LifecycleContract()
	if contract.SourceID != "lifecycle_source" || len(contract.Kinds) != 2 {
		t.Fatalf("LifecycleContract() = %#v, want lifecycle_source contract", contract)
	}
	contracts := registry.LifecycleContracts()
	if len(contracts) != 1 || contracts[0].SourceID != "lifecycle_source" {
		t.Fatalf("LifecycleContracts() = %#v, want lifecycle_source", contracts)
	}
}

func TestNewRegistryPreservesCatalogCoverageAndLifecycleWithEventContracts(t *testing.T) {
	_, err := LoadSourceCatalog([]byte(`
id: combined_contract_source
name: Combined Contract Source
emitted_kinds:
  - combined_contract_source.event
event_contracts:
  - kind: combined_contract_source.event
    schema_ref: combined_contract_source/event/v1
    required_attributes:
      - tenant_id
coverage_contract:
  owner_domain: code
  dimensions:
    - id: incremental
      type: incremental_sync
      title: Incremental sync
      support: supported
kind_lifecycle:
  - kind: combined_contract_source.event
    status: active
  - kind: combined_contract_source.legacy
    status: deprecated
    replacement: combined_contract_source.event
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	registry, err := NewRegistry(catalogTestSource{id: "combined_contract_source"})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registered, ok := registry.Get("combined_contract_source")
	if !ok {
		t.Fatal("registry missing combined_contract_source")
	}
	eventProvider, ok := registered.(EventContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement EventContractProvider")
	}
	if got := eventProvider.EventContracts(); len(got) != 1 || got[0].Kind != "combined_contract_source.event" {
		t.Fatalf("EventContracts() = %#v, want combined_contract_source.event", got)
	}
	coverageProvider, ok := registered.(CoverageContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement CoverageContractProvider")
	}
	if got := coverageProvider.CoverageContract(); got.SourceID != "combined_contract_source" || len(got.Dimensions) != 1 {
		t.Fatalf("CoverageContract() = %#v, want combined_contract_source contract", got)
	}
	lifecycleProvider, ok := registered.(LifecycleContractProvider)
	if !ok {
		t.Fatalf("registered source does not implement LifecycleContractProvider")
	}
	if got := lifecycleProvider.LifecycleContract(); got.SourceID != "combined_contract_source" || len(got.Kinds) != 2 {
		t.Fatalf("LifecycleContract() = %#v, want combined_contract_source contract", got)
	}
	if contracts := registry.CoverageContracts(); len(contracts) != 1 || contracts[0].SourceID != "combined_contract_source" {
		t.Fatalf("CoverageContracts() = %#v, want combined_contract_source", contracts)
	}
	if contracts := registry.LifecycleContracts(); len(contracts) != 1 || contracts[0].SourceID != "combined_contract_source" {
		t.Fatalf("LifecycleContracts() = %#v, want combined_contract_source", contracts)
	}
}

func TestNewRegistryPreservesCatalogCheckpointAwareSources(t *testing.T) {
	_, err := LoadSourceCatalog([]byte(`
id: checkpoint_catalog_source
name: Checkpoint Catalog Source
emitted_kinds:
  - checkpoint_catalog_source.event
event_contracts:
  - kind: checkpoint_catalog_source.event
    schema_ref: checkpoint_catalog_source/event/v1
    required_attributes:
      - required_attribute
coverage_contract:
  owner_domain: code
  dimensions:
    - id: incremental
      type: incremental_sync
      title: Incremental sync
      support: supported
`))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	source := &catalogCheckpointAwareSource{
		catalogTestSource: catalogTestSource{id: "checkpoint_catalog_source"},
		pull:              Pull{ShortCircuitReason: PullShortCircuitReasonNotModified},
	}
	registry, err := NewRegistry(source)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	registered, ok := registry.Get("checkpoint_catalog_source")
	if !ok {
		t.Fatal("registry missing checkpoint_catalog_source")
	}
	if _, ok := registered.(EventContractProvider); !ok {
		t.Fatalf("registered source does not implement EventContractProvider")
	}
	if _, ok := registered.(CoverageContractProvider); !ok {
		t.Fatalf("registered source does not implement CoverageContractProvider")
	}
	reader, ok := registered.(CheckpointAwareSource)
	if !ok {
		t.Fatalf("registered source does not implement CheckpointAwareSource")
	}
	checkpoint := &cerebrov1.SourceCheckpoint{CursorOpaque: "checkpoint"}
	pull, err := reader.ReadWithCheckpoint(context.Background(), NewConfig(nil), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if source.seenCheckpoint != checkpoint {
		t.Fatalf("ReadWithCheckpoint checkpoint = %p, want %p", source.seenCheckpoint, checkpoint)
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want %q", pull.ShortCircuitReason, PullShortCircuitReasonNotModified)
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

type catalogCheckpointAwareSource struct {
	catalogTestSource
	pull           Pull
	seenCheckpoint *cerebrov1.SourceCheckpoint
}

func (s *catalogCheckpointAwareSource) ReadWithCheckpoint(_ context.Context, _ Config, _ *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
	s.seenCheckpoint = checkpoint
	return s.pull, nil
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

func TestLoadCatalogRejectsActiveLifecycleKindNotEmitted(t *testing.T) {
	if _, err := LoadCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.secret_scanning
    status: active
`)); err == nil {
		t.Fatal("LoadCatalog() error = nil, want active not emitted lifecycle error")
	}
}

func TestLoadCatalogRejectsDanglingLifecycleReplacement(t *testing.T) {
	if _, err := LoadCatalog([]byte(`
id: github
name: GitHub
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.audit
    status: deprecated
    replacement: github.next
`)); err == nil {
		t.Fatal("LoadCatalog() error = nil, want dangling replacement error")
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
