package main

const (
	requestSchemaVersion     = "cerebro.rustcarve.request/v1"
	migrationIRSchemaVersion = "cerebro.rustcarve.migration-ir/v1"
	standardSourceIRVersion  = "standard-source/v1"
	providerSourceIRVersion  = "provider-source/v1"
	graphQueryIRVersion      = "graph-query/v1"
	findingRuleIRVersion     = "finding-rule/v1"
	differentialReceiptV1    = "cerebro.rustcarve.differential-receipt/v1"
	deletionManifestV1       = "cerebro.rustcarve.deletion-manifest/v1"
	unsupportedReportV1      = "cerebro.rustcarve.unsupported/v1"
	rustcarveToolRevision    = "cerebro.rustcarve/v1"
)

type behaviorKind string

const (
	behaviorStandardSource behaviorKind = "standard_source"
	behaviorProviderSource behaviorKind = "provider_source"
	behaviorGraphQuery     behaviorKind = "graph_query"
	behaviorFindingRule    behaviorKind = "finding_rule"
)

type carveRequest struct {
	SchemaVersion string              `json:"schema_version"`
	BehaviorKind  behaviorKind        `json:"behavior_kind"`
	Subject       subjectRequest      `json:"subject"`
	Scope         scopeContract       `json:"scope"`
	FixtureCorpus []artifactRequest   `json:"fixture_corpus"`
	PortTraces    []artifactRequest   `json:"port_traces"`
	Receipts      []artifactRequest   `json:"differential_receipts"`
	Deletion      deletionRequest     `json:"deletion"`
	GraphQuery    *graphQueryIR       `json:"graph_query,omitempty"`
	FindingRule   *findingRuleIR      `json:"finding_rule,omitempty"`
	Options       distillationOptions `json:"options"`
}

type subjectRequest struct {
	ID                         string   `json:"id"`
	PackageDir                 string   `json:"package_dir"`
	CatalogPath                string   `json:"catalog_path"`
	GoFiles                    []string `json:"go_files"`
	OwnerSymbols               []string `json:"owner_symbols"`
	RustImplementationRevision string   `json:"rust_implementation_revision"`
	AuthorityState             string   `json:"authority_state"`
}

type distillationOptions struct {
	ExpectedRegistrationShape string `json:"expected_registration_shape"`
	MaxInputBytes             int64  `json:"max_input_bytes"`
}

type artifactRequest struct {
	Path string `json:"path"`
	Role string `json:"role"`
}

type artifactDigest struct {
	Path         string `json:"path"`
	Role         string `json:"role"`
	DigestSHA256 string `json:"digest_sha256"`
}

type deletionRequest struct {
	Paths   []string `json:"paths"`
	Imports []string `json:"imports"`
	Symbols []string `json:"symbols"`
}

type typedInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type scopeContract struct {
	Tenant          typedInput  `json:"tenant"`
	WorkspacePolicy string      `json:"workspace_policy"`
	Workspace       *typedInput `json:"workspace,omitempty"`
}

type migrationIR struct {
	SchemaVersion string            `json:"schema_version"`
	ToolRevision  string            `json:"tool_revision"`
	IRVersion     string            `json:"ir_version"`
	DigestSHA256  string            `json:"digest_sha256"`
	BehaviorKind  behaviorKind      `json:"behavior_kind"`
	Subject       distilledSubject  `json:"subject"`
	Scope         scopeContract     `json:"scope"`
	GoFacts       goPackageFacts    `json:"go_facts"`
	Evidence      evidenceContract  `json:"evidence"`
	Standard      *standardSourceIR `json:"standard_source,omitempty"`
	Provider      *standardSourceIR `json:"provider_source,omitempty"`
	GraphQuery    *graphQueryIR     `json:"graph_query,omitempty"`
	FindingRule   *findingRuleIR    `json:"finding_rule,omitempty"`
}

type distilledSubject struct {
	ID                         string `json:"id"`
	RustImplementationRevision string `json:"rust_implementation_revision"`
	AuthorityState             string `json:"authority_state"`
}

type goPackageFacts struct {
	PackageName  string           `json:"package_name"`
	Files        []string         `json:"files"`
	FileDigests  []artifactDigest `json:"file_digests"`
	Imports      []string         `json:"imports"`
	OwnerSymbols []string         `json:"owner_symbols"`
	Calls        []string         `json:"calls"`
	DigestSHA256 string           `json:"digest_sha256"`
}

type evidenceContract struct {
	Fixtures []artifactDigest `json:"fixtures"`
	Traces   []artifactDigest `json:"traces"`
}

type standardSourceIR struct {
	CatalogPath     string          `json:"catalog_path"`
	Registration    string          `json:"registration_shape"`
	ExecutionOwner  string          `json:"execution_owner"`
	FailClosed      bool            `json:"fail_closed"`
	RuntimeFamilies []string        `json:"runtime_families"`
	EventContracts  []eventContract `json:"event_contracts"`
}

type eventContract struct {
	Kind                  string   `json:"kind" yaml:"kind"`
	SchemaRef             string   `json:"schema_ref" yaml:"schema_ref"`
	RequiredAttributes    []string `json:"required_attributes" yaml:"required_attributes"`
	RequiredPayloadFields []string `json:"required_payload_fields" yaml:"required_payload_fields"`
}

type deletionManifest struct {
	SchemaVersion              string           `json:"schema_version"`
	ToolRevision               string           `json:"tool_revision"`
	BehaviorKind               behaviorKind     `json:"behavior_kind"`
	SubjectID                  string           `json:"subject_id"`
	IRVersion                  string           `json:"ir_version"`
	IRDigestSHA256             string           `json:"ir_digest_sha256"`
	GoFactsDigestSHA256        string           `json:"go_facts_digest_sha256"`
	RustImplementationRevision string           `json:"rust_implementation_revision"`
	Eligible                   bool             `json:"eligible"`
	ReasonCodes                []reasonCode     `json:"reason_codes"`
	Paths                      []string         `json:"paths"`
	Imports                    []string         `json:"imports"`
	Symbols                    []string         `json:"symbols"`
	RequiredReceiptModes       []string         `json:"required_receipt_modes"`
	AcceptedReceipts           []artifactDigest `json:"accepted_receipts"`
}

type unsupportedReport struct {
	SchemaVersion string       `json:"schema_version"`
	BehaviorKind  behaviorKind `json:"behavior_kind"`
	SubjectID     string       `json:"subject_id"`
	ReasonCodes   []reasonCode `json:"reason_codes"`
	Details       []string     `json:"details"`
}

type typedInputError struct {
	Reason reasonCode
	Err    error
}

func (e typedInputError) Error() string { return e.Err.Error() }

func (e typedInputError) Unwrap() error { return e.Err }
