// Package cloudidentity evaluates Kubernetes cloud-identity evidence without I/O.
package cloudidentity

import "time"

const (
	SchemaVersion     = "cloud-identity-evidence/v1"
	SourceID          = "cloud_identity"
	EventKind         = "cloud_identity.principal_evidence"
	CoverageEventKind = "cloud_identity.coverage"
)

type Provider string

const (
	AWS Provider = "aws"
	GCP Provider = "gcp"
)

// Reference identifies immutable source material or a dated provider observation.
// It never contains credentials or complete application source files.
type Reference struct {
	Repository string    `json:"repository,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	Path       string    `json:"path,omitempty"`
	StartLine  int       `json:"start_line,omitempty"`
	EndLine    int       `json:"end_line,omitempty"`
	API        string    `json:"api,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	Digest     string    `json:"digest"`
}

type Gap struct {
	Code       string      `json:"code"`
	Scope      string      `json:"scope"`
	Message    string      `json:"message"`
	References []Reference `json:"references,omitempty"`
}

type Principal struct {
	ID       string   `json:"id"`
	Provider Provider `json:"provider"`
	Kind     string   `json:"kind"`
	Account  string   `json:"account,omitempty"`
	Project  string   `json:"project,omitempty"`
}

type SourcePin struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
	Root       string `json:"root,omitempty"`
	Digest     string `json:"digest,omitempty"`
	Exact      bool   `json:"exact"`
}

type Workload struct {
	ID           string `json:"id"`
	Service      string `json:"service"`
	Environment  string `json:"environment"`
	Cluster      string `json:"cluster"`
	CloudAccount string `json:"cloud_account,omitempty"`
	CloudProject string `json:"cloud_project,omitempty"`
	// Region is the owning scan target's cluster location, used to route
	// regional reads (EKS) and to build location-qualified principal forms.
	Region         string            `json:"region,omitempty"`
	Namespace      string            `json:"namespace"`
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	ServiceAccount string            `json:"service_account"`
	Image          string            `json:"image"`
	ImageDigest    string            `json:"image_digest,omitempty"`
	Source         SourcePin         `json:"source"`
	Principals     []Principal       `json:"principals"`
	Configuration  map[string]string `json:"configuration,omitempty"`
	References     []Reference       `json:"references"`
}

// Condition preserves AWS condition operators and GCP CEL expressions. An
// unsupported expression is unknown; its presence must not be discarded.
type Condition struct {
	Operator   string   `json:"operator,omitempty"`
	Key        string   `json:"key,omitempty"`
	Values     []string `json:"values,omitempty"`
	Expression string   `json:"expression,omitempty"`
}

type Grant struct {
	ID           string      `json:"id"`
	Effect       string      `json:"effect"`
	Actions      []string    `json:"actions,omitempty"`
	NotActions   []string    `json:"not_actions,omitempty"`
	Resources    []string    `json:"resources,omitempty"`
	NotResources []string    `json:"not_resources,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
	Role         string      `json:"role,omitempty"`
	Members      []string    `json:"members,omitempty"`
	References   []Reference `json:"references"`
}

// PolicyState describes the reviewed identity-policy surface, not every layer
// of effective cloud authorization. Each boundary intersects the identity grants.
type PolicyState struct {
	Grants     []Grant     `json:"grants"`
	Boundaries [][]Grant   `json:"boundaries,omitempty"`
	Trust      []Grant     `json:"trust,omitempty"`
	Complete   bool        `json:"complete"`
	ObservedAt time.Time   `json:"observed_at,omitempty"`
	References []Reference `json:"references"`
	Gaps       []Gap       `json:"gaps,omitempty"`
}

type OperationDefinition struct {
	Provider               Provider `json:"provider"`
	Service                string   `json:"service"`
	Operation              string   `json:"operation"`
	SDKServices            []string `json:"sdk_services,omitempty"`
	SDKMethods             []string `json:"sdk_methods,omitempty"`
	Permissions            []string `json:"permissions"`
	ConditionalPermissions []string `json:"conditional_permissions,omitempty"`
	// DependenciesComplete means the documented permission set is a conservative
	// upper bound, including possible downstream and conditional permissions.
	DependenciesComplete bool        `json:"dependencies_complete"`
	References           []Reference `json:"references"`
}

type ActionDefinition struct {
	Name          string      `json:"name"`
	ResourceTypes []string    `json:"resource_types,omitempty"`
	References    []Reference `json:"references"`
}

type RoleDefinition struct {
	Name        string      `json:"name"`
	Permissions []string    `json:"permissions"`
	References  []Reference `json:"references"`
}

type ManagedPolicy struct {
	ARN        string      `json:"arn"`
	Grants     []Grant     `json:"grants"`
	References []Reference `json:"references"`
}

type Definitions struct {
	Actions    []ActionDefinition    `json:"actions,omitempty"`
	Operations []OperationDefinition `json:"operations,omitempty"`
	Roles      []RoleDefinition      `json:"roles,omitempty"`
	Policies   []ManagedPolicy       `json:"policies,omitempty"`
	Digest     string                `json:"digest"`
	Complete   bool                  `json:"complete"`
	// AWSServiceCatalogComplete reports that Actions contains every action of
	// every service listed in the AWS Service Reference index (a bare "*"
	// service request was fully acquired). Only then can a cross-service
	// pattern (NotAction-only grants, "*" service wildcards) be expanded to an
	// exact action set; without it such grants have an unknown action surface.
	AWSServiceCatalogComplete bool  `json:"aws_service_catalog_complete,omitempty"`
	Gaps                      []Gap `json:"gaps,omitempty"`
}

type Requirement struct {
	Provider    Provider    `json:"provider"`
	Service     string      `json:"service"`
	Operation   string      `json:"operation"`
	Action      string      `json:"action"`
	Resources   []string    `json:"resources"`
	Conditions  []Condition `json:"conditions,omitempty"`
	ConsumerIDs []string    `json:"consumer_ids"`
	References  []Reference `json:"references"`
}

// Validation is produced by the deterministic source validator, never decoded
// from a model's response. ScopeComplete refers only to the documented analyzer
// boundary; unsupported code or unresolved consumers must keep it false.
type Validation struct {
	Analyzer           string   `json:"analyzer"`
	SourceDigest       string   `json:"source_digest"`
	CitationsVerified  bool     `json:"citations_verified"`
	OperationsVerified bool     `json:"operations_verified"`
	ScopeComplete      bool     `json:"scope_complete"`
	CoveredFiles       []string `json:"covered_files"`
	Gaps               []Gap    `json:"gaps,omitempty"`
}

type Investigation struct {
	ConsumerID   string        `json:"consumer_id"`
	Source       SourcePin     `json:"source"`
	Requirements []Requirement `json:"requirements"`
	Validation   Validation    `json:"validation"`
	Model        string        `json:"model,omitempty"`
}

// Evidence is one principal's bounded collection cohort. Collectors emit facts;
// only the evaluator decides whether these facts establish excess or sharing.
type Evidence struct {
	Schema                    string            `json:"schema"`
	Principal                 Principal         `json:"principal"`
	Scope                     string            `json:"scope"`
	Consumers                 []Workload        `json:"consumers"`
	ConsumerInventoryComplete bool              `json:"consumer_inventory_complete"`
	Declared                  PolicyState       `json:"declared"`
	Observed                  PolicyState       `json:"observed"`
	Definitions               Definitions       `json:"definitions"`
	ResolvedIdentifiers       map[string]string `json:"resolved_identifiers,omitempty"`
	Investigations            []Investigation   `json:"investigations"`
	CollectedAt               time.Time         `json:"collected_at"`
	Gaps                      []Gap             `json:"gaps,omitempty"`
}

type Status string

const (
	Supported  Status = "supported"
	Candidate  Status = "candidate"
	Clear      Status = "clear"
	Incomplete Status = "incomplete"
)

type Excess struct {
	GrantID           string      `json:"grant_id"`
	Action            string      `json:"action"`
	Resources         []string    `json:"resources"`
	RequiredResources []string    `json:"required_resources,omitempty"`
	Reason            string      `json:"reason"`
	References        []Reference `json:"references"`
}

type Assessment struct {
	Status         Status   `json:"status"`
	Side           string   `json:"side,omitempty"`
	Drift          bool     `json:"drift"`
	DeclaredExcess []Excess `json:"declared_excess,omitempty"`
	ObservedExcess []Excess `json:"observed_excess,omitempty"`
	Gaps           []Gap    `json:"gaps,omitempty"`
}

type Sharing struct {
	Status      Status   `json:"status"`
	Services    []string `json:"services"`
	ConsumerIDs []string `json:"consumer_ids"`
	Gaps        []Gap    `json:"gaps,omitempty"`
}
