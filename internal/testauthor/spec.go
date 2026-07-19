package testauthor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const APIVersion = "testauthor.cerebro.dev/v1alpha1"

type Family string

const (
	FamilyFindingRule Family = "finding_rule"
)

type SignalKind string

const (
	SignalContractGap           SignalKind = "contract_gap"
	SignalRuntimeCounterexample SignalKind = "runtime_counterexample"
	SignalChangeGap             SignalKind = "change_gap"
	SignalMutationSurvivor      SignalKind = "mutation_survivor"
)

type OracleKind string

const (
	OracleLifecycleContract     OracleKind = "lifecycle_contract"
	OracleSchemaContract        OracleKind = "schema_contract"
	OracleAuthorizationContract OracleKind = "authorization_contract"
	OracleIdempotencyContract   OracleKind = "idempotency_contract"
	OracleMutation              OracleKind = "mutation"
)

type FixtureKind string

const (
	FixtureSyntheticEvent         FixtureKind = "synthetic_event"
	FixtureSyntheticEventSequence FixtureKind = "synthetic_event_sequence"
	FixtureContractCase           FixtureKind = "contract_case"
)

type TestSpec struct {
	APIVersion string    `json:"api_version"`
	ID         string    `json:"id"`
	Family     Family    `json:"family"`
	Subject    string    `json:"subject"`
	Behavior   string    `json:"behavior"`
	Signal     Signal    `json:"signal"`
	Oracle     Oracle    `json:"oracle"`
	Fixture    Fixture   `json:"fixture"`
	Generator  Generator `json:"generator"`
}

type Signal struct {
	Kind      SignalKind `json:"kind"`
	Reference string     `json:"reference"`
}

type Oracle struct {
	Kind      OracleKind `json:"kind"`
	Assertion string     `json:"assertion"`
}

type Fixture struct {
	Kind      FixtureKind `json:"kind"`
	SchemaRef string      `json:"schema_ref"`
}

type Generator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ValidationIssue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type ValidationError struct {
	Issues []ValidationIssue `json:"issues"`
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Issues))
	for _, issue := range e.Issues {
		parts = append(parts, issue.Field+": "+issue.Message)
	}
	return "invalid test specification: " + strings.Join(parts, "; ")
}

var stableIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func (spec TestSpec) Normalize() TestSpec {
	spec.APIVersion = strings.TrimSpace(spec.APIVersion)
	spec.ID = strings.ToLower(strings.TrimSpace(spec.ID))
	spec.Family = Family(strings.ToLower(strings.TrimSpace(string(spec.Family))))
	spec.Subject = strings.TrimSpace(spec.Subject)
	spec.Behavior = strings.TrimSpace(spec.Behavior)
	spec.Signal.Kind = SignalKind(strings.ToLower(strings.TrimSpace(string(spec.Signal.Kind))))
	spec.Signal.Reference = strings.TrimSpace(spec.Signal.Reference)
	spec.Oracle.Kind = OracleKind(strings.ToLower(strings.TrimSpace(string(spec.Oracle.Kind))))
	spec.Oracle.Assertion = strings.TrimSpace(spec.Oracle.Assertion)
	spec.Fixture.Kind = FixtureKind(strings.ToLower(strings.TrimSpace(string(spec.Fixture.Kind))))
	spec.Fixture.SchemaRef = strings.TrimSpace(spec.Fixture.SchemaRef)
	spec.Generator.Name = strings.TrimSpace(spec.Generator.Name)
	spec.Generator.Version = strings.TrimSpace(spec.Generator.Version)
	return spec
}

func (spec TestSpec) Validate() error {
	spec = spec.Normalize()
	issues := make([]ValidationIssue, 0)
	add := func(field string, message string) {
		issues = append(issues, ValidationIssue{Field: field, Message: message})
	}

	if spec.APIVersion != APIVersion {
		add("api_version", fmt.Sprintf("must equal %q", APIVersion))
	}
	if !stableIDPattern.MatchString(spec.ID) {
		add("id", "must be a non-empty lowercase kebab-case identifier")
	}
	if spec.Family != FamilyFindingRule {
		add("family", fmt.Sprintf("unsupported family %q", spec.Family))
	}
	if spec.Subject == "" {
		add("subject", "is required")
	}
	if spec.Behavior == "" {
		add("behavior", "is required")
	}
	if !validSignalKind(spec.Signal.Kind) {
		add("signal.kind", fmt.Sprintf("unsupported signal kind %q", spec.Signal.Kind))
	}
	if spec.Signal.Reference == "" {
		add("signal.reference", "is required")
	}
	if !validOracleKind(spec.Oracle.Kind) {
		add("oracle.kind", fmt.Sprintf("unsupported oracle kind %q", spec.Oracle.Kind))
	}
	if spec.Oracle.Assertion == "" {
		add("oracle.assertion", "is required")
	}
	if !validFixtureKind(spec.Fixture.Kind) {
		add("fixture.kind", fmt.Sprintf("unsupported fixture kind %q", spec.Fixture.Kind))
	}
	if spec.Fixture.SchemaRef == "" {
		add("fixture.schema_ref", "is required")
	}
	if spec.Generator.Name == "" {
		add("generator.name", "is required")
	}
	if spec.Generator.Version == "" {
		add("generator.version", "is required")
	}

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}
	return nil
}

func (spec TestSpec) Digest() (string, error) {
	spec = spec.Normalize()
	if err := spec.Validate(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("marshal test specification: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func validSignalKind(kind SignalKind) bool {
	switch kind {
	case SignalContractGap, SignalRuntimeCounterexample, SignalChangeGap, SignalMutationSurvivor:
		return true
	default:
		return false
	}
}

func validOracleKind(kind OracleKind) bool {
	switch kind {
	case OracleLifecycleContract, OracleSchemaContract, OracleAuthorizationContract, OracleIdempotencyContract, OracleMutation:
		return true
	default:
		return false
	}
}

func validFixtureKind(kind FixtureKind) bool {
	switch kind {
	case FixtureSyntheticEvent, FixtureSyntheticEventSequence, FixtureContractCase:
		return true
	default:
		return false
	}
}
