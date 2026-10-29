package requirements

import (
	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// ClaimCitation is a model-proposed pointer at exact pinned source text. The
// validator re-reads the pinned file at Path and requires the content at
// StartLine..EndLine to equal Quote byte-for-byte before trusting anything
// else about the claim.
type ClaimCitation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Quote     string `json:"quote"`
}

// ModelClaim is exactly what a model may propose. It intentionally has no
// consumer-identity field and no validation/trust field: ConsumerIDs are
// assigned deterministically by Validate from the investigated Workload, and
// Validation is always derived by this package, never decoded from a model
// response.
type ModelClaim struct {
	Provider   ci.Provider     `json:"provider"`
	Service    string          `json:"service"`
	Operation  string          `json:"operation"`
	Action     string          `json:"action"`
	Resources  []string        `json:"resources"`
	Conditions []ci.Condition  `json:"conditions,omitempty"`
	Citations  []ClaimCitation `json:"citations"`
	Rationale  string          `json:"rationale,omitempty"`
}

// ModelClaims is the exact top-level schema an adapter must strictly decode
// a model response into (DisallowUnknownFields). Any field outside this
// shape, including an attempted trusted-validation field, fails decoding.
type ModelClaims struct {
	Claims []ModelClaim `json:"claims"`
}

// StaticOperation is one independently, deterministically extracted direct
// cloud SDK call site. Token is the literal identifier found in source (a Go
// method name, a boto3 snake_case method name, or an AWS SDK v3 `XCommand`
// class name) prior to Definitions normalization.
type StaticOperation struct {
	Provider  ci.Provider
	Service   string
	Token     string
	Path      string
	StartLine int
	EndLine   int
	Quote     string
	// Resources holds only literal identifiers independently extracted from
	// the call site itself (an AST input-struct field or a GCP fluent
	// accessor argument). It is empty whenever the resource is dynamic;
	// Validate must never substitute a model-claimed value here.
	Resources []string
}

// StaticFindings is the result of ExtractStatic: the operations it could
// prove exist in source, which files it fully reviewed with no unsupported
// construct, and the gaps explaining everything it could not prove.
type StaticFindings struct {
	Operations   []StaticOperation
	CoveredFiles []string
	Gaps         []ci.Gap
}

// ValidateInput is everything Validate needs to deterministically derive one
// workload's ci.Investigation. It never performs I/O.
type ValidateInput struct {
	Workload    ci.Workload
	Repository  ci.Repository
	Definitions ci.Definitions
	ModelClaims []ModelClaim
	Analyzer    string
	Model       string
}
