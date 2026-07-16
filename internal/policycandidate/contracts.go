// Package policycandidate owns durable, draft-only policy discovery candidates.
package policycandidate

import (
	"context"
	"errors"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

const (
	StatusGrounded       = "grounded"
	StatusProved         = "proved"
	StatusReadyForReview = "ready_for_review"
	StatusBlocked        = "blocked"

	MaxListLimit          = 100
	MaxShadowRows         = 100
	DefaultListLimit      = 25
	MaxGroundingNodes     = 16
	MaxGroundingEdges     = 32
	MaxGroundingRows      = 512
	MaxCoverageRules      = 512
	MaxCoverageQueryBytes = 128 << 10
)

var (
	ErrInvalidRequest      = errors.New("invalid policy candidate request")
	ErrNotFound            = errors.New("policy candidate not found")
	ErrConflict            = errors.New("policy candidate revision conflict")
	ErrStoreUnavailable    = errors.New("policy candidate store is unavailable")
	ErrAuthorUnavailable   = errors.New("policy candidate authoring runtime is unavailable")
	ErrGraphUnavailable    = errors.New("policy candidate graph runtime is unavailable")
	ErrCoverageUnavailable = errors.New("policy candidate coverage catalog is unavailable")
)

// Origin identifies the private conversation or operational workflow that
// proposed a hypothesis. ExternalRef is never copied into model context.
type Origin struct {
	Kind        string `json:"kind"`
	ExternalRef string `json:"external_ref"`
}

// GroundingBinding maps one request-local evidence node to its current,
// tenant-scoped graph entity. Bindings are used during creation and are not
// persisted or returned.
type GroundingBinding struct {
	NodeID    string `json:"node_id"`
	EntityURN string `json:"entity_urn"`
}

type GroundingRequest struct {
	Bindings []GroundingBinding `json:"bindings"`
}

// GroundingReceipt confirms that every stored local node, edge, relation and
// declared risk attribute was rehydrated from current graph rows.
type GroundingReceipt struct {
	Execution  string    `json:"execution"`
	NodeCount  int       `json:"node_count"`
	EdgeCount  int       `json:"edge_count"`
	ReceiptID  string    `json:"receipt_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// CoverageGapReceipt confirms that the current registered graph-rule catalog
// did not contain one bounded query covering the candidate's full semantic
// signature. It deliberately omits rule identifiers and query text.
type CoverageGapReceipt struct {
	Execution          string    `json:"execution"`
	CatalogDigest      string    `json:"catalog_digest"`
	ComparedRuleCount  int       `json:"compared_rule_count"`
	CandidateSignature string    `json:"candidate_signature"`
	ObservedAt         time.Time `json:"observed_at"`
}

type CoverageQuery struct {
	CatalogKey          string
	Query               string
	RequiredEntityTypes []string
	RequiredEdges       []CoverageEdge
	RequiredPredicates  []CoveragePredicate
	SemanticsComplete   bool
}

type CoverageEdge struct {
	FromEntityType string
	Relation       string
	ToEntityType   string
}

type CoveragePredicate struct {
	EntityType string
	Key        string
	Value      string
}

type CoverageCatalog interface {
	ListCoverageQueries(context.Context, string, int) ([]CoverageQuery, error)
}

// Artifacts are bounded, reviewable policy files. Paths are safe repository-
// relative paths; no filesystem write occurs during candidate authoring.
type Artifacts struct {
	Rule         findingdsl.PolicyFindingRule   `json:"rule"`
	PolicyPath   string                         `json:"policy_path"`
	PolicyYAML   string                         `json:"policy_yaml"`
	PolicyDigest string                         `json:"policy_digest"`
	Suite        findingdsl.PolicyRuleTestSuite `json:"suite"`
	TestPath     string                         `json:"test_path"`
	TestYAML     string                         `json:"test_yaml"`
	TestDigest   string                         `json:"test_digest"`
}

// ShadowReceipt summarizes a current-graph read without returning graph rows
// or provider identifiers.
type ShadowReceipt struct {
	Execution  string    `json:"execution"`
	MatchCount int       `json:"match_count"`
	Truncated  bool      `json:"truncated"`
	ReceiptID  string    `json:"receipt_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// Candidate is a durable draft. It deliberately has no promoted state or
// mutation endpoint: review and repository delivery remain separate systems.
type Candidate struct {
	ID            string                      `json:"id"`
	TenantID      string                      `json:"tenant_id"`
	Status        string                      `json:"status"`
	Revision      int64                       `json:"revision"`
	Hypothesis    string                      `json:"hypothesis"`
	Domain        string                      `json:"domain"`
	Origin        Origin                      `json:"origin"`
	GraphEvidence *policyauthor.GraphEvidence `json:"graph_evidence,omitempty"`
	Grounding     *GroundingReceipt           `json:"grounding,omitempty"`
	CoverageGap   *CoverageGapReceipt         `json:"coverage_gap,omitempty"`
	Artifacts     *Artifacts                  `json:"artifacts,omitempty"`
	Proof         *policyauthor.ProofResult   `json:"proof,omitempty"`
	Shadow        *ShadowReceipt              `json:"shadow,omitempty"`
	PRReady       bool                        `json:"pr_ready"`
	CreatedAt     time.Time                   `json:"created_at"`
	UpdatedAt     time.Time                   `json:"updated_at"`
}

type CreateRequest struct {
	TenantID      string                      `json:"tenant_id"`
	Hypothesis    string                      `json:"hypothesis"`
	Domain        string                      `json:"domain"`
	Origin        Origin                      `json:"origin"`
	GraphEvidence *policyauthor.GraphEvidence `json:"graph_evidence,omitempty"`
	Grounding     GroundingRequest            `json:"grounding"`
}

type ListRequest struct {
	TenantID string
	Status   string
	Limit    int
}

// Store is the Postgres current-state projection boundary.
type Store interface {
	CreatePolicyCandidate(context.Context, *Candidate) error
	GetPolicyCandidate(context.Context, string) (*Candidate, error)
	ListPolicyCandidates(context.Context, ListRequest) ([]*Candidate, error)
	SavePolicyCandidate(context.Context, *Candidate, int64) error
}
