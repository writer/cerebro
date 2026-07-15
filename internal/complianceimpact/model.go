// Package complianceimpact computes bounded, explainable impact sets from exact
// immutable domain facts.
package complianceimpact

import (
	"errors"

	"github.com/writer/cerebro/internal/complianceintegration"
)

var (
	ErrInvalidLimits   = errors.New("invalid compliance impact limits")
	ErrInvalidGraph    = errors.New("invalid compliance impact graph")
	ErrRevisionMissing = errors.New("compliance impact revision missing")
	ErrTenantBoundary  = errors.New("compliance impact tenant boundary violation")
)

// Limits bound every graph read and traversal dimension.
type Limits struct {
	MaxNodes uint32
	MaxEdges uint32
	MaxDepth uint32
	PageSize uint32
}

func DefaultLimits() Limits {
	return Limits{MaxNodes: 10000, MaxEdges: 50000, MaxDepth: 32, PageSize: 250}
}

type ReasonCode string

const (
	ReasonRevisionChanged     ReasonCode = "revision_changed"
	ReasonRevisionDeleted     ReasonCode = "revision_deleted"
	ReasonRevisionRevoked     ReasonCode = "revision_revoked"
	ReasonDependencyChanged   ReasonCode = "dependency_revision_changed"
	ReasonDependencyDeleted   ReasonCode = "dependency_deleted"
	ReasonDependencyRevoked   ReasonCode = "dependency_revoked"
	ReasonCycleDetected       ReasonCode = "cycle_detected"
	ReasonNodeBudgetExceeded  ReasonCode = "node_budget_exceeded"
	ReasonEdgeBudgetExceeded  ReasonCode = "edge_budget_exceeded"
	ReasonDepthBudgetExceeded ReasonCode = "depth_budget_exceeded"
)

// AffectedFact explains one impacted exact revision.
type AffectedFact struct {
	Revision  complianceintegration.RevisionRef
	Reasons   []ReasonCode
	Relations []string
	Distance  uint32
}

// Invalidation identifies a mutable claim or projection that must be marked
// invalid without rewriting completed artifacts.
type Invalidation struct {
	Revision complianceintegration.RevisionRef
	Reason   ReasonCode
}

// Issue records why a result is incomplete. References contain stable exact
// revision identities and no copied domain payload.
type Issue struct {
	Code     ReasonCode
	Revision complianceintegration.RevisionRef
	Related  complianceintegration.RevisionRef
}

// Result separates operator-facing target classes and preserves completeness.
type Result struct {
	TenantID      string
	Signal        complianceintegration.ChangeSignal
	Complete      bool
	Programs      []AffectedFact
	Plans         []AffectedFact
	Objectives    []AffectedFact
	Packages      []AffectedFact
	WorkItems     []AffectedFact
	Invalidations []Invalidation
	Issues        []Issue
}
