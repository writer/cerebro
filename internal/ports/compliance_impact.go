package ports

import (
	"context"
	"errors"
	"time"
)

// ErrComplianceImpactRevisionNotFound means an exact immutable revision is not
// available. Impact analysis must fail rather than silently omit its dependents.
var ErrComplianceImpactRevisionNotFound = errors.New("compliance impact revision not found")

// ComplianceImpactRevisionRef is the storage-boundary representation of one
// exact immutable domain revision. Services validate it into their own domain
// value before using it for traversal.
type ComplianceImpactRevisionRef struct {
	TenantID      string
	Domain        string
	Kind          string
	ID            string
	RevisionID    string
	Version       uint64
	ContentDigest string
	LastModified  time.Time
}

// ComplianceImpactDependencyRef is one explicit upstream edge.
type ComplianceImpactDependencyRef struct {
	Revision ComplianceImpactRevisionRef
	Relation string
}

// ComplianceImpactDomainFact is the storage-boundary representation of an
// immutable domain fact.
type ComplianceImpactDomainFact struct {
	Revision     ComplianceImpactRevisionRef
	Dependencies []ComplianceImpactDependencyRef
}

// ComplianceImpactDependentRequest pages exact dependents of one exact revision.
type ComplianceImpactDependentRequest struct {
	TenantID    string
	Dependency  ComplianceImpactRevisionRef
	AfterCursor string
	Limit       uint32
}

// ComplianceImpactDependentPage is ordered by a store-defined stable cursor.
type ComplianceImpactDependentPage struct {
	Dependents []ComplianceImpactRevisionRef
	NextCursor string
	Complete   bool
}

// ComplianceImpactGraph exposes immutable domain facts and reverse dependency
// edges. Implementations must scope every read to TenantID.
type ComplianceImpactGraph interface {
	GetComplianceImpactFact(context.Context, string, ComplianceImpactRevisionRef) (ComplianceImpactDomainFact, error)
	ListComplianceImpactDependents(context.Context, ComplianceImpactDependentRequest) (ComplianceImpactDependentPage, error)
}
