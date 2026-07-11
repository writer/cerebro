// Package complianceintegration defines immutable, transport-independent facts
// that source-domain adapters expose to compliance impact analysis.
package complianceintegration

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

var ErrInvalidFact = errors.New("invalid compliance integration fact")

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

// FactKind identifies the lifecycle-owning shape of an immutable domain fact.
type FactKind string

const (
	FactCatalog             FactKind = "catalog"
	FactMapping             FactKind = "mapping"
	FactSourceCoverage      FactKind = "source_coverage"
	FactInventory           FactKind = "inventory"
	FactPolicy              FactKind = "policy"
	FactVendor              FactKind = "vendor"
	FactClaim               FactKind = "claim"
	FactFinding             FactKind = "finding"
	FactProgram             FactKind = "program"
	FactAssessmentPlan      FactKind = "assessment_plan"
	FactObjective           FactKind = "objective"
	FactAuditPackage        FactKind = "audit_package"
	FactWorkItem            FactKind = "work_item"
	FactProjection          FactKind = "projection"
	FactQuestionnaireAnswer FactKind = "questionnaire_answer"
)

// RevisionRef is an immutable adapter over one canonical compliance revision.
// Tenant, domain, and kind make the otherwise transport-neutral revision safe
// to use as an impact-graph identity.
type RevisionRef struct {
	valid    bool
	tenantID string
	domain   string
	kind     FactKind
	revision compliance.RevisionRef
}

// AdaptRevisionRef validates and normalizes an exact canonical revision.
func AdaptRevisionRef(tenantID, domain string, kind FactKind, source compliance.RevisionRef) (RevisionRef, error) {
	tenantID = strings.TrimSpace(tenantID)
	domain = strings.ToLower(strings.TrimSpace(domain))
	kind = FactKind(strings.ToLower(strings.TrimSpace(string(kind))))
	source = compliance.NormalizeRevisionRef(source)
	if tenantID == "" || len(tenantID) > 255 || strings.ContainsRune(tenantID, '\x00') {
		return RevisionRef{}, fmt.Errorf("%w: tenant_id is required and must be bounded", ErrInvalidFact)
	}
	if !identifierPattern.MatchString(domain) {
		return RevisionRef{}, fmt.Errorf("%w: invalid domain %q", ErrInvalidFact, domain)
	}
	if !validFactKind(kind) {
		return RevisionRef{}, fmt.Errorf("%w: invalid fact kind %q", ErrInvalidFact, kind)
	}
	if err := source.Validate(); err != nil {
		return RevisionRef{}, fmt.Errorf("%w: revision: %v", ErrInvalidFact, err)
	}
	if strings.ContainsRune(source.ID, '\x00') || strings.ContainsRune(source.RevisionID, '\x00') {
		return RevisionRef{}, fmt.Errorf("%w: revision identifiers contain a reserved character", ErrInvalidFact)
	}
	return RevisionRef{valid: true, tenantID: tenantID, domain: domain, kind: kind, revision: source}, nil
}

func validFactKind(kind FactKind) bool {
	switch kind {
	case FactCatalog, FactMapping, FactSourceCoverage, FactInventory, FactPolicy,
		FactVendor, FactClaim, FactFinding, FactProgram, FactAssessmentPlan,
		FactObjective, FactAuditPackage, FactWorkItem, FactProjection,
		FactQuestionnaireAnswer:
		return true
	default:
		return false
	}
}

func (r RevisionRef) TenantID() string                  { return r.tenantID }
func (r RevisionRef) Domain() string                    { return r.domain }
func (r RevisionRef) Kind() FactKind                    { return r.kind }
func (r RevisionRef) ID() string                        { return r.revision.ID }
func (r RevisionRef) RevisionID() string                { return r.revision.RevisionID }
func (r RevisionRef) Version() uint64                   { return r.revision.Version }
func (r RevisionRef) Canonical() compliance.RevisionRef { return r.revision }
func (r RevisionRef) ExactKey() string {
	if !r.valid {
		return ""
	}
	return r.subjectKey() + "\x00" + r.revision.RevisionID + "\x00" + strconv.FormatUint(r.revision.Version, 10) + "\x00" + string(r.revision.ContentDigest) + "\x00" + r.revision.LastModified.Format(time.RFC3339Nano)
}
func (r RevisionRef) SameSubject(other RevisionRef) bool { return r.subjectKey() == other.subjectKey() }
func (r RevisionRef) Equal(other RevisionRef) bool       { return r.ExactKey() == other.ExactKey() }
func (r RevisionRef) subjectKey() string {
	return r.tenantID + "\x00" + r.domain + "\x00" + string(r.kind) + "\x00" + r.revision.ID
}

// DependencyRef identifies the exact upstream revision and why it is used.
type DependencyRef struct {
	revision RevisionRef
	relation string
}

// NewDependencyRef creates one explicit, exact dependency edge.
func NewDependencyRef(revision RevisionRef, relation string) (DependencyRef, error) {
	relation = strings.ToLower(strings.TrimSpace(relation))
	if revision.ExactKey() == "" {
		return DependencyRef{}, fmt.Errorf("%w: dependency revision is required", ErrInvalidFact)
	}
	if !identifierPattern.MatchString(relation) {
		return DependencyRef{}, fmt.Errorf("%w: invalid dependency relation %q", ErrInvalidFact, relation)
	}
	return DependencyRef{revision: revision, relation: relation}, nil
}

func (d DependencyRef) Revision() RevisionRef { return d.revision }
func (d DependencyRef) Relation() string      { return d.relation }

// DomainFact is an immutable exact revision plus explicit upstream revisions.
// Dependencies returns a copy so callers cannot mutate the fact after creation.
type DomainFact struct {
	revision     RevisionRef
	dependencies []DependencyRef
}

// NewDomainFact validates tenant isolation and canonicalizes dependency order.
func NewDomainFact(revision RevisionRef, dependencies []DependencyRef) (DomainFact, error) {
	if revision.ExactKey() == "" {
		return DomainFact{}, fmt.Errorf("%w: revision is required", ErrInvalidFact)
	}
	result := append([]DependencyRef(nil), dependencies...)
	for index, dependency := range result {
		if dependency.revision.TenantID() != revision.TenantID() {
			return DomainFact{}, fmt.Errorf("%w: dependency[%d] crosses tenant boundary", ErrInvalidFact, index)
		}
		if dependency.relation == "" {
			return DomainFact{}, fmt.Errorf("%w: dependency[%d] relation is required", ErrInvalidFact, index)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].revision.ExactKey() + "\x00" + result[i].relation
		right := result[j].revision.ExactKey() + "\x00" + result[j].relation
		return left < right
	})
	result = deduplicateDependencies(result)
	return DomainFact{revision: revision, dependencies: result}, nil
}

func deduplicateDependencies(values []DependencyRef) []DependencyRef {
	result := make([]DependencyRef, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1].revision.Equal(value.revision) && result[len(result)-1].relation == value.relation {
			continue
		}
		result = append(result, value)
	}
	return result
}

func (f DomainFact) Revision() RevisionRef { return f.revision }
func (f DomainFact) Dependencies() []DependencyRef {
	return append([]DependencyRef(nil), f.dependencies...)
}
