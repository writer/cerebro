package complianceimpact

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

// Analyzer traverses reverse dependency edges with hard tenant and budget
// boundaries.
type Analyzer struct {
	graph  ports.ComplianceImpactGraph
	limits Limits
}

func NewAnalyzer(graph ports.ComplianceImpactGraph, limits Limits) (*Analyzer, error) {
	if graph == nil {
		return nil, fmt.Errorf("%w: graph is required", ErrInvalidGraph)
	}
	if limits.MaxNodes == 0 || limits.MaxEdges == 0 || limits.MaxDepth == 0 || limits.PageSize == 0 ||
		limits.MaxNodes > math.MaxInt32 || limits.PageSize > math.MaxInt32 {
		return nil, ErrInvalidLimits
	}
	return &Analyzer{graph: graph, limits: limits}, nil
}

type traversalNode struct {
	fact      complianceintegration.DomainFact
	distance  uint32
	ancestors map[string]struct{}
}

type accumulatedFact struct {
	revision  complianceintegration.RevisionRef
	distance  uint32
	reasons   map[ReasonCode]struct{}
	relations map[string]struct{}
}

// Analyze returns a deterministic impact set. Missing exact revisions and any
// tenant boundary violation are hard errors with no partial result.
func (a *Analyzer) Analyze(ctx context.Context, signal complianceintegration.ChangeSignal) (Result, error) {
	rootRef := signal.Revision()
	tenantID := rootRef.TenantID()
	root, err := a.getFact(ctx, tenantID, rootRef)
	if err != nil {
		return Result{}, err
	}
	result := Result{TenantID: tenantID, Signal: signal, Complete: true}
	visited := map[string]struct{}{rootRef.ExactKey(): {}}
	queue := []traversalNode{{fact: root, ancestors: map[string]struct{}{rootRef.ExactKey(): {}}}}
	affected := make(map[string]*accumulatedFact)
	if isReportedKind(rootRef.Kind()) {
		addAffected(affected, rootRef, 0, directReason(signal.Kind()), "")
	}
	if isInvalidatable(rootRef.Kind()) && invalidationReason(signal.Kind()) != "" {
		result.Invalidations = append(result.Invalidations, Invalidation{Revision: rootRef, Reason: directReason(signal.Kind())})
	}
	var traversedEdges uint32
	for len(queue) != 0 {
		if traversedEdges >= a.limits.MaxEdges && len(queue) != 0 {
			result.Complete = false
			result.Issues = append(result.Issues, Issue{Code: ReasonEdgeBudgetExceeded})
			break
		}
		current := queue[0]
		queue = queue[1:]
		dependents, edgeCount, issues, complete, err := a.listDependents(ctx, tenantID, current, a.limits.MaxEdges-traversedEdges)
		if err != nil {
			return Result{}, err
		}
		traversedEdges += edgeCount
		result.Issues = append(result.Issues, issues...)
		result.Complete = result.Complete && complete
		for _, dependent := range dependents {
			relations, err := explicitRelations(dependent.fact, current.fact.Revision())
			if err != nil {
				return Result{}, err
			}
			ref := dependent.fact.Revision()
			if _, cyclic := current.ancestors[ref.ExactKey()]; cyclic {
				for _, relation := range relations {
					addAffected(affected, ref, dependent.distance, dependencyReason(signal.Kind()), relation)
				}
				result.Complete = false
				result.Issues = append(result.Issues, Issue{Code: ReasonCycleDetected, Revision: current.fact.Revision(), Related: ref})
				continue
			}
			if _, seen := visited[ref.ExactKey()]; seen {
				for _, relation := range relations {
					addAffected(affected, ref, dependent.distance, dependencyReason(signal.Kind()), relation)
				}
				continue
			}
			// #nosec G115 -- NewAnalyzer bounds MaxNodes to MaxInt32.
			if len(visited) >= int(a.limits.MaxNodes) {
				result.Complete = false
				result.Issues = append(result.Issues, Issue{Code: ReasonNodeBudgetExceeded, Revision: current.fact.Revision(), Related: ref})
				continue
			}
			for _, relation := range relations {
				addAffected(affected, ref, dependent.distance, dependencyReason(signal.Kind()), relation)
			}
			visited[ref.ExactKey()] = struct{}{}
			if isInvalidatable(ref.Kind()) && invalidationReason(signal.Kind()) != "" {
				result.Invalidations = append(result.Invalidations, Invalidation{Revision: ref, Reason: invalidationReason(signal.Kind())})
			}
			ancestors := copySet(current.ancestors)
			ancestors[ref.ExactKey()] = struct{}{}
			queue = append(queue, traversalNode{fact: dependent.fact, distance: dependent.distance, ancestors: ancestors})
		}
	}
	materializeResult(&result, affected)
	canonicalizeResult(&result)
	return result, nil
}

func (a *Analyzer) getFact(ctx context.Context, tenantID string, ref complianceintegration.RevisionRef) (complianceintegration.DomainFact, error) {
	if ref.TenantID() != tenantID {
		return complianceintegration.DomainFact{}, fmt.Errorf("%w: requested revision belongs to another tenant", ErrTenantBoundary)
	}
	rawFact, err := a.graph.GetComplianceImpactFact(ctx, tenantID, portRevision(ref))
	if err != nil {
		if errors.Is(err, ports.ErrComplianceImpactRevisionNotFound) {
			return complianceintegration.DomainFact{}, fmt.Errorf("%w: %s/%s@%s", ErrRevisionMissing, ref.Domain(), ref.ID(), ref.RevisionID())
		}
		return complianceintegration.DomainFact{}, err
	}
	fact, err := adaptPortFact(rawFact)
	if err != nil {
		return complianceintegration.DomainFact{}, err
	}
	if fact.Revision().TenantID() != tenantID {
		return complianceintegration.DomainFact{}, fmt.Errorf("%w: store returned another tenant", ErrTenantBoundary)
	}
	if !fact.Revision().Equal(ref) {
		return complianceintegration.DomainFact{}, fmt.Errorf("%w: store returned a different exact revision", ErrInvalidGraph)
	}
	return fact, nil
}

type dependentNode struct {
	fact     complianceintegration.DomainFact
	distance uint32
}

func (a *Analyzer) listDependents(ctx context.Context, tenantID string, current traversalNode, edgeBudget uint32) ([]dependentNode, uint32, []Issue, bool, error) {
	if current.distance >= a.limits.MaxDepth {
		page, err := a.graph.ListComplianceImpactDependents(ctx, ports.ComplianceImpactDependentRequest{TenantID: tenantID, Dependency: portRevision(current.fact.Revision()), Limit: 1})
		if err != nil {
			return nil, 0, nil, false, err
		}
		if len(page.Dependents) > 1 {
			return nil, 0, nil, false, fmt.Errorf("%w: dependent page exceeds requested limit", ErrInvalidGraph)
		}
		if len(page.Dependents) == 0 {
			return nil, 0, nil, true, nil
		}
		related, err := adaptPortRevision(page.Dependents[0])
		if err != nil {
			return nil, 0, nil, false, err
		}
		if related.TenantID() != tenantID {
			return nil, 0, nil, false, fmt.Errorf("%w: dependent reference belongs to another tenant", ErrTenantBoundary)
		}
		return nil, 1, []Issue{{Code: ReasonDepthBudgetExceeded, Revision: current.fact.Revision(), Related: related}}, false, nil
	}
	var result []dependentNode
	var edges uint32
	cursor := ""
	for {
		remaining := edgeBudget - edges
		if remaining == 0 {
			return result, edges, []Issue{{Code: ReasonEdgeBudgetExceeded, Revision: current.fact.Revision()}}, false, nil
		}
		limit := min(a.limits.PageSize, remaining)
		page, err := a.graph.ListComplianceImpactDependents(ctx, ports.ComplianceImpactDependentRequest{TenantID: tenantID, Dependency: portRevision(current.fact.Revision()), AfterCursor: cursor, Limit: limit})
		if err != nil {
			return nil, 0, nil, false, err
		}
		// #nosec G115 -- NewAnalyzer bounds PageSize, and limit cannot exceed it.
		if len(page.Dependents) > int(limit) {
			return nil, 0, nil, false, fmt.Errorf("%w: dependent page exceeds requested limit", ErrInvalidGraph)
		}
		for _, rawRef := range page.Dependents {
			ref, err := adaptPortRevision(rawRef)
			if err != nil {
				return nil, 0, nil, false, err
			}
			if ref.TenantID() != tenantID {
				return nil, 0, nil, false, fmt.Errorf("%w: dependent reference belongs to another tenant", ErrTenantBoundary)
			}
			fact, err := a.getFact(ctx, tenantID, ref)
			if err != nil {
				return nil, 0, nil, false, err
			}
			result = append(result, dependentNode{fact: fact, distance: current.distance + 1})
			edges++
			if edges == edgeBudget && !page.Complete {
				return result, edges, []Issue{{Code: ReasonEdgeBudgetExceeded, Revision: current.fact.Revision()}}, false, nil
			}
		}
		if page.Complete {
			break
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return nil, 0, nil, false, fmt.Errorf("%w: dependent cursor did not advance", ErrInvalidGraph)
		}
		cursor = page.NextCursor
	}
	return result, edges, nil, true, nil
}

func explicitRelations(fact complianceintegration.DomainFact, dependency complianceintegration.RevisionRef) ([]string, error) {
	relations := make([]string, 0, 1)
	for _, candidate := range fact.Dependencies() {
		if candidate.Revision().Equal(dependency) {
			relations = append(relations, candidate.Relation())
		}
	}
	if len(relations) == 0 {
		return nil, fmt.Errorf("%w: reverse edge is not backed by an explicit dependency", ErrInvalidGraph)
	}
	sort.Strings(relations)
	return relations, nil
}

func addAffected(values map[string]*accumulatedFact, ref complianceintegration.RevisionRef, distance uint32, reason ReasonCode, relation string) {
	if !isReportedKind(ref.Kind()) {
		return
	}
	value, ok := values[ref.ExactKey()]
	if !ok {
		value = &accumulatedFact{revision: ref, distance: distance, reasons: map[ReasonCode]struct{}{}, relations: map[string]struct{}{}}
		values[ref.ExactKey()] = value
	}
	if distance < value.distance {
		value.distance = distance
	}
	if reason != "" {
		value.reasons[reason] = struct{}{}
	}
	if relation != "" {
		value.relations[relation] = struct{}{}
	}
}

func directReason(kind complianceintegration.ChangeKind) ReasonCode {
	switch kind {
	case complianceintegration.ChangeDeleted:
		return ReasonRevisionDeleted
	case complianceintegration.ChangeRevoked:
		return ReasonRevisionRevoked
	default:
		return ReasonRevisionChanged
	}
}

func dependencyReason(kind complianceintegration.ChangeKind) ReasonCode {
	switch kind {
	case complianceintegration.ChangeDeleted:
		return ReasonDependencyDeleted
	case complianceintegration.ChangeRevoked:
		return ReasonDependencyRevoked
	default:
		return ReasonDependencyChanged
	}
}

func invalidationReason(kind complianceintegration.ChangeKind) ReasonCode {
	switch kind {
	case complianceintegration.ChangeDeleted:
		return ReasonDependencyDeleted
	case complianceintegration.ChangeRevoked:
		return ReasonDependencyRevoked
	default:
		return ""
	}
}

func isReportedKind(kind complianceintegration.FactKind) bool {
	switch kind {
	case complianceintegration.FactProgram, complianceintegration.FactAssessmentPlan,
		complianceintegration.FactObjective, complianceintegration.FactAuditPackage,
		complianceintegration.FactWorkItem:
		return true
	default:
		return false
	}
}

func isInvalidatable(kind complianceintegration.FactKind) bool {
	return kind == complianceintegration.FactClaim || kind == complianceintegration.FactProjection
}

func copySet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source)+1)
	for key := range source {
		result[key] = struct{}{}
	}
	return result
}

func materializeResult(result *Result, values map[string]*accumulatedFact) {
	for _, value := range values {
		affected := AffectedFact{Revision: value.revision, Distance: value.distance}
		for reason := range value.reasons {
			affected.Reasons = append(affected.Reasons, reason)
		}
		for relation := range value.relations {
			affected.Relations = append(affected.Relations, relation)
		}
		sort.Slice(affected.Reasons, func(i, j int) bool { return affected.Reasons[i] < affected.Reasons[j] })
		sort.Strings(affected.Relations)
		switch value.revision.Kind() {
		case complianceintegration.FactProgram:
			result.Programs = append(result.Programs, affected)
		case complianceintegration.FactAssessmentPlan:
			result.Plans = append(result.Plans, affected)
		case complianceintegration.FactObjective:
			result.Objectives = append(result.Objectives, affected)
		case complianceintegration.FactAuditPackage:
			result.Packages = append(result.Packages, affected)
		case complianceintegration.FactWorkItem:
			result.WorkItems = append(result.WorkItems, affected)
		}
	}
}

func canonicalizeResult(result *Result) {
	sortAffected := func(values []AffectedFact) {
		sort.Slice(values, func(i, j int) bool { return values[i].Revision.ExactKey() < values[j].Revision.ExactKey() })
	}
	sortAffected(result.Programs)
	sortAffected(result.Plans)
	sortAffected(result.Objectives)
	sortAffected(result.Packages)
	sortAffected(result.WorkItems)
	sort.Slice(result.Invalidations, func(i, j int) bool {
		left := result.Invalidations[i].Revision.ExactKey() + "\x00" + string(result.Invalidations[i].Reason)
		right := result.Invalidations[j].Revision.ExactKey() + "\x00" + string(result.Invalidations[j].Reason)
		return left < right
	})
	result.Invalidations = deduplicateInvalidations(result.Invalidations)
	sort.Slice(result.Issues, func(i, j int) bool {
		left := string(result.Issues[i].Code) + "\x00" + result.Issues[i].Revision.ExactKey() + "\x00" + result.Issues[i].Related.ExactKey()
		right := string(result.Issues[j].Code) + "\x00" + result.Issues[j].Revision.ExactKey() + "\x00" + result.Issues[j].Related.ExactKey()
		return left < right
	})
	result.Issues = deduplicateIssues(result.Issues)
}

func deduplicateInvalidations(values []Invalidation) []Invalidation {
	result := make([]Invalidation, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1].Revision.Equal(value.Revision) && result[len(result)-1].Reason == value.Reason {
			continue
		}
		result = append(result, value)
	}
	return result
}

func deduplicateIssues(values []Issue) []Issue {
	result := make([]Issue, 0, len(values))
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1].Code == value.Code && result[len(result)-1].Revision.Equal(value.Revision) && result[len(result)-1].Related.Equal(value.Related) {
			continue
		}
		result = append(result, value)
	}
	return result
}

func portRevision(ref complianceintegration.RevisionRef) ports.ComplianceImpactRevisionRef {
	canonical := ref.Canonical()
	return ports.ComplianceImpactRevisionRef{
		TenantID:      ref.TenantID(),
		Domain:        ref.Domain(),
		Kind:          string(ref.Kind()),
		ID:            canonical.ID,
		RevisionID:    canonical.RevisionID,
		Version:       canonical.Version,
		ContentDigest: string(canonical.ContentDigest),
		LastModified:  canonical.LastModified,
	}
}

func adaptPortRevision(ref ports.ComplianceImpactRevisionRef) (complianceintegration.RevisionRef, error) {
	result, err := complianceintegration.AdaptRevisionRef(ref.TenantID, ref.Domain, complianceintegration.FactKind(ref.Kind), compliance.RevisionRef{
		ID:            ref.ID,
		RevisionID:    ref.RevisionID,
		Version:       ref.Version,
		ContentDigest: compliance.ContentDigest(ref.ContentDigest),
		LastModified:  ref.LastModified,
	})
	if err != nil {
		return complianceintegration.RevisionRef{}, fmt.Errorf("%w: invalid stored revision: %w", ErrInvalidGraph, err)
	}
	return result, nil
}

func adaptPortFact(raw ports.ComplianceImpactDomainFact) (complianceintegration.DomainFact, error) {
	revision, err := adaptPortRevision(raw.Revision)
	if err != nil {
		return complianceintegration.DomainFact{}, err
	}
	dependencies := make([]complianceintegration.DependencyRef, 0, len(raw.Dependencies))
	for index, rawDependency := range raw.Dependencies {
		dependencyRevision, err := adaptPortRevision(rawDependency.Revision)
		if err != nil {
			return complianceintegration.DomainFact{}, fmt.Errorf("%w: dependency[%d]: %w", ErrInvalidGraph, index, err)
		}
		dependency, err := complianceintegration.NewDependencyRef(dependencyRevision, rawDependency.Relation)
		if err != nil {
			return complianceintegration.DomainFact{}, fmt.Errorf("%w: dependency[%d]: %w", ErrInvalidGraph, index, err)
		}
		dependencies = append(dependencies, dependency)
	}
	fact, err := complianceintegration.NewDomainFact(revision, dependencies)
	if err != nil {
		return complianceintegration.DomainFact{}, fmt.Errorf("%w: stored fact: %w", ErrInvalidGraph, err)
	}
	return fact, nil
}
