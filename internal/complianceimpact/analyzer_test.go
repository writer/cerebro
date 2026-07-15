package complianceimpact

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
)

func TestAnalyzeReportsAllTargetClassesAndDeletionInvalidations(t *testing.T) {
	policy := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	claim := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactClaim, "claim", 1), edge(t, policy, "policy_source"))
	objective := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactObjective, "objective", 1), edge(t, claim.Revision(), "claim_source"))
	plan := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan", 1), edge(t, objective.Revision(), "objective_input"))
	program := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program", 1), edge(t, policy, "policy_scope"))
	pack := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactAuditPackage, "package", 1), edge(t, plan.Revision(), "plan_result"))
	work := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactWorkItem, "work", 1), edge(t, objective.Revision(), "objective_gap"))
	projection := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProjection, "projection", 1), edge(t, claim.Revision(), "claim_projection"))
	root := impactFact(t, policy)
	graph := newFakeGraph(root, claim, objective, plan, program, pack, work, projection)
	result := analyzeSignal(t, graph, policy, complianceintegration.ChangeDeleted, DefaultLimits())

	if !result.Complete || len(result.Issues) != 0 {
		t.Fatalf("result complete=%v issues=%v", result.Complete, result.Issues)
	}
	for label, count := range map[string]int{"programs": len(result.Programs), "plans": len(result.Plans), "objectives": len(result.Objectives), "packages": len(result.Packages), "work": len(result.WorkItems)} {
		if count != 1 {
			t.Fatalf("%s count = %d, want 1", label, count)
		}
	}
	if got := result.Packages[0].Reasons; !reflect.DeepEqual(got, []ReasonCode{ReasonDependencyDeleted}) {
		t.Fatalf("package reasons = %v", got)
	}
	if result.Packages[0].Distance != 4 {
		t.Fatalf("package distance = %d, want 4", result.Packages[0].Distance)
	}
	if got := invalidatedIDs(result.Invalidations); !reflect.DeepEqual(got, []string{"claim", "projection"}) {
		t.Fatalf("invalidations = %v, want claim and projection", got)
	}
}

func TestAnalyzeUsesRevocationAndUpdateReasonCodes(t *testing.T) {
	policy := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	program := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program", 1), edge(t, policy, "policy_scope"))
	graph := newFakeGraph(impactFact(t, policy), program)
	revoked := analyzeSignal(t, graph, policy, complianceintegration.ChangeRevoked, DefaultLimits())
	if !reflect.DeepEqual(revoked.Programs[0].Reasons, []ReasonCode{ReasonDependencyRevoked}) {
		t.Fatalf("revoked reasons = %v", revoked.Programs[0].Reasons)
	}

	replacement := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 2)
	signal, err := complianceintegration.NewChangeSignal(complianceintegration.ChangeUpdated, policy, &replacement, time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := NewAnalyzer(graph, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := analyzer.Analyze(context.Background(), signal)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updated.Programs[0].Reasons, []ReasonCode{ReasonDependencyChanged}) {
		t.Fatalf("updated reasons = %v", updated.Programs[0].Reasons)
	}
}

func TestAnalyzeMissingRevisionIsHardError(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	missing := impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program", 1)
	graph := newFakeGraph(impactFact(t, root))
	graph.dependents[root.ExactKey()] = []ports.ComplianceImpactRevisionRef{portRef(missing)}

	result, err := analyze(t, graph, root, complianceintegration.ChangeDeleted, DefaultLimits())
	if !errors.Is(err, ErrRevisionMissing) {
		t.Fatalf("error = %v, want ErrRevisionMissing", err)
	}
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatalf("returned partial best-effort result: %#v", result)
	}
}

func TestAnalyzeRejectsAlteredExactRevisionMetadata(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	graph := newFakeGraph(impactFact(t, root))
	raw := graph.facts[root.ExactKey()]
	raw.Revision.ContentDigest = "sha256:" + strings.Repeat("b", 64)
	graph.facts[root.ExactKey()] = raw

	if _, err := analyze(t, graph, root, complianceintegration.ChangeDeleted, DefaultLimits()); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("error = %v, want ErrInvalidGraph", err)
	}
}

func TestAnalyzeRejectsCrossTenantAndUnbackedEdges(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	foreign := impactRevision(t, "tenant-b", complianceintegration.FactProgram, "program", 1)
	graph := newFakeGraph(impactFact(t, root), impactFact(t, foreign))
	graph.dependents[root.ExactKey()] = []ports.ComplianceImpactRevisionRef{portRef(foreign)}
	if _, err := analyze(t, graph, root, complianceintegration.ChangeUpdated, DefaultLimits()); !errors.Is(err, ErrTenantBoundary) {
		t.Fatalf("cross-tenant error = %v", err)
	}

	program := impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program", 1)
	graph = newFakeGraph(impactFact(t, root), impactFact(t, program))
	graph.dependents[root.ExactKey()] = []ports.ComplianceImpactRevisionRef{portRef(program)}
	if _, err := analyze(t, graph, root, complianceintegration.ChangeUpdated, DefaultLimits()); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("unbacked edge error = %v", err)
	}
}

func TestAnalyzeDetectsCyclesWithoutConfusingConvergentPaths(t *testing.T) {
	policy := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	projectionRef := impactRevision(t, "tenant-a", complianceintegration.FactProjection, "projection", 1)
	policyFact := impactFact(t, policy, edge(t, projectionRef, "projection_source"))
	projection := impactFact(t, projectionRef, edge(t, policy, "policy_source"))
	cycle := analyzeSignal(t, newFakeGraph(policyFact, projection), policy, complianceintegration.ChangeUpdated, DefaultLimits())
	if cycle.Complete || len(cycle.Issues) != 1 || cycle.Issues[0].Code != ReasonCycleDetected {
		t.Fatalf("cycle result complete=%v issues=%v", cycle.Complete, cycle.Issues)
	}

	left := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactClaim, "left", 1), edge(t, policy, "left_source"))
	right := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactClaim, "right", 1), edge(t, policy, "right_source"))
	objective := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactObjective, "objective", 1), edge(t, left.Revision(), "left_claim"), edge(t, right.Revision(), "right_claim"))
	convergent := analyzeSignal(t, newFakeGraph(impactFact(t, policy), left, right, objective), policy, complianceintegration.ChangeUpdated, DefaultLimits())
	if !convergent.Complete || len(convergent.Issues) != 0 || len(convergent.Objectives) != 1 {
		t.Fatalf("convergent graph misclassified: complete=%v issues=%v objectives=%d", convergent.Complete, convergent.Issues, len(convergent.Objectives))
	}
}

func TestAnalyzeEnforcesNodeDepthAndGlobalEdgeBudgets(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	objective := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactObjective, "objective", 1), edge(t, root, "policy_source"))
	plan := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactAssessmentPlan, "plan", 1), edge(t, objective.Revision(), "objective_source"))
	pack := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactAuditPackage, "package", 1), edge(t, plan.Revision(), "plan_source"))
	graph := newFakeGraph(impactFact(t, root), objective, plan, pack)

	nodeLimited := analyzeSignal(t, graph, root, complianceintegration.ChangeUpdated, Limits{MaxNodes: 2, MaxEdges: 10, MaxDepth: 10, PageSize: 2})
	if nodeLimited.Complete || len(nodeLimited.Objectives) != 1 || len(nodeLimited.Plans) != 0 || !hasIssue(nodeLimited, ReasonNodeBudgetExceeded) {
		t.Fatalf("node-limited result: %#v", nodeLimited)
	}

	depthLimited := analyzeSignal(t, graph, root, complianceintegration.ChangeUpdated, Limits{MaxNodes: 10, MaxEdges: 10, MaxDepth: 1, PageSize: 2})
	if depthLimited.Complete || len(depthLimited.Objectives) != 1 || len(depthLimited.Plans) != 0 || !hasIssue(depthLimited, ReasonDepthBudgetExceeded) {
		t.Fatalf("depth-limited result: %#v", depthLimited)
	}

	work := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactWorkItem, "work", 1), edge(t, objective.Revision(), "objective_work"))
	graph = newFakeGraph(impactFact(t, root), objective, plan, work)
	edgeLimited := analyzeSignal(t, graph, root, complianceintegration.ChangeUpdated, Limits{MaxNodes: 10, MaxEdges: 2, MaxDepth: 10, PageSize: 10})
	if edgeLimited.Complete || !hasIssue(edgeLimited, ReasonEdgeBudgetExceeded) || len(edgeLimited.Plans)+len(edgeLimited.WorkItems) > 1 {
		t.Fatalf("edge-limited result escaped global budget: %#v", edgeLimited)
	}
}

func TestAnalyzePaginatesAndReturnsDeterministicOrdering(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	programA := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "a", 1), edge(t, root, "z_relation"), edge(t, root, "a_relation"))
	programB := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "b", 1), edge(t, root, "policy_scope"))
	graphA := newFakeGraph(impactFact(t, root), programB, programA)
	graphB := newFakeGraph(impactFact(t, root), programA, programB)
	limits := Limits{MaxNodes: 10, MaxEdges: 10, MaxDepth: 10, PageSize: 1}
	left := analyzeSignal(t, graphA, root, complianceintegration.ChangeUpdated, limits)
	right := analyzeSignal(t, graphB, root, complianceintegration.ChangeUpdated, limits)
	if !reflect.DeepEqual(left.Programs, right.Programs) {
		t.Fatalf("ordering changed with source order:\nleft=%#v\nright=%#v", left.Programs, right.Programs)
	}
	if got := left.Programs[0].Relations; !reflect.DeepEqual(got, []string{"a_relation", "z_relation"}) {
		t.Fatalf("relations = %v", got)
	}
}

func TestAnalyzerRejectsInvalidLimitsAndStalledCursor(t *testing.T) {
	root := impactRevision(t, "tenant-a", complianceintegration.FactPolicy, "policy", 1)
	graph := newFakeGraph(impactFact(t, root))
	if _, err := NewAnalyzer(graph, Limits{}); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("limits error = %v", err)
	}
	programA := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program-a", 1), edge(t, root, "policy_scope"))
	programB := impactFact(t, impactRevision(t, "tenant-a", complianceintegration.FactProgram, "program-b", 1), edge(t, root, "policy_scope"))
	graph = newFakeGraph(impactFact(t, root), programA, programB)
	graph.stallCursor = true
	if _, err := analyze(t, graph, root, complianceintegration.ChangeUpdated, Limits{MaxNodes: 10, MaxEdges: 10, MaxDepth: 10, PageSize: 1}); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("cursor error = %v", err)
	}
}

type fakeGraph struct {
	facts       map[string]ports.ComplianceImpactDomainFact
	dependents  map[string][]ports.ComplianceImpactRevisionRef
	stallCursor bool
}

func newFakeGraph(facts ...complianceintegration.DomainFact) *fakeGraph {
	result := &fakeGraph{facts: map[string]ports.ComplianceImpactDomainFact{}, dependents: map[string][]ports.ComplianceImpactRevisionRef{}}
	for _, fact := range facts {
		result.facts[fact.Revision().ExactKey()] = portFact(fact)
		for _, dependency := range fact.Dependencies() {
			key := dependency.Revision().ExactKey()
			result.dependents[key] = append(result.dependents[key], portRef(fact.Revision()))
		}
	}
	for key := range result.dependents {
		sort.Slice(result.dependents[key], func(i, j int) bool {
			return result.dependents[key][i].ID < result.dependents[key][j].ID
		})
	}
	return result
}

func (f *fakeGraph) GetComplianceImpactFact(_ context.Context, tenantID string, ref ports.ComplianceImpactRevisionRef) (ports.ComplianceImpactDomainFact, error) {
	if tenantID != ref.TenantID {
		return ports.ComplianceImpactDomainFact{}, ports.ErrComplianceImpactRevisionNotFound
	}
	fact, ok := f.facts[portKey(ref)]
	if !ok {
		return ports.ComplianceImpactDomainFact{}, ports.ErrComplianceImpactRevisionNotFound
	}
	return fact, nil
}

func (f *fakeGraph) ListComplianceImpactDependents(_ context.Context, request ports.ComplianceImpactDependentRequest) (ports.ComplianceImpactDependentPage, error) {
	values := f.dependents[portKey(request.Dependency)]
	start := 0
	if request.AfterCursor != "" {
		value, err := strconv.Atoi(request.AfterCursor)
		if err != nil {
			return ports.ComplianceImpactDependentPage{}, err
		}
		start = value
	}
	end := min(len(values), start+int(request.Limit))
	page := ports.ComplianceImpactDependentPage{Dependents: append([]ports.ComplianceImpactRevisionRef(nil), values[start:end]...), Complete: end == len(values)}
	if !page.Complete && !f.stallCursor {
		page.NextCursor = strconv.Itoa(end)
	}
	return page, nil
}

func impactRevision(t *testing.T, tenant string, kind complianceintegration.FactKind, id string, version uint64) complianceintegration.RevisionRef {
	t.Helper()
	ref, err := complianceintegration.AdaptRevisionRef(tenant, "test.domain", kind, compliance.RevisionRef{
		ID: id, RevisionID: id + "-r" + strconv.FormatUint(version, 10), Version: version,
		ContentDigest: compliance.ContentDigest("sha256:" + strings.Repeat("a", 64)), LastModified: time.Unix(1, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func edge(t *testing.T, revision complianceintegration.RevisionRef, relation string) complianceintegration.DependencyRef {
	t.Helper()
	result, err := complianceintegration.NewDependencyRef(revision, relation)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func impactFact(t *testing.T, revision complianceintegration.RevisionRef, dependencies ...complianceintegration.DependencyRef) complianceintegration.DomainFact {
	t.Helper()
	result, err := complianceintegration.NewDomainFact(revision, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func analyzeSignal(t *testing.T, graph ports.ComplianceImpactGraph, revision complianceintegration.RevisionRef, kind complianceintegration.ChangeKind, limits Limits) Result {
	t.Helper()
	result, err := analyze(t, graph, revision, kind, limits)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func analyze(t *testing.T, graph ports.ComplianceImpactGraph, revision complianceintegration.RevisionRef, kind complianceintegration.ChangeKind, limits Limits) (Result, error) {
	t.Helper()
	signal, err := complianceintegration.NewChangeSignal(kind, revision, nil, time.Unix(10, 0))
	if kind == complianceintegration.ChangeUpdated {
		replacement := impactRevision(t, revision.TenantID(), revision.Kind(), revision.ID(), revision.Version()+1)
		signal, err = complianceintegration.NewChangeSignal(kind, revision, &replacement, time.Unix(10, 0))
	}
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := NewAnalyzer(graph, limits)
	if err != nil {
		return Result{}, err
	}
	return analyzer.Analyze(context.Background(), signal)
}

func portRef(ref complianceintegration.RevisionRef) ports.ComplianceImpactRevisionRef {
	return portRevision(ref)
}

func portFact(fact complianceintegration.DomainFact) ports.ComplianceImpactDomainFact {
	result := ports.ComplianceImpactDomainFact{Revision: portRef(fact.Revision())}
	for _, dependency := range fact.Dependencies() {
		result.Dependencies = append(result.Dependencies, ports.ComplianceImpactDependencyRef{Revision: portRef(dependency.Revision()), Relation: dependency.Relation()})
	}
	return result
}

func portKey(ref ports.ComplianceImpactRevisionRef) string {
	return ref.TenantID + "\x00" + ref.Domain + "\x00" + ref.Kind + "\x00" + ref.ID + "\x00" + ref.RevisionID + "\x00" + strconv.FormatUint(ref.Version, 10) + "\x00" + ref.ContentDigest + "\x00" + ref.LastModified.UTC().Format(time.RFC3339Nano)
}

func invalidatedIDs(values []Invalidation) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Revision.ID())
	}
	sort.Strings(result)
	return result
}

func hasIssue(result Result, code ReasonCode) bool {
	for _, issue := range result.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
