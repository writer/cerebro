package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentauthoring"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/policycandidate"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) handleCreatePolicyCandidate(w http.ResponseWriter, r *http.Request) {
	var request policycandidate.CreateRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writePolicyCandidateError(w, fmt.Errorf("%w: decode request: %w", policycandidate.ErrInvalidRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	request.TenantID = tenantID
	candidate, err := a.policyCandidateService().Create(r.Context(), request)
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newPolicyCandidateView(candidate))
}

func (a *App) handleListPolicyCandidates(w http.ResponseWriter, r *http.Request) {
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			writePolicyCandidateError(w, fmt.Errorf("%w: limit must be an integer", policycandidate.ErrInvalidRequest))
			return
		}
	}
	candidates, err := a.policyCandidateService().List(r.Context(), policycandidate.ListRequest{TenantID: tenantID, Status: r.URL.Query().Get("status"), Limit: limit})
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	views := make([]policyCandidateView, 0, len(candidates))
	for _, candidate := range candidates {
		views = append(views, newPolicyCandidateView(candidate))
	}
	writeJSON(w, http.StatusOK, map[string]any{"candidates": views})
}

func (a *App) handleGetPolicyCandidate(w http.ResponseWriter, r *http.Request) {
	candidate, err := a.authorizedPolicyCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newPolicyCandidateView(candidate))
}

func (a *App) handleProvePolicyCandidate(w http.ResponseWriter, r *http.Request) {
	candidate, err := a.authorizedPolicyCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	candidate, err = a.policyCandidateService().Prove(r.Context(), candidate.ID)
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newPolicyCandidateView(candidate))
}

func (a *App) handleShadowPolicyCandidate(w http.ResponseWriter, r *http.Request) {
	candidate, err := a.authorizedPolicyCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	candidate, err = a.policyCandidateService().Shadow(r.Context(), candidate.ID)
	if err != nil {
		writePolicyCandidateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, newPolicyCandidateView(candidate))
}

type policyCandidateGraphSummary struct {
	NodeCount   int      `json:"node_count"`
	EdgeCount   int      `json:"edge_count"`
	EntityTypes []string `json:"entity_types"`
	Relations   []string `json:"relations"`
}

type policyCandidateView struct {
	ID          string                              `json:"id"`
	TenantID    string                              `json:"tenant_id"`
	Status      string                              `json:"status"`
	Revision    int64                               `json:"revision"`
	Hypothesis  string                              `json:"hypothesis"`
	Domain      string                              `json:"domain"`
	OriginKind  string                              `json:"origin_kind"`
	Graph       policyCandidateGraphSummary         `json:"graph"`
	Grounding   *policycandidate.GroundingReceipt   `json:"grounding,omitempty"`
	CoverageGap *policycandidate.CoverageGapReceipt `json:"coverage_gap,omitempty"`
	Artifacts   *policycandidate.Artifacts          `json:"artifacts,omitempty"`
	Proof       any                                 `json:"proof,omitempty"`
	Shadow      *policycandidate.ShadowReceipt      `json:"shadow,omitempty"`
	PRReady     bool                                `json:"pr_ready"`
	CreatedAt   time.Time                           `json:"created_at"`
	UpdatedAt   time.Time                           `json:"updated_at"`
}

func newPolicyCandidateView(candidate *policycandidate.Candidate) policyCandidateView {
	view := policyCandidateView{
		ID: candidate.ID, TenantID: candidate.TenantID, Status: candidate.Status, Revision: candidate.Revision,
		Hypothesis: candidate.Hypothesis, Domain: candidate.Domain, OriginKind: candidate.Origin.Kind,
		Grounding:   candidate.Grounding,
		CoverageGap: candidate.CoverageGap,
		Artifacts:   candidate.Artifacts, Proof: candidate.Proof, Shadow: candidate.Shadow, PRReady: candidate.PRReady,
		CreatedAt: candidate.CreatedAt, UpdatedAt: candidate.UpdatedAt,
	}
	if candidate.GraphEvidence == nil {
		return view
	}
	view.Graph.NodeCount = len(candidate.GraphEvidence.Nodes)
	view.Graph.EdgeCount = len(candidate.GraphEvidence.Edges)
	entityTypes := map[string]struct{}{}
	for _, node := range candidate.GraphEvidence.Nodes {
		if value := strings.TrimSpace(node.EntityType); value != "" {
			entityTypes[value] = struct{}{}
		}
	}
	relations := map[string]struct{}{}
	for _, edge := range candidate.GraphEvidence.Edges {
		if value := strings.TrimSpace(edge.Relation); value != "" {
			relations[value] = struct{}{}
		}
	}
	for value := range entityTypes {
		view.Graph.EntityTypes = append(view.Graph.EntityTypes, value)
	}
	for value := range relations {
		view.Graph.Relations = append(view.Graph.Relations, value)
	}
	slices.Sort(view.Graph.EntityTypes)
	slices.Sort(view.Graph.Relations)
	return view
}

func (a *App) authorizedPolicyCandidate(r *http.Request, id string) (*policycandidate.Candidate, error) {
	candidate, err := a.policyCandidateService().Get(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if err := authorizeTenantID(r.Context(), candidate.TenantID); err != nil {
		return nil, err
	}
	return candidate, nil
}

func (a *App) policyCandidateService() policycandidate.Service {
	store, _ := a.deps.StateStore.(policycandidate.Store)
	experiments, _ := a.deps.StateStore.(policycandidate.ExperimentStore)
	datasets, _ := a.deps.StateStore.(policycandidate.PolicyEvaluationDatasetStore)
	graph := dependencyGraphQueryStore(a.deps)
	var author *agentauthoring.Service
	if a.deps.PolicyAuthoring != nil {
		copy := *a.deps.PolicyAuthoring
		if graphStore, ok := a.deps.GraphStore.(findingdsl.PolicyGraphTestStore); ok {
			copy.PolicyGraphStore = graphStore
		}
		author = &copy
	}
	var catalog policycandidate.CoverageCatalog
	if a.deps.FindingRules != nil {
		catalog = findingRuleCoverageCatalog{registry: a.deps.FindingRules}
	}
	return policycandidate.Service{Store: store, Experiments: experiments, Datasets: datasets, Author: author, Graph: graph, Catalog: catalog}
}

func policyCandidateServiceForStore(store ports.StateStore) policycandidate.Service {
	candidates, _ := store.(policycandidate.Store)
	experiments, _ := store.(policycandidate.ExperimentStore)
	datasets, _ := store.(policycandidate.PolicyEvaluationDatasetStore)
	return policycandidate.Service{Store: candidates, Experiments: experiments, Datasets: datasets}
}

type findingRuleCoverageCatalog struct{ registry *findings.Registry }

func (c findingRuleCoverageCatalog) ListCoverageQueries(_ context.Context, tenantID string, limit int) ([]policycandidate.CoverageQuery, error) {
	entries, err := c.registry.GraphRuleCatalog(tenantID, limit)
	if err != nil {
		return nil, err
	}
	queries := make([]policycandidate.CoverageQuery, 0, len(entries))
	for _, entry := range entries {
		params, err := json.Marshal(entry.Request.Params)
		if err != nil {
			return nil, fmt.Errorf("encode graph rule %q parameters: %w", entry.RuleID, err)
		}
		query := policycandidate.CoverageQuery{CatalogKey: entry.RuleID, Query: entry.Request.Query + "\n" + string(params), SemanticsComplete: entry.SemanticsComplete}
		query.RequiredEntityTypes = append(query.RequiredEntityTypes, entry.Signature.RequiredEntityTypes...)
		for _, edge := range entry.Signature.RequiredEdges {
			query.RequiredEdges = append(query.RequiredEdges, policycandidate.CoverageEdge{FromEntityType: edge.FromEntityType, Relation: edge.Relation, ToEntityType: edge.ToEntityType})
		}
		for _, predicate := range entry.Signature.RequiredPredicates {
			query.RequiredPredicates = append(query.RequiredPredicates, policycandidate.CoveragePredicate{EntityType: predicate.EntityType, Key: predicate.Key, Value: predicate.Value})
		}
		queries = append(queries, query)
	}
	return queries, nil
}

func writePolicyCandidateError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, policycandidate.ErrInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, policycandidate.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, policycandidate.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, policycandidate.ErrStoreUnavailable), errors.Is(err, policycandidate.ErrAuthorUnavailable), errors.Is(err, policycandidate.ErrGraphUnavailable), errors.Is(err, policycandidate.ErrCoverageUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errTenantForbidden), errors.Is(err, errScopeForbidden):
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}
