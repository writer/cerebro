package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/graph"
	risk "github.com/evalops/cerebro/internal/graph/risk"
)

func (s *Server) graphStats(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	meta := g.Metadata()
	s.json(w, http.StatusOK, map[string]interface{}{
		"built_at":       meta.BuiltAt,
		"node_count":     meta.NodeCount,
		"edge_count":     meta.EdgeCount,
		"providers":      meta.Providers,
		"accounts":       meta.Accounts,
		"build_duration": meta.BuildDuration.String(),
	})
}

func (s *Server) blastRadius(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := risk.BlastRadius(g, principalID, maxDepth)
	s.json(w, http.StatusOK, result)
}

func (s *Server) cascadingBlastRadius(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	maxDepth := 6
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := risk.CascadingBlastRadius(g, principalID, maxDepth)
	s.json(w, http.StatusOK, result)
}

func (s *Server) reverseAccess(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	resourceID := chi.URLParam(r, "resourceId")
	if resourceID == "" {
		s.error(w, http.StatusBadRequest, "resource ID required")
		return
	}

	maxDepth := 3
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := risk.ReverseAccess(g, resourceID, maxDepth)
	s.json(w, http.StatusOK, result)
}

func (s *Server) rebuildGraph(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraphBuilder == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	if err := s.app.RebuildSecurityGraph(r.Context()); err != nil {
		s.errorFromErr(w, err)
		return
	}

	meta := s.app.SecurityGraph.Metadata()
	s.json(w, http.StatusOK, map[string]interface{}{
		"success":        true,
		"built_at":       meta.BuiltAt,
		"node_count":     meta.NodeCount,
		"edge_count":     meta.EdgeCount,
		"build_duration": meta.BuildDuration.String(),
	})
}

// Risk Intelligence endpoints

func (s *Server) riskReport(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	engine := s.currentTenantRiskEngine(r.Context())
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	report := engine.Analyze()
	// Persist only for global requests. Context-derived scope is stable even if the
	// live graph pointer changes during a concurrent rebuild.
	if !requestUsesTenantScope(r.Context()) {
		s.persistRiskEngineState(r.Context(), engine)
	}
	s.json(w, http.StatusOK, report)
}

func (s *Server) listToxicCombinations(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	pagination := ParsePagination(r, 100, 1000)

	engine := risk.NewToxicCombinationEngine()
	results := engine.Analyze(g)

	// Filter by severity if requested
	severityFilter := r.URL.Query().Get("severity")
	if severityFilter != "" {
		filtered := make([]*risk.ToxicCombination, 0)
		for _, tc := range results {
			if string(tc.Severity) == severityFilter {
				filtered = append(filtered, tc)
			}
		}
		results = filtered
	}

	paged, paginationResp := paginateSlice(results, pagination)

	s.json(w, http.StatusOK, map[string]interface{}{
		"total":       len(results),
		"results":     paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(results),
	})
}

func (s *Server) listGraphAttackPaths(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	simulator := risk.NewAttackPathSimulator(g)

	maxDepth := 6
	if depthStr := r.URL.Query().Get("max_depth"); depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil && d > 0 && d <= 10 {
			maxDepth = d
		}
	}

	result := simulator.Simulate(maxDepth)

	// Filter by score threshold
	threshold := 0.0
	if threshStr := r.URL.Query().Get("threshold"); threshStr != "" {
		if t, err := strconv.ParseFloat(threshStr, 64); err == nil {
			threshold = t
		}
	}

	if threshold > 0 {
		filtered := make([]*risk.ScoredAttackPath, 0)
		for _, path := range result.Paths {
			if path.TotalScore >= threshold {
				filtered = append(filtered, path)
			}
		}
		result.Paths = filtered
	}

	// Limit results
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}
	if len(result.Paths) > limit {
		result.Paths = result.Paths[:limit]
	}

	s.json(w, http.StatusOK, result)
}

func (s *Server) simulateAttackPathFix(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	nodeID := chi.URLParam(r, "id")
	if nodeID == "" {
		s.error(w, http.StatusBadRequest, "node ID required")
		return
	}

	simulator := risk.NewAttackPathSimulator(g)
	result := simulator.Simulate(6)
	fixSim := simulator.SimulateFix(result, nodeID)

	s.json(w, http.StatusOK, fixSim)
}

func (s *Server) listChokepoints(w http.ResponseWriter, r *http.Request) {
	g := s.currentTenantSecurityGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	simulator := risk.NewAttackPathSimulator(g)
	result := simulator.Simulate(6)

	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	chokepoints := result.Chokepoints
	if len(chokepoints) > limit {
		chokepoints = chokepoints[:limit]
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"total":       len(result.Chokepoints),
		"chokepoints": chokepoints,
	})
}

func (s *Server) detectPrivilegeEscalation(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	risks := graph.DetectPrivilegeEscalationRisks(s.app.SecurityGraph, principalID)

	s.json(w, http.StatusOK, map[string]interface{}{
		"principal_id": principalID,
		"risk_count":   len(risks),
		"risks":        risks,
	})
}

// Peer Groups and Access Analysis endpoints

func (s *Server) analyzePeerGroups(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	pagination := ParsePagination(r, 100, 1000)

	minSimilarity := 0.7
	if simStr := r.URL.Query().Get("min_similarity"); simStr != "" {
		if sim, err := strconv.ParseFloat(simStr, 64); err == nil && sim > 0 && sim <= 1 {
			minSimilarity = sim
		}
	}

	minGroupSize := 2
	if sizeStr := r.URL.Query().Get("min_group_size"); sizeStr != "" {
		if size, err := strconv.Atoi(sizeStr); err == nil && size > 1 {
			minGroupSize = size
		}
	}

	analysis := graph.AnalyzePeerGroups(s.app.SecurityGraph, minSimilarity, minGroupSize)
	privilegeCreep := graph.FindPrivilegeCreep(s.app.SecurityGraph, 1.5)
	pagedGroups, paginationResp := paginateSlice(analysis.Groups, pagination)

	s.json(w, http.StatusOK, map[string]interface{}{
		"total_principals": analysis.TotalPrincipals,
		"groups":           pagedGroups,
		"ungrouped":        analysis.Ungrouped,
		"outliers":         analysis.Outliers,
		"privilege_creep":  privilegeCreep,
		"count":            len(pagedGroups),
		"pagination":       paginationResp,
		"total_count":      len(analysis.Groups),
	})
}

func (s *Server) getEffectivePermissions(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	principalID := chi.URLParam(r, "principalId")
	if principalID == "" {
		s.error(w, http.StatusBadRequest, "principal ID required")
		return
	}

	calc := graph.NewEffectivePermissionsCalculator(s.app.SecurityGraph)
	if ctx := permissionEvaluationContextFromRequest(r); ctx != nil {
		s.json(w, http.StatusOK, calc.CalculateWithContext(principalID, ctx))
		return
	}
	perms := calc.Calculate(principalID)

	s.json(w, http.StatusOK, perms)
}

func permissionEvaluationContextFromRequest(r *http.Request) *graph.PermissionEvaluationContext {
	if r == nil || r.URL == nil {
		return nil
	}

	query := r.URL.Query()
	ctx := &graph.PermissionEvaluationContext{
		Keys:          make(map[string]any),
		Request:       make(map[string]any),
		Principal:     make(map[string]any),
		Resource:      make(map[string]any),
		PrincipalTags: make(map[string]string),
		ResourceTags:  make(map[string]string),
	}
	populated := false

	if value := strings.TrimSpace(query.Get("source_ip")); value != "" {
		ctx.SourceIP = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("source_vpce")); value != "" {
		ctx.SourceVPCe = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("principal_arn")); value != "" {
		ctx.PrincipalARN = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("principal_account")); value != "" {
		ctx.PrincipalAccount = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("resource_arn")); value != "" {
		ctx.ResourceARN = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("resource_account")); value != "" {
		ctx.ResourceAccount = value
		populated = true
	}
	if value := strings.TrimSpace(query.Get("current_time")); value != "" {
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			ctx.CurrentTime = parsed.UTC()
			populated = true
		}
	}

	for key, values := range query {
		if len(values) == 0 {
			continue
		}
		assign := func(target map[string]any, trimmedKey string) {
			if trimmedKey == "" {
				return
			}
			populated = true
			if len(values) == 1 {
				target[trimmedKey] = values[0]
				return
			}
			target[trimmedKey] = append([]string(nil), values...)
		}

		switch {
		case strings.HasPrefix(key, "context."):
			assign(ctx.Keys, strings.TrimPrefix(key, "context."))
		case strings.HasPrefix(key, "request."):
			assign(ctx.Request, strings.TrimPrefix(key, "request."))
		case strings.HasPrefix(key, "principal."):
			assign(ctx.Principal, strings.TrimPrefix(key, "principal."))
		case strings.HasPrefix(key, "resource."):
			assign(ctx.Resource, strings.TrimPrefix(key, "resource."))
		case strings.HasPrefix(key, "principal_tag."):
			tagKey := strings.TrimPrefix(key, "principal_tag.")
			if tagKey != "" {
				ctx.PrincipalTags[tagKey] = values[len(values)-1]
				populated = true
			}
		case strings.HasPrefix(key, "resource_tag."):
			tagKey := strings.TrimPrefix(key, "resource_tag.")
			if tagKey != "" {
				ctx.ResourceTags[tagKey] = values[len(values)-1]
				populated = true
			}
		}
	}

	if !populated {
		return nil
	}
	if len(ctx.Keys) == 0 {
		ctx.Keys = nil
	}
	if len(ctx.Request) == 0 {
		ctx.Request = nil
	}
	if len(ctx.Principal) == 0 {
		ctx.Principal = nil
	}
	if len(ctx.Resource) == 0 {
		ctx.Resource = nil
	}
	if len(ctx.PrincipalTags) == 0 {
		ctx.PrincipalTags = nil
	}
	if len(ctx.ResourceTags) == 0 {
		ctx.ResourceTags = nil
	}
	return ctx
}

func (s *Server) comparePermissions(w http.ResponseWriter, r *http.Request) {
	if s.app.SecurityGraph == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	principal1 := r.URL.Query().Get("principal1")
	principal2 := r.URL.Query().Get("principal2")
	if principal1 == "" || principal2 == "" {
		s.error(w, http.StatusBadRequest, "principal1 and principal2 query params required")
		return
	}

	comparison := graph.CompareAccess(s.app.SecurityGraph, principal1, principal2)

	s.json(w, http.StatusOK, comparison)
}
