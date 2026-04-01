package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

func (s *Server) syncStatus(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "warehouse not configured")
		return
	}

	// Query _cq_sync_time from key tables to determine freshness
	tables := []string{
		"aws_s3_buckets",
		"aws_iam_users",
		"aws_ec2_instances",
		"gcp_storage_buckets",
		"gcp_compute_instances",
		"azure_storage_accounts",
		"k8s_core_pods",
	}

	sources := make(map[string]interface{})
	staleThreshold := 6 * time.Hour

	for _, table := range tables {
		// Validate table name (these are hardcoded above, but validate for safety)
		if err := snowflake.ValidateTableName(table); err != nil {
			continue
		}
		query := fmt.Sprintf("SELECT MAX(_cq_sync_time) as last_sync FROM %s", table)
		result, err := s.app.Warehouse.Query(r.Context(), query)
		if err != nil {
			continue // Table might not exist
		}

		if len(result.Rows) > 0 {
			lastSync := parseLastSyncRow(result.Rows[0])
			if !lastSync.IsZero() {
				status := "fresh"
				if time.Since(lastSync) > staleThreshold {
					status = "stale"
				}

				// Extract provider from table name
				provider := "unknown"
				if len(table) > 4 {
					switch {
					case table[:3] == "aws":
						provider = "aws"
					case table[:3] == "gcp":
						provider = "gcp"
					case table[:5] == "azure":
						provider = "azure"
					case table[:3] == "k8s":
						provider = "kubernetes"
					}
				}

				if existing, ok := sources[provider].(map[string]interface{}); ok {
					// Keep the most recent sync time
					if existingTime, ok := existing["last_sync"].(time.Time); ok {
						if lastSync.After(existingTime) {
							sources[provider] = map[string]interface{}{
								"last_sync": lastSync,
								"status":    status,
								"age":       time.Since(lastSync).String(),
							}
						}
					}
				} else {
					sources[provider] = map[string]interface{}{
						"last_sync": lastSync,
						"status":    status,
						"age":       time.Since(lastSync).String(),
					}
				}
			}
		}
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"sources":         sources,
		"stale_threshold": staleThreshold.String(),
		"checked_at":      time.Now().UTC(),
	})
}

func parseLastSyncRow(row map[string]interface{}) time.Time {
	value, ok := queryRowValue(row, "last_sync")
	if !ok {
		return time.Time{}
	}
	return parseLastSyncValue(value)
}

func parseLastSyncValue(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed
	case *time.Time:
		if typed == nil {
			return time.Time{}
		}
		return *typed
	case string:
		if typed == "" {
			return time.Time{}
		}
		if parsed, err := time.Parse(time.RFC3339Nano, typed); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339, typed); err == nil {
			return parsed
		}
	}

	return time.Time{}
}

// Query endpoints

func (s *Server) listTables(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}
	pagination := ParsePagination(r, 100, 1000)

	tables, err := s.app.Warehouse.ListTables(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	sort.Strings(tables)
	paged, paginationResp := paginateSlice(tables, pagination)

	s.json(w, http.StatusOK, map[string]interface{}{
		"tables":      paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(tables),
	})
}

func (s *Server) executeQuery(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Query          string `json:"query"`
		Limit          int    `json:"limit"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	boundedQuery, boundedLimit, err := warehouse.BuildReadOnlyLimitedQuery(req.Query, req.Limit)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	queryCtx, cancel := context.WithTimeout(r.Context(), warehouse.ClampReadOnlyQueryTimeout(req.TimeoutSeconds))
	defer cancel()

	result, err := s.app.Warehouse.Query(queryCtx, boundedQuery)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "query execution failed")
		return
	}

	if result != nil && result.Count > boundedLimit {
		result.Rows = result.Rows[:boundedLimit]
		result.Count = len(result.Rows)
	}

	s.json(w, http.StatusOK, result)
}

// Asset endpoints

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	limit := queryPositiveInt(r, "limit", 100)

	assets, err := s.app.Warehouse.GetAssets(r.Context(), table, snowflake.AssetFilter{
		Limit:   limit,
		Account: r.URL.Query().Get("account"),
		Region:  r.URL.Query().Get("region"),
	})
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"assets": assets, "count": len(assets)})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	if s.app.Warehouse == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	id := chi.URLParam(r, "id")

	asset, err := s.app.Warehouse.GetAssetByID(r.Context(), table, id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	if asset == nil {
		s.error(w, http.StatusNotFound, "asset not found")
		return
	}
	s.json(w, http.StatusOK, asset)
}

// Policy endpoints

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	pagination := ParsePagination(r, 100, 1000)
	policies := s.app.Policy.ListPolicies()
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })

	paged, paginationResp := paginateSlice(policies, pagination)
	s.json(w, http.StatusOK, map[string]interface{}{
		"policies":    paged,
		"count":       len(paged),
		"pagination":  paginationResp,
		"total_count": len(policies),
	})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, ok := s.app.Policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}
	s.json(w, http.StatusOK, p)
}

func (s *Server) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		s.error(w, http.StatusBadRequest, "policy id required")
		return
	}

	versions := s.app.Policy.ListPolicyVersions(id)
	if len(versions) == 0 {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"policy_id": id,
		"versions":  versions,
		"count":     len(versions),
	})
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.app.Policy.ValidatePolicyDefinition(&p); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.app.Policy.AddPolicy(&p)

	persisted, ok := s.app.Policy.GetPolicy(strings.TrimSpace(p.ID))
	if !ok {
		s.error(w, http.StatusInternalServerError, "failed to persist policy")
		return
	}
	if err := s.persistPolicyHistory(r.Context(), persisted.ID); err != nil {
		s.app.Logger.Warn("failed to persist policy history", "policy_id", persisted.ID, "error", err)
	}

	s.json(w, http.StatusCreated, persisted)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		s.error(w, http.StatusBadRequest, "policy id required")
		return
	}

	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if strings.TrimSpace(p.ID) != "" && p.ID != id {
		s.error(w, http.StatusBadRequest, "policy id in body must match path id")
		return
	}

	p.ID = id
	if err := s.app.Policy.ValidatePolicyDefinition(&p); err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	if ok := s.app.Policy.UpdatePolicy(id, &p); !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}

	updated, ok := s.app.Policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusInternalServerError, "failed to load updated policy")
		return
	}
	if err := s.persistPolicyHistory(r.Context(), id); err != nil {
		s.app.Logger.Warn("failed to persist policy history", "policy_id", id, "error", err)
	}

	s.json(w, http.StatusOK, updated)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if strings.TrimSpace(id) == "" {
		s.error(w, http.StatusBadRequest, "policy id required")
		return
	}
	if ok := s.app.Policy.DeletePolicy(id); !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}
	if err := s.persistPolicyHistory(r.Context(), id); err != nil {
		s.app.Logger.Warn("failed to persist policy history", "policy_id", id, "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

type policyRollbackRequest struct {
	Version int `json:"version"`
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		s.error(w, http.StatusBadRequest, "policy id required")
		return
	}

	var req policyRollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Version <= 0 {
		s.error(w, http.StatusBadRequest, "version must be positive")
		return
	}

	rolledBack, err := s.app.Policy.RollbackPolicy(id, req.Version)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	if err := s.persistPolicyHistory(r.Context(), id); err != nil {
		s.app.Logger.Warn("failed to persist policy history", "policy_id", id, "error", err)
	}

	s.json(w, http.StatusOK, rolledBack)
}

type policyDryRunRequest struct {
	Policy     policy.Policy            `json:"policy"`
	Assets     []map[string]interface{} `json:"assets"`
	AssetLimit int                      `json:"asset_limit,omitempty"`
}

func (s *Server) dryRunPolicyChange(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		s.error(w, http.StatusBadRequest, "policy id required")
		return
	}

	current, ok := s.app.Policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}

	var req policyDryRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	candidate := req.Policy
	candidate.ID = id
	candidate.Version = current.Version
	candidate.LastModified = current.LastModified

	assets := req.Assets
	assetSource := "request"
	if len(assets) == 0 {
		fetched, err := s.loadPolicyDryRunAssets(r.Context(), current, &candidate, req.AssetLimit)
		if err != nil {
			s.errorFromErr(w, err)
			return
		}
		assets = fetched
		if len(assets) == 0 {
			assetSource = "none"
		} else {
			assetSource = "snowflake"
		}
	}

	diff := policy.DiffPolicies(current, &candidate)
	impact, err := s.app.Policy.DryRunPolicyChange(r.Context(), current, &candidate, assets)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"dry_run":      true,
		"policy_id":    id,
		"asset_source": assetSource,
		"diff":         diff,
		"impact":       impact,
	})
}

func (s *Server) persistPolicyHistory(ctx context.Context, policyID string) error {
	if s.app.PolicyHistoryRepo == nil {
		return nil
	}

	events := s.app.Policy.ListPolicyVersions(policyID)
	for _, event := range events {
		content, err := json.Marshal(event.Content)
		if err != nil {
			return fmt.Errorf("marshal policy history content: %w", err)
		}

		var pinnedVersion *int
		if event.Content != nil && event.Content.PinnedVersion > 0 {
			pinned := event.Content.PinnedVersion
			pinnedVersion = &pinned
		}

		if err := s.app.PolicyHistoryRepo.Upsert(ctx, &snowflake.PolicyHistoryRecord{
			PolicyID:      event.PolicyID,
			Version:       event.Version,
			Content:       content,
			ChangeType:    string(event.EventType),
			PinnedVersion: pinnedVersion,
			EffectiveFrom: event.EffectiveFrom,
			EffectiveTo:   event.EffectiveTo,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) loadPolicyDryRunAssets(ctx context.Context, current, candidate *policy.Policy, limit int) ([]map[string]interface{}, error) {
	if s.app.Warehouse == nil {
		return nil, nil
	}

	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	tables := make(map[string]struct{})
	addTables := func(policyDef *policy.Policy) {
		if policyDef == nil {
			return
		}
		for _, table := range policyDef.GetRequiredTables() {
			table = strings.ToLower(strings.TrimSpace(table))
			if table == "" || table == "*" {
				continue
			}
			tables[table] = struct{}{}
		}
	}
	addTables(current)
	addTables(candidate)

	if len(tables) == 0 {
		return nil, nil
	}

	assets := make([]map[string]interface{}, 0, limit*len(tables))
	for table := range tables {
		rows, err := s.app.Warehouse.GetAssets(ctx, table, snowflake.AssetFilter{Limit: limit})
		if err != nil {
			s.app.Logger.Warn("dry-run asset load failed", "table", table, "error", err)
			continue
		}
		for _, row := range rows {
			if _, hasTable := row["_cq_table"]; !hasTable {
				row["_cq_table"] = table
			}
			assets = append(assets, row)
		}
	}

	return assets, nil
}

func (s *Server) evaluatePolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		policy.EvalRequest
		ProposedChange *graphEvaluateChangeRequest `json:"proposed_change,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request")
		return
	}

	policyResp, err := s.app.Policy.Evaluate(r.Context(), &req.EvalRequest)
	if err != nil {
		s.errorFromErr(w, err)
		return
	}

	decision := strings.ToLower(strings.TrimSpace(policyResp.Decision))
	if decision == "" {
		decision = "allow"
	}
	if decision == "needs_approval" {
		decision = "require_approval"
	}
	matched := append([]string(nil), policyResp.Matched...)
	reasons := append([]string(nil), policyResp.Reasons...)

	var propagationResult *graph.PropagationResult
	if decision != "deny" && req.ProposedChange != nil {
		g, err := s.currentTenantSecurityGraphView(r.Context())
		if err != nil {
			s.errorFromErr(w, err)
			return
		}

		delta := graph.GraphDelta{
			Nodes: append([]graph.NodeMutation(nil), req.ProposedChange.Nodes...),
			Edges: append([]graph.EdgeMutation(nil), req.ProposedChange.Edges...),
		}
		if len(req.ProposedChange.Mutations) > 0 {
			parsed, parseErr := parseGraphMutations(req.ProposedChange.Mutations)
			if parseErr != nil {
				s.error(w, http.StatusBadRequest, parseErr.Error())
				return
			}
			delta.Nodes = append(delta.Nodes, parsed.Nodes...)
			delta.Edges = append(delta.Edges, parsed.Edges...)
		}

		if len(delta.Nodes) > 0 || len(delta.Edges) > 0 {
			options := make([]graph.PropagationOption, 0, 1)
			if req.ProposedChange.ApprovalARRThreshold != nil {
				options = append(options, graph.WithApprovalARRThreshold(*req.ProposedChange.ApprovalARRThreshold))
			}

			proposal := &graph.ChangeProposal{
				ID:     strings.TrimSpace(req.ProposedChange.ID),
				Source: strings.TrimSpace(req.ProposedChange.Source),
				Reason: strings.TrimSpace(req.ProposedChange.Reason),
				Delta:  delta,
			}
			engine := graph.NewPropagationEngine(g, options...)
			propagationResult, err = engine.Evaluate(proposal)
			if err != nil {
				s.error(w, http.StatusBadRequest, err.Error())
				return
			}

			switch propagationResult.Decision {
			case graph.DecisionBlocked:
				decision = "deny"
				reasons = append(reasons, propagationResult.BlockReasons...)
			case graph.DecisionNeedsApproval:
				decision = "require_approval"
				reasons = append(reasons, propagationResult.ApprovalReasons...)
			}
		}
	}

	remediationSteps := policyEvaluationRemediationSteps(decision, matched, reasons, propagationResult)
	response := map[string]any{
		"decision":          decision,
		"requires_approval": decision == "require_approval",
		"matched":           matched,
		"reasons":           dedupeAndSortStrings(reasons),
		"remediation_steps": remediationSteps,
		"policy_evaluation": policyResp,
	}
	if propagationResult != nil {
		response["propagation"] = propagationResult
	}

	s.logPolicyEvaluationDecision(r.Context(), r, &req.EvalRequest, decision, matched, reasons, remediationSteps)
	s.json(w, http.StatusOK, response)
}

func (s *Server) logPolicyEvaluationDecision(ctx context.Context, r *http.Request, req *policy.EvalRequest, decision string, matched []string, reasons []string, remediation []string) {
	if req == nil || auditLoggerIsNil(s.auditLogger) {
		return
	}

	actorID := strings.TrimSpace(GetUserID(ctx))
	if actorID == "" {
		for _, key := range []string{"id", "user_id", "email"} {
			value := strings.TrimSpace(stringValue(req.Principal[key]))
			if value != "" {
				actorID = value
				break
			}
		}
	}
	if actorID == "" {
		actorID = "api"
	}

	resourceType := strings.TrimSpace(stringValue(req.Resource["type"]))
	if resourceType == "" {
		resourceType = "policy_enforcement"
	}
	resourceID := strings.TrimSpace(stringValue(req.Resource["id"]))

	entry := &snowflake.AuditEntry{
		Action:       "policy.evaluate",
		ActorID:      actorID,
		ActorType:    "user",
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details: map[string]any{
			"decision":          decision,
			"requires_approval": decision == "require_approval",
			"action":            strings.TrimSpace(req.Action),
			"matched":           dedupeAndSortStrings(matched),
			"reasons":           dedupeAndSortStrings(reasons),
			"remediation_steps": dedupeAndSortStrings(remediation),
			"evaluated_at":      time.Now().UTC().Format(time.RFC3339Nano),
		},
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	if err := s.auditLogger.Log(ctx, entry); err != nil && s.app != nil && s.app.Logger != nil {
		s.app.Logger.Warn("failed to persist policy evaluation audit log", "error", err, "decision", decision, "action", req.Action)
	}
}

func auditLoggerIsNil(logger auditLogWriter) bool {
	if logger == nil {
		return true
	}
	value := reflect.ValueOf(logger)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func policyEvaluationRemediationSteps(decision string, matched []string, reasons []string, propagation *graph.PropagationResult) []string {
	steps := make([]string, 0, 6)
	if decision == "deny" {
		if len(matched) > 0 {
			steps = append(steps, "Review matched policy requirements and update action context before retrying")
		}
		steps = append(steps, "Apply least-privilege scope or required controls, then re-run evaluation")
	}
	if decision == "require_approval" {
		steps = append(steps, "Submit this action for manual approval with business justification")
		steps = append(steps, "Attach impact analysis and mitigation plan to the approval request")
	}
	if propagation != nil {
		if propagation.AffectedARR > 0 {
			steps = append(steps, fmt.Sprintf("Validate customer impact (affected ARR %.0f) and stage rollout safely", propagation.AffectedARR))
		}
		if len(propagation.SLARisk) > 0 {
			steps = append(steps, "Coordinate with service owners for SLA-risked systems before execution")
		}
		if propagation.AttackPathsCreated > 0 || propagation.ToxicCombosIntroduced > 0 {
			steps = append(steps, "Adjust proposed change to avoid introducing new attack paths or toxic combinations")
		}
	}
	if len(steps) == 0 && len(reasons) > 0 {
		steps = append(steps, "Address listed evaluation reasons and re-submit for policy check")
	}
	if len(steps) == 0 {
		steps = append(steps, "No remediation required")
	}
	return dedupeAndSortStrings(steps)
}

func dedupeAndSortStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// Finding endpoints

// Identity/Access Review endpoints
