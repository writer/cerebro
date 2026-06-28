package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcpolicylifecycle"
)

func (a *App) handleGRCPolicyLifecycle(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	store := graphQueryStore(a.deps.GraphStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	ruleProfile := strings.TrimSpace(r.URL.Query().Get("rule_profile"))
	response, err := grcpolicylifecycle.Build(r.Context(), store, grcpolicylifecycle.Scope{
		TenantID:    scope.TenantID,
		SourceID:    scope.SourceID,
		RuntimeID:   scope.RuntimeID,
		Limit:       scope.Limit,
		RuleProfile: ruleProfile,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGRCPolicyLifecycleAction(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	var request grcpolicylifecycle.ActionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode policy lifecycle action: %w", grcpolicylifecycle.ErrInvalidRequest, err))
		return
	}
	if strings.TrimSpace(request.TenantID) == "" {
		request.TenantID = scope.TenantID
	} else if err := authorizeTenantID(r.Context(), request.TenantID); err != nil {
		writeGRCError(w, err)
		return
	}
	if strings.TrimSpace(request.SourceID) == "" {
		request.SourceID = scope.SourceID
	}
	if strings.TrimSpace(request.RuntimeID) == "" {
		request.RuntimeID = scope.RuntimeID
	}
	request.ActorUserID = customDashboardActorID(r.Context())
	if a.deps.AppendLog == nil {
		writeGRCError(w, grcpolicylifecycle.ErrRuntimeUnavailable)
		return
	}
	projector := sourceProjector(a.deps.StateStore, a.deps.GraphStore)
	if projector == nil {
		writeGRCError(w, grcpolicylifecycle.ErrRuntimeUnavailable)
		return
	}
	event, response, err := grcpolicylifecycle.BuildActionEvent(request, time.Now().UTC())
	if err != nil {
		writeGRCError(w, err)
		return
	}
	if err := a.deps.AppendLog.Append(r.Context(), event); err != nil {
		writeGRCError(w, fmt.Errorf("%w: append policy lifecycle event: %w", grcpolicylifecycle.ErrRuntimeUnavailable, err))
		return
	}
	if _, err := projector.Project(r.Context(), event); err != nil {
		writeGRCError(w, fmt.Errorf("%w: project policy lifecycle event: %w", grcpolicylifecycle.ErrRuntimeUnavailable, err))
		return
	}
	a.bumpGRCCacheVersions(r.Context(), request.TenantID, grcCacheScopeGraph)
	writeJSON(w, http.StatusAccepted, response)
}

func (a *App) handleGRCPolicyLifecycleExport(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	store := graphQueryStore(a.deps.GraphStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	window, err := grcPolicyLifecycleExportWindowFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	ruleProfile := strings.TrimSpace(r.URL.Query().Get("rule_profile"))
	response, err := grcpolicylifecycle.Build(r.Context(), store, grcpolicylifecycle.Scope{
		TenantID:    scope.TenantID,
		SourceID:    scope.SourceID,
		RuntimeID:   scope.RuntimeID,
		Limit:       grcExportLimit,
		RuleProfile: ruleProfile,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeGRCCSV(w, grcExportFilename("policy-lifecycle"), grcpolicylifecycle.AuditExportHeader(), grcpolicylifecycle.AuditExportRows(response, window))
}

func grcPolicyLifecycleExportWindowFromRequest(r *http.Request) (grcpolicylifecycle.ExportWindow, error) {
	var window grcpolicylifecycle.ExportWindow
	if r == nil || r.URL == nil {
		return window, nil
	}
	start, err := grcpolicylifecycle.ParseExportWindowTime(r.URL.Query().Get("start"), false)
	if err != nil {
		return window, fmt.Errorf("%w: invalid start", grcpolicylifecycle.ErrInvalidRequest)
	}
	end, err := grcpolicylifecycle.ParseExportWindowTime(r.URL.Query().Get("end"), true)
	if err != nil {
		return window, fmt.Errorf("%w: invalid end", grcpolicylifecycle.ErrInvalidRequest)
	}
	window.Start, window.End = start, end
	return window, nil
}
