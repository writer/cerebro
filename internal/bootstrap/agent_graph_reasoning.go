package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/graphagent"
)

func (a *App) handleAgentPlatformGraphReason(w http.ResponseWriter, r *http.Request) {
	var request graphagent.AskRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCAskBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, "", nil)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	request.TenantID = resolved.TenantID
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			writeGRCError(w, err)
			return
		}
	}
	preflight := agentplatform.PreflightAgentRun(agentplatform.AgentRunPreflightRequest{
		TenantID:              request.TenantID,
		ActorID:               resolved.ActorID,
		CapabilityIDs:         []string{agentplatform.DefaultAgentRunCapabilityID},
		Question:              request.Question,
		ScopeURN:              request.ScopeURN,
		Model:                 request.Model,
		RequestedScopes:       resolved.RequestedScopes,
		ScopeUnrestricted:     resolved.ScopeUnrestricted || !resolved.Authenticated,
		ProvenanceRequirement: "graph-reasoning",
	})
	if !preflight.Enabled {
		writeGRCError(w, agentPreflightDeniedError(preflight))
		return
	}
	request.PlatformContext = &preflight
	if err := graphagent.ValidateRequest(request); err != nil {
		writeGRCError(w, err)
		return
	}
	service, err := a.newGraphReasoningService()
	if err != nil {
		writeGRCError(w, err)
		return
	}
	clearLongRunningWriteDeadline(w)
	response, err := service.Reason(r.Context(), request)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) newGraphReasoningService() (*graphagent.Service, error) {
	return newGraphReasoningFeatureService(newGraphReasoningFeatureDeps(a.deps))
}

func agentPreflightDeniedError(preflight agentplatform.AgentRunPreflight) error {
	for _, blocker := range preflight.Blockers {
		if blocker.Code == "tenant_required" {
			return fmt.Errorf("%w: tenant_id is required", graphagent.ErrInvalidRequest)
		}
	}
	return errScopeForbidden
}
