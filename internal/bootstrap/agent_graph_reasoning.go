package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/graphquery"
)

func (a *App) handleAgentPlatformGraphReason(w http.ResponseWriter, r *http.Request) {
	var request graphagent.AskRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCAskBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	if err := forceGraphReasoningTenant(r.Context(), &request); err != nil {
		writeGRCError(w, err)
		return
	}
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			writeGRCError(w, err)
			return
		}
	}
	if err := graphagent.ValidateRequest(request); err != nil {
		writeGRCError(w, err)
		return
	}
	service, err := a.newGraphReasoningService()
	if err != nil {
		writeGRCError(w, err)
		return
	}
	response, err := service.Reason(r.Context(), request)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func forceGraphReasoningTenant(ctx context.Context, request *graphagent.AskRequest) error {
	if request == nil {
		return nil
	}
	requestedTenantID := strings.TrimSpace(request.TenantID)
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		request.TenantID = requestedTenantID
		return nil
	}
	tenantID := strings.TrimSpace(auth.principal.TenantID)
	if tenantID == "" {
		return errTenantForbidden
	}
	if requestedTenantID != "" && requestedTenantID != tenantID {
		recordAccessAuditRequestedTenant(ctx, requestedTenantID)
		return errTenantForbidden
	}
	request.TenantID = tenantID
	return authorizeTenantID(ctx, tenantID)
}

func (a *App) newGraphReasoningService() (*graphagent.Service, error) {
	graphStore := graphQueryStore(a.deps.GraphStore)
	if graphStore == nil {
		return nil, graphquery.ErrRuntimeUnavailable
	}
	llm := a.deps.GraphAgentLLM
	if llm == nil {
		return nil, errors.Join(graphagent.ErrRuntimeUnavailable, errors.New("graph agent llm is not configured"))
	}
	return graphagent.NewServiceWithOptions(graphStore, llm, graphagent.ValidatorOptions{Explain: true}, graphagent.ServiceOptions{
		TrajectoryStore:             askTrajectoryStore(a.deps.StateStore),
		EnableGraphProbes:           true,
		EnableDeterministicFastPath: true,
		EnableRecovery:              true,
		EnableMapReduce:             true,
		MaxDepth:                    2,
		MaxChildren:                 2,
	}), nil
}
