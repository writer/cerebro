package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/agentplatform"
)

func (a *App) handleAgentPlatformContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.Snapshot())
}

func (a *App) handleAgentPlatformCapabilities(w http.ResponseWriter, r *http.Request) {
	filter, err := agentPlatformCapabilityFilterFromRequest(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, agentplatform.ListCapabilities(filter))
}

func (a *App) handleAgentPlatformCapabilityDecision(w http.ResponseWriter, r *http.Request) {
	var request agentplatform.CapabilityDecisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes)).Decode(&request); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, request.ActorID, request.RequestedScopes)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	request.TenantID = resolved.TenantID
	request.ActorID = resolved.ActorID
	request.RequestedScopes = resolved.RequestedScopes
	request.ScopeUnrestricted = resolved.ScopeUnrestricted
	if strings.TrimSpace(request.CapabilityID) == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	decision, ok := agentplatform.DecideCapability(request)
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (a *App) handleAgentPlatformPreflight(w http.ResponseWriter, r *http.Request) {
	var request agentplatform.AgentRunPreflightRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, request.ActorID, request.RequestedScopes)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	request.TenantID = resolved.TenantID
	request.ActorID = resolved.ActorID
	request.RequestedScopes = resolved.RequestedScopes
	request.ScopeUnrestricted = resolved.ScopeUnrestricted
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	writeJSON(w, http.StatusOK, agentplatform.PreflightAgentRun(request))
}

func agentPlatformCapabilityFilterFromRequest(r *http.Request) (agentplatform.CapabilityRegistryFilter, error) {
	query := r.URL.Query()
	filter := agentplatform.CapabilityRegistryFilter{
		DomainID: strings.TrimSpace(query.Get("domain_id")),
		Kind:     strings.TrimSpace(query.Get("kind")),
		Owner:    strings.TrimSpace(query.Get("owner")),
		Risk:     strings.TrimSpace(query.Get("risk")),
	}
	if raw := strings.TrimSpace(query.Get("default_on")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return agentplatform.CapabilityRegistryFilter{}, err
		}
		filter.DefaultOn = &value
	}
	return filter, nil
}

type agentPlatformResolvedContext struct {
	TenantID          string
	ActorID           string
	RequestedScopes   []string
	ScopeUnrestricted bool
	Authenticated     bool
}

func resolveAgentPlatformRequestContext(ctx context.Context, requestedTenantID string, requestedActorID string, requestedScopes []string) (agentPlatformResolvedContext, error) {
	resolved := agentPlatformResolvedContext{
		TenantID:        strings.TrimSpace(requestedTenantID),
		ActorID:         strings.TrimSpace(requestedActorID),
		RequestedScopes: append([]string(nil), requestedScopes...),
	}
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return resolved, nil
	}
	resolved.Authenticated = true
	tenantID := strings.TrimSpace(auth.principal.TenantID)
	if tenantID == "" {
		return agentPlatformResolvedContext{}, errTenantForbidden
	}
	if resolved.TenantID != "" && resolved.TenantID != tenantID {
		recordAccessAuditRequestedTenant(ctx, resolved.TenantID)
		return agentPlatformResolvedContext{}, errTenantForbidden
	}
	resolved.TenantID = tenantID
	resolved.ActorID = agentPlatformPrincipalActorID(auth.principal, resolved.ActorID)
	if principalScopeRestricted(auth.principal) {
		resolved.RequestedScopes = append([]string(nil), auth.principal.Scopes...)
		resolved.ScopeUnrestricted = false
	} else {
		resolved.RequestedScopes = nil
		resolved.ScopeUnrestricted = true
	}
	return resolved, authorizeTenantID(ctx, tenantID)
}

func agentPlatformPrincipalActorID(principal authPrincipal, fallback string) string {
	for _, value := range []string{principal.Name, principal.ClientID, principal.DeviceID, principal.CredentialID} {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return strings.TrimSpace(fallback)
}
