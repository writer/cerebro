package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/a2agateway"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/agentplatformcoverage"
	"github.com/writer/cerebro/internal/authz"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) handleAgentPlatformContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.Snapshot())
}

func (a *App) handleA2AAgentCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, agentplatform.BuildA2AAgentCard(externalOrigin(r, a.cfg.Auth.RequestOrigin)))
}

func (a *App) handleA2AJSONRPC(w http.ResponseWriter, r *http.Request) {
	var request agentplatform.A2AJSONRPCRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, agentplatform.A2AJSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &agentplatform.A2AJSONError{Code: -32700, Message: "Parse error"},
		})
		return
	}
	response := a2agateway.Handler{
		Store:                 jobStore(a.deps.StateStore),
		Card:                  agentplatform.BuildA2AAgentCard(externalOrigin(r, a.cfg.Auth.RequestOrigin)),
		Resolve:               a.resolveA2AGatewayContext,
		CoverageContext:       a.agentCoverageContext,
		AuthorizeEvidence:     authorizeAgentPlatformPacketURNs,
		RecordRequestedTenant: recordAccessAuditRequestedTenant,
		IdempotencyKey:        r.Header.Get("Idempotency-Key"),
	}.Respond(r.Context(), request)
	writeJSON(w, http.StatusOK, response)
}

func (a *App) resolveA2AGatewayContext(ctx context.Context, tenantID string, actorID string, scopes []string) (a2agateway.ResolvedContext, error) {
	resolved, err := resolveAgentPlatformRequestContext(ctx, tenantID, actorID, scopes)
	return a2agateway.ResolvedContext{
		TenantID:          resolved.TenantID,
		ActorID:           resolved.ActorID,
		RequestedScopes:   resolved.RequestedScopes,
		ScopeUnrestricted: resolved.ScopeUnrestricted,
	}, err
}

func (a *App) handleEventSubscriptionContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.EventSubscriptions())
}

func (a *App) handleIdempotencyContract(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.Idempotency())
}

func (a *App) handleAgentPlatformCapabilities(w http.ResponseWriter, r *http.Request) {
	filter, err := agentPlatformCapabilityFilterFromRequest(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, agentplatform.ListCapabilities(filter))
}

func (a *App) handleAgentPlatformSecurityControlPlane(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, agentplatform.SecurityControlPlaneSnapshot())
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
	request.CoverageContext = a.agentCoverageContext(r.Context(), request.TenantID)
	if request.ScopeURN != "" {
		if err := authorizeCerebroURNTenant(r.Context(), request.ScopeURN); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	writeJSON(w, http.StatusOK, agentplatform.PreflightAgentRun(request))
}

func (a *App) handleAgentPlatformEvidencePacket(w http.ResponseWriter, r *http.Request) {
	var request agentplatform.EvidencePacketRequest
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
	request.CoverageContext = a.agentCoverageContext(r.Context(), request.TenantID)
	if err := authorizeAgentPlatformPacketURNs(r.Context(), request); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, agentplatform.BuildEvidencePacket(request))
}

func (a *App) handleAgentPlatformClaimVerification(w http.ResponseWriter, r *http.Request) {
	var request agentplatform.ClaimVerificationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProtoJSONBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	resolved, err := resolveAgentPlatformRequestContext(r.Context(), request.TenantID, request.ActorID, nil)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	request.TenantID = resolved.TenantID
	request.ActorID = resolved.ActorID
	request.CoverageContext = a.agentCoverageContext(r.Context(), request.TenantID)
	if strings.TrimSpace(request.Claim) == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := authorizeAgentPlatformClaimVerificationURNs(r.Context(), request); err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, agentplatform.BuildClaimVerification(request))
}

func authorizeAgentPlatformPacketURNs(ctx context.Context, request agentplatform.EvidencePacketRequest) error {
	urns := append([]string{request.ScopeURN}, request.EvidenceURNs...)
	urns = append(urns, request.Action.TargetURNs...)
	for _, hint := range request.MemoryHints {
		urns = append(urns, hint.URN)
	}
	for _, urn := range urns {
		urn = strings.TrimSpace(urn)
		if urn == "" {
			continue
		}
		if err := authorizeCerebroURNTenant(ctx, urn); err != nil {
			return err
		}
	}
	return nil
}

func authorizeAgentPlatformClaimVerificationURNs(ctx context.Context, request agentplatform.ClaimVerificationRequest) error {
	urns := []string{request.ScopeURN}
	urns = append(urns, request.SupportingEvidenceURNs...)
	urns = append(urns, request.CounterEvidenceURNs...)
	urns = append(urns, request.MissingEvidence...)
	for _, urn := range urns {
		urn = strings.TrimSpace(urn)
		if urn == "" || !strings.HasPrefix(urn, "urn:cerebro:") {
			continue
		}
		if err := authorizeCerebroURNTenant(ctx, urn); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) agentCoverageContext(ctx context.Context, tenantID string) *agentplatform.AgentCoverageContext {
	generatedAt := time.Now().UTC()
	lister, _ := sourceRuntimeStore(a.deps.StateStore).(ports.SourceRuntimeListStore)
	return agentplatformcoverage.FromRuntimeStore(ctx, a.sources, lister, tenantID, generatedAt, func(runtime *cerebrov1.SourceRuntime) string {
		return runtimeHealthStatus(runtime, generatedAt)
	}, 5)
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
	tenantID := firstNonEmpty(auth.principal.TenantID, resolved.TenantID)
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
		resolved.RequestedScopes = expandedPrincipalScopes(auth.principal)
		resolved.ScopeUnrestricted = false
	} else {
		resolved.RequestedScopes = nil
		resolved.ScopeUnrestricted = true
	}
	return resolved, authorizeTenantID(ctx, tenantID)
}

func agentPlatformPrincipalActorID(principal authPrincipal, fallback string) string {
	return authz.PrincipalActorID(principal.Name, principal.ClientID, principal.DeviceID, principal.CredentialID, fallback)
}
