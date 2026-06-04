package bootstrap

import (
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/endpointidentity"
	"github.com/writer/cerebro/internal/ports"
)

type trustContextRequest struct {
	TenantID           string   `json:"tenant_id"`
	RuntimeID          string   `json:"runtime_id,omitempty"`
	AgentID            string   `json:"agent_id,omitempty"`
	DeviceID           string   `json:"device_id,omitempty"`
	HardwareUUID       string   `json:"hardware_uuid,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	MaxAllowedSeverity string   `json:"max_allowed_severity,omitempty"`
	GraphRootURNs      []string `json:"graph_root_urns,omitempty"`
}

type trustContextResponse struct {
	GraphNeighborhoodLoaded bool     `json:"graph_neighborhood_loaded"`
	ActiveFindingCount      uint64   `json:"active_finding_count"`
	MaxFindingSeverity      string   `json:"max_finding_severity,omitempty"`
	RiskScore               uint64   `json:"risk_score,omitempty"`
	StaleEvidenceCount      uint64   `json:"stale_evidence_count"`
	GraphRootURNs           []string `json:"graph_root_urns"`
	ResolvedDeviceID        string   `json:"resolved_device_id,omitempty"`
	CandidateDeviceIDs      []string `json:"candidate_device_ids,omitempty"`
	AmbiguousIdentity       bool     `json:"ambiguous_identity,omitempty"`
}

func (app *App) handleGetTrustContext(w http.ResponseWriter, r *http.Request) {
	var request trustContextRequest
	if err := readJSONRequest(r, &request); err != nil {
		writeGraphQueryError(w, errInvalidHTTPRequest)
		return
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required")
		return
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeDeviceAuthError(w, http.StatusForbidden, "tenant_forbidden", err.Error())
		return
	}
	response := trustContextResponse{
		GraphNeighborhoodLoaded: true,
		GraphRootURNs:           trustContextRootURNs(tenantID, request),
	}
	if identity := endpointIdentityStore(app.deps.StateStore); identity != nil {
		resolution, err := identity.ResolveEndpointIdentity(r.Context(), ports.EndpointIdentityResolveRequest{
			TenantID: tenantID,
			Aliases:  trustContextAliases(request),
			Limit:    20,
		})
		if err != nil {
			writeDeviceAuthError(w, http.StatusServiceUnavailable, "identity_unavailable", err.Error())
			return
		}
		response.ResolvedDeviceID = resolution.CanonicalDeviceID
		response.CandidateDeviceIDs = resolution.CandidateDeviceIDs
		response.AmbiguousIdentity = resolution.Ambiguous
		if resolution.CanonicalDeviceID != "" {
			response.GraphRootURNs = append(response.GraphRootURNs, trustEndpointAgentURN(tenantID, resolution.CanonicalDeviceID))
		}
	}
	response.GraphRootURNs = uniqueStrings(response.GraphRootURNs)
	if findings := findingStore(app.deps.StateStore); findings != nil {
		applyTrustContextFindings(r, findings, tenantID, strings.TrimSpace(firstNonEmpty(request.RuntimeID, "trusted-endpoint")), &response)
	} else {
		response.GraphNeighborhoodLoaded = false
	}
	writeJSON(w, http.StatusOK, response)
}

func trustContextAliases(request trustContextRequest) []ports.EndpointIdentityAlias {
	tenantID := strings.TrimSpace(request.TenantID)
	now := time.Now().UTC()
	return []ports.EndpointIdentityAlias{
		{TenantID: tenantID, AliasType: endpointidentity.AliasDeviceID, AliasValue: request.DeviceID, ObservedAt: now},
		{TenantID: tenantID, AliasType: endpointidentity.AliasTrustedEndpointAgentID, AliasValue: request.AgentID, ObservedAt: now},
		{TenantID: tenantID, AliasType: endpointidentity.AliasHardwareUUID, AliasValue: request.HardwareUUID, ObservedAt: now},
		{TenantID: tenantID, AliasType: endpointidentity.AliasSerialNumber, AliasValue: request.SerialNumber, ObservedAt: now},
		{TenantID: tenantID, AliasType: endpointidentity.AliasHostname, AliasValue: request.Hostname, ObservedAt: now},
	}
}

func trustContextRootURNs(tenantID string, request trustContextRequest) []string {
	roots := append([]string(nil), request.GraphRootURNs...)
	if strings.TrimSpace(request.AgentID) != "" {
		roots = append(roots, trustEndpointAgentURN(tenantID, request.AgentID))
	}
	if strings.TrimSpace(request.DeviceID) != "" {
		roots = append(roots, trustEndpointAgentURN(tenantID, request.DeviceID))
	}
	return uniqueStrings(roots)
}

func applyTrustContextFindings(r *http.Request, store ports.FindingStore, tenantID string, runtimeID string, response *trustContextResponse) {
	seen := map[string]struct{}{}
	maxSeverity := ""
	var maxRisk uint64
	var stale uint64
	for _, root := range response.GraphRootURNs {
		findings, err := store.ListFindings(r.Context(), ports.ListFindingsRequest{
			TenantID:    tenantID,
			RuntimeID:   runtimeID,
			Status:      "active",
			ResourceURN: root,
			Limit:       100,
		})
		if err != nil {
			continue
		}
		for _, finding := range findings {
			if finding == nil {
				continue
			}
			if _, ok := seen[finding.ID]; ok {
				continue
			}
			seen[finding.ID] = struct{}{}
			response.ActiveFindingCount++
			if maxSeverity == "" || severityRank(finding.Severity) < severityRank(maxSeverity) {
				maxSeverity = finding.Severity
			}
			if finding.RiskScore > int(maxRisk) {
				maxRisk = uint64(finding.RiskScore)
			}
			if !finding.LastObservedAt.IsZero() && time.Since(finding.LastObservedAt) > 24*time.Hour {
				stale++
			}
		}
	}
	response.MaxFindingSeverity = maxSeverity
	response.RiskScore = maxRisk
	response.StaleEvidenceCount = stale
}

func trustEndpointAgentURN(tenantID string, agentID string) string {
	values := []string{"urn", "cerebro", strings.TrimSpace(tenantID), "trusted_endpoint_agent", strings.TrimSpace(agentID)}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return strings.Join(out, ":")
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
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
	return out
}
