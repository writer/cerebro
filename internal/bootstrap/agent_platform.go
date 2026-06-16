package bootstrap

import (
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
