package bootstrap

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findingapi"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) handleListFindingRules(w http.ResponseWriter, r *http.Request) {
	writeProtoJSON(w, http.StatusOK, a.findingService().ListRules())
}

func (a *App) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), r.PathValue("findingID")); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().GetFinding(r.Context(), r.PathValue("findingID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleResolveFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ResolveFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawReason := r.URL.Query().Get("reason"); rawReason != "" {
		request.Reason = rawReason
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	options, err := findingapi.StatusUpdateOptions(request.GetExpectedStatus(), timestampValue(request.GetLastObservedBefore()), request.GetStatusSource())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	finding, err := a.findingService().ResolveFindingWithOptions(r.Context(), request.GetId(), request.GetReason(), options)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ResolveFindingResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleSuppressFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SuppressFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawReason := r.URL.Query().Get("reason"); rawReason != "" {
		request.Reason = rawReason
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	options, err := findingapi.StatusUpdateOptions(request.GetExpectedStatus(), timestampValue(request.GetLastObservedBefore()), request.GetStatusSource())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	finding, err := a.findingService().SuppressFindingWithOptions(r.Context(), request.GetId(), request.GetReason(), options)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.SuppressFindingResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleAssignFinding(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.AssignFindingRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if rawAssignee, ok := r.URL.Query()["assignee"]; ok && len(rawAssignee) != 0 {
		request.Assignee = rawAssignee[len(rawAssignee)-1]
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().AssignFinding(r.Context(), request.GetId(), request.GetAssignee())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.AssignFindingResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleSetFindingDueDate(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SetFindingDueDateRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	var dueAt time.Time
	if request.GetDueAt() != nil {
		dueAt = request.GetDueAt().AsTime()
	}
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().SetFindingDueDate(r.Context(), request.GetId(), dueAt)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.SetFindingDueDateResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleAddFindingNote(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.AddFindingNoteRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().AddFindingNote(r.Context(), request.GetId(), request.GetNote())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.AddFindingNoteResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleLinkFindingTicket(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.LinkFindingTicketRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().LinkFindingTicket(
		r.Context(),
		request.GetId(),
		request.GetUrl(),
		request.GetName(),
		request.GetExternalId(),
	)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.LinkFindingTicketResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleLinkFindingExternalRef(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.LinkFindingExternalRefRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("findingID")
	if err := authorizeFindingIDTenant(r.Context(), findingStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingNotFound))
		return
	}
	finding, err := a.findingService().LinkFindingExternalRef(r.Context(), request.GetId(), findingapi.ExternalRefFromLinkRequest(request))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), finding)
	writeProtoJSON(w, http.StatusOK, &cerebrov1.LinkFindingExternalRefResponse{
		Finding: safeFindingMessage(finding),
	})
}

func (a *App) handleListEndpointVulnerabilityFindings(w http.ResponseWriter, r *http.Request) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeFindingError(w, fmt.Errorf("%w: %w", findings.ErrInvalidRequest, err))
		return
	}
	includeStale, err := boolQueryParam(r, "include_stale")
	if err != nil {
		writeFindingError(w, fmt.Errorf("%w: %w", findings.ErrInvalidRequest, err))
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok && strings.TrimSpace(auth.principal.TenantID) != "" {
			tenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant"))
	}
	if tenantID == "" && requiresTenantFilter(r.Context()) {
		writeFindingError(w, errTenantForbidden)
		return
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeFindingError(w, err)
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceKey"))
	if deviceID == "" {
		deviceID = strings.TrimSpace(r.URL.Query().Get("device_id"))
	}
	response, err := findings.ListEndpointVulnerabilityFindings(r.Context(), endpointVulnerabilityFindingStore(a.deps.StateStore), findings.EndpointVulnerabilityRequest{
		TenantID:     tenantID,
		DeviceID:     deviceID,
		SerialNumber: r.URL.Query().Get("serial_number"),
		AgentID:      r.URL.Query().Get("agent_id"),
		Limit:        limit,
		IncludeStale: includeStale,
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) handleGetFindingEvaluationRun(w http.ResponseWriter, r *http.Request) {
	response, err := a.findingService().GetEvaluationRun(r.Context(), r.PathValue("runID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), response.GetRuntimeId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingEvaluationRunNotFound))
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingEvaluationRunResponse{
		Run: response,
	})
}

func (a *App) handleGetFindingEvidence(w http.ResponseWriter, r *http.Request) {
	response, err := a.findingService().GetEvidence(r.Context(), r.PathValue("evidenceID"))
	if err != nil {
		writeFindingError(w, err)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), response.GetRuntimeId()); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingEvidenceNotFound))
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingEvidenceResponse{
		Evidence: safeFindingEvidence(response),
	})
}

func (a *App) handleEvaluateSourceRuntimeFindings(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingsRequest{}
	request.RuleId = r.URL.Query().Get("rule_id")
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	request.RuleId = r.URL.Query().Get("rule_id")
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().EvaluateSourceRuntime(r.Context(), findings.EvaluateRequest{
		RuntimeID:  request.GetId(),
		RuleID:     request.GetRuleId(),
		EventLimit: request.GetEventLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	bumpGRCCacheForRuntime(r.Context(), a.deps, request.GetId(), grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	writeProtoJSON(w, http.StatusOK, findingResponse(response))
}

func (a *App) handleEvaluateSourceRuntimeFindingRules(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		// Unmarshal the override into a separate message so we do not reset
		// rule_ids (or any future field) provided in the request body.
		overrides := &cerebrov1.EvaluateSourceRuntimeFindingRulesRequest{}
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := unmarshalHTTPProtoJSON(body, overrides); err != nil {
			writeFindingError(w, err)
			return
		}
		request.EventLimit = overrides.GetEventLimit()
	}
	request.Id = r.PathValue("runtimeID")
	if ruleIDs := r.URL.Query()["rule_id"]; len(ruleIDs) != 0 {
		request.RuleIds = ruleIDs
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().EvaluateSourceRuntimeRules(r.Context(), findings.EvaluateRulesRequest{
		RuntimeID:  request.GetId(),
		RuleIDs:    request.GetRuleIds(),
		EventLimit: request.GetEventLimit(),
	})
	if response != nil {
		bumpGRCCacheForRuntime(r.Context(), a.deps, request.GetId(), grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
	}
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, findingRulesResponse(response))
}

func (a *App) handleEvaluateSourceRuntimeFindingCandidates(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.EvaluateSourceRuntimeFindingCandidatesRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	if eventLimit := r.URL.Query().Get("event_limit"); eventLimit != "" {
		overrides := &cerebrov1.EvaluateSourceRuntimeFindingCandidatesRequest{}
		body := []byte(`{"event_limit":` + eventLimit + `}`)
		if err := unmarshalHTTPProtoJSON(body, overrides); err != nil {
			writeFindingError(w, err)
			return
		}
		request.EventLimit = overrides.GetEventLimit()
	}
	request.Id = r.PathValue("runtimeID")
	if ruleIDs := r.URL.Query()["rule_id"]; len(ruleIDs) != 0 {
		request.RuleIds = ruleIDs
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().EvaluateSourceRuntimeCandidateRules(r.Context(), findings.EvaluateCandidateRulesRequest{
		RuntimeID:  request.GetId(),
		RuleIDs:    request.GetRuleIds(),
		EventLimit: request.GetEventLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, findingCandidateRulesResponse(response))
}

func (a *App) handleListFindings(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingsRequest{
		RuntimeId:   r.PathValue("runtimeID"),
		FindingId:   r.URL.Query().Get("finding_id"),
		RuleId:      r.URL.Query().Get("rule_id"),
		Severity:    r.URL.Query().Get("severity"),
		ResourceUrn: r.URL.Query().Get("resource_urn"),
		EventId:     r.URL.Query().Get("event_id"),
		PolicyId:    r.URL.Query().Get("policy_id"),
	}
	if rawStatus := r.URL.Query().Get("status"); rawStatus != "" {
		status, err := parseFindingStatus(rawStatus)
		if err != nil {
			writeFindingError(w, err)
			return
		}
		request.Status = status
	}
	if rawOrder := r.URL.Query().Get("order"); rawOrder != "" {
		order, err := parseFindingOrder(rawOrder)
		if err != nil {
			writeFindingError(w, err)
			return
		}
		request.Order = order
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.FindingId = r.URL.Query().Get("finding_id")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.Severity = r.URL.Query().Get("severity")
		request.ResourceUrn = r.URL.Query().Get("resource_urn")
		request.EventId = r.URL.Query().Get("event_id")
		request.PolicyId = r.URL.Query().Get("policy_id")
		if rawStatus := r.URL.Query().Get("status"); rawStatus != "" {
			status, err := parseFindingStatus(rawStatus)
			if err != nil {
				writeFindingError(w, err)
				return
			}
			request.Status = status
		}
		if rawOrder := r.URL.Query().Get("order"); rawOrder != "" {
			order, err := parseFindingOrder(rawOrder)
			if err != nil {
				writeFindingError(w, err)
				return
			}
			request.Order = order
		}
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().ListFindings(r.Context(), findings.ListRequest{
		RuntimeID:   request.GetRuntimeId(),
		FindingID:   request.GetFindingId(),
		RuleID:      request.GetRuleId(),
		Severity:    request.GetSeverity(),
		Status:      findingStatusString(request.GetStatus()),
		ResourceURN: request.GetResourceUrn(),
		EventID:     request.GetEventId(),
		PolicyID:    request.GetPolicyId(),
		Limit:       request.GetLimit(),
		Order:       findingOrder(request.GetOrder()),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, listFindingsResponse(response))
}

func (a *App) handleListFindingCandidates(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingCandidatesRequest{
		RuntimeId:   r.PathValue("runtimeID"),
		CandidateId: r.URL.Query().Get("candidate_id"),
		RuleId:      r.URL.Query().Get("rule_id"),
		Status:      r.URL.Query().Get("status"),
		Fingerprint: r.URL.Query().Get("fingerprint"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.CandidateId = r.URL.Query().Get("candidate_id")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.Status = r.URL.Query().Get("status")
		request.Fingerprint = r.URL.Query().Get("fingerprint")
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().ListFindingCandidates(r.Context(), findings.ListCandidatesRequest{
		RuntimeID:   request.GetRuntimeId(),
		CandidateID: request.GetCandidateId(),
		RuleID:      request.GetRuleId(),
		Status:      request.GetStatus(),
		Fingerprint: request.GetFingerprint(),
		Limit:       request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, listFindingCandidatesResponse(response))
}

func (a *App) handleGetFindingCandidate(w http.ResponseWriter, r *http.Request) {
	candidateID := r.PathValue("candidateID")
	candidate, err := a.findingService().GetFindingCandidate(r.Context(), candidateID)
	if err != nil {
		writeFindingError(w, err)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), candidate.RuntimeID); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.GetFindingCandidateResponse{Candidate: safeFindingCandidateMessage(candidate)})
}

func (a *App) handlePromoteFindingCandidate(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.PromoteFindingCandidateRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("candidateID")
	candidate, err := a.findingService().GetFindingCandidate(r.Context(), request.GetId())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), candidate.RuntimeID); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
		return
	}
	if err := authorizeFindingCandidatePromotion(r.Context()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().PromoteFindingCandidate(r.Context(), findings.PromoteCandidateRequest{
		CandidateID:           request.GetId(),
		PromotedBy:            request.GetPromotedBy(),
		Rationale:             request.GetRationale(),
		ChangeTicket:          request.GetChangeTicket(),
		FalsePositiveReviewed: request.GetFalsePositiveReviewed(),
		GraphCoverageReviewed: request.GetGraphCoverageReviewed(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	a.bumpGRCCacheForFinding(r.Context(), response.Finding)
	writeProtoJSON(w, http.StatusOK, promoteFindingCandidateResponse(response))
}

func (a *App) handleRejectFindingCandidate(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.RejectFindingCandidateRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeFindingError(w, err)
		return
	}
	request.Id = r.PathValue("candidateID")
	candidate, err := a.findingService().GetFindingCandidate(r.Context(), request.GetId())
	if err != nil {
		writeFindingError(w, err)
		return
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), candidate.RuntimeID); err != nil {
		writeFindingError(w, normalizeIDLookupError(err, ports.ErrFindingCandidateNotFound))
		return
	}
	if err := authorizeFindingCandidatePromotion(r.Context()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().RejectFindingCandidate(r.Context(), findings.RejectCandidateRequest{
		CandidateID: request.GetId(),
		RejectedBy:  request.GetRejectedBy(),
		Rationale:   request.GetRationale(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, rejectFindingCandidateResponse(response))
}

func (a *App) handleListFindingEvidence(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingEvidenceRequest{
		RuntimeId:    r.PathValue("runtimeID"),
		FindingId:    r.URL.Query().Get("finding_id"),
		RunId:        r.URL.Query().Get("run_id"),
		RuleId:       r.URL.Query().Get("rule_id"),
		ClaimId:      r.URL.Query().Get("claim_id"),
		EventId:      r.URL.Query().Get("event_id"),
		GraphRootUrn: r.URL.Query().Get("graph_root_urn"),
		GraphPathUrn: r.URL.Query().Get("graph_path_urn"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.FindingId = r.URL.Query().Get("finding_id")
		request.RunId = r.URL.Query().Get("run_id")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.ClaimId = r.URL.Query().Get("claim_id")
		request.EventId = r.URL.Query().Get("event_id")
		request.GraphRootUrn = r.URL.Query().Get("graph_root_urn")
		request.GraphPathUrn = r.URL.Query().Get("graph_path_urn")
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().ListEvidence(r.Context(), findings.ListEvidenceRequest{
		RuntimeID:    request.GetRuntimeId(),
		FindingID:    request.GetFindingId(),
		RunID:        request.GetRunId(),
		RuleID:       request.GetRuleId(),
		ClaimID:      request.GetClaimId(),
		EventID:      request.GetEventId(),
		GraphRootURN: request.GetGraphRootUrn(),
		GraphPathURN: request.GetGraphPathUrn(),
		Limit:        request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, listFindingEvidenceResponse(response))
}

func (a *App) handleListFindingEvaluationRuns(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.ListFindingEvaluationRunsRequest{
		RuntimeId: r.PathValue("runtimeID"),
		RuleId:    r.URL.Query().Get("rule_id"),
		Status:    r.URL.Query().Get("status"),
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		body := []byte(`{"limit":` + limit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeFindingError(w, err)
			return
		}
		request.RuntimeId = r.PathValue("runtimeID")
		request.RuleId = r.URL.Query().Get("rule_id")
		request.Status = r.URL.Query().Get("status")
	}
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntimeId()); err != nil {
		writeFindingError(w, err)
		return
	}
	response, err := a.findingService().ListEvaluationRuns(r.Context(), findings.ListEvaluationRunsRequest{
		RuntimeID: request.GetRuntimeId(),
		RuleID:    request.GetRuleId(),
		Status:    request.GetStatus(),
		Limit:     request.GetLimit(),
	})
	if err != nil {
		writeFindingError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, &cerebrov1.ListFindingEvaluationRunsResponse{
		Runs: response.Runs,
	})
}
