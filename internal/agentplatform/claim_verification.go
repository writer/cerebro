package agentplatform

import "strings"

const (
	ClaimVerdictSupported       = "supported"
	ClaimVerdictWeaklySupported = "weakly_supported"
	ClaimVerdictContradicted    = "contradicted"
	ClaimVerdictUnknown         = "unknown"
)

type ClaimVerificationContract struct {
	ID                    string              `json:"id"`
	Purpose               string              `json:"purpose"`
	RequiredFields        []string            `json:"required_fields"`
	Verdicts              []ClaimVerdict      `json:"verdicts"`
	Gates                 []ClaimVerifierGate `json:"gates"`
	AllowedStageByVerdict map[string]string   `json:"allowed_stage_by_verdict"`
	RequiredOutputs       []string            `json:"required_outputs"`
}

type ClaimVerdict struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type ClaimVerifierGate struct {
	ID       string   `json:"id"`
	Purpose  string   `json:"purpose"`
	BlocksOn []string `json:"blocks_on,omitempty"`
	WarnsOn  []string `json:"warns_on,omitempty"`
}

type AgentWorkContract struct {
	ID                string   `json:"id"`
	Purpose           string   `json:"purpose"`
	RequiredFields    []string `json:"required_fields"`
	StateModel        []string `json:"state_model"`
	RequiredArtifacts []string `json:"required_artifacts"`
	EventVocabulary   []string `json:"event_vocabulary"`
	CloseConditions   []string `json:"close_conditions"`
}

type ClaimVerificationRequest struct {
	TenantID               string                `json:"tenant_id,omitempty"`
	ActorID                string                `json:"actor_id,omitempty"`
	Claim                  string                `json:"claim"`
	ClaimType              string                `json:"claim_type,omitempty"`
	ScopeURN               string                `json:"scope_urn,omitempty"`
	SupportingEvidenceURNs []string              `json:"supporting_evidence_urns,omitempty"`
	CounterEvidenceURNs    []string              `json:"counter_evidence_urns,omitempty"`
	MissingEvidence        []string              `json:"missing_evidence,omitempty"`
	FreshnessState         string                `json:"freshness_state,omitempty"`
	CoverageContext        *AgentCoverageContext `json:"coverage_context,omitempty"`
	RequestedActionStage   string                `json:"requested_action_stage,omitempty"`
	HumanApproved          bool                  `json:"human_approved,omitempty"`
}

type ClaimVerification struct {
	Version              string                      `json:"version"`
	TenantID             string                      `json:"tenant_id,omitempty"`
	ActorID              string                      `json:"actor_id,omitempty"`
	Claim                string                      `json:"claim"`
	ClaimType            string                      `json:"claim_type,omitempty"`
	ScopeURN             string                      `json:"scope_urn,omitempty"`
	Verdict              string                      `json:"verdict"`
	AllowedNextStage     string                      `json:"allowed_next_stage"`
	RequestedActionStage string                      `json:"requested_action_stage,omitempty"`
	Blockers             []CapabilityDecisionBlocker `json:"blockers,omitempty"`
	Warnings             []string                    `json:"warnings,omitempty"`
	SupportingEvidence   []EvidenceReference         `json:"supporting_evidence"`
	CounterEvidence      []EvidenceReference         `json:"counter_evidence"`
	MissingEvidence      []string                    `json:"missing_evidence,omitempty"`
	FreshnessState       string                      `json:"freshness_state,omitempty"`
	VerifierResults      []AgentVerifierResult       `json:"verifier_results"`
	RequiredWriteBack    []string                    `json:"required_write_back"`
}

func claimVerificationContract() ClaimVerificationContract {
	return ClaimVerificationContract{
		ID:      "agent-claim-verification",
		Purpose: "Verify each agent conclusion as a typed claim before it becomes a recommendation, action proposal, finding update, or memory.",
		RequiredFields: []string{
			"tenant_id",
			"claim",
			"scope_urn",
			"supporting_evidence_urns",
			"counter_evidence_urns",
			"missing_evidence",
			"freshness_state",
			"verdict",
			"allowed_next_stage",
		},
		Verdicts: []ClaimVerdict{
			{ID: ClaimVerdictSupported, Description: "Evidence supports the claim and no required counterevidence or missing evidence blocks recommendation."},
			{ID: ClaimVerdictWeaklySupported, Description: "Some evidence supports the claim, but freshness, coverage, or missing-evidence caveats must remain visible."},
			{ID: ClaimVerdictContradicted, Description: "Counterevidence conflicts with the claim; remediation or promotion is blocked."},
			{ID: ClaimVerdictUnknown, Description: "The evidence set is insufficient to support the claim."},
		},
		Gates: []ClaimVerifierGate{
			{ID: "tenant-scope", Purpose: "All claim, scope, and evidence URNs must belong to the authenticated tenant.", BlocksOn: []string{"missing_tenant", "cross_tenant_scope"}},
			{ID: "supporting-evidence", Purpose: "Claims need at least one cited supporting evidence URN before recommendation.", BlocksOn: []string{"missing_supporting_evidence"}},
			{ID: "counterevidence", Purpose: "Counterevidence overrides supporting evidence until the conflict is resolved.", BlocksOn: []string{"counterevidence_present"}},
			{ID: "freshness", Purpose: "Stale or unknown freshness downgrades support and must be carried into the answer.", WarnsOn: []string{"stale", "unknown"}},
			{ID: "coverage", Purpose: "Coverage blind spots downgrade conclusions and block claims that require absent sources.", WarnsOn: []string{"blind_spots", "coverage_unavailable"}},
			{ID: "action-stage", Purpose: "The claim verdict determines the highest action stage an agent may enter next.", BlocksOn: []string{"stage_skip", "unapproved_mutation"}},
		},
		AllowedStageByVerdict: map[string]string{
			ClaimVerdictSupported:       ActionStageRecommend,
			ClaimVerdictWeaklySupported: ActionStageExplain,
			ClaimVerdictContradicted:    ActionStageObserve,
			ClaimVerdictUnknown:         ActionStageObserve,
		},
		RequiredOutputs: []string{"verdict", "allowed_next_stage", "blockers", "warnings", "supporting_evidence", "counter_evidence", "missing_evidence", "required_write_back"},
	}
}

func agentWorkContract() AgentWorkContract {
	return AgentWorkContract{
		ID:      "agent-work-ledger",
		Purpose: "Represent an agent investigation as a durable work object so claims, evidence, verifier results, action proposals, approvals, and closure can survive context loss.",
		RequiredFields: []string{
			"work_id",
			"tenant_id",
			"objective",
			"current_hypothesis",
			"status",
			"trace_ids",
			"claim_ids",
			"evidence_urns",
			"verifier_results",
			"action_proposals",
			"closure_reason",
		},
		StateModel:        []string{"open", "waiting_on_evidence", "waiting_on_approval", "verifying", "closed", "blocked"},
		RequiredArtifacts: []string{"preflight", "evidence_packet", "claim_verification", "tool_call_refs", "action_delta", "verification_query", "closure_summary"},
		EventVocabulary:   []string{"agent.work.created", "agent.work.updated", "claim.verification.completed", "adapter.execution.started", "adapter.execution.completed", "agent.work.closed"},
		CloseConditions: []string{
			"all supported claims cite evidence visible to the tenant",
			"warnings are copied into the final conclusion",
			"approved actions have verification results or an explicit blocked reason",
			"memory writes are typed, scoped, and carry expiry or invalidation criteria",
		},
	}
}

func cloneClaimVerificationContract(contract ClaimVerificationContract) ClaimVerificationContract {
	contract.RequiredFields = cloneStrings(contract.RequiredFields)
	contract.Verdicts = append([]ClaimVerdict(nil), contract.Verdicts...)
	contract.Gates = cloneClaimVerifierGates(contract.Gates)
	if contract.AllowedStageByVerdict != nil {
		cloned := make(map[string]string, len(contract.AllowedStageByVerdict))
		for key, value := range contract.AllowedStageByVerdict {
			cloned[key] = value
		}
		contract.AllowedStageByVerdict = cloned
	}
	contract.RequiredOutputs = cloneStrings(contract.RequiredOutputs)
	return contract
}

func cloneClaimVerifierGates(gates []ClaimVerifierGate) []ClaimVerifierGate {
	out := make([]ClaimVerifierGate, 0, len(gates))
	for _, gate := range gates {
		gate.BlocksOn = cloneStrings(gate.BlocksOn)
		gate.WarnsOn = cloneStrings(gate.WarnsOn)
		out = append(out, gate)
	}
	return out
}

func cloneAgentWorkContract(contract AgentWorkContract) AgentWorkContract {
	contract.RequiredFields = cloneStrings(contract.RequiredFields)
	contract.StateModel = cloneStrings(contract.StateModel)
	contract.RequiredArtifacts = cloneStrings(contract.RequiredArtifacts)
	contract.EventVocabulary = cloneStrings(contract.EventVocabulary)
	contract.CloseConditions = cloneStrings(contract.CloseConditions)
	return contract
}

func BuildClaimVerification(request ClaimVerificationRequest) ClaimVerification {
	request = normalizeClaimVerificationRequest(request)
	verifiers := evaluateClaimVerification(request)
	verdict := claimVerdict(request, verifiers)
	allowedStage := claimAllowedNextStage(verdict)
	blockers := claimBlockers(request, allowedStage, verifiers)
	warnings := claimWarnings(verifiers)
	return ClaimVerification{
		Version:              ContractVersion,
		TenantID:             request.TenantID,
		ActorID:              request.ActorID,
		Claim:                request.Claim,
		ClaimType:            request.ClaimType,
		ScopeURN:             request.ScopeURN,
		Verdict:              verdict,
		AllowedNextStage:     allowedStage,
		RequestedActionStage: request.RequestedActionStage,
		Blockers:             blockers,
		Warnings:             warnings,
		SupportingEvidence:   claimEvidenceReferences(request.SupportingEvidenceURNs, "supporting_evidence"),
		CounterEvidence:      claimEvidenceReferences(request.CounterEvidenceURNs, "counter_evidence"),
		MissingEvidence:      cloneStrings(request.MissingEvidence),
		FreshnessState:       request.FreshnessState,
		VerifierResults:      verifiers,
		RequiredWriteBack:    []string{"claim_verification", "verifier_results", "coverage_caveats", "freshness_state"},
	}
}

func normalizeClaimVerificationRequest(request ClaimVerificationRequest) ClaimVerificationRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.Claim = strings.TrimSpace(request.Claim)
	request.ClaimType = strings.TrimSpace(request.ClaimType)
	request.ScopeURN = strings.TrimSpace(request.ScopeURN)
	request.SupportingEvidenceURNs = uniqueSortedStrings(request.SupportingEvidenceURNs)
	request.CounterEvidenceURNs = uniqueSortedStrings(request.CounterEvidenceURNs)
	request.MissingEvidence = uniqueSortedStrings(request.MissingEvidence)
	request.FreshnessState = strings.ToLower(strings.TrimSpace(request.FreshnessState))
	request.RequestedActionStage = normalizeActionStage(request.RequestedActionStage)
	request.CoverageContext = cloneCoverageContext(request.CoverageContext)
	return request
}

func evaluateClaimVerification(request ClaimVerificationRequest) []AgentVerifierResult {
	results := []AgentVerifierResult{}
	tenantEvidence := append([]string{request.ScopeURN}, request.SupportingEvidenceURNs...)
	tenantEvidence = append(tenantEvidence, request.CounterEvidenceURNs...)
	tenantEvidence = append(tenantEvidence, request.MissingEvidence...)
	if request.TenantID == "" {
		results = append(results, verifierBlocked("tenant-scope", "Claim verification requires an authenticated tenant.", nil))
	} else if crossTenantURN(request.TenantID, tenantEvidence...) {
		results = append(results, verifierBlocked("tenant-scope", "Claim evidence or scope belongs to a different tenant.", tenantEvidence))
	} else {
		results = append(results, verifierPassed("tenant-scope", "Claim scope and evidence are tenant-scoped.", tenantEvidence))
	}
	if len(request.SupportingEvidenceURNs) == 0 {
		results = append(results, verifierBlocked("supporting-evidence", "Claim has no supporting evidence URN.", nil))
	} else {
		results = append(results, verifierPassed("supporting-evidence", "Claim has cited supporting evidence.", request.SupportingEvidenceURNs))
	}
	if len(request.CounterEvidenceURNs) > 0 {
		results = append(results, verifierBlocked("counterevidence", "Counterevidence conflicts with the claim.", request.CounterEvidenceURNs))
	} else {
		results = append(results, verifierPassed("counterevidence", "No counterevidence was supplied.", nil))
	}
	switch request.FreshnessState {
	case "fresh":
		results = append(results, verifierPassed("freshness", "Freshness state supports claim use.", []string{request.FreshnessState}))
	default:
		results = append(results, verifierWarning("freshness", "Freshness is missing, stale, failed, or unknown.", []string{request.FreshnessState}))
	}
	if request.CoverageContext == nil {
		results = append(results, verifierWarning("coverage", "No coverage context was supplied for claim verification.", nil))
	} else if request.CoverageContext.BlindSpotCount+request.CoverageContext.StaleCount+request.CoverageContext.FailedCount > 0 {
		results = append(results, verifierWarning("coverage", "Coverage caveats must be carried into the claim conclusion.", []string{request.CoverageContext.TenantID}))
	} else {
		results = append(results, verifierPassed("coverage", "Coverage context has no reported blind spots, stale sources, or failed sources.", []string{request.CoverageContext.TenantID}))
	}
	if len(request.MissingEvidence) > 0 {
		results = append(results, verifierWarning("missing-evidence", "Claim has missing evidence that must be stated.", request.MissingEvidence))
	} else {
		results = append(results, verifierPassed("missing-evidence", "No missing evidence was supplied.", nil))
	}
	return results
}

func claimVerdict(request ClaimVerificationRequest, verifiers []AgentVerifierResult) string {
	if verifierResultStatus(verifiers, "tenant-scope") == "blocked" || verifierResultStatus(verifiers, "supporting-evidence") == "blocked" {
		return ClaimVerdictUnknown
	}
	if verifierResultStatus(verifiers, "counterevidence") == "blocked" {
		return ClaimVerdictContradicted
	}
	if verifierStatusCount(verifiers, "warning") > 0 || len(request.MissingEvidence) > 0 {
		return ClaimVerdictWeaklySupported
	}
	return ClaimVerdictSupported
}

func claimAllowedNextStage(verdict string) string {
	if stage := claimVerificationContract().AllowedStageByVerdict[verdict]; stage != "" {
		return stage
	}
	return ActionStageObserve
}

func claimBlockers(request ClaimVerificationRequest, allowedStage string, verifiers []AgentVerifierResult) []CapabilityDecisionBlocker {
	blockers := []CapabilityDecisionBlocker{}
	for _, result := range verifiers {
		if result.Status == "blocked" {
			blockers = append(blockers, CapabilityDecisionBlocker{Code: result.ID, Message: result.Message, Fields: cloneStrings(result.Evidence)})
		}
	}
	if actionStageOrder(request.RequestedActionStage) > actionStageOrder(allowedStage) {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "stage_skip",
			Message: "Requested action stage is not allowed by the claim verdict.",
			Fields:  []string{request.RequestedActionStage, allowedStage},
		})
	}
	if actionStageRequiresMutationApproval(request.RequestedActionStage) && !request.HumanApproved {
		blockers = append(blockers, CapabilityDecisionBlocker{
			Code:    "unapproved_mutation",
			Message: "Mutating execution requires human approval.",
			Fields:  []string{request.RequestedActionStage},
		})
	}
	return dedupeDecisionBlockers(blockers)
}

func claimWarnings(verifiers []AgentVerifierResult) []string {
	warnings := []string{}
	for _, result := range verifiers {
		if result.Status == "warning" {
			warnings = append(warnings, result.ID+": "+result.Message)
		}
	}
	return uniqueSortedStrings(warnings)
}

func claimEvidenceReferences(urns []string, kind string) []EvidenceReference {
	refs := make([]EvidenceReference, 0, len(urns))
	for _, urn := range urns {
		refs = append(refs, EvidenceReference{
			URN:            urn,
			Kind:           kind,
			CitationStatus: "required",
			SourceURNs:     []string{urn},
		})
	}
	return refs
}

func verifierResultStatus(results []AgentVerifierResult, id string) string {
	for _, result := range results {
		if result.ID == id {
			return result.Status
		}
	}
	return ""
}

func crossTenantURN(tenantID string, urns ...string) bool {
	for _, urn := range urns {
		urnTenant := tenantIDFromCerebroURN(urn)
		if urnTenant != "" && urnTenant != tenantID {
			return true
		}
	}
	return false
}
