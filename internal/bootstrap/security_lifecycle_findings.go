package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/sourcehttp/organizationalgraph"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxSecurityLifecycleReconcileBodyBytes = 4 << 10

type securityLifecycleReconcileRequest struct {
	TenantID string `json:"tenant_id"`
}

type securityLifecycleReconcileResponse struct {
	FindingID       string `json:"finding_id"`
	Status          string `json:"status"`
	Verification    string `json:"verification"`
	Reason          string `json:"reason,omitempty"`
	AuditPreviewURL string `json:"audit_preview_url"`
}

func (a *App) handleReconcileSecurityLifecycleFinding(w http.ResponseWriter, r *http.Request) {
	if a.deps.SecurityLifecycleQueries == nil {
		http.Error(w, "Security lifecycle finding reads are unavailable.", http.StatusServiceUnavailable)
		return
	}
	var request securityLifecycleReconcileRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecurityLifecycleReconcileBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeGRCError(w, fmt.Errorf("%w: decode security lifecycle reconcile request: %w", errInvalidHTTPRequest, err))
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), request.TenantID)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	findingID := strings.TrimSpace(r.PathValue("findingID"))
	if findingID == "" {
		writeGRCError(w, fmt.Errorf("%w: finding id is required", errInvalidHTTPRequest))
		return
	}

	resolved, err := a.deps.SecurityLifecycleQueries.ResolveSecurityLifecycleFinding(r.Context(), tenantID, findingID)
	if err == nil {
		observation, mapErr := lifecycleOpenObservation(tenantID, findingID, resolved)
		if mapErr != nil {
			writeGRCError(w, mapErr)
			return
		}
		finding, recordErr := a.findingService().RecordSecurityLifecycleFinding(r.Context(), observation)
		if recordErr != nil {
			writeGRCError(w, recordErr)
			return
		}
		verification := "source_collection_linked"
		reason := ""
		if observation.SourceCollectionID == "" {
			verification = "provenance_pending"
			reason = "The current lifecycle row does not identify its final source collection. A later source sync is required before verified closure."
		}
		a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeFindings, grcCacheScopeEvidence)
		writeJSON(w, http.StatusOK, securityLifecycleReconcileResponse{
			FindingID:       finding.ID,
			Status:          finding.Status,
			Verification:    verification,
			Reason:          reason,
			AuditPreviewURL: lifecycleAuditPreviewURL(finding.ID),
		})
		return
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		writeSecurityLifecycleDependencyError(w, err)
		return
	}

	response, status, reconcileErr := a.reconcileClosedSecurityLifecycleFinding(r, tenantID, findingID)
	if reconcileErr != nil {
		if status != 0 {
			http.Error(w, "Security lifecycle verification dependency failed.", status)
			return
		}
		writeGRCError(w, reconcileErr)
		return
	}
	writeJSON(w, status, response)
}

func (a *App) reconcileClosedSecurityLifecycleFinding(r *http.Request, tenantID, findingID string) (securityLifecycleReconcileResponse, int, error) {
	current, err := a.findingService().GetFinding(r.Context(), findingID)
	if err != nil {
		return securityLifecycleReconcileResponse{}, 0, err
	}
	if current.TenantID != tenantID {
		return securityLifecycleReconcileResponse{}, 0, errTenantForbidden
	}
	locator, ok := findings.SecurityLifecycleLocatorForFinding(current)
	if !ok {
		return securityLifecycleReconcileResponse{}, 0, fmt.Errorf("%w: finding is not a projected security lifecycle finding", errInvalidHTTPRequest)
	}
	subjectKind, ok := lifecycleSubjectKind(locator.SubjectKind)
	if !ok {
		return lifecyclePendingResponse(findingID, "subject_locator_unavailable", "The stored lifecycle finding does not contain a recognized subject kind. Run a fresh source sync."), http.StatusAccepted, nil
	}
	result, err := a.deps.SecurityLifecycleQueries.ListSecurityLifecycle(r.Context(), &cerebrov1.SecurityLifecycleQuery{
		TenantId: tenantID,
		Limit:    2,
		SubjectLocator: &cerebrov1.SecurityLifecycleSubjectLocator{
			SubjectKind:   subjectKind,
			AuthorityId:   locator.AuthorityID,
			StableLocator: locator.StableLocator,
		},
	})
	if err != nil {
		return securityLifecycleReconcileResponse{}, lifecycleDependencyStatus(err), fmt.Errorf("read exact lifecycle subject: %w", err)
	}
	if len(result.GetRecords()) != 1 {
		return lifecyclePendingResponse(findingID, "exact_observation_unavailable", "The exact lifecycle subject does not have one current observation. Run a fresh source sync before retrying verification."), http.StatusAccepted, nil
	}
	record := result.GetRecords()[0]
	observation := record.GetObservation()
	if observation == nil ||
		observation.GetSubjectRef().GetId() != locator.SubjectURN ||
		observation.GetAuthorityId() != locator.AuthorityID ||
		observation.GetStableLocator() != locator.StableLocator ||
		observation.GetSubjectKind() != subjectKind {
		return lifecyclePendingResponse(findingID, "subject_identity_mismatch", "The current lifecycle observation does not match the finding subject. The finding remains open."), http.StatusAccepted, nil
	}
	if strings.TrimSpace(record.GetSourceRuntimeId()) == "" || strings.TrimSpace(record.GetSourceCollectionId()) == "" {
		return lifecyclePendingResponse(findingID, "provenance_pending", "The current lifecycle row does not identify its source runtime and final collection. The finding remains open."), http.StatusAccepted, nil
	}
	if record.GetSourceRuntimeId() != locator.SourceRuntimeID {
		return lifecyclePendingResponse(findingID, "runtime_mismatch", "The current lifecycle observation came from a different source runtime. The finding remains open."), http.StatusAccepted, nil
	}
	evaluation, ok := lifecyclePolicyEvaluation(record, locator.PolicyID)
	if !ok {
		return lifecyclePendingResponse(findingID, "policy_observation_unavailable", "The current lifecycle row does not contain the finding policy evaluation. The finding remains open."), http.StatusAccepted, nil
	}
	if !strings.EqualFold(strings.TrimSpace(evaluation.GetState()), "compliant") {
		return lifecyclePendingResponse(findingID, "policy_still_matches", "The current lifecycle policy is not compliant. Provider execution alone does not close this finding."), http.StatusAccepted, nil
	}
	metadata := result.GetMetadata()
	coverage := metadata.GetCoverage()
	freshness := metadata.GetFreshness()
	if metadata == nil || coverage == nil || freshness == nil ||
		!coverage.GetComplete() || coverage.GetTruncated() || metadata.GetPageTruncated() {
		return lifecyclePendingResponse(findingID, "source_coverage_incomplete", "The exact lifecycle read is incomplete or truncated. The finding remains open until a complete source observation is available."), http.StatusAccepted, nil
	}
	if a.deps.SourceCollectionReceipts == nil {
		return lifecyclePendingResponse(findingID, "collection_receipt_unavailable", "The final source collection receipt is unavailable. The finding remains open."), http.StatusAccepted, nil
	}
	manifest, err := a.deps.SourceCollectionReceipts.GetSourceCollection(
		r.Context(),
		tenantID,
		record.GetSourceRuntimeId(),
		record.GetSourceCollectionId(),
	)
	if errors.Is(err, organizationalgraph.ErrSourceCollectionNotFound) {
		return lifecyclePendingResponse(findingID, "collection_receipt_pending", "The matching final source collection receipt is not available. The finding remains open."), http.StatusAccepted, nil
	}
	if err != nil {
		return securityLifecycleReconcileResponse{}, http.StatusBadGateway, fmt.Errorf("load exact source collection receipt: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(manifest.Status), "complete") || len(manifest.IncompletenessReasons) != 0 {
		return lifecyclePendingResponse(findingID, "collection_incomplete", "The matching source collection is incomplete. The finding remains open."), http.StatusAccepted, nil
	}

	updated, err := a.findingService().ResolveSecurityLifecycleFindingAfterObservation(r.Context(), findings.SecurityLifecycleClosureObservation{
		FindingURN:                      findingID,
		SourceRuntimeID:                 record.GetSourceRuntimeId(),
		SourceCollectionID:              record.GetSourceCollectionId(),
		SubjectURN:                      observation.GetSubjectRef().GetId(),
		AuthorityID:                     observation.GetAuthorityId(),
		StableLocator:                   observation.GetStableLocator(),
		PolicyState:                     evaluation.GetState(),
		ObservedAt:                      timestampTime(observation.GetObservedAt()),
		FreshnessAsOf:                   timestampTime(freshness.GetAsOf()),
		CoverageComplete:                coverage.GetComplete(),
		CoverageTruncated:               coverage.GetTruncated(),
		PageTruncated:                   metadata.GetPageTruncated(),
		CollectionReceiptTenantID:       manifest.TenantID,
		CollectionReceiptRuntimeID:      manifest.RuntimeID,
		CollectionReceiptID:             manifest.CollectionID,
		CollectionReceiptStatus:         manifest.Status,
		CollectionReceiptCompletedAt:    time.UnixMilli(manifest.CompletedAtUnixMS).UTC(),
		CollectionIncompletenessReasons: append([]string(nil), manifest.IncompletenessReasons...),
		EvidenceClaimRefs:               lifecycleEvidenceRefs(observation, evaluation, nil),
	})
	if err != nil {
		return securityLifecycleReconcileResponse{}, 0, err
	}
	a.bumpGRCCacheVersions(r.Context(), tenantID, grcCacheScopeFindings, grcCacheScopeEvidence)
	return securityLifecycleReconcileResponse{
		FindingID:       updated.ID,
		Status:          updated.Status,
		Verification:    "verified_closed",
		Reason:          "A later complete source collection observed the exact subject as compliant.",
		AuditPreviewURL: lifecycleAuditPreviewURL(updated.ID),
	}, http.StatusOK, nil
}

func lifecycleOpenObservation(tenantID, findingID string, resolved *cerebrov1.ResolveSecurityLifecycleFindingResponse) (findings.SecurityLifecycleFindingObservation, error) {
	if resolved == nil || resolved.GetRecord() == nil {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver omitted the record", findings.ErrInvalidRequest)
	}
	record := resolved.GetRecord()
	if resolved.GetGraphRevision() == 0 {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver omitted the durable graph revision", findings.ErrInvalidRequest)
	}
	if strings.TrimSpace(record.GetSourceRuntimeId()) == "" ||
		record.GetSourceRuntimeId() != resolved.GetSourceRuntimeId() ||
		record.GetSourceCollectionId() != resolved.GetSourceCollectionId() {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver provenance aliases do not match the record", findings.ErrInvalidRequest)
	}
	observation := record.GetObservation()
	if observation == nil || observation.GetSubjectRef() == nil {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver omitted the observation subject", findings.ErrInvalidRequest)
	}
	var binding *cerebrov1.SecurityLifecycleFindingBinding
	for _, candidate := range record.GetFindings() {
		if candidate.GetFindingRef().GetId() == findingID {
			if binding != nil {
				return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver returned duplicate finding bindings", findings.ErrInvalidRequest)
			}
			binding = candidate
		}
	}
	if binding == nil || !strings.EqualFold(strings.TrimSpace(binding.GetStatus()), "open") ||
		binding.GetSubjectRef().GetId() != observation.GetSubjectRef().GetId() {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver did not return the requested open finding binding", findings.ErrInvalidRequest)
	}
	if len(record.GetPolicyEvaluations()) != 1 {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver did not return one exact policy evaluation", findings.ErrInvalidRequest)
	}
	evaluation := record.GetPolicyEvaluations()[0]
	if evaluation.GetSubjectRef().GetId() != observation.GetSubjectRef().GetId() {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle policy evaluation subject does not match the observation", findings.ErrInvalidRequest)
	}
	subjectKind, ok := lifecycleSubjectKindName(observation.GetSubjectKind())
	if !ok {
		return findings.SecurityLifecycleFindingObservation{}, fmt.Errorf("%w: lifecycle resolver returned an unsupported subject kind", findings.ErrInvalidRequest)
	}
	return findings.SecurityLifecycleFindingObservation{
		TenantID:           tenantID,
		FindingURN:         findingID,
		SourceRuntimeID:    record.GetSourceRuntimeId(),
		SourceCollectionID: record.GetSourceCollectionId(),
		SubjectURN:         observation.GetSubjectRef().GetId(),
		SubjectKind:        subjectKind,
		AuthorityID:        observation.GetAuthorityId(),
		StableLocator:      observation.GetStableLocator(),
		MaterialRevision:   observation.GetSubjectRef().GetRevision(),
		Provider:           observation.GetProvider(),
		DisplayName:        observation.GetDisplayName(),
		OwnerURN:           observation.GetOwnerUrn(),
		ObservedState:      lifecycleStateName(observation.GetState()),
		PolicyState:        evaluation.GetState(),
		PolicyID:           evaluation.GetPolicyId(),
		PolicyVersion:      evaluation.GetPolicyVersion(),
		ObservedAt:         timestampTime(observation.GetObservedAt()),
		ExpiresAt:          timestampTime(observation.GetExpiresAt()),
		GraphRevision:      resolved.GetGraphRevision(),
		EvidenceClaimRefs:  lifecycleEvidenceRefs(observation, evaluation, binding),
	}, nil
}

func lifecyclePolicyEvaluation(record *cerebrov1.SecurityLifecycleRecord, policyID string) (*cerebrov1.SecurityLifecyclePolicyEvaluation, bool) {
	var matched *cerebrov1.SecurityLifecyclePolicyEvaluation
	for _, evaluation := range record.GetPolicyEvaluations() {
		if strings.TrimSpace(evaluation.GetPolicyId()) != strings.TrimSpace(policyID) {
			continue
		}
		if matched != nil {
			return nil, false
		}
		matched = evaluation
	}
	return matched, matched != nil
}

func lifecycleEvidenceRefs(observation *cerebrov1.SecurityLifecycleObservation, evaluation *cerebrov1.SecurityLifecyclePolicyEvaluation, binding *cerebrov1.SecurityLifecycleFindingBinding) []string {
	refs := make([]string, 0)
	appendRefs := func(values []*cerebrov1.ResourceRef) {
		for _, ref := range values {
			if value := strings.TrimSpace(ref.GetId()); value != "" {
				refs = append(refs, value)
			}
		}
	}
	appendRefs(observation.GetEvidenceClaimRefs())
	appendRefs(evaluation.GetEvidenceClaimRefs())
	if binding != nil {
		appendRefs(binding.GetEvidenceClaimRefs())
	}
	return refs
}

func lifecycleSubjectKind(value string) (cerebrov1.SecurityLifecycleSubjectKind, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "credential":
		return cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL, true
	case "certificate":
		return cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CERTIFICATE, true
	default:
		return cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_UNSPECIFIED, false
	}
}

func lifecycleSubjectKindName(value cerebrov1.SecurityLifecycleSubjectKind) (string, bool) {
	switch value {
	case cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL:
		return "credential", true
	case cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CERTIFICATE:
		return "certificate", true
	default:
		return "", false
	}
}

func lifecycleStateName(value cerebrov1.SecurityLifecycleState) string {
	return strings.ToLower(strings.TrimPrefix(value.String(), "SECURITY_LIFECYCLE_STATE_"))
}

func timestampTime(value *timestamppb.Timestamp) time.Time {
	if value == nil || value.CheckValid() != nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func lifecyclePendingResponse(findingID, verification, reason string) securityLifecycleReconcileResponse {
	return securityLifecycleReconcileResponse{
		FindingID:       findingID,
		Status:          "open",
		Verification:    verification,
		Reason:          reason,
		AuditPreviewURL: lifecycleAuditPreviewURL(findingID),
	}
}

func lifecycleAuditPreviewURL(findingID string) string {
	return "/grc/findings/" + url.PathEscape(strings.TrimSpace(findingID)) + "/audit-preview"
}

func writeSecurityLifecycleDependencyError(w http.ResponseWriter, err error) {
	http.Error(w, "Security lifecycle finding read failed.", lifecycleDependencyStatus(err))
}

func lifecycleDependencyStatus(err error) int {
	if connect.CodeOf(err) == connect.CodeUnavailable {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}
