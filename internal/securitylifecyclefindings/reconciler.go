package securitylifecyclefindings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehttp/organizationalgraph"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrDependency      = errors.New("security lifecycle verification dependency failed")
	ErrTenantForbidden = errors.New("security lifecycle finding belongs to another tenant")
)

type QueryReader interface {
	ListSecurityLifecycle(context.Context, *cerebrov1.SecurityLifecycleQuery) (*cerebrov1.SecurityLifecycleQueryResult, error)
	ResolveSecurityLifecycleFinding(context.Context, string, string) (*cerebrov1.ResolveSecurityLifecycleFindingResponse, error)
}

type Result struct {
	FindingID    string
	Status       string
	Verification string
	Reason       string
	Pending      bool
	Changed      bool
}

type Reconciler struct {
	findings *findings.Service
	queries  QueryReader
	receipts ports.SourceCollectionReader
}

func New(findingsService *findings.Service, queries QueryReader, receipts ports.SourceCollectionReader) *Reconciler {
	return &Reconciler{findings: findingsService, queries: queries, receipts: receipts}
}

func (r *Reconciler) Reconcile(ctx context.Context, tenantID, findingID string) (Result, error) {
	tenantID = strings.TrimSpace(tenantID)
	findingID = strings.TrimSpace(findingID)
	if r == nil || r.queries == nil {
		return Result{}, fmt.Errorf("%w: lifecycle query reader is unavailable", ErrDependency)
	}
	if tenantID == "" || findingID == "" {
		return Result{}, fmt.Errorf("%w: tenant and finding are required", findings.ErrInvalidRequest)
	}
	resolved, err := r.queries.ResolveSecurityLifecycleFinding(ctx, tenantID, findingID)
	if err == nil {
		observation, mapErr := ObservationFromResolved(tenantID, findingID, resolved)
		if mapErr != nil {
			return Result{}, mapErr
		}
		finding, recordErr := r.findings.RecordSecurityLifecycleFinding(ctx, observation)
		if recordErr != nil {
			return Result{}, recordErr
		}
		result := Result{
			FindingID:    finding.ID,
			Status:       finding.Status,
			Verification: "source_collection_linked",
			Changed:      true,
		}
		if observation.SourceCollectionID == "" {
			result.Verification = "provenance_pending"
			result.Reason = "The current lifecycle row does not identify its final source collection. A later source sync is required before verified closure."
		}
		return result, nil
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		return Result{}, fmt.Errorf("%w: resolve open lifecycle finding: %w", ErrDependency, err)
	}
	return r.reconcileClosed(ctx, tenantID, findingID)
}

func (r *Reconciler) reconcileClosed(ctx context.Context, tenantID, findingID string) (Result, error) {
	current, err := r.findings.GetFinding(ctx, findingID)
	if err != nil {
		return Result{}, err
	}
	if current.TenantID != tenantID {
		return Result{}, ErrTenantForbidden
	}
	locator, ok := findings.SecurityLifecycleLocatorForFinding(current)
	if !ok {
		return Result{}, fmt.Errorf("%w: finding is not a projected security lifecycle finding", findings.ErrInvalidRequest)
	}
	subjectKind, ok := lifecycleSubjectKind(locator.SubjectKind)
	if !ok {
		return pendingResult(findingID, "subject_locator_unavailable", "The stored lifecycle finding does not contain a recognized subject kind. Run a fresh source sync."), nil
	}
	result, err := r.queries.ListSecurityLifecycle(ctx, &cerebrov1.SecurityLifecycleQuery{
		TenantId: tenantID,
		Limit:    2,
		SubjectLocator: &cerebrov1.SecurityLifecycleSubjectLocator{
			SubjectKind:   subjectKind,
			AuthorityId:   locator.AuthorityID,
			StableLocator: locator.StableLocator,
		},
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: read exact lifecycle subject: %w", ErrDependency, err)
	}
	if len(result.GetRecords()) != 1 {
		return pendingResult(findingID, "exact_observation_unavailable", "The exact lifecycle subject does not have one current observation. Run a fresh source sync before retrying verification."), nil
	}
	record := result.GetRecords()[0]
	observation := record.GetObservation()
	if observation == nil ||
		observation.GetSubjectRef().GetId() != locator.SubjectURN ||
		observation.GetAuthorityId() != locator.AuthorityID ||
		observation.GetStableLocator() != locator.StableLocator ||
		observation.GetSubjectKind() != subjectKind {
		return pendingResult(findingID, "subject_identity_mismatch", "The current lifecycle observation does not match the finding subject. The finding remains open."), nil
	}
	if strings.TrimSpace(record.GetSourceRuntimeId()) == "" || strings.TrimSpace(record.GetSourceCollectionId()) == "" {
		return pendingResult(findingID, "provenance_pending", "The current lifecycle row does not identify its source runtime and final collection. The finding remains open."), nil
	}
	if record.GetSourceRuntimeId() != locator.SourceRuntimeID {
		return pendingResult(findingID, "runtime_mismatch", "The current lifecycle observation came from a different source runtime. The finding remains open."), nil
	}
	evaluation, ok := lifecyclePolicyEvaluation(record, locator.PolicyID)
	if !ok {
		return pendingResult(findingID, "policy_observation_unavailable", "The current lifecycle row does not contain the finding policy evaluation. The finding remains open."), nil
	}
	if !strings.EqualFold(strings.TrimSpace(evaluation.GetState()), "compliant") {
		return pendingResult(findingID, "policy_still_matches", "The current lifecycle policy is not compliant. Provider execution alone does not close this finding."), nil
	}
	metadata := result.GetMetadata()
	coverage := metadata.GetCoverage()
	freshness := metadata.GetFreshness()
	if metadata == nil || coverage == nil || freshness == nil ||
		!coverage.GetComplete() || coverage.GetTruncated() || metadata.GetPageTruncated() {
		return pendingResult(findingID, "source_coverage_incomplete", "The exact lifecycle read is incomplete or truncated. The finding remains open until a complete source observation is available."), nil
	}
	if r.receipts == nil {
		return pendingResult(findingID, "collection_receipt_unavailable", "The final source collection receipt is unavailable. The finding remains open."), nil
	}
	manifest, err := r.receipts.GetSourceCollection(
		ctx,
		tenantID,
		record.GetSourceRuntimeId(),
		record.GetSourceCollectionId(),
	)
	if errors.Is(err, organizationalgraph.ErrSourceCollectionNotFound) {
		return pendingResult(findingID, "collection_receipt_pending", "The matching final source collection receipt is not available. The finding remains open."), nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("%w: load exact source collection receipt: %w", ErrDependency, err)
	}
	if !strings.EqualFold(strings.TrimSpace(manifest.Status), "complete") || len(manifest.IncompletenessReasons) != 0 {
		return pendingResult(findingID, "collection_incomplete", "The matching source collection is incomplete. The finding remains open."), nil
	}

	updated, err := r.findings.ResolveSecurityLifecycleFindingAfterObservation(ctx, findings.SecurityLifecycleClosureObservation{
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
		return Result{}, err
	}
	return Result{
		FindingID:    updated.ID,
		Status:       updated.Status,
		Verification: "verified_closed",
		Reason:       "A later complete source collection observed the exact subject as compliant.",
		Changed:      true,
	}, nil
}

func ObservationFromResolved(tenantID, findingID string, resolved *cerebrov1.ResolveSecurityLifecycleFindingResponse) (findings.SecurityLifecycleFindingObservation, error) {
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

func pendingResult(findingID, verification, reason string) Result {
	return Result{
		FindingID:    findingID,
		Status:       "open",
		Verification: verification,
		Reason:       reason,
		Pending:      true,
	}
}
