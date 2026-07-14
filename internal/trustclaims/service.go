package trustclaims

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/workflowevents"
)

var (
	ErrInvalidReceipt            = errors.New("invalid trust claim receipt")
	ErrInvalidVersionedReference = errors.New("control and policy refs require exact versions")
	ErrInvalidResourceReference  = errors.New("resource refs require urn and revision")
	ErrNotShareable              = errors.New("trust claim is not shareable")
	ErrTenantMismatch            = errors.New("tenant mismatch")
	ErrReceiptNotFound           = errors.New("trust claim receipt not found")
	ErrObligationNotFound        = errors.New("trust obligation not found")
	ErrHumanConfirmationRequired = errors.New("human confirmation is required")
)

func IssueReceipt(input ReceiptInput) (ClaimReceipt, error) {
	if err := validateReceiptReferenceInput(input); err != nil {
		return ClaimReceipt{}, err
	}
	normalizeReceiptInput(&input)
	if err := validateReceiptInput(input); err != nil {
		return ClaimReceipt{}, err
	}
	receipt := ClaimReceipt{
		SchemaVersion:     ReceiptSchemaVersion,
		TenantID:          input.TenantID,
		ReceiptID:         input.ReceiptID,
		ClaimID:           input.ClaimID,
		Version:           input.Version,
		Statement:         input.Statement,
		Origin:            input.Origin,
		Status:            input.RequestedStatus,
		DisclosureClass:   input.DisclosureClass,
		Citations:         input.Citations,
		Controls:          input.Controls,
		Policies:          input.Policies,
		ResourceRefs:      input.ResourceRefs,
		Generation:        input.Generation,
		UnsupportedClaims: input.UnsupportedClaims,
		Approval:          input.Approval,
		FreshUntil:        utcTimePtr(input.FreshUntil),
		ExpiresAt:         utcTimePtr(input.ExpiresAt),
		IssuedAt:          input.IssuedAt.UTC(),
		PreviousDigest:    input.PreviousDigest,
	}
	if receipt.Status == "" {
		receipt.Status = ClaimStatusDraft
	}
	if isExternalStatus(receipt.Status) {
		if err := validateExternalEligibility(receipt, receipt.IssuedAt); err != nil {
			return ClaimReceipt{}, err
		}
	}
	digest, err := digestValue(receiptWithoutDigest(receipt))
	if err != nil {
		return ClaimReceipt{}, err
	}
	receipt.Digest = digest
	return receipt, nil
}

func validateReceiptReferenceInput(input ReceiptInput) error {
	for _, ref := range append(append([]VersionedRef(nil), input.Controls...), input.Policies...) {
		if strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.Version) == "" {
			return fmt.Errorf("%w: %w", ErrInvalidReceipt, ErrInvalidVersionedReference)
		}
	}
	for _, ref := range input.ResourceRefs {
		if strings.TrimSpace(ref.URN) == "" || strings.TrimSpace(ref.Revision) == "" {
			return fmt.Errorf("%w: %w", ErrInvalidReceipt, ErrInvalidResourceReference)
		}
	}
	return nil
}

func validateReceiptInput(input ReceiptInput) error {
	if input.TenantID == "" || input.ReceiptID == "" || input.ClaimID == "" || input.Statement == "" || input.IssuedAt.IsZero() {
		return fmt.Errorf("%w: tenant_id, receipt_id, claim_id, statement, and issued_at are required", ErrInvalidReceipt)
	}
	if !utf8.ValidString(input.Statement) || strings.ContainsRune(input.Statement, '\x00') {
		return fmt.Errorf("%w: statement must be valid text without NUL bytes", ErrInvalidReceipt)
	}
	if input.Version < 1 {
		return fmt.Errorf("%w: version must be positive", ErrInvalidReceipt)
	}
	if len(input.Citations) == 0 {
		if isExternalStatus(input.RequestedStatus) {
			return fmt.Errorf("%w: current citations are required", ErrNotShareable)
		}
		return fmt.Errorf("%w: evidence citations are required", ErrInvalidReceipt)
	}
	if len(input.Controls) == 0 || len(input.Policies) == 0 || len(input.ResourceRefs) == 0 {
		return fmt.Errorf("%w: versioned controls, versioned policies, and resource refs are required", ErrInvalidReceipt)
	}
	if input.FreshUntil == nil || input.ExpiresAt == nil || !input.FreshUntil.After(input.IssuedAt) || !input.ExpiresAt.After(input.IssuedAt) {
		return fmt.Errorf("%w: future freshness and expiry bounds are required", ErrInvalidReceipt)
	}
	switch input.Origin {
	case ClaimOriginAuthored, ClaimOriginGenerated, ClaimOriginExtracted:
	default:
		return fmt.Errorf("%w: unsupported claim origin %q", ErrInvalidReceipt, input.Origin)
	}
	if input.Origin == ClaimOriginGenerated {
		if input.Generation == nil || input.Generation.ModelID == "" || input.Generation.ModelVersion == "" || input.Generation.PromptVersion == "" {
			return fmt.Errorf("%w: generated claims require model and prompt versions", ErrInvalidReceipt)
		}
	}
	switch input.RequestedStatus {
	case "", ClaimStatusDraft, ClaimStatusShareable, ClaimStatusAuditorReady:
	default:
		return fmt.Errorf("%w: status %q cannot be issued directly", ErrInvalidReceipt, input.RequestedStatus)
	}
	switch input.DisclosureClass {
	case DisclosureInternal, DisclosureCustomer, DisclosureAuditor:
	default:
		return fmt.Errorf("%w: unsupported disclosure class %q", ErrInvalidReceipt, input.DisclosureClass)
	}
	if isExternalStatus(input.RequestedStatus) && input.DisclosureClass == DisclosureInternal {
		return fmt.Errorf("%w: external status requires customer or auditor disclosure", ErrInvalidReceipt)
	}
	for _, citation := range input.Citations {
		if citation.ID == "" || citation.EvidenceID == "" || citation.SourceID == "" || citation.ObservedAt.IsZero() || len(citation.SourceEventIDs) == 0 {
			return fmt.Errorf("%w: citations require id, evidence_id, source_id, observed_at, and source event ids", ErrInvalidReceipt)
		}
		if citation.ObservedAt.After(input.IssuedAt) {
			return fmt.Errorf("%w: citation %s was observed after receipt issuance", ErrInvalidReceipt, citation.ID)
		}
		switch citation.State {
		case CitationCurrent, CitationStale, CitationRevoked, CitationConflicted:
		default:
			return fmt.Errorf("%w: unsupported citation state %q", ErrInvalidReceipt, citation.State)
		}
	}
	return nil
}

func validateExternalEligibility(receipt ClaimReceipt, at time.Time) error {
	if len(receipt.Citations) == 0 {
		return fmt.Errorf("%w: current citations are required", ErrNotShareable)
	}
	if receipt.Approval == nil || receipt.Approval.Decision != ApprovalApproved || receipt.Approval.ReviewerID == "" || receipt.Approval.ApprovedAt.IsZero() {
		return fmt.Errorf("%w: reviewer approval is required", ErrNotShareable)
	}
	if len(receipt.UnsupportedClaims) != 0 {
		return fmt.Errorf("%w: unsupported claims remain", ErrNotShareable)
	}
	if receipt.ExpiresAt != nil && !receipt.ExpiresAt.After(at) {
		return fmt.Errorf("%w: receipt has expired", ErrNotShareable)
	}
	if receipt.FreshUntil != nil && !receipt.FreshUntil.After(at) {
		return fmt.Errorf("%w: receipt freshness window has elapsed", ErrNotShareable)
	}
	for _, citation := range receipt.Citations {
		if citation.State != CitationCurrent || !citation.Trusted {
			return fmt.Errorf("%w: citation %s is not current and trusted", ErrNotShareable, citation.ID)
		}
		if citation.ExpiresAt != nil && !citation.ExpiresAt.After(at) {
			return fmt.Errorf("%w: citation %s has expired", ErrNotShareable, citation.ID)
		}
	}
	if receipt.Status == ClaimStatusAuditorReady && receipt.DisclosureClass != DisclosureAuditor {
		return fmt.Errorf("%w: auditor-ready claims require auditor disclosure", ErrNotShareable)
	}
	return nil
}

// ApplyEvidenceChange creates a new immutable receipt version and a workflow
// transition. It never updates citations in place or transfers prior approval.
func ApplyEvidenceChange(receipt ClaimReceipt, change EvidenceChange) (ClaimTransition, error) {
	if err := verifyReceipt(receipt); err != nil {
		return ClaimTransition{}, err
	}
	if receipt.Status == ClaimStatusSuperseded {
		return ClaimTransition{}, fmt.Errorf("%w: superseded claims cannot be reopened", ErrInvalidReceipt)
	}
	change.TenantID = strings.TrimSpace(change.TenantID)
	change.CitationID = strings.TrimSpace(change.CitationID)
	change.State = strings.TrimSpace(change.State)
	change.Reason = strings.TrimSpace(change.Reason)
	if change.TenantID != receipt.TenantID {
		return ClaimTransition{}, ErrTenantMismatch
	}
	if change.ObservedAt.IsZero() || change.CitationID == "" {
		return ClaimTransition{}, fmt.Errorf("%w: citation_id and observed_at are required", ErrInvalidReceipt)
	}
	switch change.State {
	case CitationStale, CitationRevoked, CitationConflicted:
	default:
		return ClaimTransition{}, fmt.Errorf("%w: evidence changes must be stale, revoked, or conflicted", ErrInvalidReceipt)
	}
	citations := append([]Citation(nil), receipt.Citations...)
	found := false
	for index := range citations {
		if citations[index].ID == change.CitationID {
			citations[index].State = change.State
			found = true
		}
	}
	if !found {
		return ClaimTransition{}, fmt.Errorf("%w: citation %s does not belong to receipt", ErrInvalidReceipt, change.CitationID)
	}
	status := ClaimStatusReopened
	transitionType := TransitionClaimReopened
	if receipt.Status == ClaimStatusShareable || receipt.Status == ClaimStatusAuditorReady || receipt.Status == ClaimStatusWithdrawn {
		status = ClaimStatusWithdrawn
		transitionType = TransitionClaimWithdrawn
	}
	next := receipt
	next.Version++
	next.Status = status
	next.Citations = citations
	next.Approval = nil
	next.IssuedAt = change.ObservedAt.UTC()
	next.PreviousDigest = receipt.Digest
	next.TransitionReason = change.Reason
	next.Digest = ""
	normalizeReceipt(&next)
	digest, err := digestValue(receiptWithoutDigest(next))
	if err != nil {
		return ClaimTransition{}, err
	}
	next.Digest = digest
	return ClaimTransition{
		EventKind:      workflowevents.EventKindKnowledgeDecisionRecorded,
		TransitionType: transitionType,
		TenantID:       receipt.TenantID,
		ClaimID:        receipt.ClaimID,
		FromDigest:     receipt.Digest,
		Receipt:        next,
	}, nil
}

// ReconcileExpiry turns elapsed receipt or citation freshness into an explicit
// transition. A nil transition means the immutable receipt remains current.
func ReconcileExpiry(receipt ClaimReceipt, at time.Time) (*ClaimTransition, error) {
	if err := verifyReceipt(receipt); err != nil {
		return nil, err
	}
	if at.IsZero() {
		return nil, fmt.Errorf("%w: reconciliation time is required", ErrInvalidReceipt)
	}
	for _, citation := range receipt.Citations {
		if citation.State != CitationCurrent {
			continue
		}
		if citation.ExpiresAt != nil && !citation.ExpiresAt.After(at) {
			transition, err := ApplyEvidenceChange(receipt, EvidenceChange{
				TenantID: receipt.TenantID, CitationID: citation.ID, State: CitationStale,
				Reason: "Cited evidence expired.", ObservedAt: at,
			})
			return &transition, err
		}
	}
	if (receipt.ExpiresAt != nil && !receipt.ExpiresAt.After(at)) || (receipt.FreshUntil != nil && !receipt.FreshUntil.After(at)) {
		citationID := ""
		for _, citation := range receipt.Citations {
			if citation.State == CitationCurrent {
				citationID = citation.ID
				break
			}
		}
		if citationID == "" {
			return nil, nil
		}
		transition, err := ApplyEvidenceChange(receipt, EvidenceChange{
			TenantID: receipt.TenantID, CitationID: citationID, State: CitationStale,
			Reason: "Claim freshness window elapsed.", ObservedAt: at,
		})
		return &transition, err
	}
	return nil, nil
}

func SupersedeReceipt(receipt ClaimReceipt, successorReceiptID string, at time.Time) (ClaimTransition, error) {
	if err := verifyReceipt(receipt); err != nil {
		return ClaimTransition{}, err
	}
	if strings.TrimSpace(successorReceiptID) == "" || at.IsZero() {
		return ClaimTransition{}, fmt.Errorf("%w: successor receipt and transition time are required", ErrInvalidReceipt)
	}
	next := receipt
	next.Version++
	next.Status = ClaimStatusSuperseded
	next.Approval = nil
	next.IssuedAt = at.UTC()
	next.PreviousDigest = receipt.Digest
	next.TransitionReason = "Superseded by receipt " + strings.TrimSpace(successorReceiptID) + "."
	next.Digest = ""
	normalizeReceipt(&next)
	digest, err := digestValue(receiptWithoutDigest(next))
	if err != nil {
		return ClaimTransition{}, err
	}
	next.Digest = digest
	return ClaimTransition{EventKind: workflowevents.EventKindKnowledgeDecisionRecorded, TransitionType: TransitionClaimSuperseded, TenantID: receipt.TenantID, ClaimID: receipt.ClaimID, FromDigest: receipt.Digest, Receipt: next}, nil
}

func SuggestObligation(input ObligationInput) (Obligation, error) {
	if input.SuggestedBy == nil {
		return Obligation{}, fmt.Errorf("%w: extracted suggestion receipt is required", ErrInvalidReceipt)
	}
	return buildObligation(input, ObligationSuggested, nil)
}

func ConfirmObligation(suggestion Obligation, approval ReviewerApproval, at time.Time) (Obligation, error) {
	if err := verifyObligation(suggestion); err != nil {
		return Obligation{}, err
	}
	if suggestion.Status != ObligationSuggested {
		return Obligation{}, fmt.Errorf("%w: only suggestions can be confirmed", ErrHumanConfirmationRequired)
	}
	normalizeApproval(&approval)
	if approval.Decision != ApprovalApproved || approval.ReviewerID == "" || approval.ApprovedAt.IsZero() {
		return Obligation{}, ErrHumanConfirmationRequired
	}
	if at.IsZero() {
		return Obligation{}, fmt.Errorf("%w: confirmation time is required", ErrInvalidReceipt)
	}
	next := suggestion
	next.Version++
	next.Status = ObligationActive
	next.ConfirmedBy = &approval
	next.IssuedAt = at.UTC()
	next.PreviousDigest = suggestion.Digest
	next.Digest = ""
	normalizeObligation(&next)
	digest, err := digestValue(obligationWithoutDigest(next))
	if err != nil {
		return Obligation{}, err
	}
	next.Digest = digest
	return next, nil
}

func SupersedeObligation(obligation Obligation, successorID string, at time.Time) (Obligation, error) {
	if err := verifyObligation(obligation); err != nil {
		return Obligation{}, err
	}
	if obligation.Status != ObligationActive || strings.TrimSpace(successorID) == "" || at.IsZero() {
		return Obligation{}, fmt.Errorf("%w: active obligation, successor id, and transition time are required", ErrInvalidReceipt)
	}
	next := obligation
	next.Version++
	next.Status = ObligationSuperseded
	next.SupersededBy = strings.TrimSpace(successorID)
	next.IssuedAt = at.UTC()
	next.PreviousDigest = obligation.Digest
	next.Digest = ""
	normalizeObligation(&next)
	digest, err := digestValue(obligationWithoutDigest(next))
	if err != nil {
		return Obligation{}, err
	}
	next.Digest = digest
	return next, nil
}

func buildObligation(input ObligationInput, status string, approval *ReviewerApproval) (Obligation, error) {
	normalizeObligationInput(&input)
	if input.TenantID == "" || input.ObligationID == "" || input.Version < 1 || input.ContractRef.ID == "" || input.ContractRef.Version == "" || input.CommitmentRef == "" || input.OwnerID == "" || input.IssuedAt.IsZero() {
		return Obligation{}, fmt.Errorf("%w: obligation identity, contract version, commitment, owner, version, and issued_at are required", ErrInvalidReceipt)
	}
	if input.SuggestedBy == nil || input.SuggestedBy.SourceRef == "" || input.SuggestedBy.ExtractorID == "" {
		return Obligation{}, fmt.Errorf("%w: extracted obligations require source and extractor receipts", ErrInvalidReceipt)
	}
	if len(input.Controls) == 0 || len(input.EvidenceRequirements) == 0 || len(input.ResourcePopulation) == 0 {
		return Obligation{}, fmt.Errorf("%w: controls, evidence requirements, and resource population are required", ErrInvalidReceipt)
	}
	obligation := Obligation{
		SchemaVersion:        ObligationSchemaVersion,
		TenantID:             input.TenantID,
		ObligationID:         input.ObligationID,
		Version:              input.Version,
		Status:               status,
		ContractRef:          input.ContractRef,
		CommitmentRef:        input.CommitmentRef,
		Controls:             input.Controls,
		EvidenceRequirements: input.EvidenceRequirements,
		ResourcePopulation:   input.ResourcePopulation,
		OwnerID:              input.OwnerID,
		Deadline:             utcTimePtr(input.Deadline),
		SuggestedBy:          input.SuggestedBy,
		ConfirmedBy:          approval,
		PreviousDigest:       input.PreviousDigest,
		IssuedAt:             input.IssuedAt.UTC(),
	}
	digest, err := digestValue(obligationWithoutDigest(obligation))
	if err != nil {
		return Obligation{}, err
	}
	obligation.Digest = digest
	return obligation, nil
}

// ReadService reads caller-supplied current-state records. Persistence remains
// owned by the existing state store and workflow event projection.
type ReadService struct {
	Receipts    []ClaimReceipt
	Obligations []Obligation
}

func (service ReadService) GetReceipt(tenantID, receiptID string) (ClaimReceipt, error) {
	tenantID = strings.TrimSpace(tenantID)
	receiptID = strings.TrimSpace(receiptID)
	for _, receipt := range service.Receipts {
		if receipt.ReceiptID != receiptID {
			continue
		}
		if receipt.TenantID != tenantID {
			return ClaimReceipt{}, ErrTenantMismatch
		}
		if err := verifyReceipt(receipt); err != nil {
			return ClaimReceipt{}, err
		}
		return receipt, nil
	}
	return ClaimReceipt{}, ErrReceiptNotFound
}

func (service ReadService) BuildPackage(request PackageRequest) (ClaimPackage, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Audience = strings.TrimSpace(request.Audience)
	request.ReceiptIDs = uniqueSortedStrings(request.ReceiptIDs)
	request.ObligationIDs = uniqueSortedStrings(request.ObligationIDs)
	if request.TenantID == "" || request.PackagedAt.IsZero() || (request.Audience != DisclosureCustomer && request.Audience != DisclosureAuditor) {
		return ClaimPackage{}, fmt.Errorf("%w: tenant, customer or auditor audience, and packaged_at are required", ErrInvalidReceipt)
	}
	pack := ClaimPackage{SchemaVersion: PackageSchemaVersion, TenantID: request.TenantID, Audience: request.Audience, PackagedAt: request.PackagedAt.UTC()}
	for _, id := range request.ReceiptIDs {
		receipt, err := service.GetReceipt(request.TenantID, id)
		if err != nil {
			return ClaimPackage{}, err
		}
		if request.Audience == DisclosureAuditor && receipt.Status != ClaimStatusAuditorReady {
			return ClaimPackage{}, fmt.Errorf("%w: receipt %s is not auditor ready", ErrNotShareable, id)
		}
		if request.Audience == DisclosureCustomer && receipt.Status != ClaimStatusShareable && receipt.Status != ClaimStatusAuditorReady {
			return ClaimPackage{}, fmt.Errorf("%w: receipt %s is not customer shareable", ErrNotShareable, id)
		}
		if err := validateExternalEligibility(receipt, request.PackagedAt); err != nil {
			return ClaimPackage{}, err
		}
		pack.Receipts = append(pack.Receipts, receipt)
	}
	for _, id := range request.ObligationIDs {
		obligation, err := service.getObligation(request.TenantID, id)
		if err != nil {
			return ClaimPackage{}, err
		}
		if obligation.Status != ObligationActive {
			return ClaimPackage{}, fmt.Errorf("%w: obligation %s is not active", ErrNotShareable, id)
		}
		pack.Obligations = append(pack.Obligations, obligation)
	}
	digest, err := digestValue(packageWithoutDigest(pack))
	if err != nil {
		return ClaimPackage{}, err
	}
	pack.Digest = digest
	return pack, nil
}

func (service ReadService) getObligation(tenantID, obligationID string) (Obligation, error) {
	for _, obligation := range service.Obligations {
		if obligation.ObligationID != obligationID {
			continue
		}
		if obligation.TenantID != tenantID {
			return Obligation{}, ErrTenantMismatch
		}
		if err := verifyObligation(obligation); err != nil {
			return Obligation{}, err
		}
		return obligation, nil
	}
	return Obligation{}, ErrObligationNotFound
}

func verifyReceipt(receipt ClaimReceipt) error {
	if receipt.SchemaVersion != ReceiptSchemaVersion || receipt.Digest == "" {
		return fmt.Errorf("%w: schema version and digest are required", ErrInvalidReceipt)
	}
	digest, err := digestValue(receiptWithoutDigest(receipt))
	if err != nil {
		return err
	}
	if digest != receipt.Digest {
		return fmt.Errorf("%w: receipt digest does not match content", ErrInvalidReceipt)
	}
	return nil
}

func verifyObligation(obligation Obligation) error {
	digest, err := digestValue(obligationWithoutDigest(obligation))
	if err != nil {
		return err
	}
	if obligation.SchemaVersion != ObligationSchemaVersion || obligation.Digest == "" || digest != obligation.Digest {
		return fmt.Errorf("%w: obligation digest does not match content", ErrInvalidReceipt)
	}
	return nil
}

func normalizeReceiptInput(input *ReceiptInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ReceiptID = strings.TrimSpace(input.ReceiptID)
	input.ClaimID = strings.TrimSpace(input.ClaimID)
	input.Statement = strings.TrimSpace(input.Statement)
	input.Origin = strings.TrimSpace(input.Origin)
	input.RequestedStatus = strings.TrimSpace(input.RequestedStatus)
	input.DisclosureClass = strings.TrimSpace(input.DisclosureClass)
	input.PreviousDigest = strings.TrimSpace(input.PreviousDigest)
	if input.Version == 0 {
		input.Version = 1
	}
	input.IssuedAt = input.IssuedAt.UTC()
	input.UnsupportedClaims = uniqueSortedStrings(input.UnsupportedClaims)
	normalizeCitations(input.Citations)
	input.Controls = normalizeVersionedRefs(input.Controls)
	input.Policies = normalizeVersionedRefs(input.Policies)
	input.ResourceRefs = normalizeResourceRefs(input.ResourceRefs)
	if input.Generation != nil {
		normalizeGeneration(input.Generation)
	}
	if input.Approval != nil {
		normalizeApproval(input.Approval)
	}
}

func normalizeReceipt(receipt *ClaimReceipt) {
	normalizeCitations(receipt.Citations)
	receipt.Controls = normalizeVersionedRefs(receipt.Controls)
	receipt.Policies = normalizeVersionedRefs(receipt.Policies)
	receipt.ResourceRefs = normalizeResourceRefs(receipt.ResourceRefs)
	receipt.UnsupportedClaims = uniqueSortedStrings(receipt.UnsupportedClaims)
	receipt.IssuedAt = receipt.IssuedAt.UTC()
}

func normalizeCitations(citations []Citation) {
	for index := range citations {
		citation := &citations[index]
		citation.ID = strings.TrimSpace(citation.ID)
		citation.EvidenceID = strings.TrimSpace(citation.EvidenceID)
		citation.EvidencePacketID = strings.TrimSpace(citation.EvidencePacketID)
		citation.EvidenceType = strings.TrimSpace(citation.EvidenceType)
		citation.SourceID = strings.TrimSpace(citation.SourceID)
		citation.RuntimeID = strings.TrimSpace(citation.RuntimeID)
		citation.State = strings.TrimSpace(citation.State)
		citation.SourceEventIDs = uniqueSortedStrings(citation.SourceEventIDs)
		citation.ResourceRefs = normalizeResourceRefs(citation.ResourceRefs)
		citation.ObservedAt = citation.ObservedAt.UTC()
		citation.ExpiresAt = utcTimePtr(citation.ExpiresAt)
	}
	sort.Slice(citations, func(i, j int) bool { return citations[i].ID < citations[j].ID })
}

func normalizeVersionedRefs(refs []VersionedRef) []VersionedRef {
	result := append([]VersionedRef(nil), refs...)
	for index := range result {
		result[index].ID = strings.TrimSpace(result[index].ID)
		result[index].Version = strings.TrimSpace(result[index].Version)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID == result[j].ID {
			return result[i].Version < result[j].Version
		}
		return result[i].ID < result[j].ID
	})
	return dedupeVersionedRefs(result)
}

func normalizeResourceRefs(refs []ResourceRef) []ResourceRef {
	result := append([]ResourceRef(nil), refs...)
	for index := range result {
		result[index].URN = strings.TrimSpace(result[index].URN)
		result[index].Revision = strings.TrimSpace(result[index].Revision)
		result[index].Type = strings.TrimSpace(result[index].Type)
	}
	sort.Slice(result, func(i, j int) bool {
		return resourceKey(result[i]) < resourceKey(result[j])
	})
	return dedupeResourceRefs(result)
}

func normalizeObligationInput(input *ObligationInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ObligationID = strings.TrimSpace(input.ObligationID)
	input.ContractRef.ID = strings.TrimSpace(input.ContractRef.ID)
	input.ContractRef.Version = strings.TrimSpace(input.ContractRef.Version)
	input.CommitmentRef = strings.TrimSpace(input.CommitmentRef)
	input.Controls = normalizeVersionedRefs(input.Controls)
	input.EvidenceRequirements = normalizeVersionedRefs(input.EvidenceRequirements)
	input.ResourcePopulation = normalizeResourceRefs(input.ResourcePopulation)
	input.OwnerID = strings.TrimSpace(input.OwnerID)
	input.IssuedAt = input.IssuedAt.UTC()
	input.PreviousDigest = strings.TrimSpace(input.PreviousDigest)
	if input.Version == 0 {
		input.Version = 1
	}
	if input.SuggestedBy != nil {
		input.SuggestedBy.SourceRef = strings.TrimSpace(input.SuggestedBy.SourceRef)
		input.SuggestedBy.ExtractorID = strings.TrimSpace(input.SuggestedBy.ExtractorID)
		input.SuggestedBy.ModelVersion = strings.TrimSpace(input.SuggestedBy.ModelVersion)
		input.SuggestedBy.PromptVersion = strings.TrimSpace(input.SuggestedBy.PromptVersion)
	}
}

func normalizeObligation(obligation *Obligation) {
	obligation.Controls = normalizeVersionedRefs(obligation.Controls)
	obligation.EvidenceRequirements = normalizeVersionedRefs(obligation.EvidenceRequirements)
	obligation.ResourcePopulation = normalizeResourceRefs(obligation.ResourcePopulation)
	obligation.IssuedAt = obligation.IssuedAt.UTC()
}

func normalizeGeneration(generation *GenerationReceipt) {
	generation.ModelID = strings.TrimSpace(generation.ModelID)
	generation.ModelVersion = strings.TrimSpace(generation.ModelVersion)
	generation.PromptVersion = strings.TrimSpace(generation.PromptVersion)
	generation.PromptDigest = strings.TrimSpace(generation.PromptDigest)
}

func normalizeApproval(approval *ReviewerApproval) {
	approval.ReviewerID = strings.TrimSpace(approval.ReviewerID)
	approval.Decision = strings.TrimSpace(approval.Decision)
	approval.Reason = strings.TrimSpace(approval.Reason)
	approval.ApprovedAt = approval.ApprovedAt.UTC()
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func dedupeVersionedRefs(refs []VersionedRef) []VersionedRef {
	result := refs[:0]
	last := ""
	for _, ref := range refs {
		key := ref.ID + "\x00" + ref.Version
		if ref.ID == "" || ref.Version == "" || key == last {
			continue
		}
		result = append(result, ref)
		last = key
	}
	return result
}

func dedupeResourceRefs(refs []ResourceRef) []ResourceRef {
	result := refs[:0]
	last := ""
	for _, ref := range refs {
		key := resourceKey(ref)
		if ref.URN == "" || key == last {
			continue
		}
		result = append(result, ref)
		last = key
	}
	return result
}

func resourceKey(ref ResourceRef) string { return ref.URN + "\x00" + ref.Revision + "\x00" + ref.Type }
func utcTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}
func isExternalStatus(status string) bool {
	return status == ClaimStatusShareable || status == ClaimStatusAuditorReady
}

func digestValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonical receipt encoding: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func receiptWithoutDigest(receipt ClaimReceipt) ClaimReceipt { receipt.Digest = ""; return receipt }
func obligationWithoutDigest(obligation Obligation) Obligation {
	obligation.Digest = ""
	return obligation
}
func packageWithoutDigest(pack ClaimPackage) ClaimPackage { pack.Digest = ""; return pack }
