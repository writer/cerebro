package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/findingevidence"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
	"github.com/writer/cerebro/internal/workflowevents"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	securityLifecycleFindingRuleID = "security-lifecycle-expiry"

	securityLifecycleAttributeAuthorityID   = "security_lifecycle_authority_id"
	securityLifecycleAttributeStableLocator = "security_lifecycle_stable_locator"
	securityLifecycleAttributeSubjectKind   = "security_lifecycle_subject_kind"
	securityLifecycleAttributeProvider      = "security_lifecycle_provider"
	securityLifecycleAttributeGraphRevision = "security_lifecycle_graph_revision"
	securityLifecycleAttributeCollectionID  = "security_lifecycle_source_collection_id"
	securityLifecycleAttributeProvenance    = "security_lifecycle_provenance"
)

// SecurityLifecycleFindingObservation is the metadata-only input accepted from
// the Rust lifecycle resolver. AuthorityID and StableLocator are the durable
// identity; MaterialRevision is evidence and never participates in identity.
type SecurityLifecycleFindingObservation struct {
	TenantID           string
	FindingURN         string
	SourceRuntimeID    string
	SourceCollectionID string
	SubjectURN         string
	SubjectKind        string
	AuthorityID        string
	StableLocator      string
	MaterialRevision   string
	Provider           string
	DisplayName        string
	OwnerURN           string
	ObservedState      string
	PolicyState        string
	PolicyID           string
	PolicyVersion      string
	ObservedAt         time.Time
	ExpiresAt          time.Time
	GraphRevision      uint64
	EvidenceClaimRefs  []string
}

// SecurityLifecycleClosureObservation is proof from a later exact-subject
// lifecycle query. Provider dispatch or execution receipts do not satisfy it.
type SecurityLifecycleClosureObservation struct {
	FindingURN                      string
	SourceRuntimeID                 string
	SourceCollectionID              string
	SubjectURN                      string
	AuthorityID                     string
	StableLocator                   string
	PolicyState                     string
	ObservedAt                      time.Time
	FreshnessAsOf                   time.Time
	CoverageComplete                bool
	CoverageTruncated               bool
	PageTruncated                   bool
	CollectionReceiptTenantID       string
	CollectionReceiptRuntimeID      string
	CollectionReceiptID             string
	CollectionReceiptStatus         string
	CollectionReceiptCompletedAt    time.Time
	CollectionIncompletenessReasons []string
	EvidenceClaimRefs               []string
}

// SecurityLifecycleFindingLocator is the stable exact-subject selector stored
// with a projected lifecycle finding.
type SecurityLifecycleFindingLocator struct {
	SubjectURN       string
	SubjectKind      string
	AuthorityID      string
	StableLocator    string
	SourceRuntimeID  string
	SourceCollection string
	PolicyID         string
}

// SecurityLifecycleLocatorForFinding returns the exact selector and
// provenance stored by this bridge without exposing its storage keys.
func SecurityLifecycleLocatorForFinding(finding *ports.FindingRecord) (SecurityLifecycleFindingLocator, bool) {
	if finding == nil || strings.TrimSpace(finding.RuleID) != securityLifecycleFindingRuleID {
		return SecurityLifecycleFindingLocator{}, false
	}
	locator := SecurityLifecycleFindingLocator{
		SubjectURN:       firstString(finding.ResourceURNs),
		SubjectKind:      strings.TrimSpace(finding.Attributes[securityLifecycleAttributeSubjectKind]),
		AuthorityID:      strings.TrimSpace(finding.Attributes[securityLifecycleAttributeAuthorityID]),
		StableLocator:    strings.TrimSpace(finding.Attributes[securityLifecycleAttributeStableLocator]),
		SourceRuntimeID:  strings.TrimSpace(finding.RuntimeID),
		SourceCollection: strings.TrimSpace(finding.Attributes[securityLifecycleAttributeCollectionID]),
		PolicyID:         strings.TrimSpace(finding.PolicyID),
	}
	if locator.SubjectURN == "" || locator.SubjectKind == "" || locator.AuthorityID == "" ||
		locator.StableLocator == "" || locator.SourceRuntimeID == "" || locator.PolicyID == "" {
		return SecurityLifecycleFindingLocator{}, false
	}
	return locator, true
}

// RecordSecurityLifecycleFinding projects one currently-open Rust lifecycle
// finding into the existing FindingRecord and FindingEvidence authorities.
func (s *Service) RecordSecurityLifecycleFinding(ctx context.Context, observation SecurityLifecycleFindingObservation) (*ports.FindingRecord, error) {
	normalized, err := normalizeSecurityLifecycleFindingObservation(observation)
	if err != nil {
		return nil, err
	}
	if s == nil || s.runtimeStore == nil || s.store == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, normalized.SourceRuntimeID)
	if err != nil {
		return nil, fmt.Errorf("load security lifecycle source runtime %q: %w", normalized.SourceRuntimeID, err)
	}
	if strings.TrimSpace(runtime.GetTenantId()) != normalized.TenantID {
		return nil, fmt.Errorf("%w: lifecycle source runtime tenant does not match the resolver tenant", ErrInvalidRequest)
	}

	record := securityLifecycleFindingRecord(normalized)
	stored, _, err := s.upsertFindingWithRiskAndNewness(ctx, record, nil, normalized.ObservedAt)
	if err != nil {
		return nil, fmt.Errorf("persist security lifecycle finding %q: %w", normalized.FindingURN, err)
	}
	evidence := securityLifecycleFindingEvidence(stored, normalized.SourceCollectionID, normalized.ObservedAt, normalized.EvidenceClaimRefs)
	if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
		return nil, fmt.Errorf("persist security lifecycle finding %q evidence: %w", normalized.FindingURN, err)
	}
	if err := s.projectFindingAnchor(ctx, stored); err != nil {
		return nil, fmt.Errorf("record security lifecycle finding %q workflow event: %w", normalized.FindingURN, err)
	}
	return stored, nil
}

// ResolveSecurityLifecycleFindingAfterObservation closes one lifecycle finding
// only when a later exact-subject observation is complete, non-truncated, and
// proves the expiry policy no longer matches.
func (s *Service) ResolveSecurityLifecycleFindingAfterObservation(ctx context.Context, proof SecurityLifecycleClosureObservation) (*ports.FindingRecord, error) {
	if s == nil || s.store == nil || s.evidenceStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	findingID := strings.TrimSpace(proof.FindingURN)
	if findingID == "" {
		return nil, fmt.Errorf("%w: lifecycle finding urn is required", ErrInvalidRequest)
	}
	if !proof.CoverageComplete || proof.CoverageTruncated || proof.PageTruncated {
		return nil, fmt.Errorf("%w: lifecycle closure requires complete, non-truncated source coverage", ErrInvalidRequest)
	}
	if securityLifecyclePolicyMatches(proof.PolicyState) {
		return nil, fmt.Errorf("%w: lifecycle policy still matches", ErrInvalidRequest)
	}
	if !strings.EqualFold(strings.TrimSpace(proof.PolicyState), "compliant") {
		return nil, fmt.Errorf("%w: lifecycle closure requires a compliant policy observation", ErrInvalidRequest)
	}

	current, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(current.Attributes[securityLifecycleAttributeAuthorityID]) != strings.TrimSpace(proof.AuthorityID) ||
		strings.TrimSpace(current.Attributes[securityLifecycleAttributeStableLocator]) != strings.TrimSpace(proof.StableLocator) {
		return nil, fmt.Errorf("%w: lifecycle closure subject does not match the persisted finding", ErrInvalidRequest)
	}
	if subjectURN := strings.TrimSpace(proof.SubjectURN); subjectURN == "" || !containsString(current.ResourceURNs, subjectURN) {
		return nil, fmt.Errorf("%w: lifecycle closure resource does not match the persisted finding", ErrInvalidRequest)
	}
	if strings.TrimSpace(proof.SourceRuntimeID) == "" || strings.TrimSpace(proof.SourceRuntimeID) != strings.TrimSpace(current.RuntimeID) {
		return nil, fmt.Errorf("%w: lifecycle closure runtime does not match the persisted finding", ErrInvalidRequest)
	}
	if strings.TrimSpace(proof.SourceCollectionID) == "" ||
		strings.TrimSpace(proof.CollectionReceiptID) != strings.TrimSpace(proof.SourceCollectionID) ||
		strings.TrimSpace(proof.CollectionReceiptTenantID) != strings.TrimSpace(current.TenantID) ||
		strings.TrimSpace(proof.CollectionReceiptRuntimeID) != strings.TrimSpace(current.RuntimeID) ||
		!strings.EqualFold(strings.TrimSpace(proof.CollectionReceiptStatus), "complete") ||
		len(uniqueSortedStrings(proof.CollectionIncompletenessReasons)) != 0 {
		return nil, fmt.Errorf("%w: lifecycle closure requires the matching complete source collection receipt", ErrInvalidRequest)
	}
	if openCollectionID := strings.TrimSpace(current.Attributes[securityLifecycleAttributeCollectionID]); openCollectionID != "" && openCollectionID == strings.TrimSpace(proof.SourceCollectionID) {
		return nil, fmt.Errorf("%w: lifecycle closure requires an independent later source collection", ErrInvalidRequest)
	}
	observedAt := proof.ObservedAt.UTC()
	if observedAt.IsZero() || !observedAt.After(current.LastObservedAt.UTC()) {
		return nil, fmt.Errorf("%w: lifecycle closure observation must be newer than the open finding", ErrInvalidRequest)
	}
	if freshnessAsOf := proof.FreshnessAsOf.UTC(); freshnessAsOf.IsZero() || freshnessAsOf.Before(observedAt) {
		return nil, fmt.Errorf("%w: lifecycle closure requires freshness through the exact observation", ErrInvalidRequest)
	}
	if completedAt := proof.CollectionReceiptCompletedAt.UTC(); completedAt.IsZero() || completedAt.Before(observedAt) {
		return nil, fmt.Errorf("%w: lifecycle collection receipt must complete after the observation", ErrInvalidRequest)
	}

	evidence := securityLifecycleFindingEvidence(current, proof.SourceCollectionID, observedAt, proof.EvidenceClaimRefs)
	if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
		return nil, fmt.Errorf("persist security lifecycle closure evidence for %q: %w", findingID, err)
	}
	updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
		FindingID:          findingID,
		Status:             findingStatusResolved,
		Reason:             workflowevents.FindingStatusReasonVerifiedObservation,
		UpdatedAt:          observedAt,
		ExpectedStatus:     findingStatusOpen,
		LastObservedBefore: observedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve security lifecycle finding %q: %w", findingID, err)
	}
	if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceVerifiedObservation); err != nil {
		return nil, fmt.Errorf("record security lifecycle finding %q verified closure: %w", findingID, err)
	}
	return updated, nil
}

func normalizeSecurityLifecycleFindingObservation(input SecurityLifecycleFindingObservation) (SecurityLifecycleFindingObservation, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.FindingURN = strings.TrimSpace(input.FindingURN)
	input.SourceRuntimeID = strings.TrimSpace(input.SourceRuntimeID)
	input.SourceCollectionID = strings.TrimSpace(input.SourceCollectionID)
	input.SubjectURN = strings.TrimSpace(input.SubjectURN)
	input.SubjectKind = strings.ToLower(strings.TrimSpace(input.SubjectKind))
	input.AuthorityID = strings.TrimSpace(input.AuthorityID)
	input.StableLocator = strings.TrimSpace(input.StableLocator)
	input.MaterialRevision = strings.TrimSpace(input.MaterialRevision)
	input.Provider = strings.TrimSpace(input.Provider)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.OwnerURN = strings.TrimSpace(input.OwnerURN)
	input.ObservedState = strings.ToLower(strings.TrimSpace(input.ObservedState))
	input.PolicyState = strings.ToLower(strings.TrimSpace(input.PolicyState))
	input.PolicyID = strings.TrimSpace(input.PolicyID)
	input.PolicyVersion = strings.TrimSpace(input.PolicyVersion)
	input.ObservedAt = input.ObservedAt.UTC()
	input.ExpiresAt = input.ExpiresAt.UTC()
	input.EvidenceClaimRefs = uniqueSortedStrings(input.EvidenceClaimRefs)
	findingURN, findingURNErr := cerebrourn.Parse(input.FindingURN)
	subjectURN, subjectURNErr := cerebrourn.Parse(input.SubjectURN)
	switch {
	case input.TenantID == "":
		return input, fmt.Errorf("%w: lifecycle tenant id is required", ErrInvalidRequest)
	case input.FindingURN == "":
		return input, fmt.Errorf("%w: lifecycle finding urn is required", ErrInvalidRequest)
	case findingURNErr != nil || findingURN.Kind != "finding" || findingURN.TenantID != input.TenantID:
		return input, fmt.Errorf("%w: lifecycle finding urn must identify a finding in the resolver tenant", ErrInvalidRequest)
	case input.SourceRuntimeID == "":
		return input, fmt.Errorf("%w: lifecycle source runtime id is required", ErrInvalidRequest)
	case input.SubjectURN == "":
		return input, fmt.Errorf("%w: lifecycle subject urn is required", ErrInvalidRequest)
	case subjectURNErr != nil || subjectURN.TenantID != input.TenantID:
		return input, fmt.Errorf("%w: lifecycle subject urn is outside the tenant", ErrInvalidRequest)
	case input.AuthorityID == "":
		return input, fmt.Errorf("%w: lifecycle authority id is required", ErrInvalidRequest)
	case input.StableLocator == "":
		return input, fmt.Errorf("%w: lifecycle stable locator is required", ErrInvalidRequest)
	case input.ObservedAt.IsZero():
		return input, fmt.Errorf("%w: lifecycle observed_at is required", ErrInvalidRequest)
	case !securityLifecyclePolicyMatches(input.PolicyState):
		return input, fmt.Errorf("%w: lifecycle resolver did not return an open expiry policy state", ErrInvalidRequest)
	}
	return input, nil
}

func securityLifecycleFindingRecord(input SecurityLifecycleFindingObservation) *ports.FindingRecord {
	identity := securityLifecycleDigest(input.TenantID, input.AuthorityID, input.StableLocator, input.SubjectKind)
	titleSubject := firstNonEmpty(input.DisplayName, input.SubjectKind, "Resource")
	state := strings.ToLower(strings.TrimSpace(input.PolicyState))
	title := fmt.Sprintf("%s expires within the policy window", titleSubject)
	summary := "The latest lifecycle observation matches the configured expiry policy."
	severity := "MEDIUM"
	if state == "expired" {
		title = fmt.Sprintf("%s is expired", titleSubject)
		summary = "The latest lifecycle observation shows that the resource is expired."
		severity = "HIGH"
	}
	attributes := map[string]string{
		"primary_resource_urn":                  input.SubjectURN,
		"resource_urn":                          input.FindingURN,
		"subject_urn":                           input.SubjectURN,
		securityLifecycleAttributeAuthorityID:   input.AuthorityID,
		securityLifecycleAttributeStableLocator: input.StableLocator,
		securityLifecycleAttributeSubjectKind:   input.SubjectKind,
		securityLifecycleAttributeProvider:      input.Provider,
		securityLifecycleAttributeGraphRevision: fmt.Sprintf("%d", input.GraphRevision),
		securityLifecycleAttributeCollectionID:  input.SourceCollectionID,
		"security_lifecycle_observed_state":     input.ObservedState,
		"security_lifecycle_policy_state":       input.PolicyState,
		"security_lifecycle_policy_version":     input.PolicyVersion,
		"security_lifecycle_material_revision":  input.MaterialRevision,
	}
	if input.SourceCollectionID == "" {
		attributes[securityLifecycleAttributeProvenance] = "pending_source_collection"
	} else {
		attributes[securityLifecycleAttributeProvenance] = "source_collection_linked"
	}
	trimEmptyAttributes(attributes)
	return &ports.FindingRecord{
		ID:                input.FindingURN,
		Fingerprint:       identity,
		TenantID:          input.TenantID,
		RuntimeID:         input.SourceRuntimeID,
		RuleID:            securityLifecycleFindingRuleID,
		Title:             title,
		Severity:          severity,
		Status:            findingStatusOpen,
		Summary:           summary,
		ResourceURNs:      []string{input.SubjectURN},
		ObservedPolicyIDs: []string{input.PolicyID},
		PolicyID:          input.PolicyID,
		PolicyName:        "Security lifecycle expiry",
		CheckID:           securityLifecycleFindingRuleID,
		CheckName:         "Security lifecycle expiry",
		FindingWorkflow: ports.FindingWorkflow{
			Assignee: input.OwnerURN,
			DueAt:    input.ExpiresAt,
		},
		Attributes:      attributes,
		FirstObservedAt: input.ObservedAt,
		LastObservedAt:  input.ObservedAt,
	}
}

func securityLifecycleFindingEvidence(finding *ports.FindingRecord, sourceCollectionID string, observedAt time.Time, claimRefs []string) *cerebrov1.FindingEvidence {
	claimRefs = uniqueSortedStrings(claimRefs)
	resourceURNs := uniqueSortedStrings(finding.ResourceURNs)
	evidence := &cerebrov1.FindingEvidence{
		Id:             "lifecycle-evidence-" + securityLifecycleDigest(finding.ID, sourceCollectionID, strings.Join(claimRefs, "\x00")),
		RuntimeId:      strings.TrimSpace(finding.RuntimeID),
		RuleId:         strings.TrimSpace(finding.RuleID),
		FindingId:      strings.TrimSpace(finding.ID),
		ClaimIds:       claimRefs,
		GraphRootUrns:  resourceURNs,
		CreatedAt:      timestamppb.New(observedAt.UTC()),
		LastObservedAt: timestamppb.New(observedAt.UTC()),
		Attributes: map[string]string{
			"evidence_kind":        "security_lifecycle_observation",
			"source_runtime_id":    strings.TrimSpace(finding.RuntimeID),
			"source_collection_id": strings.TrimSpace(sourceCollectionID),
		},
	}
	trimEmptyAttributes(evidence.Attributes)
	if observation := findingevidence.ObservationFor(evidence); observation != nil {
		evidence.Observations = []*cerebrov1.FindingEvidenceObservation{observation}
		evidence.ObservationCount = 1
	}
	return evidence
}

func securityLifecyclePolicyMatches(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "expiring", "expired":
		return true
	default:
		return false
	}
}

func securityLifecycleDigest(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(strings.TrimSpace(value)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func firstString(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
