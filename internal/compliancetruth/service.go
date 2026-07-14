package compliancetruth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/trustclaims"
)

var (
	ErrInvalidTruthRecord = errors.New("invalid compliance truth record")
	ErrTenantMismatch     = errors.New("tenant mismatch")
	ErrUnresolvedConflict = errors.New("unresolved compliance truth conflict")
)

func IssueRevision(input RevisionInput) (TruthRevision, error) {
	normalizeRevisionInput(&input)
	if err := validateRevisionInput(input); err != nil {
		return TruthRevision{}, err
	}
	revision := TruthRevision{
		SchemaVersion: RevisionSchemaVersion,
		TenantID:      input.TenantID,
		AssertionID:   input.AssertionID,
		RevisionID:    input.RevisionID,
		Version:       input.Version,
		Subject:       input.Subject,
		Predicate:     input.Predicate,
		Value:         input.Value,
		ValidTime:     input.ValidTime,
		RecordedTime:  Interval{From: input.RecordedAt},
		ClaimBindings: input.ClaimBindings,
	}
	digest, err := digestValue(revisionWithoutDigest(revision))
	if err != nil {
		return TruthRevision{}, err
	}
	revision.Digest = digest
	return revision, nil
}

// CorrectRevision creates a late-arriving successor and a separate receipt
// that closes the prior recorded-time interval. The prior revision is unchanged.
func CorrectRevision(previous TruthRevision, input RevisionInput) (TruthRevision, SupersessionReceipt, error) {
	if err := verifyRevision(previous); err != nil {
		return TruthRevision{}, SupersessionReceipt{}, err
	}
	normalizeRevisionInput(&input)
	if input.TenantID != previous.TenantID {
		return TruthRevision{}, SupersessionReceipt{}, ErrTenantMismatch
	}
	if input.AssertionID != previous.AssertionID || !sameSubject(input.Subject, previous.Subject) || input.Predicate != previous.Predicate {
		return TruthRevision{}, SupersessionReceipt{}, fmt.Errorf("%w: correction must preserve assertion identity", ErrInvalidTruthRecord)
	}
	if !input.RecordedAt.After(previous.RecordedTime.From) {
		return TruthRevision{}, SupersessionReceipt{}, fmt.Errorf("%w: correction must be recorded after the prior revision", ErrInvalidTruthRecord)
	}
	input.Version = previous.Version + 1
	successor, err := IssueRevision(input)
	if err != nil {
		return TruthRevision{}, SupersessionReceipt{}, err
	}
	successor.PreviousDigest = previous.Digest
	digest, err := digestValue(revisionWithoutDigest(successor))
	if err != nil {
		return TruthRevision{}, SupersessionReceipt{}, err
	}
	successor.Digest = digest
	receipt := SupersessionReceipt{
		SchemaVersion:   SupersessionSchemaVersion,
		TenantID:        previous.TenantID,
		AssertionID:     previous.AssertionID,
		PriorDigest:     previous.Digest,
		SuccessorDigest: successor.Digest,
		RecordedAt:      input.RecordedAt.UTC(),
	}
	receiptDigest, err := digestValue(supersessionWithoutDigest(receipt))
	if err != nil {
		return TruthRevision{}, SupersessionReceipt{}, err
	}
	receipt.Digest = receiptDigest
	return successor, receipt, nil
}

func ResolveConflict(input ResolutionInput) (ConflictResolutionReceipt, error) {
	normalizeResolutionInput(&input)
	if input.TenantID == "" || input.AssertionID == "" || input.ConflictID == "" || input.RecordedAt.IsZero() {
		return ConflictResolutionReceipt{}, fmt.Errorf("%w: resolution identity and recorded time are required", ErrInvalidTruthRecord)
	}
	if input.Decision != ResolutionAcceptRevision || len(input.InputDigests) < 2 || !contains(input.InputDigests, input.SelectedRevisionDigest) {
		return ConflictResolutionReceipt{}, fmt.Errorf("%w: resolution must select one exact conflicting revision", ErrInvalidTruthRecord)
	}
	if input.Reviewer.Decision != trustclaims.ApprovalApproved || input.Reviewer.ReviewerID == "" || input.Reviewer.ApprovedAt.IsZero() || input.Reviewer.ApprovedAt.After(input.RecordedAt) {
		return ConflictResolutionReceipt{}, fmt.Errorf("%w: reviewer approval must precede the recorded resolution", ErrInvalidTruthRecord)
	}
	receipt := ConflictResolutionReceipt{
		SchemaVersion:          ResolutionSchemaVersion,
		TenantID:               input.TenantID,
		AssertionID:            input.AssertionID,
		ConflictID:             input.ConflictID,
		InputDigests:           input.InputDigests,
		Decision:               input.Decision,
		SelectedRevisionDigest: input.SelectedRevisionDigest,
		Reviewer:               input.Reviewer,
		RecordedAt:             input.RecordedAt.UTC(),
	}
	digest, err := digestValue(resolutionWithoutDigest(receipt))
	if err != nil {
		return ConflictResolutionReceipt{}, err
	}
	receipt.Digest = digest
	return receipt, nil
}

func Evaluate(ledger Ledger, query EvaluationQuery) (TruthEvaluation, error) {
	normalizeQuery(&query)
	if query.TenantID == "" || query.AssertionID == "" || query.AsKnownAt.IsZero() || query.EffectiveAt.IsZero() {
		return TruthEvaluation{}, fmt.Errorf("%w: tenant, assertion, as-known-at, and effective-at are required", ErrInvalidTruthRecord)
	}
	closures, err := supersessionClosures(ledger, query)
	if err != nil {
		return TruthEvaluation{}, err
	}
	candidates := []TruthRevision{}
	for _, revision := range ledger.Revisions {
		if strings.TrimSpace(revision.AssertionID) != query.AssertionID {
			continue
		}
		if revision.TenantID != query.TenantID {
			return TruthEvaluation{}, ErrTenantMismatch
		}
		if err := verifyRevision(revision); err != nil {
			return TruthEvaluation{}, err
		}
		if !intervalContains(revision.ValidTime, query.EffectiveAt) || !recordedAtContains(revision, closures[revision.Digest], query.AsKnownAt) {
			continue
		}
		candidates = append(candidates, revision)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Digest < candidates[j].Digest })
	evaluation := TruthEvaluation{
		TenantID:    query.TenantID,
		AssertionID: query.AssertionID,
		AsKnownAt:   query.AsKnownAt,
		EffectiveAt: query.EffectiveAt,
		State:       EvaluationUnknown,
	}
	if len(candidates) == 0 {
		return finishEvaluation(evaluation)
	}

	blocking, err := claimConflicts(ledger.Claims, candidates, query)
	if err != nil {
		return TruthEvaluation{}, err
	}
	valueConflict := conflictingValues(candidates)
	if valueConflict != nil {
		resolution, err := matchingResolution(ledger.Resolutions, query, *valueConflict)
		if err != nil {
			return TruthEvaluation{}, err
		}
		if resolution == nil {
			blocking = append(blocking, *valueConflict)
		} else {
			valueConflict.ResolutionDigest = resolution.Digest
			evaluation.ResolvedConflicts = append(evaluation.ResolvedConflicts, *valueConflict)
			evaluation.ResolutionReceipts = append(evaluation.ResolutionReceipts, resolution.Digest)
			candidates = filterRevision(candidates, resolution.SelectedRevisionDigest)
		}
	}
	blocking = normalizeConflicts(blocking)
	evaluation.RevisionDigests = revisionDigests(candidates)
	evaluation.Conflicts = blocking
	if len(blocking) != 0 {
		evaluation.State = EvaluationConflicted
		return finishEvaluation(evaluation)
	}
	values := revisionValues(candidates)
	if len(values) != 1 {
		return TruthEvaluation{}, ErrUnresolvedConflict
	}
	evaluation.State = EvaluationQualified
	evaluation.Qualified = true
	evaluation.Shareable = true
	evaluation.Value = values[0]
	return finishEvaluation(evaluation)
}

func validateRevisionInput(input RevisionInput) error {
	if input.TenantID == "" || input.AssertionID == "" || input.RevisionID == "" || input.Version < 1 || input.Subject.URN == "" || input.Subject.Revision == "" || input.Predicate == "" || input.Value == "" || input.RecordedAt.IsZero() {
		return fmt.Errorf("%w: revision identity, versioned subject, predicate, value, and recorded time are required", ErrInvalidTruthRecord)
	}
	if err := validateInterval(input.ValidTime); err != nil {
		return err
	}
	if len(input.ClaimBindings) == 0 {
		return fmt.Errorf("%w: at least one exact claim receipt binding is required", ErrInvalidTruthRecord)
	}
	for _, binding := range input.ClaimBindings {
		if binding.ReceiptID == "" || binding.ReceiptDigest == "" || (binding.Position != PositionSupports && binding.Position != PositionRefutes) {
			return fmt.Errorf("%w: claim bindings require receipt id, digest, and position", ErrInvalidTruthRecord)
		}
	}
	return nil
}

func supersessionClosures(ledger Ledger, query EvaluationQuery) (map[string]time.Time, error) {
	closures := map[string]time.Time{}
	successors := map[string]string{}
	revisions := map[string]TruthRevision{}
	for _, revision := range ledger.Revisions {
		if revision.AssertionID != query.AssertionID {
			continue
		}
		if revision.TenantID != query.TenantID {
			return nil, ErrTenantMismatch
		}
		if err := verifyRevision(revision); err != nil {
			return nil, err
		}
		revisions[revision.Digest] = revision
	}
	for _, receipt := range ledger.Supersessions {
		if receipt.AssertionID != query.AssertionID {
			continue
		}
		if receipt.TenantID != query.TenantID {
			return nil, ErrTenantMismatch
		}
		if err := verifySupersession(receipt); err != nil {
			return nil, err
		}
		prior, priorOK := revisions[receipt.PriorDigest]
		successor, successorOK := revisions[receipt.SuccessorDigest]
		if !priorOK || !successorOK || successor.PreviousDigest != prior.Digest ||
			successor.Version != prior.Version+1 || successor.AssertionID != prior.AssertionID ||
			!sameSubject(successor.Subject, prior.Subject) || successor.Predicate != prior.Predicate ||
			!successor.RecordedTime.From.Equal(receipt.RecordedAt) || !receipt.RecordedAt.After(prior.RecordedTime.From) {
			return nil, fmt.Errorf("%w: supersession receipt does not bind an exact revision transition", ErrInvalidTruthRecord)
		}
		if existing, ok := successors[receipt.PriorDigest]; ok && existing != receipt.SuccessorDigest {
			return nil, fmt.Errorf("%w: revision has multiple successor receipts", ErrInvalidTruthRecord)
		}
		successors[receipt.PriorDigest] = receipt.SuccessorDigest
		closures[receipt.PriorDigest] = receipt.RecordedAt
	}
	return closures, nil
}

func claimConflicts(claims []trustclaims.ClaimReceipt, revisions []TruthRevision, query EvaluationQuery) ([]Conflict, error) {
	byDigest := map[string]trustclaims.ClaimReceipt{}
	for _, claim := range claims {
		byDigest[claim.Digest] = claim
	}
	conflicts := []Conflict{}
	for _, revision := range revisions {
		for _, binding := range revision.ClaimBindings {
			claim, ok := byDigest[binding.ReceiptDigest]
			if !ok || claim.ReceiptID != binding.ReceiptID {
				conflicts = append(conflicts, makeConflict(ConflictClaimMissing, []string{revision.Digest, binding.ReceiptDigest}, nil, nil, "The exact bound claim receipt is unavailable.", false))
				continue
			}
			if claim.TenantID != query.TenantID {
				return nil, ErrTenantMismatch
			}
			if _, err := (trustclaims.ReadService{Receipts: []trustclaims.ClaimReceipt{claim}}).GetReceipt(query.TenantID, claim.ReceiptID); err != nil {
				return nil, err
			}
			hasLaterRevision, err := claimHasLaterRevision(claims, claim, query.AsKnownAt)
			if err != nil {
				return nil, err
			}
			if binding.Position == PositionRefutes || claim.IssuedAt.After(query.AsKnownAt) || claim.IssuedAt.After(revision.RecordedTime.From) || hasLaterRevision || (claim.Status != trustclaims.ClaimStatusShareable && claim.Status != trustclaims.ClaimStatusAuditorReady) || expiredAt(claim.FreshUntil, query.AsKnownAt) || expiredAt(claim.ExpiresAt, query.AsKnownAt) {
				conflicts = append(conflicts, makeConflict(ConflictClaimState, []string{revision.Digest, claim.Digest}, []string{claim.Status, binding.Position}, nil, "A bound claim is not current and shareable for this assertion.", false))
			}
			for _, citation := range claim.Citations {
				if citation.State != trustclaims.CitationCurrent || !citation.Trusted || expiredAt(citation.ExpiresAt, query.AsKnownAt) {
					conflicts = append(conflicts, makeConflict(ConflictCitationState, []string{revision.Digest, claim.Digest}, []string{citation.State}, []string{citation.ID}, "A bound citation is stale, revoked, conflicted, expired, or untrusted.", false))
				}
			}
		}
	}
	return normalizeConflicts(conflicts), nil
}

func conflictingValues(revisions []TruthRevision) *Conflict {
	values := revisionValues(revisions)
	if len(values) < 2 {
		return nil
	}
	conflict := makeConflict(ConflictValueDisagreement, revisionDigests(revisions), values, nil, "Current evidence supports conflicting assertion values.", true)
	return &conflict
}

func matchingResolution(receipts []ConflictResolutionReceipt, query EvaluationQuery, conflict Conflict) (*ConflictResolutionReceipt, error) {
	matching := []ConflictResolutionReceipt{}
	for _, receipt := range receipts {
		if receipt.AssertionID != query.AssertionID || receipt.ConflictID != conflict.ID {
			continue
		}
		if receipt.TenantID != query.TenantID {
			return nil, ErrTenantMismatch
		}
		if err := verifyResolution(receipt); err != nil {
			return nil, err
		}
		if receipt.RecordedAt.After(query.AsKnownAt) || !equalStrings(receipt.InputDigests, conflict.InputDigests) {
			continue
		}
		matching = append(matching, receipt)
	}
	if len(matching) == 0 {
		return nil, nil
	}
	sort.Slice(matching, func(i, j int) bool {
		if matching[i].RecordedAt.Equal(matching[j].RecordedAt) {
			return matching[i].Digest < matching[j].Digest
		}
		return matching[i].RecordedAt.Before(matching[j].RecordedAt)
	})
	selected := matching[len(matching)-1]
	return &selected, nil
}

func makeConflict(kind string, inputs, values, citationIDs []string, reason string, resolvable bool) Conflict {
	inputs = uniqueSortedStrings(inputs)
	values = uniqueSortedStrings(values)
	citationIDs = uniqueSortedStrings(citationIDs)
	payload := struct {
		Kind                      string
		Inputs, Values, Citations []string
	}{kind, inputs, values, citationIDs}
	id, _ := digestValue(payload)
	return Conflict{ID: id, Kind: kind, InputDigests: inputs, Values: values, CitationIDs: citationIDs, Reason: reason, Resolvable: resolvable}
}

func finishEvaluation(evaluation TruthEvaluation) (TruthEvaluation, error) {
	evaluation.RevisionDigests = uniqueSortedStrings(evaluation.RevisionDigests)
	evaluation.ResolutionReceipts = uniqueSortedStrings(evaluation.ResolutionReceipts)
	evaluation.AsKnownAt = evaluation.AsKnownAt.UTC()
	evaluation.EffectiveAt = evaluation.EffectiveAt.UTC()
	digest, err := digestValue(evaluationWithoutDigest(evaluation))
	if err != nil {
		return TruthEvaluation{}, err
	}
	evaluation.Digest = digest
	return evaluation, nil
}

func verifyRevision(revision TruthRevision) error {
	digest, err := digestValue(revisionWithoutDigest(revision))
	if err != nil {
		return err
	}
	if revision.SchemaVersion != RevisionSchemaVersion || revision.Digest == "" || digest != revision.Digest {
		return fmt.Errorf("%w: revision digest does not match content", ErrInvalidTruthRecord)
	}
	if revision.TenantID == "" || revision.AssertionID == "" || revision.RevisionID == "" || revision.Version < 1 || revision.Subject.URN == "" || revision.Subject.Revision == "" || revision.Predicate == "" || revision.Value == "" || revision.RecordedTime.From.IsZero() || len(revision.ClaimBindings) == 0 {
		return fmt.Errorf("%w: revision content is incomplete", ErrInvalidTruthRecord)
	}
	if err := validateInterval(revision.ValidTime); err != nil {
		return err
	}
	if revision.RecordedTime.To != nil && !revision.RecordedTime.To.After(revision.RecordedTime.From) {
		return fmt.Errorf("%w: recorded-time interval end must follow its start", ErrInvalidTruthRecord)
	}
	for _, binding := range revision.ClaimBindings {
		if binding.ReceiptID == "" || binding.ReceiptDigest == "" || (binding.Position != PositionSupports && binding.Position != PositionRefutes) {
			return fmt.Errorf("%w: revision claim binding is incomplete", ErrInvalidTruthRecord)
		}
	}
	return nil
}

func verifySupersession(receipt SupersessionReceipt) error {
	digest, err := digestValue(supersessionWithoutDigest(receipt))
	if err != nil {
		return err
	}
	if receipt.SchemaVersion != SupersessionSchemaVersion || receipt.PriorDigest == "" || receipt.SuccessorDigest == "" || receipt.RecordedAt.IsZero() || receipt.Digest == "" || digest != receipt.Digest {
		return fmt.Errorf("%w: supersession receipt digest does not match content", ErrInvalidTruthRecord)
	}
	return nil
}

func verifyResolution(receipt ConflictResolutionReceipt) error {
	digest, err := digestValue(resolutionWithoutDigest(receipt))
	if err != nil {
		return err
	}
	if receipt.SchemaVersion != ResolutionSchemaVersion || receipt.Digest == "" || digest != receipt.Digest {
		return fmt.Errorf("%w: conflict resolution digest does not match content", ErrInvalidTruthRecord)
	}
	if receipt.TenantID == "" || receipt.AssertionID == "" || receipt.ConflictID == "" || receipt.Decision != ResolutionAcceptRevision || len(receipt.InputDigests) < 2 || !contains(receipt.InputDigests, receipt.SelectedRevisionDigest) || receipt.Reviewer.Decision != trustclaims.ApprovalApproved || receipt.Reviewer.ReviewerID == "" || receipt.Reviewer.ApprovedAt.IsZero() || receipt.RecordedAt.IsZero() || receipt.Reviewer.ApprovedAt.After(receipt.RecordedAt) {
		return fmt.Errorf("%w: conflict resolution content is incomplete", ErrInvalidTruthRecord)
	}
	return nil
}

func normalizeRevisionInput(input *RevisionInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.AssertionID = strings.TrimSpace(input.AssertionID)
	input.RevisionID = strings.TrimSpace(input.RevisionID)
	input.Subject.URN = strings.TrimSpace(input.Subject.URN)
	input.Subject.Revision = strings.TrimSpace(input.Subject.Revision)
	input.Subject.Type = strings.TrimSpace(input.Subject.Type)
	input.Predicate = strings.TrimSpace(input.Predicate)
	input.Value = strings.TrimSpace(input.Value)
	if input.Version == 0 {
		input.Version = 1
	}
	input.ValidTime = normalizeInterval(input.ValidTime)
	input.RecordedAt = input.RecordedAt.UTC()
	input.ClaimBindings = normalizeBindings(input.ClaimBindings)
}

func normalizeResolutionInput(input *ResolutionInput) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.AssertionID = strings.TrimSpace(input.AssertionID)
	input.ConflictID = strings.TrimSpace(input.ConflictID)
	input.InputDigests = uniqueSortedStrings(input.InputDigests)
	input.Decision = strings.TrimSpace(input.Decision)
	input.SelectedRevisionDigest = strings.TrimSpace(input.SelectedRevisionDigest)
	input.Reviewer.ReviewerID = strings.TrimSpace(input.Reviewer.ReviewerID)
	input.Reviewer.Decision = strings.TrimSpace(input.Reviewer.Decision)
	input.Reviewer.Reason = strings.TrimSpace(input.Reviewer.Reason)
	input.Reviewer.ApprovedAt = input.Reviewer.ApprovedAt.UTC()
	input.RecordedAt = input.RecordedAt.UTC()
}

func normalizeQuery(query *EvaluationQuery) {
	query.TenantID = strings.TrimSpace(query.TenantID)
	query.AssertionID = strings.TrimSpace(query.AssertionID)
	query.AsKnownAt = query.AsKnownAt.UTC()
	query.EffectiveAt = query.EffectiveAt.UTC()
}

func normalizeBindings(bindings []ClaimBinding) []ClaimBinding {
	result := append([]ClaimBinding(nil), bindings...)
	for index := range result {
		result[index].ReceiptID = strings.TrimSpace(result[index].ReceiptID)
		result[index].ReceiptDigest = strings.TrimSpace(result[index].ReceiptDigest)
		result[index].Position = strings.TrimSpace(result[index].Position)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ReceiptDigest == result[j].ReceiptDigest {
			return result[i].Position < result[j].Position
		}
		return result[i].ReceiptDigest < result[j].ReceiptDigest
	})
	return result
}

func normalizeConflicts(conflicts []Conflict) []Conflict {
	byID := map[string]Conflict{}
	for _, conflict := range conflicts {
		byID[conflict.ID] = conflict
	}
	result := make([]Conflict, 0, len(byID))
	for _, conflict := range byID {
		result = append(result, conflict)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func validateInterval(interval Interval) error {
	if interval.From.IsZero() || (interval.To != nil && !interval.To.After(interval.From)) {
		return fmt.Errorf("%w: valid-time interval requires a start and an optional later end", ErrInvalidTruthRecord)
	}
	return nil
}

func normalizeInterval(interval Interval) Interval {
	interval.From = interval.From.UTC()
	if interval.To != nil {
		value := interval.To.UTC()
		interval.To = &value
	}
	return interval
}

func intervalContains(interval Interval, at time.Time) bool {
	return !at.Before(interval.From) && (interval.To == nil || at.Before(*interval.To))
}

func recordedAtContains(revision TruthRevision, supersededAt time.Time, at time.Time) bool {
	if at.Before(revision.RecordedTime.From) {
		return false
	}
	if revision.RecordedTime.To != nil && !at.Before(*revision.RecordedTime.To) {
		return false
	}
	return supersededAt.IsZero() || at.Before(supersededAt)
}

func expiredAt(value *time.Time, at time.Time) bool { return value != nil && !value.After(at) }
func claimHasLaterRevision(claims []trustclaims.ClaimReceipt, claim trustclaims.ClaimReceipt, at time.Time) (bool, error) {
	for _, candidate := range claims {
		if candidate.TenantID == claim.TenantID && candidate.ClaimID == claim.ClaimID && candidate.PreviousDigest == claim.Digest && !candidate.IssuedAt.After(at) {
			if _, err := (trustclaims.ReadService{Receipts: []trustclaims.ClaimReceipt{candidate}}).GetReceipt(claim.TenantID, candidate.ReceiptID); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}
func sameSubject(a, b trustclaims.ResourceRef) bool {
	return a.URN == b.URN && a.Revision == b.Revision && a.Type == b.Type
}
func contains(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func revisionDigests(revisions []TruthRevision) []string {
	result := make([]string, 0, len(revisions))
	for _, revision := range revisions {
		result = append(result, revision.Digest)
	}
	return uniqueSortedStrings(result)
}
func revisionValues(revisions []TruthRevision) []string {
	result := make([]string, 0, len(revisions))
	for _, revision := range revisions {
		result = append(result, revision.Value)
	}
	return uniqueSortedStrings(result)
}
func filterRevision(revisions []TruthRevision, digest string) []TruthRevision {
	for _, revision := range revisions {
		if revision.Digest == digest {
			return []TruthRevision{revision}
		}
	}
	return nil
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

func digestValue(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonical compliance truth encoding: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func revisionWithoutDigest(value TruthRevision) TruthRevision { value.Digest = ""; return value }
func supersessionWithoutDigest(value SupersessionReceipt) SupersessionReceipt {
	value.Digest = ""
	return value
}
func resolutionWithoutDigest(value ConflictResolutionReceipt) ConflictResolutionReceipt {
	value.Digest = ""
	return value
}
func evaluationWithoutDigest(value TruthEvaluation) TruthEvaluation { value.Digest = ""; return value }
