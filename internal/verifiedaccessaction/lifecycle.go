package verifiedaccessaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphactions"
)

func Propose(input ProposalInput) (Outcome, error) {
	if err := validateProposal(input); err != nil {
		return Outcome{}, err
	}
	record := Record{
		SchemaVersion: SchemaVersion, ID: actionID(input), TenantID: clean(input.TenantID), Status: StatusProposed,
		Definition: input.Definition, Binding: input.Binding, Parameters: cloneMap(input.Parameters), Proposer: input.Proposer,
		IdempotencyKey: clean(input.IdempotencyKey), Rollback: cloneRollback(input.Rollback), Reason: clean(input.Reason), ProposedAt: input.ProposedAt.UTC(),
	}
	return transition(record, "", StatusProposed, ResultProposed, input.Proposer, input.ProposedAt)
}

func Preflight(record Record, input PreflightInput) (Outcome, error) {
	if err := requireState(record, StatusProposed); err != nil {
		return Outcome{}, err
	}
	if input.ProposalDigest != record.Digest || input.Binding != record.Binding || input.ParametersDigest != digestValue(record.Parameters) || input.RollbackDigest != digestValue(record.Rollback) {
		return Outcome{}, fmt.Errorf("%w: preflight bindings do not match the proposal", ErrStale)
	}
	if !validActor(input.Actor) || clean(input.ExpectedEffect) != clean(record.Definition.Metadata.Effect) || !input.TargetExists || !input.WouldChange || input.ProviderMutation || input.SimulatedAt.IsZero() || !input.ValidUntil.After(input.SimulatedAt) {
		return Outcome{}, fmt.Errorf("%w: preflight must be a bounded, non-mutating simulation with a concrete change", ErrInvalid)
	}
	if !input.SourceHealthy {
		return Outcome{}, ErrSourceUnhealthy
	}
	receipt := PreflightReceipt{PreflightInput: input}
	receipt.Digest = digestValue(receipt)
	updated := cloneRecord(record)
	updated.Preflight, updated.Status = &receipt, StatusPreflighted
	return transition(updated, StatusProposed, StatusPreflighted, ResultPreflightPassed, input.Actor, input.SimulatedAt)
}

func Approve(record Record, input ApprovalInput) (Outcome, error) {
	if err := requireState(record, StatusPreflighted); err != nil {
		return Outcome{}, err
	}
	if input.ProposalDigest != proposalDigest(record) || record.Preflight == nil || input.PreflightDigest != record.Preflight.Digest {
		return Outcome{}, fmt.Errorf("%w: approval does not bind the current proposal and preflight", ErrStale)
	}
	if !human(input.Actor) || sameActor(input.Actor, record.Proposer) {
		return Outcome{}, ErrSeparationOfDuty
	}
	if input.ApprovedAt.IsZero() || input.ApprovedAt.Before(record.Preflight.SimulatedAt) || input.ApprovedAt.After(record.Preflight.ValidUntil) || clean(input.Reason) == "" {
		return Outcome{}, fmt.Errorf("%w: approval is outside the preflight window or has no reason", ErrStale)
	}
	receipt := ApprovalReceipt{ApprovalInput: input}
	receipt.Digest = digestValue(receipt)
	updated := cloneRecord(record)
	updated.Approval, updated.Status = &receipt, StatusApproved
	return transition(updated, StatusPreflighted, StatusApproved, ResultApproved, input.Actor, input.ApprovedAt)
}

// IngestExecution records an existing provider receipt. It never invokes a
// provider and accepts only a successful graph-action result bound to approval.
func IngestExecution(record Record, input ExecutionInput) (Outcome, error) {
	if err := requireState(record, StatusApproved); err != nil {
		return Outcome{}, err
	}
	if record.Preflight == nil || record.Approval == nil || input.ProposalDigest != proposalDigest(record) || input.PreflightDigest != record.Preflight.Digest || input.ApprovalDigest != record.Approval.Digest || input.ParametersDigest != digestValue(record.Parameters) || input.Binding != record.Binding || input.DefinitionVersion != record.Definition.Version {
		return Outcome{}, fmt.Errorf("%w: execution receipt does not bind the approved action", ErrStale)
	}
	if !validActor(input.ExecutedBy) || !validActor(input.IngestedBy) || input.OccurredAt.IsZero() || input.OccurredAt.Before(record.Approval.ApprovedAt) {
		return Outcome{}, fmt.Errorf("%w: execution actor or occurrence time is invalid", ErrInvalid)
	}
	if err := validateGraphAction(record, input); err != nil {
		return Outcome{}, err
	}
	if input.ProviderReceiptDigest == "" || input.ProviderReceiptDigest != digestGraphAction(input.GraphAction) {
		return Outcome{}, fmt.Errorf("%w: provider receipt digest mismatch", ErrInvalid)
	}
	receipt := ExecutionReceipt{ExecutionInput: input}
	receipt.Digest = digestValue(receipt)
	updated := cloneRecord(record)
	updated.Execution, updated.Status = &receipt, StatusExecuted
	return transition(updated, StatusApproved, StatusExecuted, ResultReceiptIngested, input.IngestedBy, input.OccurredAt)
}

func VerifyClosure(record Record, input VerificationInput) (Outcome, error) {
	if err := requireState(record, StatusExecuted); err != nil {
		return Outcome{}, err
	}
	if err := validateVerification(record, input); err != nil {
		return Outcome{}, err
	}
	if !input.SourceHealthy {
		return Outcome{}, ErrSourceUnhealthy
	}
	if !input.Effective {
		return Outcome{}, ErrVerificationMismatch
	}
	receipt := VerificationReceipt{VerificationInput: cloneVerification(input)}
	receipt.Digest = digestValue(receipt)
	updated := cloneRecord(record)
	updated.Verification, updated.Status = &receipt, StatusClosed
	return transition(updated, StatusExecuted, StatusClosed, ResultVerifiedClosed, input.Actor, input.VerifiedAt)
}

// Reverify preserves closure only with fresh independent evidence. An
// unhealthy source or mismatched effect reopens the action instead of keeping
// an unsupported closed state.
func Reverify(record Record, input VerificationInput) (Outcome, error) {
	if err := requireState(record, StatusClosed); err != nil {
		return Outcome{}, err
	}
	if err := validateVerification(record, input); err != nil {
		return Outcome{}, err
	}
	if record.Verification != nil && !input.VerifiedAt.After(record.Verification.VerifiedAt) {
		return Outcome{}, fmt.Errorf("%w: re-verification is not newer than closure", ErrStale)
	}
	if record.Verification != nil && (input.Binding.SourceRevision == record.Verification.Binding.SourceRevision || input.Binding.SubjectRevision == record.Verification.Binding.SubjectRevision) {
		return Outcome{}, fmt.Errorf("%w: re-verification must use fresh source and subject revisions", ErrStale)
	}
	receipt := VerificationReceipt{VerificationInput: cloneVerification(input)}
	receipt.Digest = digestValue(receipt)
	updated := cloneRecord(record)
	updated.Verification, updated.Status = &receipt, StatusClosed
	code := ResultVerifiedClosed
	to := StatusClosed
	if !input.SourceHealthy {
		code, to, updated.Status = ResultReopenedSourceUnhealthy, StatusReopened, StatusReopened
	} else if !input.Effective {
		code, to, updated.Status = ResultReopenedMismatch, StatusReopened, StatusReopened
	}
	return transition(updated, StatusClosed, to, code, input.Actor, input.VerifiedAt)
}

func validateProposal(input ProposalInput) error {
	metadata, binding := input.Definition.Metadata, input.Binding
	if clean(input.TenantID) == "" || clean(input.Definition.Version) == "" || clean(metadata.ID) == "" || clean(metadata.Provider) == "" || clean(metadata.ProviderAction) == "" || clean(metadata.TargetKind) == "" || !metadata.Destructive || (clean(metadata.Effect) != "deny_access" && clean(metadata.Effect) != "remove_privilege") || clean(metadata.ReversibleBy) == "" {
		return fmt.Errorf("%w: action must be a versioned, reversible access denial or privilege removal", ErrInvalid)
	}
	if clean(binding.TargetID) == "" || clean(binding.SubjectURN) == "" || clean(binding.SubjectRevision) == "" || clean(binding.ResourceURN) == "" || clean(binding.ResourceRevision) == "" || clean(binding.SourceRuntimeID) == "" || clean(binding.SourceRevision) == "" {
		return fmt.Errorf("%w: target and source revisions are required", ErrInvalid)
	}
	if !human(input.Proposer) || clean(input.IdempotencyKey) == "" || clean(input.Reason) == "" || input.ProposedAt.IsZero() {
		return fmt.Errorf("%w: proposer, idempotency key, reason, and time are required", ErrInvalid)
	}
	if clean(input.Rollback.ActionID) != clean(metadata.ReversibleBy) || clean(input.Rollback.DefinitionVersion) == "" || len(input.Rollback.Steps) == 0 {
		return fmt.Errorf("%w: an exact rollback action and steps are required", ErrInvalid)
	}
	for _, step := range input.Rollback.Steps {
		if clean(step) == "" {
			return fmt.Errorf("%w: rollback steps cannot be empty", ErrInvalid)
		}
	}
	return nil
}

func validateGraphAction(record Record, input ExecutionInput) error {
	action, metadata := input.GraphAction, record.Definition.Metadata
	status := graphactions.NormalizeActionStatus(first(action.ExternalStatus, action.Status))
	if clean(action.Action) != clean(metadata.ID) || clean(action.Provider) != clean(metadata.Provider) || clean(action.Target) != clean(record.Binding.TargetID) || clean(action.IdempotencyKey) != clean(record.IdempotencyKey) || status != graphactions.ActionStatusSucceeded || clean(action.ExternalID) == "" {
		return fmt.Errorf("%w: graph action receipt does not match the approved successful action", ErrVerificationMismatch)
	}
	if action.CompletedAtUnix <= 0 || input.OccurredAt.Unix() != action.CompletedAtUnix {
		return fmt.Errorf("%w: execution occurrence time does not match provider completion", ErrStale)
	}
	for key, expected := range map[string]string{"tenant_id": record.TenantID, "subject_urn": record.Binding.SubjectURN, "resource_urn": record.Binding.ResourceURN, "source_runtime_id": record.Binding.SourceRuntimeID, "source_revision": record.Binding.SourceRevision, "definition_version": record.Definition.Version} {
		if clean(action.Metadata[key]) != clean(expected) {
			return fmt.Errorf("%w: graph action metadata %s mismatch", ErrStale, key)
		}
	}
	if clean(action.ActorSubject) == "" || clean(action.ActorSubject) != clean(input.ExecutedBy.ID) {
		return fmt.Errorf("%w: provider execution actor mismatch", ErrVerificationMismatch)
	}
	return nil
}

func validateVerification(record Record, input VerificationInput) error {
	if record.Execution == nil || record.Approval == nil {
		return fmt.Errorf("%w: execution and approval receipts are required", ErrState)
	}
	if input.ExecutionDigest != record.Execution.Digest || input.PreviousSourceRevision != record.Binding.SourceRevision || input.Binding.TargetID != record.Binding.TargetID || input.Binding.SubjectURN != record.Binding.SubjectURN || input.Binding.ResourceURN != record.Binding.ResourceURN || input.Binding.SourceRuntimeID != record.Binding.SourceRuntimeID || clean(input.Binding.ResourceRevision) == "" || clean(input.Binding.SourceRevision) == "" || input.Binding.SourceRevision == record.Binding.SourceRevision || clean(input.Binding.SubjectRevision) == "" || input.Binding.SubjectRevision == record.Binding.SubjectRevision || clean(input.ExpectedEffect) != clean(record.Definition.Metadata.Effect) {
		return fmt.Errorf("%w: verification does not bind fresh source and subject revisions", ErrStale)
	}
	if !validActor(input.Actor) || sameActor(input.Actor, record.Proposer) || sameActor(input.Actor, record.Approval.Actor) || sameActor(input.Actor, record.Execution.ExecutedBy) || sameActor(input.Actor, record.Execution.IngestedBy) {
		return ErrSeparationOfDuty
	}
	if input.VerifiedAt.IsZero() || input.VerifiedAt.Before(record.Execution.OccurredAt) || len(input.Evidence) == 0 {
		return fmt.Errorf("%w: verification time and evidence are required", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, evidence := range input.Evidence {
		if clean(evidence.ID) == "" || !validDigest(evidence.Digest) || seen[evidence.ID] {
			return fmt.Errorf("%w: verification evidence is invalid", ErrInvalid)
		}
		seen[evidence.ID] = true
	}
	return nil
}

func transition(record Record, from, to, code string, actor Actor, at time.Time) (Outcome, error) {
	previous := record.LastTransitionDigest
	record.Status, record.Digest = to, ""
	record.LastTransitionDigest = ""
	record.Digest = digestValue(record)
	receipt := TransitionReceipt{SchemaVersion: TransitionSchemaVersion, TenantID: record.TenantID, ActionID: record.ID, FromStatus: from, ToStatus: to, PreviousTransitionDigest: previous, RecordDigest: record.Digest, ResultCode: code, Actor: actor, OccurredAt: at.UTC()}
	receipt.ID = "access-transition-" + shortDigest(digestValue(receipt))
	receipt.Digest = digestValue(receipt)
	record.LastTransitionDigest = receipt.Digest
	return Outcome{Record: record, Transition: receipt, Metrics: metrics(to, code)}, nil
}

func requireState(record Record, status string) error {
	if err := VerifyRecord(record); err != nil || record.Status != status {
		return fmt.Errorf("%w: expected %s", ErrState, status)
	}
	return nil
}

// VerifyRecord checks a record without consulting a store, graph, or provider.
func VerifyRecord(record Record) error {
	if record.SchemaVersion != SchemaVersion || record.ID == "" || record.TenantID == "" || record.Digest == "" || record.Digest != recordDigest(record) {
		return fmt.Errorf("%w: record digest verification failed", ErrInvalid)
	}
	return nil
}

// VerifyTransition checks the receipt digest, deterministic ID, chained
// predecessor, and exact record state it claims to persist.
func VerifyTransition(record Record, receipt TransitionReceipt) error {
	if err := VerifyRecord(record); err != nil {
		return err
	}
	copy := receipt
	wantDigest := copy.Digest
	copy.Digest = ""
	if receipt.SchemaVersion != TransitionSchemaVersion || receipt.ActionID != record.ID || receipt.TenantID != record.TenantID || receipt.ToStatus != record.Status || receipt.RecordDigest != record.Digest || wantDigest == "" || wantDigest != digestValue(copy) || record.LastTransitionDigest != wantDigest {
		return fmt.Errorf("%w: transition receipt verification failed", ErrInvalid)
	}
	idCopy := copy
	idCopy.ID = ""
	wantID := "access-transition-" + shortDigest(digestValue(idCopy))
	if receipt.ID != wantID {
		return fmt.Errorf("%w: transition receipt id verification failed", ErrInvalid)
	}
	return nil
}

// ParametersDigest returns the canonical binding digest expected by preflight
// and execution receipts.
func ParametersDigest(parameters map[string]string) string {
	return digestValue(parameters)
}

// RollbackPlanDigest returns the canonical binding digest expected by a
// preflight receipt.
func RollbackPlanDigest(plan RollbackPlan) string {
	return digestValue(plan)
}

// GraphActionReceiptDigest returns the canonical digest for an already
// executed provider action receipt. It does not execute or query a provider.
func GraphActionReceiptDigest(action graphactions.GraphAction) string {
	return digestGraphAction(action)
}

// ProposalRecordDigest returns the original proposal digest from any valid
// lifecycle record. This lets receipt producers bind later stages without
// reproducing the lifecycle's private canonicalization rules.
func ProposalRecordDigest(record Record) (string, error) {
	if err := VerifyRecord(record); err != nil {
		return "", err
	}
	return proposalDigest(record), nil
}

func proposalDigest(record Record) string {
	copy := cloneRecord(record)
	copy.Status, copy.Preflight, copy.Approval, copy.Execution, copy.Verification = StatusProposed, nil, nil, nil, nil
	copy.Digest, copy.LastTransitionDigest = "", ""
	return digestValue(copy)
}

func recordDigest(record Record) string {
	copy := cloneRecord(record)
	copy.Digest, copy.LastTransitionDigest = "", ""
	return digestValue(copy)
}

func digestGraphAction(action graphactions.GraphAction) string { return digestValue(action) }

func digestValue(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func actionID(input ProposalInput) string {
	return "verified-access-action-" + shortDigest(digestValue([]string{clean(input.TenantID), clean(input.Definition.Metadata.ID), clean(input.Definition.Version), clean(input.Binding.SubjectURN), clean(input.Binding.ResourceURN), clean(input.Binding.SourceRevision), clean(input.IdempotencyKey)}))
}

func shortDigest(value string) string { return strings.TrimPrefix(value, "sha256:")[:32] }
func validDigest(value string) bool   { return strings.HasPrefix(value, "sha256:") && len(value) == 71 }
func clean(value string) string       { return strings.TrimSpace(value) }
func validActor(actor Actor) bool     { return clean(actor.Type) != "" && clean(actor.ID) != "" }
func human(actor Actor) bool {
	return strings.EqualFold(clean(actor.Type), "human") && clean(actor.ID) != ""
}
func sameActor(left, right Actor) bool {
	return clean(left.ID) != "" && strings.EqualFold(clean(left.Type), clean(right.Type)) && clean(left.ID) == clean(right.ID)
}
func first(values ...string) string {
	for _, value := range values {
		if clean(value) != "" {
			return value
		}
	}
	return ""
}

func cloneMap(input map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range input {
		result[key] = value
	}
	return result
}
func cloneRollback(input RollbackPlan) RollbackPlan {
	input.Parameters = cloneMap(input.Parameters)
	input.Steps = append([]string(nil), input.Steps...)
	return input
}
func cloneVerification(input VerificationInput) VerificationInput {
	input.Evidence = append([]EvidenceReference(nil), input.Evidence...)
	return input
}
func cloneRecord(input Record) Record {
	payload, _ := json.Marshal(input)
	var output Record
	_ = json.Unmarshal(payload, &output)
	return output
}

func metrics(status, code string) Metrics {
	order := map[string]int{StatusProposed: 1, StatusPreflighted: 2, StatusApproved: 3, StatusExecuted: 4, StatusClosed: 5, StatusReopened: 5}
	return Metrics{Status: status, ResultCode: code, PreflightPassed: order[status] >= 2, Approved: order[status] >= 3, ReceiptAccepted: order[status] >= 4, VerificationClosed: status == StatusClosed, Reopened: status == StatusReopened}
}
