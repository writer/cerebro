// Package decisionops records authenticated packet dispositions and terminal
// outcomes through Cerebro's append-first knowledge workflow.
package decisionops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var (
	ErrRuntimeUnavailable = errors.New("decision outcome runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid decision outcome request")
	ErrDecisionNotFound   = errors.New("durable decision not found")
)

const (
	metadataWorkflow       = "decision_workflow"
	metadataState          = "decision_state"
	metadataDisposition    = "decision_disposition"
	metadataDispositionWhy = "decision_disposition_reason"
	metadataPacketID       = "packet_id"
	metadataPacketSchema   = "packet_schema_version"
	metadataPacketDigest   = "packet_digest"
	metadataTenantAuth     = "authenticated_tenant"
	metadataAuditReceipt   = "audit_packet_export_receipt_id"
)

type knowledgeWriter interface {
	WriteAuthenticatedPacketDecision(context.Context, knowledge.DecisionWriteRequest) (*knowledge.DecisionWriteResult, error)
	WriteOutcome(context.Context, knowledge.OutcomeWriteRequest) (*knowledge.OutcomeWriteResult, error)
}

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type Service struct {
	receipts      ports.DecisionPacketReceiptStore
	replayer      ports.EventReplayer
	writer        knowledgeWriter
	clock         Clock
	auditVerifier AuditDeliveryVerifier
}

type AuditDeliveryVerifier interface {
	VerifyAuditPacketExportReceipt(context.Context, string, string) error
}

func New(receipts ports.DecisionPacketReceiptStore, replayer ports.EventReplayer, writer knowledgeWriter, clock Clock) *Service {
	if clock == nil {
		clock = systemClock{}
	}
	return &Service{receipts: receipts, replayer: replayer, writer: writer, clock: clock}
}

func (s *Service) WithAuditDeliveryVerifier(verifier AuditDeliveryVerifier) *Service {
	if s != nil {
		s.auditVerifier = verifier
	}
	return s
}

type RecordDecisionRequest struct {
	TenantID    string
	ActorID     string
	PacketID    string
	Disposition decisionworkflow.Disposition
	Reason      decisionworkflow.DismissalReason
}

type RecordDecisionResult struct {
	Record decisionworkflow.DecisionRecord
	Write  knowledge.DecisionWriteResult
}

func (s *Service) RecordDecision(ctx context.Context, request RecordDecisionRequest) (RecordDecisionResult, error) {
	if s == nil || s.receipts == nil || s.writer == nil {
		return RecordDecisionResult{}, ErrRuntimeUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.PacketID = strings.TrimSpace(request.PacketID)
	if request.TenantID == "" || request.ActorID == "" || request.PacketID == "" || !validDisposition(request.Disposition) {
		return RecordDecisionResult{}, ErrInvalidRequest
	}
	if request.Reason == "" {
		request.Reason = decisionworkflow.DismissalNone
	}
	if !validReason(request.Disposition, request.Reason) {
		return RecordDecisionResult{}, ErrInvalidRequest
	}
	receipt, err := s.receipts.GetDecisionPacketReceipt(ctx, request.TenantID, request.PacketID)
	if err != nil {
		return RecordDecisionResult{}, err
	}
	if receipt == nil || strings.TrimSpace(receipt.TenantID) != request.TenantID || strings.TrimSpace(receipt.PacketID) != request.PacketID ||
		strings.TrimSpace(receipt.SchemaVersion) == "" || strings.TrimSpace(receipt.PacketDigest) == "" {
		return RecordDecisionResult{}, fmt.Errorf("%w: incomplete packet receipt", ErrInvalidRequest)
	}
	workflow, err := decisionworkflow.ParseWorkflow(receipt.Workflow)
	if err != nil {
		return RecordDecisionResult{}, fmt.Errorf("%w: receipt workflow", ErrInvalidRequest)
	}
	state, err := decisionworkflow.ParseDecisionState(receipt.DecisionState)
	if err != nil {
		return RecordDecisionResult{}, fmt.Errorf("%w: receipt decision state", ErrInvalidRequest)
	}
	recordedAt := s.clock.Now().UTC()
	target := strings.TrimSpace(receipt.ScopeURN)
	if target == "" {
		target = "urn:cerebro:" + request.TenantID + ":decision_packet:" + request.PacketID
	} else if !strings.HasPrefix(target, "urn:cerebro:"+request.TenantID+":") {
		return RecordDecisionResult{}, fmt.Errorf("%w: packet scope tenant", ErrInvalidRequest)
	}
	metadata := map[string]any{
		"tenant_id":      request.TenantID,
		metadataWorkflow: string(workflow), metadataState: string(state),
		metadataDisposition: string(request.Disposition), metadataDispositionWhy: string(request.Reason),
		metadataPacketID: receipt.PacketID, metadataPacketSchema: receipt.SchemaVersion,
		metadataPacketDigest: receipt.PacketDigest, metadataTenantAuth: true,
	}
	result, err := s.writer.WriteAuthenticatedPacketDecision(ctx, knowledge.DecisionWriteRequest{
		ID:           request.PacketID + ":" + string(request.Disposition),
		DecisionType: "evidence-backed-" + string(workflow), Status: string(request.Disposition),
		MadeBy: request.ActorID, TargetIDs: []string{target}, EvidenceIDs: []string{receipt.PacketID},
		SourceSystem: "platform.decision-workflow", ObservedAt: recordedAt, ValidFrom: recordedAt,
		Metadata: metadata,
	})
	if err != nil {
		return RecordDecisionResult{}, err
	}
	if result.DurabilityStatus != knowledge.DurabilityRecorded {
		return RecordDecisionResult{}, ErrRuntimeUnavailable
	}
	outcome := dispositionOutcome(request.Disposition)
	metrics := observability.DecisionMetrics{Workflow: workflow, DecisionState: state, Outcome: outcome}
	if !receipt.CreatedAt.IsZero() && !recordedAt.Before(receipt.CreatedAt) {
		metrics.Duration = recordedAt.Sub(receipt.CreatedAt)
		metrics.HasDuration = true
	}
	observability.RecordDecisionOutcome(ctx, metrics, decisionworkflow.Completion{
		Workflow: workflow, DecisionID: result.DecisionID, DecisionState: state, Outcome: outcome,
		AuthenticatedTenant: true, Durable: true,
	})
	return RecordDecisionResult{
		Record: decisionworkflow.DecisionRecord{
			ID: result.DecisionID, TenantID: request.TenantID, Workflow: workflow, State: state,
			Disposition: request.Disposition, RecordedAt: recordedAt,
			AuthenticatedTenant: true, Durable: true,
		},
		Write: *result,
	}, nil
}

type RecordOutcomeRequest struct {
	TenantID                   string
	ActorID                    string
	DecisionID                 string
	Outcome                    decisionworkflow.Outcome
	AuditPacketExportReceiptID string
}

type RecordOutcomeResult struct {
	Record decisionworkflow.OutcomeRecord
	Write  knowledge.OutcomeWriteResult
}

type RecordPacketOutcomeRequest struct {
	TenantID                   string
	ActorID                    string
	DecisionID                 string
	OutcomeType                string
	AuditPacketExportReceiptID string
}

// RecordPacketOutcome records an outcome only when the durable decision belongs
// to the authenticated packet workflow. The handled result is false for a
// single durable legacy decision and true for a packet decision.
func (s *Service) RecordPacketOutcome(ctx context.Context, request RecordPacketOutcomeRequest) (RecordOutcomeResult, bool, error) {
	packetDecision, err := s.IsAuthenticatedPacketDecision(ctx, request.TenantID, request.DecisionID)
	if err != nil || !packetDecision {
		return RecordOutcomeResult{}, false, err
	}
	outcome := decisionworkflow.NormalizeOutcome(request.OutcomeType)
	if outcome == decisionworkflow.OutcomeUnknown || outcome == decisionworkflow.OutcomeNone {
		return RecordOutcomeResult{}, true, ErrInvalidRequest
	}
	result, err := s.RecordOutcome(ctx, RecordOutcomeRequest{
		TenantID: request.TenantID, ActorID: request.ActorID, DecisionID: request.DecisionID, Outcome: outcome,
		AuditPacketExportReceiptID: request.AuditPacketExportReceiptID,
	})
	return result, true, err
}

// IsAuthenticatedPacketDecision reports whether the durable decision was
// created through the authenticated packet workflow. A malformed decision that
// carries the server-only trust marker fails closed instead of falling back to
// the legacy outcome path.
func (s *Service) IsAuthenticatedPacketDecision(ctx context.Context, tenantID, decisionID string) (bool, error) {
	if s == nil || s.replayer == nil {
		return false, ErrRuntimeUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return false, ErrInvalidRequest
	}
	events, err := s.replayDecisionEvents(ctx, tenantID, decisionID)
	if err != nil {
		return false, err
	}
	if len(events) != 1 {
		return false, ErrDecisionNotFound
	}
	if events[0].GetAttributes()[workflowevents.EventAttributeDecisionTrust] != workflowevents.DecisionTrustAuthenticatedPacket {
		return false, nil
	}
	if _, err := resolveDecision(events, tenantID, decisionID); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) RecordOutcome(ctx context.Context, request RecordOutcomeRequest) (RecordOutcomeResult, error) {
	if s == nil || s.replayer == nil || s.writer == nil {
		return RecordOutcomeResult{}, ErrRuntimeUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ActorID = strings.TrimSpace(request.ActorID)
	request.DecisionID = strings.TrimSpace(request.DecisionID)
	request.AuditPacketExportReceiptID = strings.TrimSpace(request.AuditPacketExportReceiptID)
	if request.TenantID == "" || request.ActorID == "" || request.DecisionID == "" || !terminalOutcome(request.Outcome) {
		return RecordOutcomeResult{}, ErrInvalidRequest
	}
	resolved, err := s.loadDecision(ctx, request.TenantID, request.DecisionID)
	if err != nil {
		return RecordOutcomeResult{}, err
	}
	if request.Outcome == decisionworkflow.OutcomeVerifiedClosed && request.ActorID == resolved.ActorID {
		return RecordOutcomeResult{}, fmt.Errorf("%w: verified closure requires an independent actor", ErrInvalidRequest)
	}
	if request.Outcome == decisionworkflow.OutcomeAuditPacketDelivered {
		if request.AuditPacketExportReceiptID == "" {
			return RecordOutcomeResult{}, ErrInvalidRequest
		}
		if s.auditVerifier == nil {
			return RecordOutcomeResult{}, ErrRuntimeUnavailable
		}
		if err := s.auditVerifier.VerifyAuditPacketExportReceipt(ctx, request.TenantID, request.AuditPacketExportReceiptID); err != nil {
			return RecordOutcomeResult{}, err
		}
	}
	recordedAt := s.clock.Now().UTC()
	metadata := map[string]any{
		"tenant_id": request.TenantID, metadataWorkflow: string(resolved.Record.Workflow),
		metadataState: string(resolved.Record.State), metadataDisposition: string(resolved.Record.Disposition),
		metadataTenantAuth: true, "outcome_recorded_by": request.ActorID,
	}
	if request.AuditPacketExportReceiptID != "" {
		metadata[metadataAuditReceipt] = request.AuditPacketExportReceiptID
	}
	result, err := s.writer.WriteOutcome(ctx, knowledge.OutcomeWriteRequest{
		ID: request.DecisionID + ":" + string(request.Outcome), DecisionID: request.DecisionID,
		OutcomeType: string(request.Outcome), Verdict: string(request.Outcome), TargetIDs: resolved.Targets,
		SourceSystem: "platform.decision-workflow", ObservedAt: recordedAt, ValidFrom: recordedAt,
		Metadata: metadata,
	})
	if err != nil {
		return RecordOutcomeResult{}, err
	}
	if result.DurabilityStatus != knowledge.DurabilityRecorded {
		return RecordOutcomeResult{}, ErrRuntimeUnavailable
	}
	metrics := observability.DecisionMetrics{
		Workflow: resolved.Record.Workflow, DecisionState: resolved.Record.State, Outcome: request.Outcome,
	}
	if !resolved.Record.RecordedAt.IsZero() && !recordedAt.Before(resolved.Record.RecordedAt) {
		metrics.Duration = recordedAt.Sub(resolved.Record.RecordedAt)
		metrics.HasDuration = true
	}
	observability.RecordDecisionOutcome(ctx, metrics, decisionworkflow.Completion{
		Workflow: resolved.Record.Workflow, DecisionID: result.DecisionID, DecisionState: resolved.Record.State,
		Outcome: request.Outcome, AuthenticatedTenant: true, Durable: true,
		Reopened:                   request.Outcome == decisionworkflow.OutcomeReopened,
		AuditPacketExportReceiptID: request.AuditPacketExportReceiptID,
	})
	return RecordOutcomeResult{
		Record: decisionworkflow.OutcomeRecord{
			ID: result.OutcomeID, DecisionID: result.DecisionID, Outcome: request.Outcome,
			RecordedAt: recordedAt, AuditPacketExportReceiptID: request.AuditPacketExportReceiptID,
		},
		Write: *result,
	}, nil
}

type resolvedDecision struct {
	Record  decisionworkflow.DecisionRecord
	Targets []string
	ActorID string
}

func (s *Service) loadDecision(ctx context.Context, tenantID, decisionID string) (resolvedDecision, error) {
	events, err := s.replayDecisionEvents(ctx, tenantID, decisionID)
	if err != nil {
		return resolvedDecision{}, err
	}
	return resolveDecision(events, tenantID, decisionID)
}

func (s *Service) replayDecisionEvents(ctx context.Context, tenantID, decisionID string) ([]*cerebrov1.EventEnvelope, error) {
	return s.replayer.Replay(ctx, ports.ReplayRequest{
		KindPrefixes: []string{workflowevents.EventKindKnowledgeDecisionRecorded}, ExactKindFilters: true,
		TenantID: tenantID, AttributeEquals: map[string]string{workflowevents.EventAttributeDecisionID: decisionID}, Limit: 2,
	})
}

func resolveDecision(events []*cerebrov1.EventEnvelope, tenantID, decisionID string) (resolvedDecision, error) {
	if len(events) != 1 {
		return resolvedDecision{}, ErrDecisionNotFound
	}
	if events[0].GetAttributes()[workflowevents.EventAttributeDecisionTrust] != workflowevents.DecisionTrustAuthenticatedPacket {
		return resolvedDecision{}, ErrDecisionNotFound
	}
	payload, err := workflowevents.DecodeDecisionRecorded(events[0])
	if err != nil || payload.TenantID != tenantID || payload.DecisionID != decisionID {
		return resolvedDecision{}, ErrDecisionNotFound
	}
	workflow, workflowOK := metadataString(payload.Metadata, metadataWorkflow)
	stateValue, stateOK := metadataString(payload.Metadata, metadataState)
	dispositionValue, dispositionOK := metadataString(payload.Metadata, metadataDisposition)
	_, packetOK := metadataString(payload.Metadata, metadataPacketID)
	_, packetSchemaOK := metadataString(payload.Metadata, metadataPacketSchema)
	_, packetDigestOK := metadataString(payload.Metadata, metadataPacketDigest)
	authenticated, authOK := payload.Metadata[metadataTenantAuth].(bool)
	workflowParsed, workflowErr := decisionworkflow.ParseWorkflow(workflow)
	state, stateErr := decisionworkflow.ParseDecisionState(stateValue)
	disposition := decisionworkflow.Disposition(dispositionValue)
	if !workflowOK || !stateOK || !dispositionOK || !packetOK || !packetSchemaOK || !packetDigestOK ||
		!authOK || !authenticated || workflowErr != nil || stateErr != nil || !validDisposition(disposition) {
		return resolvedDecision{}, ErrDecisionNotFound
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, payload.ObservedAt)
	if err != nil {
		return resolvedDecision{}, ErrDecisionNotFound
	}
	return resolvedDecision{
		Record: decisionworkflow.DecisionRecord{
			ID: decisionID, TenantID: tenantID, Workflow: workflowParsed, State: state, Disposition: disposition,
			RecordedAt: recordedAt, AuthenticatedTenant: true, Durable: true,
		},
		Targets: append([]string(nil), payload.TargetIDs...), ActorID: strings.TrimSpace(payload.MadeBy),
	}, nil
}

func metadataString(metadata map[string]any, key string) (string, bool) {
	value, ok := metadata[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func validDisposition(value decisionworkflow.Disposition) bool {
	return value == decisionworkflow.DispositionAccepted || value == decisionworkflow.DispositionRejected || value == decisionworkflow.DispositionDeferred
}

func validReason(disposition decisionworkflow.Disposition, reason decisionworkflow.DismissalReason) bool {
	if disposition == decisionworkflow.DispositionAccepted {
		return reason == decisionworkflow.DismissalNone
	}
	switch reason {
	case decisionworkflow.DismissalNotRelevant, decisionworkflow.DismissalInsufficientEvidence,
		decisionworkflow.DismissalDuplicate, decisionworkflow.DismissalAcceptedRisk, decisionworkflow.DismissalOther:
		return true
	default:
		return false
	}
}

func terminalOutcome(value decisionworkflow.Outcome) bool {
	switch value {
	case decisionworkflow.OutcomeAccepted, decisionworkflow.OutcomeRejected, decisionworkflow.OutcomeDeferred,
		decisionworkflow.OutcomeVerifiedClosed, decisionworkflow.OutcomeAuditPacketDelivered,
		decisionworkflow.OutcomeFailed, decisionworkflow.OutcomeReopened:
		return true
	default:
		return false
	}
}

func dispositionOutcome(value decisionworkflow.Disposition) decisionworkflow.Outcome {
	switch value {
	case decisionworkflow.DispositionAccepted:
		return decisionworkflow.OutcomeAccepted
	case decisionworkflow.DispositionRejected:
		return decisionworkflow.OutcomeRejected
	case decisionworkflow.DispositionDeferred:
		return decisionworkflow.OutcomeDeferred
	default:
		return decisionworkflow.OutcomeUnknown
	}
}
