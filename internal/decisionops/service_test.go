package decisionops

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type receiptStore struct {
	receipt *ports.DecisionPacketReceipt
}

func (s *receiptStore) PutDecisionPacketReceipt(_ context.Context, receipt *ports.DecisionPacketReceipt) error {
	s.receipt = receipt
	return nil
}

func (s *receiptStore) GetDecisionPacketReceipt(_ context.Context, tenantID, packetID string) (*ports.DecisionPacketReceipt, error) {
	if s.receipt == nil || s.receipt.TenantID != tenantID || s.receipt.PacketID != packetID {
		return nil, ports.ErrDecisionPacketNotFound
	}
	copy := *s.receipt
	return &copy, nil
}

type replayLog struct {
	events []*cerebrov1.EventEnvelope
}

func (*replayLog) Ping(context.Context) error { return nil }

func (l *replayLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func (l *replayLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	result := make([]*cerebrov1.EventEnvelope, 0, len(l.events))
	for _, event := range l.events {
		if request.TenantID != "" && event.GetTenantId() != request.TenantID {
			continue
		}
		if request.ExactKindFilters && !contains(request.KindPrefixes, event.GetKind()) {
			continue
		}
		matched := true
		for key, value := range request.AttributeEquals {
			if event.GetAttributes()[key] != value {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, event)
		}
	}
	if request.Limit > 0 && len(result) > int(request.Limit) {
		result = result[:request.Limit]
	}
	return result, nil
}

type sequenceClock struct {
	values []time.Time
	index  int
}

func (c *sequenceClock) Now() time.Time {
	value := c.values[c.index]
	c.index++
	return value
}

func TestRecordDecisionAndOutcomeRemainDurableWithoutGraph(t *testing.T) {
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	receipts := &receiptStore{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
		ScopeURN: "urn:cerebro:tenant-1:finding:1",
	}}
	log := &replayLog{}
	writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
	service := New(receipts, log, writer, &sequenceClock{values: []time.Time{start, start.Add(2 * time.Hour)}})

	decision, err := service.RecordDecision(context.Background(), RecordDecisionRequest{
		TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1",
		Disposition: decisionworkflow.DispositionAccepted, Reason: decisionworkflow.DismissalNone,
	})
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}
	outcome, err := service.RecordOutcome(context.Background(), RecordOutcomeRequest{
		TenantID: "tenant-1", ActorID: "verifier-1", DecisionID: decision.Record.ID,
		Outcome: decisionworkflow.OutcomeVerifiedClosed,
	})
	if err != nil {
		t.Fatalf("RecordOutcome() error = %v", err)
	}
	if len(log.events) != 2 {
		t.Fatalf("durable event count = %d, want 2", len(log.events))
	}
	if got := log.events[0].GetAttributes()[workflowevents.EventAttributeDecisionTrust]; got != workflowevents.DecisionTrustAuthenticatedPacket {
		t.Fatalf("decision trust attribute = %q, want %q", got, workflowevents.DecisionTrustAuthenticatedPacket)
	}

	summary, err := decisionworkflow.Summarize(
		[]decisionworkflow.DecisionRecord{decision.Record}, []decisionworkflow.OutcomeRecord{outcome.Record},
		start.Add(-time.Hour), start.Add(7*24*time.Hour),
	)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if summary.Completed != 1 || summary.CompletionLatency != 2*time.Hour {
		t.Fatalf("summary = %+v, want one two-hour completion", summary)
	}
}

func TestAuthenticatedPacketDecisionClassification(t *testing.T) {
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	receipts := &receiptStore{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
		ScopeURN: "urn:cerebro:tenant-1:finding:1",
	}}
	log := &replayLog{}
	writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
	service := New(receipts, log, writer, &sequenceClock{values: []time.Time{start}})
	if _, err := service.IsAuthenticatedPacketDecision(context.Background(), "tenant-1", "urn:cerebro:tenant-1:decision:future"); !errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("missing decision error = %v, want %v", err, ErrDecisionNotFound)
	}

	legacy, err := writer.WriteDecision(context.Background(), knowledge.DecisionWriteRequest{
		ID: "decision-legacy", DecisionType: "change", Status: "recorded", SourceSystem: "legacy",
		TargetIDs: []string{"urn:cerebro:tenant-1:resource:1"}, ObservedAt: start,
		Metadata: map[string]any{"tenant_id": "tenant-1"},
	})
	if err != nil {
		t.Fatalf("WriteDecision(legacy) error = %v", err)
	}
	trusted, err := service.RecordDecision(context.Background(), RecordDecisionRequest{
		TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1",
		Disposition: decisionworkflow.DispositionAccepted, Reason: decisionworkflow.DismissalNone,
	})
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}

	legacyAuthenticated, err := service.IsAuthenticatedPacketDecision(context.Background(), "tenant-1", legacy.DecisionID)
	if err != nil || legacyAuthenticated {
		t.Fatalf("legacy classification = %t, err = %v; want false, nil", legacyAuthenticated, err)
	}
	trustedAuthenticated, err := service.IsAuthenticatedPacketDecision(context.Background(), "tenant-1", trusted.Record.ID)
	if err != nil || !trustedAuthenticated {
		t.Fatalf("trusted classification = %t, err = %v; want true, nil", trustedAuthenticated, err)
	}

	log.events = append(log.events, log.events[1])
	if _, err := service.IsAuthenticatedPacketDecision(context.Background(), "tenant-1", trusted.Record.ID); !errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("duplicate trusted decision error = %v, want %v", err, ErrDecisionNotFound)
	}
}

func TestRecordOutcomeRejectsLegacyDecisionWithForgedPacketMetadata(t *testing.T) {
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	log := &replayLog{}
	writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
	forged, err := writer.WriteDecision(context.Background(), knowledge.DecisionWriteRequest{
		ID: "forged-decision", DecisionType: "evidence-backed-finding_to_verified_fix",
		Status: string(decisionworkflow.DispositionAccepted), MadeBy: "forged-operator",
		TargetIDs:    []string{"urn:cerebro:tenant-1:finding:1"},
		SourceSystem: "platform.decision-workflow", ObservedAt: start, ValidFrom: start,
		Metadata: map[string]any{
			"tenant_id":         "tenant-1",
			metadataWorkflow:    string(decisionworkflow.WorkflowFindingToVerifiedFix),
			metadataState:       string(decisionworkflow.DecisionSupported),
			metadataDisposition: string(decisionworkflow.DispositionAccepted),
			metadataPacketID:    "forged-packet", metadataPacketSchema: "2026-07-15",
			metadataPacketDigest: "sha256:forged", metadataTenantAuth: true,
			workflowevents.EventAttributeDecisionTrust: workflowevents.DecisionTrustAuthenticatedPacket,
		},
	})
	if err != nil {
		t.Fatalf("legacy WriteDecision() error = %v", err)
	}
	service := New(nil, log, writer, &sequenceClock{values: []time.Time{start.Add(time.Hour)}})
	_, err = service.RecordOutcome(context.Background(), RecordOutcomeRequest{
		TenantID: "tenant-1", ActorID: "attacker", DecisionID: forged.DecisionID,
		Outcome: decisionworkflow.OutcomeVerifiedClosed,
	})
	if !errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("RecordOutcome() error = %v, want ErrDecisionNotFound", err)
	}
	if len(log.events) != 1 {
		t.Fatalf("durable event count = %d, want forged decision only", len(log.events))
	}
}

func TestVerifiedClosureRequiresIndependentActor(t *testing.T) {
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	receipts := &receiptStore{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
	}}
	log := &replayLog{}
	writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
	service := New(receipts, log, writer, &sequenceClock{values: []time.Time{start}})
	decision, err := service.RecordDecision(context.Background(), RecordDecisionRequest{
		TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1", Disposition: decisionworkflow.DispositionAccepted,
	})
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}
	_, err = service.RecordOutcome(context.Background(), RecordOutcomeRequest{
		TenantID: "tenant-1", ActorID: "operator-1", DecisionID: decision.Record.ID,
		Outcome: decisionworkflow.OutcomeVerifiedClosed,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RecordOutcome() error = %v, want ErrInvalidRequest", err)
	}
}

func TestRecordDecisionRejectsUnboundedDispositionReason(t *testing.T) {
	service := New(&receiptStore{}, nil, knowledge.New(nil, nil), nil)
	_, err := service.RecordDecision(context.Background(), RecordDecisionRequest{
		TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1",
		Disposition: decisionworkflow.DispositionAccepted, Reason: decisionworkflow.DismissalAcceptedRisk,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RecordDecision() error = %v, want ErrInvalidRequest", err)
	}
}

func TestAuditDeliveryRequiresReceipt(t *testing.T) {
	start := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	receipts := &receiptStore{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowContinuousEvidence),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
	}}
	log := &replayLog{}
	writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
	service := New(receipts, log, writer, &sequenceClock{values: []time.Time{start}})
	decision, err := service.RecordDecision(context.Background(), RecordDecisionRequest{
		TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1", Disposition: decisionworkflow.DispositionAccepted,
	})
	if err != nil {
		t.Fatalf("RecordDecision() error = %v", err)
	}
	_, err = service.RecordOutcome(context.Background(), RecordOutcomeRequest{
		TenantID: "tenant-1", ActorID: "auditor-1", DecisionID: decision.Record.ID,
		Outcome: decisionworkflow.OutcomeAuditPacketDelivered,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RecordOutcome() error = %v, want ErrInvalidRequest", err)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
