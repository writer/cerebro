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
