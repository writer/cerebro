package prototransport

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionpacket"
)

func Packet(packet *decisionpacket.Packet) (*cerebrov1.DecisionPacket, error) {
	if packet == nil {
		return nil, fmt.Errorf("decision packet is required")
	}
	guardrails, err := decisionPacketStruct(packet.Guardrails)
	if err != nil {
		return nil, err
	}
	claim, err := decisionPacketStruct(packet.Claim)
	if err != nil {
		return nil, err
	}
	result := &cerebrov1.DecisionPacket{
		SchemaVersion: packet.SchemaVersion, Id: packet.ID, GeneratedAt: decisionPacketTimestamp(packet.GeneratedAt),
		Workflow:   &cerebrov1.DecisionPacketWorkflow{Id: packet.Workflow.ID, Question: packet.Workflow.Question},
		Scope:      &cerebrov1.DecisionPacketScope{TenantId: packet.Scope.TenantID, ActorId: packet.Scope.ActorID, Urn: packet.Scope.URN},
		Guardrails: guardrails, Claim: claim,
		Decision:   &cerebrov1.DecisionPacketDecision{State: packet.Decision.State, Rationale: packet.Decision.Rationale, Reasons: packet.Decision.Reasons},
		Confidence: &cerebrov1.DecisionPacketConfidence{Level: packet.Confidence.Level, Basis: packet.Confidence.Basis},
		Freshness: &cerebrov1.DecisionPacketFreshness{
			State: packet.Freshness.State, OldestObservedAt: decisionPacketTimestamp(packet.Freshness.OldestObservedAt),
			NewestObservedAt: decisionPacketTimestamp(packet.Freshness.NewestObservedAt), RequiredStale: packet.Freshness.RequiredStale,
		},
		Provenance: &cerebrov1.DecisionPacketProvenance{
			TraceId: packet.Provenance.TraceID, ResolverIds: packet.Provenance.ResolverIDs,
			SourceIds: packet.Provenance.SourceIDs, EvidenceDigest: packet.Provenance.EvidenceDigest,
			CoverageDigest: packet.Provenance.CoverageDigest,
		},
		Limits: decisionPacketLimitsProto(packet.Limits),
	}
	for _, value := range packet.Evidence {
		result.Evidence = append(result.Evidence, decisionPacketEvidenceProto(value))
	}
	for _, value := range packet.Contradictions {
		result.Contradictions = append(result.Contradictions, &cerebrov1.DecisionPacketContradiction{
			Id: value.ID, SubjectUrn: value.SubjectURN, Predicate: value.Predicate,
			Left: decisionPacketEvidenceProto(value.Left), Right: decisionPacketEvidenceProto(value.Right),
			ResolutionState: value.ResolutionState, PrimaryClaim: value.PrimaryClaim,
		})
	}
	for _, value := range packet.CoverageGaps {
		result.CoverageGaps = append(result.CoverageGaps, &cerebrov1.DecisionPacketCoverageGap{
			Id: value.ID, SourceId: value.SourceID, Dimension: value.Dimension, State: value.State,
			Required: value.Required, CouldChangeConclusion: value.CouldChangeConclusion, Reason: value.Reason,
		})
	}
	for _, value := range packet.Affected {
		result.Affected = append(result.Affected, &cerebrov1.DecisionPacketSubjectReference{Urn: value.URN, Kind: value.Kind, Name: value.Name})
	}
	for _, value := range packet.Controls {
		result.Controls = append(result.Controls, &cerebrov1.DecisionPacketControlReference{Id: value.ID, Framework: value.Framework, Applicability: value.Applicability})
	}
	for _, value := range packet.AuditPackets {
		result.AuditPackets = append(result.AuditPackets, &cerebrov1.DecisionPacketAuditPacketReference{
			Id: value.ID, ScopeUrn: value.ScopeURN, Digest: value.Digest,
			GeneratedAt: decisionPacketTimestamp(value.GeneratedAt), Freshness: value.Freshness,
		})
	}
	for _, value := range packet.Actions {
		result.Actions = append(result.Actions, &cerebrov1.DecisionPacketActionProposal{
			Id: value.ID, ActionId: value.ActionID, State: value.State, TargetUrns: value.TargetURNs,
			Rationale: value.Rationale, ApprovalRequirements: value.ApprovalRequirements,
			CatalogVersion: value.CatalogVersion, ProposalDigest: value.ProposalDigest,
		})
	}
	return result, nil
}

func decisionPacketStruct(value any) (*structpb.Struct, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	result := &structpb.Struct{}
	if err := protojson.Unmarshal(encoded, result); err != nil {
		return nil, fmt.Errorf("convert decision packet value: %w", err)
	}
	return result, nil
}

func decisionPacketEvidenceProto(value decisionpacket.EvidenceReference) *cerebrov1.DecisionPacketEvidenceReference {
	return &cerebrov1.DecisionPacketEvidenceReference{
		Id: value.ID, Urn: value.URN, Kind: value.Kind, SourceId: value.SourceID,
		SubjectUrn: value.SubjectURN, Predicate: value.Predicate, Value: value.Value,
		ObservedAt: decisionPacketTimestamp(value.ObservedAt), ValidFrom: decisionPacketTimestamp(value.ValidFrom),
		ValidTo: decisionPacketTimestamp(value.ValidTo), Digest: value.Digest,
	}
}

func decisionPacketLimitsProto(value decisionpacket.ResultLimits) *cerebrov1.DecisionPacketResultLimits {
	return &cerebrov1.DecisionPacketResultLimits{
		Evidence: decisionPacketLimitProto(value.Evidence), Contradictions: decisionPacketLimitProto(value.Contradictions),
		CoverageGaps: decisionPacketLimitProto(value.CoverageGaps), Affected: decisionPacketLimitProto(value.Affected),
		Controls: decisionPacketLimitProto(value.Controls), AuditPackets: decisionPacketLimitProto(value.AuditPackets),
		Actions: decisionPacketLimitProto(value.Actions), GraphRows: decisionPacketLimitProto(value.GraphRows),
		GraphDepth: decisionPacketLimitProto(value.GraphDepth),
	}
}

func decisionPacketLimitProto(value decisionpacket.ResultLimit) *cerebrov1.DecisionPacketResultLimit {
	return &cerebrov1.DecisionPacketResultLimit{
		Requested: decisionPacketUint32(value.Requested), Applied: decisionPacketUint32(value.Applied), Returned: decisionPacketUint32(value.Returned),
		TotalKnown: decisionPacketUint32(value.TotalKnown), Truncated: value.Truncated,
	}
}

func decisionPacketUint32(value int) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value) // #nosec G115 -- the value is bounded above and below before conversion.
}

func decisionPacketTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}
