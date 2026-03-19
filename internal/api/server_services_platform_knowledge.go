package api

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graph/knowledge"
)

var (
	errPlatformKnowledgeUnavailable          = errors.New("graph platform not initialized")
	errPlatformKnowledgeSnapshotsUnavailable = errors.New("graph snapshot store not configured")
)

// platformKnowledgeService narrows the handler dependency surface to the
// platform-knowledge reads and adjudication flow consumed by the API layer.
type platformKnowledgeService interface {
	QueryClaims(ctx context.Context, opts knowledge.ClaimQueryOptions) (knowledge.ClaimCollection, error)
	QueryEvidence(ctx context.Context, opts knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error)
	QueryObservations(ctx context.Context, opts knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error)
	GetClaim(ctx context.Context, claimID string, validAt, recordedAt time.Time) (knowledge.ClaimRecord, bool, error)
	GetEvidence(ctx context.Context, evidenceID string, validAt, recordedAt time.Time) (knowledge.KnowledgeArtifactRecord, bool, error)
	GetObservation(ctx context.Context, observationID string, validAt, recordedAt time.Time) (knowledge.KnowledgeArtifactRecord, bool, error)
	QueryClaimGroups(ctx context.Context, opts knowledge.ClaimGroupQueryOptions) (knowledge.ClaimGroupCollection, error)
	GetClaimGroup(ctx context.Context, groupID string, validAt, recordedAt time.Time, includeResolved bool) (knowledge.ClaimGroupRecord, bool, error)
	GetClaimTimeline(ctx context.Context, claimID string, opts knowledge.ClaimTimelineOptions) (knowledge.ClaimTimeline, bool, error)
	ExplainClaim(ctx context.Context, claimID string, validAt, recordedAt time.Time) (knowledge.ClaimExplanation, bool, error)
	BuildClaimProofs(ctx context.Context, claimID string, opts knowledge.ClaimProofOptions) (knowledge.ClaimProofCollection, bool, error)
	DiffClaims(ctx context.Context, opts knowledge.ClaimDiffQueryOptions) (knowledge.ClaimDiffCollection, error)
	DiffKnowledge(ctx context.Context, opts knowledge.KnowledgeDiffQueryOptions) (knowledge.KnowledgeDiffCollection, error)
	AdjudicateClaimGroup(ctx context.Context, req knowledge.ClaimAdjudicationWriteRequest) (knowledge.ClaimAdjudicationWriteResult, error)
}

type serverPlatformKnowledgeService struct {
	deps *serverDependencies
}

func newPlatformKnowledgeService(deps *serverDependencies) platformKnowledgeService {
	return serverPlatformKnowledgeService{deps: deps}
}

func (s serverPlatformKnowledgeService) QueryClaims(ctx context.Context, opts knowledge.ClaimQueryOptions) (knowledge.ClaimCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimCollection{}, err
	}
	return knowledge.QueryClaims(g, opts), nil
}

func (s serverPlatformKnowledgeService) QueryEvidence(ctx context.Context, opts knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.KnowledgeArtifactCollection{}, err
	}
	return knowledge.QueryEvidence(g, opts), nil
}

func (s serverPlatformKnowledgeService) QueryObservations(ctx context.Context, opts knowledge.KnowledgeArtifactQueryOptions) (knowledge.KnowledgeArtifactCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.KnowledgeArtifactCollection{}, err
	}
	return knowledge.QueryObservations(g, opts), nil
}

func (s serverPlatformKnowledgeService) GetClaim(ctx context.Context, claimID string, validAt, recordedAt time.Time) (knowledge.ClaimRecord, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimRecord{}, false, err
	}
	record, ok := knowledge.GetClaimRecord(g, claimID, validAt, recordedAt)
	return record, ok, nil
}

func (s serverPlatformKnowledgeService) GetEvidence(ctx context.Context, evidenceID string, validAt, recordedAt time.Time) (knowledge.KnowledgeArtifactRecord, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.KnowledgeArtifactRecord{}, false, err
	}
	record, ok := knowledge.GetEvidenceRecord(g, evidenceID, validAt, recordedAt)
	return record, ok, nil
}

func (s serverPlatformKnowledgeService) GetObservation(ctx context.Context, observationID string, validAt, recordedAt time.Time) (knowledge.KnowledgeArtifactRecord, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.KnowledgeArtifactRecord{}, false, err
	}
	record, ok := knowledge.GetObservationRecord(g, observationID, validAt, recordedAt)
	return record, ok, nil
}

func (s serverPlatformKnowledgeService) QueryClaimGroups(ctx context.Context, opts knowledge.ClaimGroupQueryOptions) (knowledge.ClaimGroupCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimGroupCollection{}, err
	}
	return knowledge.QueryClaimGroups(g, opts), nil
}

func (s serverPlatformKnowledgeService) GetClaimGroup(ctx context.Context, groupID string, validAt, recordedAt time.Time, includeResolved bool) (knowledge.ClaimGroupRecord, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimGroupRecord{}, false, err
	}
	record, ok := knowledge.GetClaimGroupRecord(g, groupID, validAt, recordedAt, includeResolved)
	return record, ok, nil
}

func (s serverPlatformKnowledgeService) GetClaimTimeline(ctx context.Context, claimID string, opts knowledge.ClaimTimelineOptions) (knowledge.ClaimTimeline, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimTimeline{}, false, err
	}
	timeline, ok := knowledge.GetClaimTimeline(g, claimID, opts)
	return timeline, ok, nil
}

func (s serverPlatformKnowledgeService) ExplainClaim(ctx context.Context, claimID string, validAt, recordedAt time.Time) (knowledge.ClaimExplanation, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimExplanation{}, false, err
	}
	explanation, ok := knowledge.ExplainClaim(g, claimID, validAt, recordedAt)
	return explanation, ok, nil
}

func (s serverPlatformKnowledgeService) BuildClaimProofs(ctx context.Context, claimID string, opts knowledge.ClaimProofOptions) (knowledge.ClaimProofCollection, bool, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimProofCollection{}, false, err
	}
	proofs, ok := knowledge.BuildClaimProofs(g, claimID, opts)
	return proofs, ok, nil
}

func (s serverPlatformKnowledgeService) DiffClaims(ctx context.Context, opts knowledge.ClaimDiffQueryOptions) (knowledge.ClaimDiffCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.ClaimDiffCollection{}, err
	}
	return knowledge.DiffClaims(g, opts), nil
}

func (s serverPlatformKnowledgeService) DiffKnowledge(ctx context.Context, opts knowledge.KnowledgeDiffQueryOptions) (knowledge.KnowledgeDiffCollection, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return knowledge.KnowledgeDiffCollection{}, err
	}

	fromGraph := g
	toGraph := g
	if opts.FromSnapshotID != "" || opts.ToSnapshotID != "" {
		store := s.snapshotStore()
		if store == nil {
			return knowledge.KnowledgeDiffCollection{}, errPlatformKnowledgeSnapshotsUnavailable
		}
		snapshots, records, err := store.LoadSnapshotsByRecordIDs(opts.FromSnapshotID, opts.ToSnapshotID)
		if err != nil {
			return knowledge.KnowledgeDiffCollection{}, err
		}
		fromGraph = s.scopeGraph(ctx, graph.GraphViewFromSnapshot(snapshots[opts.FromSnapshotID]))
		toGraph = s.scopeGraph(ctx, graph.GraphViewFromSnapshot(snapshots[opts.ToSnapshotID]))
		opts.FromValidAt = snapshotKnowledgeComparisonTime(snapshots[opts.FromSnapshotID], records[opts.FromSnapshotID])
		opts.FromRecordedAt = opts.FromValidAt
		opts.ToValidAt = snapshotKnowledgeComparisonTime(snapshots[opts.ToSnapshotID], records[opts.ToSnapshotID])
		opts.ToRecordedAt = opts.ToValidAt
	}

	return knowledge.DiffKnowledgeGraphs(fromGraph, toGraph, opts), nil
}

func (s serverPlatformKnowledgeService) AdjudicateClaimGroup(ctx context.Context, req knowledge.ClaimAdjudicationWriteRequest) (knowledge.ClaimAdjudicationWriteResult, error) {
	req.GroupID = strings.TrimSpace(req.GroupID)
	if tenantID := currentTenantScopeID(ctx); tenantID != "" {
		scoped, err := s.tenantGraph(ctx)
		if err != nil {
			return knowledge.ClaimAdjudicationWriteResult{}, err
		}
		if _, ok := knowledge.GetClaimGroupRecord(scoped, req.GroupID, time.Time{}, time.Time{}, true); !ok {
			return knowledge.ClaimAdjudicationWriteResult{}, errors.New("claim group not found")
		}
	}
	var result knowledge.ClaimAdjudicationWriteResult
	if _, err := s.mutate(ctx, func(g *graph.Graph) error {
		writeResult, err := knowledge.AdjudicateClaimGroup(g, req)
		if err != nil {
			return err
		}
		result = writeResult
		return nil
	}); err != nil {
		return knowledge.ClaimAdjudicationWriteResult{}, err
	}
	return result, nil
}

func (s serverPlatformKnowledgeService) tenantGraph(ctx context.Context) (*graph.Graph, error) {
	if s.deps == nil {
		return nil, errPlatformKnowledgeUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	view, err := currentOrStoredGraphView(ctx, s.deps.CurrentSecurityGraphForTenant(tenantID), s.deps.CurrentSecurityGraphStoreForTenant(tenantID))
	if err != nil {
		return nil, errPlatformKnowledgeUnavailable
	}
	return view, nil
}

func (s serverPlatformKnowledgeService) snapshotStore() *graph.GraphPersistenceStore {
	if s.deps == nil {
		return nil
	}
	return s.deps.PlatformGraphSnapshotStore()
}

func (s serverPlatformKnowledgeService) mutate(ctx context.Context, mutate func(*graph.Graph) error) (*graph.Graph, error) {
	if s.deps == nil || s.deps.graphMutator == nil {
		return nil, errPlatformKnowledgeUnavailable
	}
	return s.deps.MutateSecurityGraph(ctx, mutate)
}

func (s serverPlatformKnowledgeService) scopeGraph(ctx context.Context, g *graph.Graph) *graph.Graph {
	if g == nil {
		return nil
	}
	if tenantID := currentTenantScopeID(ctx); tenantID != "" {
		return g.SubgraphForTenant(tenantID)
	}
	return g
}
