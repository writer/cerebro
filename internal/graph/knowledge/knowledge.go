package knowledge

import (
	"time"

	graph "github.com/writer/cerebro/internal/graph"
)

type (
	ClaimQueryOptions                  = graph.ClaimQueryOptions
	ClaimQueryFilters                  = graph.ClaimQueryFilters
	ClaimCollectionPagination          = graph.ClaimCollectionPagination
	ClaimCollectionSummary             = graph.ClaimCollectionSummary
	ClaimLinkSummary                   = graph.ClaimLinkSummary
	ClaimDerivedState                  = graph.ClaimDerivedState
	ClaimRecord                        = graph.ClaimRecord
	ClaimCollection                    = graph.ClaimCollection
	ClaimWriteRequest                  = graph.ClaimWriteRequest
	ClaimWriteResult                   = graph.ClaimWriteResult
	ClaimConflictReportOptions         = graph.ClaimConflictReportOptions
	ClaimConflictReport                = graph.ClaimConflictReport
	ClaimConflictReportSummary         = graph.ClaimConflictReportSummary
	ClaimConflict                      = graph.ClaimConflict
	ClaimConflictRecommendation        = graph.ClaimConflictRecommendation
	ClaimGroupQueryOptions             = graph.ClaimGroupQueryOptions
	ClaimGroupQueryFilters             = graph.ClaimGroupQueryFilters
	ClaimGroupValueRecord              = graph.ClaimGroupValueRecord
	ClaimGroupDerivedState             = graph.ClaimGroupDerivedState
	ClaimGroupRecord                   = graph.ClaimGroupRecord
	ClaimGroupCollectionSummary        = graph.ClaimGroupCollectionSummary
	ClaimGroupCollection               = graph.ClaimGroupCollection
	ClaimTimelineOptions               = graph.ClaimTimelineOptions
	ClaimTimelineEntry                 = graph.ClaimTimelineEntry
	ClaimTimelineSummary               = graph.ClaimTimelineSummary
	ClaimTimeline                      = graph.ClaimTimeline
	ClaimExplanationSummary            = graph.ClaimExplanationSummary
	ClaimExplanation                   = graph.ClaimExplanation
	ClaimDiffQueryOptions              = graph.ClaimDiffQueryOptions
	ClaimDiffQueryFilters              = graph.ClaimDiffQueryFilters
	ClaimDiffRecord                    = graph.ClaimDiffRecord
	ClaimDiffSummary                   = graph.ClaimDiffSummary
	ClaimDiffCollection                = graph.ClaimDiffCollection
	KnowledgeArtifactQueryOptions      = graph.KnowledgeArtifactQueryOptions
	KnowledgeArtifactQueryFilters      = graph.KnowledgeArtifactQueryFilters
	KnowledgeArtifactLinks             = graph.KnowledgeArtifactLinks
	KnowledgeArtifactDerivedState      = graph.KnowledgeArtifactDerivedState
	KnowledgeArtifactRecord            = graph.KnowledgeArtifactRecord
	KnowledgeArtifactCollectionSummary = graph.KnowledgeArtifactCollectionSummary
	KnowledgeArtifactCollection        = graph.KnowledgeArtifactCollection
	KnowledgeSourceDerivedState        = graph.KnowledgeSourceDerivedState
	KnowledgeSourceRecord              = graph.KnowledgeSourceRecord
	ClaimProofOptions                  = graph.ClaimProofOptions
	ClaimProofNode                     = graph.ClaimProofNode
	ClaimProofEdge                     = graph.ClaimProofEdge
	ClaimProofRecord                   = graph.ClaimProofRecord
	ClaimProofSummary                  = graph.ClaimProofSummary
	ClaimProofCollection               = graph.ClaimProofCollection
	ObservationWriteRequest            = graph.ObservationWriteRequest
	ObservationWriteResult             = graph.ObservationWriteResult
	ClaimAdjudicationWriteRequest      = graph.ClaimAdjudicationWriteRequest
	ClaimAdjudicationWriteResult       = graph.ClaimAdjudicationWriteResult
	KnowledgeDiffQueryOptions          = graph.KnowledgeDiffQueryOptions
	KnowledgeDiffQueryFilters          = graph.KnowledgeDiffQueryFilters
	KnowledgeArtifactDiffRecord        = graph.KnowledgeArtifactDiffRecord
	KnowledgeDiffSummary               = graph.KnowledgeDiffSummary
	KnowledgeDiffCollection            = graph.KnowledgeDiffCollection
	KnowledgeQuery                     = graph.KnowledgeQuery
	KnowledgeTarget                    = graph.KnowledgeTarget
	KnowledgeCandidate                 = graph.KnowledgeCandidate
	KnowledgeRoutingResult             = graph.KnowledgeRoutingResult
)

func QueryClaims(g *graph.Graph, opts ClaimQueryOptions) ClaimCollection {
	return graph.QueryClaims(g, opts)
}

func GetClaimRecord(g *graph.Graph, claimID string, validAt, recordedAt time.Time) (ClaimRecord, bool) {
	return graph.GetClaimRecord(g, claimID, validAt, recordedAt)
}

func QueryEvidence(g *graph.Graph, opts KnowledgeArtifactQueryOptions) KnowledgeArtifactCollection {
	return graph.QueryEvidence(g, opts)
}

func GetEvidenceRecord(g *graph.Graph, evidenceID string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	return graph.GetEvidenceRecord(g, evidenceID, validAt, recordedAt)
}

func QueryObservations(g *graph.Graph, opts KnowledgeArtifactQueryOptions) KnowledgeArtifactCollection {
	return graph.QueryObservations(g, opts)
}

func GetObservationRecord(g *graph.Graph, observationID string, validAt, recordedAt time.Time) (KnowledgeArtifactRecord, bool) {
	return graph.GetObservationRecord(g, observationID, validAt, recordedAt)
}

func QueryClaimGroups(g *graph.Graph, opts ClaimGroupQueryOptions) ClaimGroupCollection {
	return graph.QueryClaimGroups(g, opts)
}

func GetClaimGroupRecord(g *graph.Graph, groupID string, validAt, recordedAt time.Time, includeResolved bool) (ClaimGroupRecord, bool) {
	return graph.GetClaimGroupRecord(g, groupID, validAt, recordedAt, includeResolved)
}

func GetClaimTimeline(g *graph.Graph, claimID string, opts ClaimTimelineOptions) (ClaimTimeline, bool) {
	return graph.GetClaimTimeline(g, claimID, opts)
}

func ExplainClaim(g *graph.Graph, claimID string, validAt, recordedAt time.Time) (ClaimExplanation, bool) {
	return graph.ExplainClaim(g, claimID, validAt, recordedAt)
}

func DiffClaims(g *graph.Graph, opts ClaimDiffQueryOptions) ClaimDiffCollection {
	return graph.DiffClaims(g, opts)
}

func GetSourceRecord(g *graph.Graph, sourceID string, validAt, recordedAt time.Time) (KnowledgeSourceRecord, bool) {
	return graph.GetSourceRecord(g, sourceID, validAt, recordedAt)
}

func BuildClaimProofs(g *graph.Graph, claimID string, opts ClaimProofOptions) (ClaimProofCollection, bool) {
	return graph.BuildClaimProofs(g, claimID, opts)
}

func WriteObservation(g *graph.Graph, req ObservationWriteRequest) (ObservationWriteResult, error) {
	return graph.WriteObservation(g, req)
}

func WriteClaim(g *graph.Graph, req ClaimWriteRequest) (ClaimWriteResult, error) {
	return graph.WriteClaim(g, req)
}

func BuildClaimConflictReport(g *graph.Graph, opts ClaimConflictReportOptions) ClaimConflictReport {
	return graph.BuildClaimConflictReport(g, opts)
}

func AdjudicateClaimGroup(g *graph.Graph, req ClaimAdjudicationWriteRequest) (ClaimAdjudicationWriteResult, error) {
	return graph.AdjudicateClaimGroup(g, req)
}

func DiffKnowledgeGraphs(fromGraph, toGraph *graph.Graph, opts KnowledgeDiffQueryOptions) KnowledgeDiffCollection {
	return graph.DiffKnowledgeGraphs(fromGraph, toGraph, opts)
}

func WhoKnows(g *graph.Graph, query KnowledgeQuery) KnowledgeRoutingResult {
	return graph.WhoKnows(g, query)
}
