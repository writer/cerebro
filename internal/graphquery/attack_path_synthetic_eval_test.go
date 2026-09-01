package graphquery

import (
	"context"
	"fmt"
	"testing"

	"github.com/writer/cerebro/internal/graphpaths"
	"github.com/writer/cerebro/internal/ports"
)

type syntheticAttackPathEvalCase struct {
	id             string
	relationChain  []string
	edgeRelations  []string
	edgeDirections []string
	blankToIndex   int
	wantPath       bool
}

func TestAttackPathsSyntheticTraversalProofEvals(t *testing.T) {
	cases := syntheticAttackPathEvalCases()
	if len(cases) < 600 {
		t.Fatalf("synthetic eval count = %d, want at least 600", len(cases))
	}
	for _, tc := range cases {
		store := &graphAttackPathStore{result: &ports.CloudAttackPathResult{
			TenantID: "synthetic",
			Paths:    []ports.CloudAttackPath{syntheticAttackPath(tc)},
		}}
		result, err := NewWithCapabilities(nil, nil, nil, store).GetAttackPaths(context.Background(), AttackPathRequest{TenantID: "synthetic"})
		if err != nil {
			t.Fatalf("%s: GetAttackPaths() error = %v", tc.id, err)
		}
		gotPath := len(result.Paths) == 1
		if gotPath != tc.wantPath {
			t.Fatalf("%s: got path=%v, want %v; paths=%#v", tc.id, gotPath, tc.wantPath, result.Paths)
		}
		if !tc.wantPath {
			continue
		}
		if got := len(result.Paths[0].TraversalEdges); got != len(tc.relationChain) {
			t.Fatalf("%s: traversal edge count = %d, want %d", tc.id, got, len(tc.relationChain))
		}
		if got := result.Paths[0].TraversalEdges[len(result.Paths[0].TraversalEdges)-1].To.URN; got != fmt.Sprintf("urn:cerebro:synthetic:principal:%s", tc.id) {
			t.Fatalf("%s: final traversal target = %q", tc.id, got)
		}
	}
}

func syntheticAttackPathEvalCases() []syntheticAttackPathEvalCase {
	relations := graphpaths.CloudExposurePrivilegeTraversalRelations()
	cases := make([]syntheticAttackPathEvalCase, 0, 640)
	for depth := 1; depth <= 4; depth++ {
		for seed := 0; seed < 32; seed++ {
			chain := make([]string, depth)
			directions := make([]string, depth)
			for idx := 0; idx < depth; idx++ {
				relation := relations[(seed+(idx*3)+depth)%len(relations)]
				chain[idx] = relation
				directions[idx] = syntheticTraversalDirection(relation)
			}

			cases = append(cases, syntheticAttackPathEvalCase{
				id:             fmt.Sprintf("valid_depth_%d_seed_%02d", depth, seed),
				relationChain:  append([]string(nil), chain...),
				edgeRelations:  append([]string(nil), chain...),
				edgeDirections: append([]string(nil), directions...),
				blankToIndex:   -1,
				wantPath:       true,
			})

			badDirections := append([]string(nil), directions...)
			badDirections[seed%depth] = syntheticOppositeTraversalDirection(chain[seed%depth])
			cases = append(cases, syntheticAttackPathEvalCase{
				id:             fmt.Sprintf("invalid_direction_depth_%d_seed_%02d", depth, seed),
				relationChain:  append([]string(nil), chain...),
				edgeRelations:  append([]string(nil), chain...),
				edgeDirections: badDirections,
				blankToIndex:   -1,
			})

			mismatchedRelations := append([]string(nil), chain...)
			mismatchIndex := (seed + 1) % depth
			mismatchedRelations[mismatchIndex] = syntheticDifferentRelation(relations, chain[mismatchIndex])
			cases = append(cases, syntheticAttackPathEvalCase{
				id:             fmt.Sprintf("relation_mismatch_depth_%d_seed_%02d", depth, seed),
				relationChain:  append([]string(nil), chain...),
				edgeRelations:  mismatchedRelations,
				edgeDirections: append([]string(nil), directions...),
				blankToIndex:   -1,
			})

			unsupportedChain := append([]string(nil), chain...)
			unsupportedDirections := append([]string(nil), directions...)
			unsupportedIndex := (seed + 2) % depth
			unsupportedChain[unsupportedIndex] = "belongs_to"
			unsupportedDirections[unsupportedIndex] = graphpaths.CloudExposurePrivilegeTraversalDirectionForward
			cases = append(cases, syntheticAttackPathEvalCase{
				id:             fmt.Sprintf("unsupported_relation_depth_%d_seed_%02d", depth, seed),
				relationChain:  unsupportedChain,
				edgeRelations:  append([]string(nil), unsupportedChain...),
				edgeDirections: unsupportedDirections,
				blankToIndex:   -1,
			})

			cases = append(cases, syntheticAttackPathEvalCase{
				id:             fmt.Sprintf("missing_endpoint_depth_%d_seed_%02d", depth, seed),
				relationChain:  append([]string(nil), chain...),
				edgeRelations:  append([]string(nil), chain...),
				edgeDirections: append([]string(nil), directions...),
				blankToIndex:   seed % depth,
			})
		}
	}
	return cases
}

func syntheticAttackPath(tc syntheticAttackPathEvalCase) ports.CloudAttackPath {
	path := graphTypedAttackPath("synthetic", tc.id)
	path.RelationChain = append([]string(nil), tc.relationChain...)
	traversalEdges := make([]ports.CloudAttackPathEdge, 0, len(tc.edgeRelations))
	for idx, relation := range tc.edgeRelations {
		fromURN := fmt.Sprintf("urn:cerebro:synthetic:node:%s:%d", tc.id, idx)
		toURN := fmt.Sprintf("urn:cerebro:synthetic:node:%s:%d", tc.id, idx+1)
		if idx == len(tc.edgeRelations)-1 {
			toURN = fmt.Sprintf("urn:cerebro:synthetic:principal:%s", tc.id)
		}
		if idx == tc.blankToIndex {
			toURN = ""
		}
		traversalEdges = append(traversalEdges, ports.CloudAttackPathEdge{
			From:      ports.CloudAttackPathNode{URN: fromURN, EntityType: "synthetic.resource", Label: fmt.Sprintf("node-%d", idx)},
			Relation:  relation,
			To:        ports.CloudAttackPathNode{URN: toURN, EntityType: "synthetic.principal", Label: fmt.Sprintf("node-%d", idx+1)},
			Direction: tc.edgeDirections[idx],
		})
	}
	path.TraversalEdges = traversalEdges
	return path
}

func syntheticTraversalDirection(relation string) string {
	if relation == "member_of" {
		return graphpaths.CloudExposurePrivilegeTraversalDirectionReverse
	}
	return graphpaths.CloudExposurePrivilegeTraversalDirectionForward
}

func syntheticOppositeTraversalDirection(relation string) string {
	if syntheticTraversalDirection(relation) == graphpaths.CloudExposurePrivilegeTraversalDirectionForward {
		return graphpaths.CloudExposurePrivilegeTraversalDirectionReverse
	}
	return graphpaths.CloudExposurePrivilegeTraversalDirectionForward
}

func syntheticDifferentRelation(relations []string, relation string) string {
	for _, candidate := range relations {
		if candidate != relation {
			return candidate
		}
	}
	return "belongs_to"
}
