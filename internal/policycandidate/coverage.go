package policycandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

type candidateCoverageSignature struct {
	entityTypes map[string]struct{}
	edges       map[string]struct{}
	predicates  map[string]struct{}
	canonical   []string
}

func verifyCoverageGap(ctx context.Context, catalog CoverageCatalog, tenantID string, evidence policyauthor.GraphEvidence, now func() time.Time) (*CoverageGapReceipt, error) {
	if catalog == nil {
		return nil, ErrCoverageUnavailable
	}
	queries, err := catalog.ListCoverageQueries(ctx, tenantID, MaxCoverageRules)
	if err != nil {
		return nil, fmt.Errorf("inspect finding-rule coverage catalog: %w", err)
	}
	if len(queries) > MaxCoverageRules {
		return nil, fmt.Errorf("%w: coverage catalog exceeds %d graph rules", ErrCoverageUnavailable, MaxCoverageRules)
	}
	signature, err := buildCandidateCoverageSignature(evidence)
	if err != nil {
		return nil, err
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i].CatalogKey < queries[j].CatalogKey })
	digestInput := strings.Builder{}
	for _, entry := range queries {
		if strings.TrimSpace(entry.Query) == "" || len(entry.Query) > MaxCoverageQueryBytes {
			return nil, fmt.Errorf("%w: coverage catalog returned an empty or oversized bounded query", ErrCoverageUnavailable)
		}
		digestInput.WriteString(canonicalCoverageQuery(entry))
		digestInput.WriteByte('\n')
		if !entry.SemanticsComplete && signatureEntityScopeOverlaps(entry.RequiredEntityTypes, signature) {
			return nil, fmt.Errorf("%w: a potentially overlapping graph rule has no complete EvaluateRows coverage semantics", ErrCoverageUnavailable)
		}
		if registeredSignatureCovered(entry, signature) {
			return nil, fmt.Errorf("%w: an existing graph rule covers a grounded semantic subpath", ErrConflict)
		}
	}
	observedAt := time.Now().UTC()
	if now != nil {
		observedAt = now().UTC()
	}
	return &CoverageGapReceipt{
		Execution: "finding_rule_catalog", CatalogDigest: sha256Hex(digestInput.String()),
		ComparedRuleCount: len(queries), CandidateSignature: sha256Hex(strings.Join(signature.canonical, "\n")), ObservedAt: observedAt,
	}, nil
}

func buildCandidateCoverageSignature(evidence policyauthor.GraphEvidence) (candidateCoverageSignature, error) {
	result := candidateCoverageSignature{entityTypes: map[string]struct{}{}, edges: map[string]struct{}{}, predicates: map[string]struct{}{}}
	nodeTypes := make(map[string]string, len(evidence.Nodes))
	for _, node := range evidence.Nodes {
		id := strings.TrimSpace(node.ID)
		entityType := normalizeCoverageValue(node.EntityType)
		if id == "" || entityType == "" {
			return result, fmt.Errorf("%w: coverage signature requires typed evidence nodes", ErrInvalidRequest)
		}
		nodeTypes[id] = entityType
		result.entityTypes[entityType] = struct{}{}
		for key, value := range node.Attributes {
			result.predicates[coveragePredicateKey(entityType, key, value)] = struct{}{}
		}
	}
	for _, edge := range evidence.Edges {
		fromType := nodeTypes[strings.TrimSpace(edge.FromID)]
		toType := nodeTypes[strings.TrimSpace(edge.ToID)]
		relation := normalizeCoverageValue(edge.Relation)
		if fromType == "" || toType == "" || relation == "" {
			return result, fmt.Errorf("%w: coverage signature requires directed typed edges", ErrInvalidRequest)
		}
		result.edges[coverageEdgeKey(fromType, relation, toType)] = struct{}{}
		for key, value := range edge.Attributes {
			result.predicates[coveragePredicateKey("relation:"+relation, key, value)] = struct{}{}
		}
	}
	for value := range result.entityTypes {
		result.canonical = append(result.canonical, "entity="+value)
	}
	for value := range result.edges {
		result.canonical = append(result.canonical, "edge="+value)
	}
	for value := range result.predicates {
		result.canonical = append(result.canonical, "predicate="+value)
	}
	sort.Strings(result.canonical)
	return result, nil
}

// registeredSignatureCovered asks whether one registered rule's requirements
// embed in the candidate. Candidate-only context does not defeat deduplication.
func registeredSignatureCovered(entry CoverageQuery, candidate candidateCoverageSignature) bool {
	if len(entry.RequiredEntityTypes) == 0 && len(entry.RequiredEdges) == 0 && len(entry.RequiredPredicates) == 0 {
		return false
	}
	for _, value := range entry.RequiredEntityTypes {
		if _, ok := candidate.entityTypes[normalizeCoverageValue(value)]; !ok {
			return false
		}
	}
	for _, edge := range entry.RequiredEdges {
		if _, ok := candidate.edges[coverageEdgeKey(edge.FromEntityType, edge.Relation, edge.ToEntityType)]; !ok {
			return false
		}
	}
	for _, predicate := range entry.RequiredPredicates {
		if _, ok := candidate.predicates[coveragePredicateKey(predicate.EntityType, predicate.Key, predicate.Value)]; !ok {
			return false
		}
	}
	return true
}

func signatureEntityScopeOverlaps(required []string, candidate candidateCoverageSignature) bool {
	if len(required) == 0 {
		return true
	}
	for _, value := range required {
		if _, ok := candidate.entityTypes[normalizeCoverageValue(value)]; ok {
			return true
		}
	}
	return false
}

func canonicalCoverageQuery(entry CoverageQuery) string {
	lines := []string{strings.TrimSpace(entry.CatalogKey), strings.TrimSpace(entry.Query), fmt.Sprintf("complete=%t", entry.SemanticsComplete)}
	for _, value := range entry.RequiredEntityTypes {
		lines = append(lines, "entity="+normalizeCoverageValue(value))
	}
	for _, edge := range entry.RequiredEdges {
		lines = append(lines, "edge="+coverageEdgeKey(edge.FromEntityType, edge.Relation, edge.ToEntityType))
	}
	for _, predicate := range entry.RequiredPredicates {
		lines = append(lines, "predicate="+coveragePredicateKey(predicate.EntityType, predicate.Key, predicate.Value))
	}
	sort.Strings(lines[2:])
	return strings.Join(lines, "\n")
}

func coverageEdgeKey(fromType string, relation string, toType string) string {
	return normalizeCoverageValue(fromType) + "|" + normalizeCoverageValue(relation) + "|" + normalizeCoverageValue(toType)
}

func coveragePredicateKey(entityType string, key string, value string) string {
	return normalizeCoverageValue(entityType) + "|" + normalizeCoverageValue(key) + "|" + normalizeCoverageValue(value)
}

func normalizeCoverageValue(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
