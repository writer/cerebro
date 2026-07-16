package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/findingdsl"
)

var (
	ErrGraphEvidenceRequired = errors.New("typed graph evidence is required for graph policy tests")
	safeGraphSourcePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
)

// GraphEvidence describes topology with local node handles instead of source
// identifiers. CriticalEdge is removed from the passing fixture; every other
// node and edge remains byte-for-byte equivalent.
type GraphEvidence struct {
	Nodes           []GraphEvidenceNode  `json:"nodes"`
	Edges           []GraphEvidenceEdge  `json:"edges"`
	CriticalEdge    GraphEvidenceEdgeRef `json:"critical_edge"`
	EvidenceNodeIDs []string             `json:"evidence_node_ids"`
}

type GraphEvidenceNode struct {
	ID         string            `json:"id"`
	SourceID   string            `json:"source_id"`
	EntityType string            `json:"entity_type"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GraphEvidenceEdge struct {
	FromID     string            `json:"from_id"`
	ToID       string            `json:"to_id"`
	SourceID   string            `json:"source_id"`
	Relation   string            `json:"relation"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GraphEvidenceEdgeRef struct {
	FromID   string `json:"from_id"`
	ToID     string `json:"to_id"`
	Relation string `json:"relation"`
}

type GraphEvidenceContext struct {
	Nodes        []GraphEvidenceContextNode  `json:"nodes"`
	Edges        []GraphEvidenceContextEdge  `json:"edges"`
	CriticalEdge GraphEvidenceContextEdgeRef `json:"critical_edge"`
	EvidenceRefs []string                    `json:"evidence_refs"`
}

type GraphEvidenceContextNode struct {
	Ref        string            `json:"ref"`
	SourceID   string            `json:"source_id"`
	EntityType string            `json:"entity_type"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GraphEvidenceContextEdge struct {
	FromRef    string            `json:"from_ref"`
	ToRef      string            `json:"to_ref"`
	SourceID   string            `json:"source_id"`
	Relation   string            `json:"relation"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type GraphEvidenceContextEdgeRef struct {
	FromRef  string `json:"from_ref"`
	ToRef    string `json:"to_ref"`
	Relation string `json:"relation"`
}

// GraphEvidenceModelContext returns request-local topology references for the
// drafting model. Local evidence IDs never cross the model boundary.
func GraphEvidenceModelContext(evidence GraphEvidence) (GraphEvidenceContext, error) {
	references := make(map[string]string, len(evidence.Nodes))
	nodes := make([]GraphEvidenceContextNode, 0, len(evidence.Nodes))
	for index, node := range evidence.Nodes {
		id := strings.TrimSpace(node.ID)
		if id == "" || strings.TrimSpace(node.EntityType) == "" || !safeGraphSourcePattern.MatchString(strings.TrimSpace(node.SourceID)) {
			return GraphEvidenceContext{}, fmt.Errorf("graph evidence nodes[%d] requires a local id, identifier-safe source_id, and entity_type", index)
		}
		if _, exists := references[id]; exists {
			return GraphEvidenceContext{}, fmt.Errorf("graph evidence node id %q is duplicated", id)
		}
		ref := fmt.Sprintf("node-%d", index+1)
		references[id] = ref
		nodes = append(nodes, GraphEvidenceContextNode{
			Ref: ref, SourceID: strings.TrimSpace(node.SourceID), EntityType: strings.TrimSpace(node.EntityType),
			Attributes: pseudonymizeGraphAttributes(node.Attributes, ref),
		})
	}
	edges := make([]GraphEvidenceContextEdge, 0, len(evidence.Edges))
	for index, edge := range evidence.Edges {
		fromRef, fromOK := references[strings.TrimSpace(edge.FromID)]
		toRef, toOK := references[strings.TrimSpace(edge.ToID)]
		if !fromOK || !toOK || !safeGraphSourcePattern.MatchString(strings.TrimSpace(edge.SourceID)) || strings.TrimSpace(edge.Relation) == "" {
			return GraphEvidenceContext{}, fmt.Errorf("graph evidence edges[%d] must reference declared nodes and include identifier-safe source_id and relation", index)
		}
		edges = append(edges, GraphEvidenceContextEdge{
			FromRef: fromRef, ToRef: toRef, SourceID: strings.TrimSpace(edge.SourceID), Relation: strings.TrimSpace(edge.Relation),
			Attributes: pseudonymizeGraphAttributes(edge.Attributes, fmt.Sprintf("edge-%d", index+1)),
		})
	}
	criticalFrom, fromOK := references[strings.TrimSpace(evidence.CriticalEdge.FromID)]
	criticalTo, toOK := references[strings.TrimSpace(evidence.CriticalEdge.ToID)]
	if !fromOK || !toOK || strings.TrimSpace(evidence.CriticalEdge.Relation) == "" {
		return GraphEvidenceContext{}, errors.New("graph evidence critical_edge must reference declared nodes and a relation")
	}
	evidenceRefs := make([]string, 0, len(evidence.EvidenceNodeIDs))
	for _, id := range evidence.EvidenceNodeIDs {
		ref, ok := references[strings.TrimSpace(id)]
		if !ok {
			return GraphEvidenceContext{}, fmt.Errorf("graph evidence evidence_node_ids references unknown node %q", strings.TrimSpace(id))
		}
		evidenceRefs = append(evidenceRefs, ref)
	}
	return GraphEvidenceContext{
		Nodes: nodes, Edges: edges,
		CriticalEdge: GraphEvidenceContextEdgeRef{FromRef: criticalFrom, ToRef: criticalTo, Relation: strings.TrimSpace(evidence.CriticalEdge.Relation)},
		EvidenceRefs: evidenceRefs,
	}, nil
}

func SuiteForGraphRule(rule findingdsl.PolicyFindingRule, evidence GraphEvidence) (findingdsl.PolicyRuleTestSuite, error) {
	if strings.TrimSpace(rule.Spec.Graph.Query) == "" {
		return findingdsl.PolicyRuleTestSuite{}, errors.New("graph evidence requires spec.graph.query")
	}
	tenantID := "test-authored-" + fixtureSlug(rule.Metadata.ID)
	if tenantID == "test-authored-" {
		return findingdsl.PolicyRuleTestSuite{}, errors.New("graph policy metadata.id is required")
	}

	nodeURNs := make(map[string]string, len(evidence.Nodes))
	nodes := make([]findingdsl.PolicyGraphFixtureNode, 0, len(evidence.Nodes))
	for index, node := range evidence.Nodes {
		id := strings.TrimSpace(node.ID)
		sourceID := strings.TrimSpace(node.SourceID)
		entityType := strings.TrimSpace(node.EntityType)
		if id == "" || sourceID == "" || entityType == "" {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence nodes[%d] requires id, source_id, and entity_type", index)
		}
		if !safeGraphSourcePattern.MatchString(sourceID) {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence nodes[%d].source_id is not identifier-safe", index)
		}
		if _, exists := nodeURNs[id]; exists {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence node id %q is duplicated", id)
		}
		urn := fmt.Sprintf("urn:cerebro:%s:fixture:%s:node-%d", tenantID, fixtureSlug(entityType), index+1)
		nodeURNs[id] = urn
		nodes = append(nodes, findingdsl.PolicyGraphFixtureNode{
			URN: urn, SourceID: sourceID, EntityType: entityType,
			Label:      fmt.Sprintf("Fixture node %d", index+1),
			Attributes: pseudonymizeGraphAttributes(node.Attributes, fmt.Sprintf("node-%d", index+1)),
		})
	}

	edges := make([]findingdsl.PolicyGraphFixtureEdge, 0, len(evidence.Edges))
	criticalIndex := -1
	for index, edge := range evidence.Edges {
		fromID, toID, relation := strings.TrimSpace(edge.FromID), strings.TrimSpace(edge.ToID), strings.TrimSpace(edge.Relation)
		fromURN, fromOK := nodeURNs[fromID]
		toURN, toOK := nodeURNs[toID]
		if !fromOK || !toOK {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence edges[%d] must reference declared node IDs", index)
		}
		if !safeGraphSourcePattern.MatchString(strings.TrimSpace(edge.SourceID)) || relation == "" {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence edges[%d] requires an identifier-safe source_id and relation", index)
		}
		if fromID == strings.TrimSpace(evidence.CriticalEdge.FromID) && toID == strings.TrimSpace(evidence.CriticalEdge.ToID) && relation == strings.TrimSpace(evidence.CriticalEdge.Relation) {
			if criticalIndex != -1 {
				return findingdsl.PolicyRuleTestSuite{}, errors.New("graph evidence critical_edge matches more than one edge")
			}
			criticalIndex = index
		}
		edges = append(edges, findingdsl.PolicyGraphFixtureEdge{
			FromURN: fromURN, ToURN: toURN, SourceID: strings.TrimSpace(edge.SourceID), Relation: relation,
			Attributes: pseudonymizeGraphAttributes(edge.Attributes, fmt.Sprintf("edge-%d", index+1)),
		})
	}
	if criticalIndex == -1 {
		return findingdsl.PolicyRuleTestSuite{}, errors.New("graph evidence critical_edge must match exactly one edge")
	}

	wantEvidenceURNs := make([]string, 0, len(evidence.EvidenceNodeIDs))
	seenEvidence := map[string]struct{}{}
	for _, rawID := range evidence.EvidenceNodeIDs {
		id := strings.TrimSpace(rawID)
		urn, ok := nodeURNs[id]
		if !ok {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence evidence_node_ids references unknown node %q", id)
		}
		if _, duplicate := seenEvidence[id]; duplicate {
			return findingdsl.PolicyRuleTestSuite{}, fmt.Errorf("graph evidence evidence_node_ids duplicates node %q", id)
		}
		seenEvidence[id] = struct{}{}
		wantEvidenceURNs = append(wantEvidenceURNs, urn)
	}

	findingFixture := &findingdsl.PolicyGraphFixture{TenantID: tenantID, Nodes: cloneGraphNodes(nodes), Edges: cloneGraphEdges(edges)}
	passingEdges := make([]findingdsl.PolicyGraphFixtureEdge, 0, len(edges)-1)
	for index, edge := range edges {
		if index != criticalIndex {
			passingEdges = append(passingEdges, cloneGraphEdge(edge))
		}
	}
	passingFixture := &findingdsl.PolicyGraphFixture{TenantID: tenantID, Nodes: cloneGraphNodes(nodes), Edges: passingEdges}
	suite := findingdsl.PolicyRuleTestSuite{APIVersion: findingdsl.APIVersion, Kind: findingdsl.KindPolicyFindingRuleTest, Cases: []findingdsl.PolicyRuleTestCase{
		{Name: "complete graph path produces a finding", GraphFixture: findingFixture, WantEvidenceURNs: wantEvidenceURNs, WantFinding: true},
		{Name: "critical graph edge removed passes", GraphFixture: passingFixture, WantFinding: false},
	}}
	if issues := findingdsl.ValidatePolicyRuleTestSuite(suite); len(issues) != 0 {
		return suite, fmt.Errorf("authored graph test suite is invalid: %s", joinIssues(issues))
	}
	return suite, nil
}

func pseudonymizeGraphAttributes(attributes map[string]string, token string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		normalizedValue := strings.TrimSpace(value)
		if graphPredicateAttribute(normalizedKey) && !looksLikeSourceIdentifier(normalizedValue) {
			out[key] = normalizedValue
			continue
		}
		if normalizedKey == "started_by" && strings.Contains(strings.ToLower(normalizedValue), "candidate") {
			out[key] = "fixture-candidate-marker"
			continue
		}
		out[key] = "fixture-ref-" + token
	}
	return out
}

func graphPredicateAttribute(key string) bool {
	if strings.HasPrefix(key, "has_") || strings.HasSuffix(key, "_count") {
		return true
	}
	switch key {
	case "event_type", "status", "state", "last_status", "observed_last_status", "role_usage":
		return true
	default:
		return false
	}
}

func looksLikeSourceIdentifier(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "arn:") || strings.Contains(lower, "://") || strings.Contains(value, "@") {
		return true
	}
	digits := 0
	for _, char := range value {
		if unicode.IsDigit(char) {
			digits++
		}
	}
	return digits >= 12
}

func fixtureSlug(value string) string {
	var out strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			out.WriteRune(char)
			lastDash = false
			continue
		}
		if !lastDash && out.Len() != 0 {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}

func cloneGraphNodes(nodes []findingdsl.PolicyGraphFixtureNode) []findingdsl.PolicyGraphFixtureNode {
	out := make([]findingdsl.PolicyGraphFixtureNode, len(nodes))
	for index, node := range nodes {
		out[index] = node
		out[index].Attributes = cloneStringMap(node.Attributes)
	}
	return out
}

func cloneGraphEdges(edges []findingdsl.PolicyGraphFixtureEdge) []findingdsl.PolicyGraphFixtureEdge {
	out := make([]findingdsl.PolicyGraphFixtureEdge, len(edges))
	for index, edge := range edges {
		out[index] = cloneGraphEdge(edge)
	}
	return out
}

func cloneGraphEdge(edge findingdsl.PolicyGraphFixtureEdge) findingdsl.PolicyGraphFixtureEdge {
	edge.Attributes = cloneStringMap(edge.Attributes)
	return edge
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
