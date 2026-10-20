package assetrisk

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const neighborPageLimit = 200

var (
	// ErrInvalidPathRequest marks a request missing its tenant or root.
	ErrInvalidPathRequest = errors.New("invalid attack path request")
	// ErrRootNotFound marks a root entity that is not in the graph.
	ErrRootNotFound = errors.New("attack path root not found")
	// ErrGraphUnavailable marks a missing graph catalog.
	ErrGraphUnavailable = errors.New("graph catalog is not configured")
)

// Graph is the read surface the traversal needs.
type Graph interface {
	ListEntities(context.Context, ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error)
	ListEntityRelations(context.Context, ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error)
}

// PathRequest asks for the riskiest attack paths starting at one entity.
type PathRequest struct {
	TenantID string
	RootURN  string
	// AssumeCompromised scores paths as if the root were already held,
	// answering "what could an attacker reach from here?".
	AssumeCompromised bool
	MaxDepth          int
	Limit             int
}

// PathStep is one hop of an attack path.
type PathStep struct {
	From            string  `json:"from"`
	To              string  `json:"to"`
	Relation        string  `json:"relation"`
	Direction       string  `json:"direction"`
	RequiresExploit bool    `json:"requires_exploit"`
	Probability     float64 `json:"probability"`
	Cumulative      float64 `json:"cumulative"`
}

// AttackPath is the most probable route from the root to one target.
type AttackPath struct {
	TargetURN   string     `json:"target_urn"`
	Probability float64    `json:"probability"`
	Value       float64    `json:"value"`
	Score       int        `json:"score"`
	Level       string     `json:"level"`
	Steps       []PathStep `json:"steps"`
}

// PathSummary describes the whole blast radius from the root.
type PathSummary struct {
	Reached     int     `json:"reached"`
	Expansions  int     `json:"expansions"`
	Truncated   bool    `json:"truncated"`
	MaxScore    int     `json:"max_score"`
	MaxLevel    string  `json:"max_level"`
	ValueAtRisk float64 `json:"value_at_risk"`
}

// PathResult is the scored attack surface from one root.
type PathResult struct {
	TenantID          string           `json:"tenant_id"`
	RootURN           string           `json:"root_urn"`
	RootProbability   float64          `json:"root_probability"`
	AssumeCompromised bool             `json:"assume_compromised"`
	Root              NodeAssessment   `json:"root"`
	Nodes             []NodeAssessment `json:"nodes"`
	Paths             []AttackPath     `json:"paths"`
	Summary           PathSummary      `json:"summary"`
	GraphRevision     uint64           `json:"graph_revision,omitempty"`
}

type neighbor struct {
	entity    ports.CatalogEntity
	relation  string
	direction string
	config    ports.AssetRiskRelation
}

type expandedNode struct {
	assessment NodeAssessment
	neighbors  []neighbor
}

type settledNode struct {
	probability float64
	depth       int
	parent      string
	step        PathStep
}

type candidate struct {
	urn         string
	entity      ports.CatalogEntity
	probability float64
	depth       int
	parent      string
	step        PathStep
	final       bool
}

type candidateQueue []candidate

func (q candidateQueue) Len() int { return len(q) }
func (q candidateQueue) Less(i, j int) bool {
	if q[i].probability != q[j].probability {
		return q[i].probability > q[j].probability
	}
	return q[i].urn < q[j].urn
}
func (q candidateQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *candidateQueue) Push(value any) {
	*q = append(*q, value.(candidate))
}
func (q *candidateQueue) Pop() any {
	old := *q
	item := old[len(old)-1]
	*q = old[:len(old)-1]
	return item
}

type traversal struct {
	graph     Graph
	model     ports.AssetRiskModel
	tenantID  string
	relations []string
	vulnRels  map[string]struct{}
	expanded  map[string]*expandedNode
	budget    int
	used      int
	truncated bool
	revision  uint64
}

// ScorePaths explores the graph from the root, most probable routes first,
// and scores the best route to every reachable entity. It settles each entity
// once, so a deeper but more probable route cut off by max depth is not
// revisited; exploration also stops when the expansion budget is spent.
func ScorePaths(ctx context.Context, graph Graph, model ports.AssetRiskModel, request PathRequest) (*PathResult, error) {
	if graph == nil {
		return nil, ErrGraphUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	rootURN := strings.TrimSpace(request.RootURN)
	if tenantID == "" || rootURN == "" {
		return nil, fmt.Errorf("%w: tenant_id and root_urn are required", ErrInvalidPathRequest)
	}
	maxDepth := model.Traversal.MaxDepth
	if request.MaxDepth > 0 && request.MaxDepth < maxDepth {
		maxDepth = request.MaxDepth
	}
	limit := model.Traversal.MaxPaths
	if request.Limit > 0 && request.Limit < limit {
		limit = request.Limit
	}
	t := newTraversal(graph, model, tenantID)
	root, err := t.loadRoot(ctx, rootURN)
	if err != nil {
		return nil, err
	}
	rootNode, err := t.expand(ctx, root)
	if err != nil {
		return nil, err
	}
	rootProbability := 1.0
	if !request.AssumeCompromised {
		rootProbability = EntryProbability(model, rootNode.assessment)
	}
	settled := map[string]settledNode{root.URN: {probability: rootProbability}}
	queue := &candidateQueue{}
	t.pushNeighbors(queue, settled, root.URN, rootNode, rootProbability, 0, maxDepth)
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := heap.Pop(queue).(candidate)
		if _, done := settled[item.urn]; done {
			continue
		}
		if !item.final {
			node, ok, err := t.tryExpand(ctx, item.entity)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			if item.step.RequiresExploit {
				item.step.Probability = clampFraction(item.step.Probability * node.assessment.ExploitProbability)
				item.probability = clampFraction(item.probability * node.assessment.ExploitProbability)
				item.step.Cumulative = item.probability
			}
			item.final = true
			if item.probability >= model.Traversal.MinProbability {
				heap.Push(queue, item)
			}
			continue
		}
		settled[item.urn] = settledNode{probability: item.probability, depth: item.depth, parent: item.parent, step: item.step}
		if item.depth >= maxDepth {
			if _, ok := t.expanded[item.urn]; !ok {
				t.expanded[item.urn] = &expandedNode{assessment: AssessEntity(model, item.entity, nil, false)}
			}
			continue
		}
		node, ok, err := t.tryExpand(ctx, item.entity)
		if err != nil {
			return nil, err
		}
		if !ok {
			t.expanded[item.urn] = &expandedNode{assessment: AssessEntity(model, item.entity, nil, false)}
			continue
		}
		t.pushNeighbors(queue, settled, item.urn, node, item.probability, item.depth, maxDepth)
	}
	return t.result(request, root.URN, rootProbability, settled, limit), nil
}

func newTraversal(graph Graph, model ports.AssetRiskModel, tenantID string) *traversal {
	relations := make([]string, 0, len(model.Relations)+len(model.Vulnerability.Relations))
	for name := range model.Relations {
		relations = append(relations, name)
	}
	vulnRels := make(map[string]struct{}, len(model.Vulnerability.Relations))
	for _, name := range model.Vulnerability.Relations {
		vulnRels[name] = struct{}{}
		relations = append(relations, name)
	}
	sort.Strings(relations)
	return &traversal{
		graph:     graph,
		model:     model,
		tenantID:  tenantID,
		relations: relations,
		vulnRels:  vulnRels,
		expanded:  map[string]*expandedNode{},
		budget:    model.Traversal.MaxExpansions,
	}
}

func (t *traversal) loadRoot(ctx context.Context, urn string) (ports.CatalogEntity, error) {
	page, err := t.graph.ListEntities(ctx, ports.EntityCatalogPageRequest{
		Filter: ports.EntityCatalogFilter{TenantID: t.tenantID, ExactAgentKey: urn},
		Limit:  1,
	})
	if err != nil {
		return ports.CatalogEntity{}, fmt.Errorf("load attack path root: %w", err)
	}
	if page == nil || page.TenantID != t.tenantID {
		return ports.CatalogEntity{}, ErrRootNotFound
	}
	for _, entity := range page.Entities {
		if entity.URN == urn {
			t.revision = page.GraphRevision
			return entity, nil
		}
	}
	return ports.CatalogEntity{}, ErrRootNotFound
}

func (t *traversal) tryExpand(ctx context.Context, entity ports.CatalogEntity) (*expandedNode, bool, error) {
	if node, ok := t.expanded[entity.URN]; ok && node.assessment.VulnerabilitiesChecked {
		return node, true, nil
	}
	if t.used >= t.budget {
		t.truncated = true
		return nil, false, nil
	}
	node, err := t.expand(ctx, entity)
	if err != nil {
		return nil, false, err
	}
	return node, true, nil
}

func (t *traversal) expand(ctx context.Context, entity ports.CatalogEntity) (*expandedNode, error) {
	t.used++
	page, err := t.graph.ListEntityRelations(ctx, ports.EntityRelationPageRequest{
		TenantID:   t.tenantID,
		AgentKey:   entity.URN,
		Directions: []ports.EntityRelationDirection{ports.EntityRelationOutgoing, ports.EntityRelationIncoming},
		Relations:  t.relations,
		Limit:      neighborPageLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("list relations for attack path step: %w", err)
	}
	if page == nil || page.TenantID != t.tenantID {
		return nil, fmt.Errorf("list relations for attack path step: tenant mismatch")
	}
	if page.Truncated {
		t.truncated = true
	}
	vulnerabilities := []VulnerabilityInput{}
	neighbors := []neighbor{}
	for _, relation := range page.Relations {
		if relation.Entity.URN == "" || relation.Entity.URN == entity.URN {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(relation.Relation))
		direction := string(relation.Direction)
		if _, ok := t.vulnRels[name]; ok {
			if IsVulnerabilityEntity(relation.Entity.EntityType) {
				vulnerabilities = append(vulnerabilities, VulnerabilityInput{Entity: relation.Entity, EdgeAttributes: edgeAttributes(relation.AttributesJSON)})
			}
			continue
		}
		config, ok := t.model.Relations[name]
		if !ok || (config.Direction != DirectionBoth && config.Direction != direction) {
			continue
		}
		if IsVulnerabilityEntity(relation.Entity.EntityType) {
			continue
		}
		neighbors = append(neighbors, neighbor{entity: relation.Entity, relation: name, direction: direction, config: config})
	}
	node := &expandedNode{assessment: AssessEntity(t.model, entity, vulnerabilities, true), neighbors: neighbors}
	t.expanded[entity.URN] = node
	return node, nil
}

func (t *traversal) pushNeighbors(queue *candidateQueue, settled map[string]settledNode, from string, node *expandedNode, probability float64, depth int, maxDepth int) {
	if depth >= maxDepth {
		return
	}
	for _, next := range node.neighbors {
		if _, done := settled[next.entity.URN]; done {
			continue
		}
		_, factor := Countermeasures(t.model, next.entity)
		step := next.config.Probability * factor
		reached := clampFraction(probability * step)
		if reached < t.model.Traversal.MinProbability {
			continue
		}
		heap.Push(queue, candidate{
			urn:         next.entity.URN,
			entity:      next.entity,
			probability: reached,
			depth:       depth + 1,
			parent:      from,
			step: PathStep{
				From:            from,
				To:              next.entity.URN,
				Relation:        next.relation,
				Direction:       next.direction,
				RequiresExploit: next.config.RequiresExploit,
				Probability:     clampFraction(step),
				Cumulative:      reached,
			},
			final: !next.config.RequiresExploit,
		})
	}
}

func (t *traversal) result(request PathRequest, rootURN string, rootProbability float64, settled map[string]settledNode, limit int) *PathResult {
	result := &PathResult{
		TenantID:          t.tenantID,
		RootURN:           rootURN,
		RootProbability:   rootProbability,
		AssumeCompromised: request.AssumeCompromised,
		Root:              t.expanded[rootURN].assessment,
		Nodes:             []NodeAssessment{},
		Paths:             []AttackPath{},
		GraphRevision:     t.revision,
	}
	urns := make([]string, 0, len(settled))
	for urn := range settled {
		if urn != rootURN {
			urns = append(urns, urn)
		}
	}
	sort.Strings(urns)
	paths := make([]AttackPath, 0, len(urns))
	for _, urn := range urns {
		entry := settled[urn]
		node, ok := t.expanded[urn]
		if !ok {
			continue
		}
		value := node.assessment.Value
		score := Score(entry.probability, value)
		result.Summary.ValueAtRisk += entry.probability * value
		if score > result.Summary.MaxScore {
			result.Summary.MaxScore = score
		}
		paths = append(paths, AttackPath{
			TargetURN:   urn,
			Probability: entry.probability,
			Value:       value,
			Score:       score,
			Level:       Level(t.model, score),
			Steps:       pathSteps(settled, urn),
		})
	}
	slices.SortStableFunc(paths, func(a, b AttackPath) int {
		if a.Score != b.Score {
			return b.Score - a.Score
		}
		if a.Probability != b.Probability {
			if a.Probability > b.Probability {
				return -1
			}
			return 1
		}
		return strings.Compare(a.TargetURN, b.TargetURN)
	})
	result.Summary.Reached = len(paths)
	if len(paths) > limit {
		paths = paths[:limit]
		result.Summary.Truncated = true
	}
	result.Paths = paths
	included := map[string]struct{}{}
	for _, path := range paths {
		for _, step := range path.Steps {
			included[step.From] = struct{}{}
			included[step.To] = struct{}{}
		}
	}
	delete(included, rootURN)
	for _, urn := range urns {
		if _, ok := included[urn]; !ok {
			continue
		}
		if node, ok := t.expanded[urn]; ok {
			result.Nodes = append(result.Nodes, node.assessment)
		}
	}
	result.Summary.Expansions = t.used
	result.Summary.Truncated = result.Summary.Truncated || t.truncated
	result.Summary.MaxLevel = Level(t.model, result.Summary.MaxScore)
	return result
}

func pathSteps(settled map[string]settledNode, target string) []PathStep {
	steps := []PathStep{}
	for current := target; ; {
		entry, ok := settled[current]
		if !ok || entry.parent == "" {
			break
		}
		steps = append(steps, entry.step)
		current = entry.parent
	}
	slices.Reverse(steps)
	return steps
}

func edgeAttributes(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil
	}
	out := make(map[string]string, len(decoded))
	for key, value := range decoded {
		switch typed := value.(type) {
		case string:
			out[key] = typed
		case bool, float64:
			out[key] = fmt.Sprint(typed)
		}
	}
	return out
}
