package graph

import (
	"sync"
	"time"
)

// Graph represents the security graph containing all nodes and edges
type Graph struct {
	nodes    map[string]*Node
	outEdges map[string][]*Edge // source -> edges
	inEdges  map[string][]*Edge // target -> edges
	mu       sync.RWMutex
	metadata Metadata
}

// Metadata contains information about the graph
type Metadata struct {
	BuiltAt       time.Time     `json:"built_at"`
	NodeCount     int           `json:"node_count"`
	EdgeCount     int           `json:"edge_count"`
	Providers     []string      `json:"providers"`
	Accounts      []string      `json:"accounts"`
	BuildDuration time.Duration `json:"build_duration_ms"`
}

// New creates a new empty graph
func New() *Graph {
	return &Graph{
		nodes:    make(map[string]*Node),
		outEdges: make(map[string][]*Edge),
		inEdges:  make(map[string][]*Edge),
	}
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
}

// AddEdge adds an edge to the graph
func (g *Graph) AddEdge(edge *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.outEdges[edge.Source] = append(g.outEdges[edge.Source], edge)
	g.inEdges[edge.Target] = append(g.inEdges[edge.Target], edge)
}

// GetNode retrieves a node by ID
func (g *Graph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// GetOutEdges returns edges originating from a node
func (g *Graph) GetOutEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.outEdges[nodeID]
}

// GetInEdges returns edges pointing to a node
func (g *Graph) GetInEdges(nodeID string) []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.inEdges[nodeID]
}

// GetAllNodes returns all nodes in the graph
func (g *Graph) GetAllNodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetNodesByKind returns nodes of specific kinds
func (g *Graph) GetNodesByKind(kinds ...NodeKind) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	kindSet := make(map[NodeKind]bool)
	for _, k := range kinds {
		kindSet[k] = true
	}
	var nodes []*Node
	for _, n := range g.nodes {
		if kindSet[n.Kind] {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// GetNodesByAccount returns nodes belonging to a specific account
func (g *Graph) GetNodesByAccount(accountID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var nodes []*Node
	for _, n := range g.nodes {
		if n.Account == accountID {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// GetCrossAccountEdges returns all edges that cross account boundaries
func (g *Graph) GetCrossAccountEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var edges []*Edge
	for _, edgeList := range g.outEdges {
		for _, e := range edgeList {
			if e.IsCrossAccount() {
				edges = append(edges, e)
			}
		}
	}
	return edges
}

// NodeCount returns the number of nodes
func (g *Graph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the total number of edges
func (g *Graph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, edges := range g.outEdges {
		count += len(edges)
	}
	return count
}

// Clear removes all nodes and edges
func (g *Graph) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes = make(map[string]*Node)
	g.outEdges = make(map[string][]*Edge)
	g.inEdges = make(map[string][]*Edge)
}

// SetMetadata sets the graph metadata
func (g *Graph) SetMetadata(m Metadata) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.metadata = m
}

// Metadata returns the graph metadata
func (g *Graph) Metadata() Metadata {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.metadata
}
