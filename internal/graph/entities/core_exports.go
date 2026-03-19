package entities

import graph "github.com/writer/cerebro/internal/graph"

type (
	Graph    = graph.Graph
	Node     = graph.Node
	NodeKind = graph.NodeKind
)

const (
	NodeKindService = graph.NodeKindService
)

var (
	New = graph.New
)
