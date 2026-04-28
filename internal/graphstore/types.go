package graphstore

// Counts summarizes entity and relationship totals in a graph store.
type Counts struct {
	Nodes     int64
	Relations int64
}

// Traversal captures one sampled two-hop graph path.
type Traversal struct {
	FromURN        string
	FromLabel      string
	FirstRelation  string
	ViaURN         string
	ViaLabel       string
	SecondRelation string
	ToURN          string
	ToLabel        string
}

// IntegrityCheck captures one graph invariant check result.
type IntegrityCheck struct {
	Name     string
	Actual   int64
	Expected int64
	Passed   bool
}

// PathPattern captures one grouped two-hop graph pattern.
type PathPattern struct {
	FromType       string
	FirstRelation  string
	ViaType        string
	SecondRelation string
	ToType         string
	Count          int64
}

// Topology summarizes node connectivity classes in a graph store.
type Topology struct {
	Isolated      int64
	SourcesOnly   int64
	SinksOnly     int64
	Intermediates int64
}
