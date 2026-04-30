package graphstore

// Counts summarizes entity and relationship totals in a graph store.
type Counts struct {
	Nodes     int64 `json:"nodes"`
	Relations int64 `json:"relations"`
}

// Traversal captures one sampled two-hop graph path.
type Traversal struct {
	FromURN        string `json:"from_urn"`
	FromLabel      string `json:"from_label"`
	FirstRelation  string `json:"first_relation"`
	ViaURN         string `json:"via_urn"`
	ViaLabel       string `json:"via_label"`
	SecondRelation string `json:"second_relation"`
	ToURN          string `json:"to_urn"`
	ToLabel        string `json:"to_label"`
}

// IntegrityCheck captures one graph invariant check result.
type IntegrityCheck struct {
	Name     string `json:"name"`
	Actual   int64  `json:"actual"`
	Expected int64  `json:"expected"`
	Passed   bool   `json:"passed"`
}

// PathPattern captures one grouped two-hop graph pattern.
type PathPattern struct {
	FromType       string `json:"from_type"`
	FirstRelation  string `json:"first_relation"`
	ViaType        string `json:"via_type"`
	SecondRelation string `json:"second_relation"`
	ToType         string `json:"to_type"`
	Count          int64  `json:"count"`
}

// Topology summarizes node connectivity classes in a graph store.
type Topology struct {
	Isolated      int64 `json:"isolated"`
	SourcesOnly   int64 `json:"sources_only"`
	SinksOnly     int64 `json:"sinks_only"`
	Intermediates int64 `json:"intermediates"`
}

// IngestCheckpoint records durable graph ingest progress in Kuzu.
type IngestCheckpoint struct {
	ID               string `json:"id"`
	SourceID         string `json:"source_id"`
	TenantID         string `json:"tenant_id,omitempty"`
	ConfigHash       string `json:"config_hash"`
	CursorOpaque     string `json:"cursor_opaque,omitempty"`
	CheckpointOpaque string `json:"checkpoint_opaque,omitempty"`
	Completed        bool   `json:"completed"`
	PagesRead        int64  `json:"pages_read"`
	EventsRead       int64  `json:"events_read"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

const (
	IngestRunStatusRunning   = "running"
	IngestRunStatusCompleted = "completed"
	IngestRunStatusFailed    = "failed"
)

// IngestRun records one operational graph ingest attempt.
type IngestRun struct {
	ID                string `json:"id"`
	RuntimeID         string `json:"runtime_id,omitempty"`
	SourceID          string `json:"source_id,omitempty"`
	TenantID          string `json:"tenant_id,omitempty"`
	CheckpointID      string `json:"checkpoint_id,omitempty"`
	Status            string `json:"status"`
	Trigger           string `json:"trigger,omitempty"`
	PagesRead         int64  `json:"pages_read"`
	EventsRead        int64  `json:"events_read"`
	EntitiesProjected int64  `json:"entities_projected"`
	LinksProjected    int64  `json:"links_projected"`
	GraphNodesBefore  int64  `json:"graph_nodes_before,omitempty"`
	GraphLinksBefore  int64  `json:"graph_links_before,omitempty"`
	GraphNodesAfter   int64  `json:"graph_nodes_after,omitempty"`
	GraphLinksAfter   int64  `json:"graph_links_after,omitempty"`
	StartedAt         string `json:"started_at,omitempty"`
	FinishedAt        string `json:"finished_at,omitempty"`
	Error             string `json:"error,omitempty"`
}

// IngestRunFilter scopes ingest run listing.
type IngestRunFilter struct {
	RuntimeID string
	Status    string
	Limit     int
}
