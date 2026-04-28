package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

const closeTimeout = 5 * time.Second

var (
	_ ports.GraphStore           = (*Store)(nil)
	_ ports.ProjectionGraphStore = (*Store)(nil)
	_ ports.GraphQueryStore      = (*Store)(nil)
)

type Counts = graphstore.Counts
type Traversal = graphstore.Traversal
type IntegrityCheck = graphstore.IntegrityCheck
type PathPattern = graphstore.PathPattern
type Topology = graphstore.Topology

// Store is the Neo4j-backed graph projection store implementation.
type Store struct {
	driver      neo4jdriver.DriverWithContext
	database    string
	schemaMu    sync.Mutex
	schemaReady bool
}

// Open opens a Neo4j-backed graph projection store.
func Open(cfg config.GraphStoreConfig) (*Store, error) {
	uri := strings.TrimSpace(cfg.Neo4jURI)
	if uri == "" {
		return nil, errors.New("neo4j uri is required")
	}
	username := strings.TrimSpace(cfg.Neo4jUsername)
	if username == "" {
		return nil, errors.New("neo4j username is required")
	}
	password := strings.TrimSpace(cfg.Neo4jPassword)
	if password == "" {
		return nil, errors.New("neo4j password is required")
	}
	driver, err := neo4jdriver.NewDriverWithContext(uri, neo4jdriver.BasicAuth(username, password, ""))
	if err != nil {
		return nil, fmt.Errorf("open neo4j: %w", err)
	}
	return &Store{
		driver:   driver,
		database: strings.TrimSpace(cfg.Neo4jDatabase),
	}, nil
}

// Close closes the underlying driver.
func (s *Store) Close() error {
	return s.CloseContext(detachedContext{})
}

// CloseContext closes the underlying driver using the provided context.
func (s *Store) CloseContext(ctx context.Context) error {
	if s == nil || s.driver == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, closeTimeout)
	defer cancel()
	return s.driver.Close(ctx)
}

// Ping verifies that Neo4j can answer connectivity checks.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.driver == nil {
		return errors.New("neo4j is not configured")
	}
	if err := s.driver.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("verify neo4j connectivity: %w", err)
	}
	return nil
}

// Counts returns the current number of projected nodes and relationships.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	if err := s.requireDriver(); err != nil {
		return Counts{}, err
	}
	nodes, err := s.countQuery(ctx, "MATCH (e:entity) RETURN count(e) AS count", nil)
	if err != nil {
		return Counts{}, fmt.Errorf("count entity nodes: %w", err)
	}
	relations, err := s.countQuery(ctx, "MATCH (:entity)-[r:relation]->(:entity) RETURN count(r) AS count", nil)
	if err != nil {
		return Counts{}, fmt.Errorf("count relation edges: %w", err)
	}
	return Counts{Nodes: nodes, Relations: relations}, nil
}

// SampleTraversals returns a bounded set of traversable two-hop paths from the graph.
func (s *Store) SampleTraversals(ctx context.Context, limit int) ([]Traversal, error) {
	if err := s.requireDriver(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	records, err := s.readRecords(ctx,
		"MATCH (src:entity)-[left:relation]->(mid:entity)-[right:relation]->(dst:entity) "+
			"RETURN src.urn AS from_urn, src.label AS from_label, left.relation AS first_relation, mid.urn AS via_urn, mid.label AS via_label, right.relation AS second_relation, dst.urn AS to_urn, dst.label AS to_label "+
			"ORDER BY src.urn, left.relation, mid.urn, right.relation, dst.urn LIMIT $limit",
		map[string]any{"limit": limit},
	)
	if err != nil {
		return nil, fmt.Errorf("sample graph traversals: %w", err)
	}
	traversals := make([]Traversal, 0, len(records))
	for _, record := range records {
		traversals = append(traversals, Traversal{
			FromURN:        recordString(record, "from_urn"),
			FromLabel:      recordString(record, "from_label"),
			FirstRelation:  recordString(record, "first_relation"),
			ViaURN:         recordString(record, "via_urn"),
			ViaLabel:       recordString(record, "via_label"),
			SecondRelation: recordString(record, "second_relation"),
			ToURN:          recordString(record, "to_urn"),
			ToLabel:        recordString(record, "to_label"),
		})
	}
	return traversals, nil
}

// PathPatterns returns bounded grouped two-hop path patterns from the graph.
func (s *Store) PathPatterns(ctx context.Context, limit int) ([]PathPattern, error) {
	if err := s.requireDriver(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	records, err := s.readRecords(ctx,
		"MATCH (src:entity)-[left:relation]->(mid:entity)-[right:relation]->(dst:entity) "+
			"RETURN src.entity_type AS from_type, left.relation AS first_relation, mid.entity_type AS via_type, right.relation AS second_relation, dst.entity_type AS to_type, count(*) AS count "+
			"ORDER BY count DESC, src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type LIMIT $limit",
		map[string]any{"limit": limit},
	)
	if err != nil {
		return nil, fmt.Errorf("query graph path patterns: %w", err)
	}
	patterns := make([]PathPattern, 0, len(records))
	for _, record := range records {
		patterns = append(patterns, PathPattern{
			FromType:       recordString(record, "from_type"),
			FirstRelation:  recordString(record, "first_relation"),
			ViaType:        recordString(record, "via_type"),
			SecondRelation: recordString(record, "second_relation"),
			ToType:         recordString(record, "to_type"),
			Count:          recordInt64(record, "count"),
		})
	}
	return patterns, nil
}

// Topology returns connectivity-class counts for nodes in the graph.
func (s *Store) Topology(ctx context.Context) (Topology, error) {
	if err := s.requireDriver(); err != nil {
		return Topology{}, err
	}
	urns, err := s.entityURNs(ctx)
	if err != nil {
		return Topology{}, err
	}
	edges, err := s.graphEdges(ctx)
	if err != nil {
		return Topology{}, err
	}
	inDegree := make(map[string]int64, len(urns))
	outDegree := make(map[string]int64, len(urns))
	for _, urn := range urns {
		inDegree[urn] = 0
		outDegree[urn] = 0
	}
	for _, edge := range edges {
		if strings.TrimSpace(edge.FromURN) != "" {
			outDegree[edge.FromURN]++
		}
		if strings.TrimSpace(edge.ToURN) != "" {
			inDegree[edge.ToURN]++
		}
	}
	var topology Topology
	for _, urn := range urns {
		incoming := inDegree[urn]
		outgoing := outDegree[urn]
		switch {
		case incoming == 0 && outgoing == 0:
			topology.Isolated++
		case incoming == 0:
			topology.SourcesOnly++
		case outgoing == 0:
			topology.SinksOnly++
		default:
			topology.Intermediates++
		}
	}
	return topology, nil
}

// IntegrityChecks returns a fixed set of graph invariant checks.
func (s *Store) IntegrityChecks(ctx context.Context) ([]IntegrityCheck, error) {
	if err := s.requireDriver(); err != nil {
		return nil, err
	}
	checks := []IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0},
		{Name: "blank_entity_labels", Expected: 0},
		{Name: "blank_entity_types", Expected: 0},
		{Name: "blank_relation_types", Expected: 0},
		{Name: "self_referential_relations", Expected: 0},
	}
	queries := []string{
		"MATCH (src:entity)-[r:relation]->(dst:entity) WHERE src.tenant_id <> dst.tenant_id OR src.tenant_id <> r.tenant_id OR dst.tenant_id <> r.tenant_id RETURN count(r) AS count",
		"MATCH (e:entity) WHERE e.label = '' RETURN count(e) AS count",
		"MATCH (e:entity) WHERE e.entity_type = '' RETURN count(e) AS count",
		"MATCH (:entity)-[r:relation]->(:entity) WHERE r.relation = '' RETURN count(r) AS count",
		"MATCH (src:entity)-[r:relation]->(dst:entity) WHERE src.urn = dst.urn RETURN count(r) AS count",
	}
	for index, query := range queries {
		actual, err := s.countQuery(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		checks[index].Actual = actual
		checks[index].Passed = actual == checks[index].Expected
	}
	return checks, nil
}

// UpsertProjectedEntity upserts one normalized entity in the graph store.
func (s *Store) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return errors.New("projected entity is required")
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return errors.New("projected entity urn is required")
	}
	tenantID := strings.TrimSpace(entity.TenantID)
	if tenantID == "" {
		return errors.New("projected entity tenant id is required")
	}
	sourceID := strings.TrimSpace(entity.SourceID)
	if sourceID == "" {
		return errors.New("projected entity source id is required")
	}
	entityType := strings.TrimSpace(entity.EntityType)
	if entityType == "" {
		return errors.New("projected entity type is required")
	}
	if err := s.requireDriver(); err != nil {
		return err
	}
	if err := s.ensureProjectionSchema(ctx); err != nil {
		return err
	}
	attributesJSON, err := graphAttributesJSON(entity.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected entity attributes: %w", err)
	}
	label := strings.TrimSpace(entity.Label)
	if label == "" {
		label = urn
	}
	if err := s.write(ctx,
		"MERGE (e:entity {urn: $urn}) "+
			"SET e.tenant_id = $tenant_id, e.source_id = $source_id, e.entity_type = $entity_type, e.label = $label, e.attributes_json = $attributes_json",
		map[string]any{
			"urn":             urn,
			"tenant_id":       tenantID,
			"source_id":       sourceID,
			"entity_type":     entityType,
			"label":           label,
			"attributes_json": attributesJSON,
		},
	); err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	return nil
}

// UpsertProjectedLink upserts one normalized link in the graph store.
func (s *Store) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return errors.New("projected link is required")
	}
	fromURN := strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return errors.New("projected link from urn is required")
	}
	toURN := strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return errors.New("projected link to urn is required")
	}
	relation := strings.TrimSpace(link.Relation)
	if relation == "" {
		return errors.New("projected link relation is required")
	}
	tenantID := strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return errors.New("projected link tenant id is required")
	}
	sourceID := strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return errors.New("projected link source id is required")
	}
	if err := s.requireDriver(); err != nil {
		return err
	}
	if err := s.ensureProjectionSchema(ctx); err != nil {
		return err
	}
	attributesJSON, err := graphAttributesJSON(link.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected link attributes: %w", err)
	}
	if err := s.write(ctx,
		"MATCH (src:entity {urn: $from_urn}), (dst:entity {urn: $to_urn}) "+
			"MERGE (src)-[r:relation {relation: $relation}]->(dst) "+
			"SET r.tenant_id = $tenant_id, r.source_id = $source_id, r.attributes_json = $attributes_json",
		map[string]any{
			"from_urn":        fromURN,
			"to_urn":          toURN,
			"relation":        relation,
			"tenant_id":       tenantID,
			"source_id":       sourceID,
			"attributes_json": attributesJSON,
		},
	); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

func (s *Store) ensureProjectionSchema(ctx context.Context) error {
	if err := s.requireDriver(); err != nil {
		return err
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemaReady {
		return nil
	}
	if err := s.write(ctx, "CREATE CONSTRAINT entity_urn IF NOT EXISTS FOR (e:entity) REQUIRE e.urn IS UNIQUE", nil); err != nil {
		return fmt.Errorf("create entity urn constraint: %w", err)
	}
	if err := s.write(ctx, "CREATE INDEX relation_type IF NOT EXISTS FOR ()-[r:relation]-() ON (r.relation)", nil); err != nil {
		return fmt.Errorf("create relation type index: %w", err)
	}
	s.schemaReady = true
	return nil
}

func (s *Store) requireDriver() error {
	if s == nil || s.driver == nil {
		return errors.New("neo4j is not configured")
	}
	return nil
}

func (s *Store) newSession(ctx context.Context, accessMode neo4jdriver.AccessMode) neo4jdriver.SessionWithContext {
	return s.driver.NewSession(ctx, neo4jdriver.SessionConfig{
		AccessMode:   accessMode,
		DatabaseName: s.database,
	})
}

func (s *Store) write(ctx context.Context, query string, params map[string]any) error {
	session := s.newSession(ctx, neo4jdriver.AccessModeWrite)
	defer func() {
		_ = session.Close(ctx)
	}()
	result, err := session.Run(ctx, query, params)
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

func (s *Store) readRecords(ctx context.Context, query string, params map[string]any) ([]*neo4jdriver.Record, error) {
	session := s.newSession(ctx, neo4jdriver.AccessModeRead)
	defer func() {
		_ = session.Close(ctx)
	}()
	result, err := session.Run(ctx, query, params)
	if err != nil {
		return nil, err
	}
	return result.Collect(ctx)
}

func (s *Store) countQuery(ctx context.Context, query string, params map[string]any) (int64, error) {
	records, err := s.readRecords(ctx, query, params)
	if err != nil {
		return 0, fmt.Errorf("count query: %w", err)
	}
	if len(records) == 0 {
		return 0, nil
	}
	return recordInt64(records[0], "count"), nil
}

func graphAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

type graphEdge struct {
	FromURN string
	ToURN   string
}

func (s *Store) entityURNs(ctx context.Context) ([]string, error) {
	records, err := s.readRecords(ctx, "MATCH (e:entity) RETURN e.urn AS urn ORDER BY e.urn", nil)
	if err != nil {
		return nil, fmt.Errorf("query entity urns: %w", err)
	}
	urns := make([]string, 0, len(records))
	for _, record := range records {
		urns = append(urns, recordString(record, "urn"))
	}
	return urns, nil
}

func (s *Store) graphEdges(ctx context.Context) ([]graphEdge, error) {
	records, err := s.readRecords(ctx, "MATCH (src:entity)-[:relation]->(dst:entity) RETURN src.urn AS from_urn, dst.urn AS to_urn", nil)
	if err != nil {
		return nil, fmt.Errorf("query graph edges: %w", err)
	}
	edges := make([]graphEdge, 0, len(records))
	for _, record := range records {
		edges = append(edges, graphEdge{
			FromURN: recordString(record, "from_urn"),
			ToURN:   recordString(record, "to_urn"),
		})
	}
	return edges, nil
}

func recordString(record *neo4jdriver.Record, key string) string {
	value, ok := record.Get(key)
	if !ok || value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func recordInt64(record *neo4jdriver.Record, key string) int64 {
	value, ok := record.Get(key)
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

type detachedContext struct{}

func (detachedContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (detachedContext) Done() <-chan struct{} {
	return nil
}

func (detachedContext) Err() error {
	return nil
}

func (detachedContext) Value(any) any {
	return nil
}
