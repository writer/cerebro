package kuzu

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	kuzudb "github.com/kuzudb/go-kuzu"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

// Store is the Kuzu-backed graph projection store implementation.
type Store struct {
	db          *sql.DB
	schemaMu    sync.Mutex
	schemaReady bool
}

type Counts = graphstore.Counts
type Traversal = graphstore.Traversal
type IntegrityCheck = graphstore.IntegrityCheck
type PathPattern = graphstore.PathPattern
type Topology = graphstore.Topology

// Open opens a Kuzu-backed graph projection store.
func Open(cfg config.GraphStoreConfig) (*Store, error) {
	rawPath := strings.TrimSpace(cfg.KuzuPath)
	if rawPath == "" {
		return nil, errors.New("kuzu path is required")
	}
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return nil, fmt.Errorf("resolve kuzu path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create kuzu parent directory: %w", err)
	}
	dsn := "kuzu://" + filepath.ToSlash(absPath)
	db, err := sql.Open(kuzudb.Name, dsn)
	if err != nil {
		return nil, fmt.Errorf("open kuzu: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping verifies that Kuzu can answer a trivial query.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	var result int64
	if err := s.db.QueryRowContext(ctx, "RETURN 1 AS ok").Scan(&result); err != nil {
		return fmt.Errorf("query kuzu: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("unexpected kuzu ping result %d", result)
	}
	return nil
}

// Counts returns the current number of projected nodes and relationships.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	if s == nil || s.db == nil {
		return Counts{}, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return Counts{}, err
	}
	if !tables["entity"] {
		return Counts{}, nil
	}
	var counts Counts
	if err := s.db.QueryRowContext(ctx, "MATCH (e:entity) RETURN COUNT(e) AS count").Scan(&counts.Nodes); err != nil {
		return Counts{}, fmt.Errorf("count entity nodes: %w", err)
	}
	if !tables["relation"] {
		return counts, nil
	}
	if err := s.db.QueryRowContext(ctx, "MATCH (src:entity)-[r:relation]->(dst:entity) RETURN COUNT(r) AS count").Scan(&counts.Relations); err != nil {
		return Counts{}, fmt.Errorf("count relation edges: %w", err)
	}
	return counts, nil
}

// SampleTraversals returns a bounded set of traversable two-hop paths from the local graph.
func (s *Store) SampleTraversals(ctx context.Context, limit int) (_ []Traversal, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("kuzu is not configured")
	}
	if limit <= 0 {
		return nil, nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return nil, err
	}
	if !tables["entity"] || !tables["relation"] {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		"MATCH (src:entity)-[left:relation]->(mid:entity)-[right:relation]->(dst:entity) "+
			"RETURN src.urn, src.label, left.relation, mid.urn, mid.label, right.relation, dst.urn, dst.label "+
			"ORDER BY src.urn, left.relation, mid.urn, right.relation, dst.urn LIMIT %d",
		limit,
	))
	if err != nil {
		return nil, fmt.Errorf("sample graph traversals: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close graph traversals: %w", closeErr)
		}
	}()

	traversals := make([]Traversal, 0, limit)
	for rows.Next() {
		var traversal Traversal
		if err := rows.Scan(
			&traversal.FromURN,
			&traversal.FromLabel,
			&traversal.FirstRelation,
			&traversal.ViaURN,
			&traversal.ViaLabel,
			&traversal.SecondRelation,
			&traversal.ToURN,
			&traversal.ToLabel,
		); err != nil {
			return nil, fmt.Errorf("scan graph traversal: %w", err)
		}
		traversals = append(traversals, traversal)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph traversals: %w", err)
	}
	return traversals, nil
}

// PathPatterns returns bounded grouped two-hop path patterns from the local graph.
func (s *Store) PathPatterns(ctx context.Context, limit int) (_ []PathPattern, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("kuzu is not configured")
	}
	if limit <= 0 {
		return nil, nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return nil, err
	}
	if !tables["entity"] || !tables["relation"] {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		"MATCH (src:entity)-[left:relation]->(mid:entity)-[right:relation]->(dst:entity) "+
			"RETURN src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type, COUNT(*) "+
			"ORDER BY COUNT(*) DESC, src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type LIMIT %d",
		limit,
	))
	if err != nil {
		return nil, fmt.Errorf("query graph path patterns: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close graph path patterns: %w", closeErr)
		}
	}()

	patterns := make([]PathPattern, 0, limit)
	for rows.Next() {
		var pattern PathPattern
		if err := rows.Scan(
			&pattern.FromType,
			&pattern.FirstRelation,
			&pattern.ViaType,
			&pattern.SecondRelation,
			&pattern.ToType,
			&pattern.Count,
		); err != nil {
			return nil, fmt.Errorf("scan graph path pattern: %w", err)
		}
		patterns = append(patterns, pattern)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph path patterns: %w", err)
	}
	return patterns, nil
}

// Topology returns connectivity-class counts for nodes in the local graph.
func (s *Store) Topology(ctx context.Context) (Topology, error) {
	if s == nil || s.db == nil {
		return Topology{}, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return Topology{}, err
	}
	if !tables["entity"] {
		return Topology{}, nil
	}
	urns, err := s.entityURNs(ctx)
	if err != nil {
		return Topology{}, err
	}
	edges, err := s.graphEdges(ctx, tables["relation"])
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

// IntegrityChecks returns a fixed set of local graph invariant checks.
func (s *Store) IntegrityChecks(ctx context.Context) ([]IntegrityCheck, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("kuzu is not configured")
	}
	checks := []IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0},
		{Name: "blank_entity_labels", Expected: 0},
		{Name: "blank_entity_types", Expected: 0},
		{Name: "blank_relation_types", Expected: 0},
		{Name: "self_referential_relations", Expected: 0},
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return nil, err
	}
	if !tables["entity"] || !tables["relation"] {
		for index := range checks {
			checks[index].Passed = true
		}
		return checks, nil
	}
	queries := []string{
		"MATCH (src:entity)-[r:relation]->(dst:entity) WHERE src.tenant_id <> dst.tenant_id OR src.tenant_id <> r.tenant_id OR dst.tenant_id <> r.tenant_id RETURN COUNT(r)",
		"MATCH (e:entity) WHERE e.label = '' RETURN COUNT(e)",
		"MATCH (e:entity) WHERE e.entity_type = '' RETURN COUNT(e)",
		"MATCH (src:entity)-[r:relation]->(dst:entity) WHERE r.relation = '' RETURN COUNT(r)",
		"MATCH (src:entity)-[r:relation]->(dst:entity) WHERE src.urn = dst.urn RETURN COUNT(r)",
	}
	for index, query := range queries {
		actual, err := s.countQuery(ctx, query)
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
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
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
	statement := fmt.Sprintf(
		"MERGE (e:entity {urn: %s}) SET e.tenant_id = %s, e.source_id = %s, e.entity_type = %s, e.label = %s, e.attributes_json = %s",
		cypherString(urn),
		cypherString(tenantID),
		cypherString(sourceID),
		cypherString(entityType),
		cypherString(label),
		cypherString(attributesJSON),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
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
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	if err := s.ensureProjectionSchema(ctx); err != nil {
		return err
	}
	attributesJSON, err := graphAttributesJSON(link.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected link attributes: %w", err)
	}
	statement := fmt.Sprintf(
		"MATCH (src:entity {urn: %s}), (dst:entity {urn: %s}) MERGE (src)-[r:relation {relation: %s}]->(dst) SET r.tenant_id = %s, r.source_id = %s, r.attributes_json = %s",
		cypherString(fromURN),
		cypherString(toURN),
		cypherString(relation),
		cypherString(tenantID),
		cypherString(sourceID),
		cypherString(attributesJSON),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

func (s *Store) ensureProjectionSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemaReady {
		return nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return err
	}
	if !tables["entity"] {
		if _, err := s.db.ExecContext(ctx, "CREATE NODE TABLE entity(urn STRING, tenant_id STRING, source_id STRING, entity_type STRING, label STRING, attributes_json STRING, PRIMARY KEY (urn))"); err != nil {
			return fmt.Errorf("create entity node table: %w", err)
		}
	}
	if !tables["relation"] {
		if _, err := s.db.ExecContext(ctx, "CREATE REL TABLE relation(FROM entity TO entity, relation STRING, tenant_id STRING, source_id STRING, attributes_json STRING)"); err != nil {
			return fmt.Errorf("create relation table: %w", err)
		}
	}
	s.schemaReady = true
	return nil
}

func (s *Store) graphTables(ctx context.Context) (_ map[string]bool, err error) {
	rows, err := s.db.QueryContext(ctx, "CALL show_tables() RETURN *")
	if err != nil {
		return nil, fmt.Errorf("show kuzu tables: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close kuzu tables: %w", closeErr)
		}
	}()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("list kuzu table columns: %w", err)
	}
	tables := make(map[string]bool)
	for rows.Next() {
		values := make([]any, len(columns))
		scanArgs := make([]any, len(columns))
		for i := range values {
			scanArgs[i] = &values[i]
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("scan kuzu tables: %w", err)
		}
		for idx, name := range columns {
			if name != "name" {
				continue
			}
			tableName := stringColumn(values[idx])
			if tableName != "" {
				tables[tableName] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate kuzu tables: %w", err)
	}
	return tables, nil
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

func (s *Store) countQuery(ctx context.Context, query string) (int64, error) {
	var count int64
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("count query: %w", err)
	}
	return count, nil
}

type graphEdge struct {
	FromURN string
	ToURN   string
}

func (s *Store) entityURNs(ctx context.Context) (_ []string, err error) {
	rows, err := s.db.QueryContext(ctx, "MATCH (e:entity) RETURN e.urn ORDER BY e.urn")
	if err != nil {
		return nil, fmt.Errorf("query entity urns: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close entity urns: %w", closeErr)
		}
	}()
	var urns []string
	for rows.Next() {
		var urn string
		if err := rows.Scan(&urn); err != nil {
			return nil, fmt.Errorf("scan entity urn: %w", err)
		}
		urns = append(urns, urn)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate entity urns: %w", err)
	}
	return urns, nil
}

func (s *Store) graphEdges(ctx context.Context, relationsReady bool) (_ []graphEdge, err error) {
	if !relationsReady {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, "MATCH (src:entity)-[r:relation]->(dst:entity) RETURN src.urn, dst.urn")
	if err != nil {
		return nil, fmt.Errorf("query graph edges: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close graph edges: %w", closeErr)
		}
	}()
	var edges []graphEdge
	for rows.Next() {
		var edge graphEdge
		if err := rows.Scan(&edge.FromURN, &edge.ToURN); err != nil {
			return nil, fmt.Errorf("scan graph edge: %w", err)
		}
		edges = append(edges, edge)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate graph edges: %w", err)
	}
	return edges, nil
}

func stringColumn(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

func cypherString(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"'", "\\'",
		"\n", "\\n",
		"\r", "\\r",
	)
	return "'" + replacer.Replace(value) + "'"
}
