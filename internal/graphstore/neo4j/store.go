package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

const defaultDatabase = "neo4j"
const defaultIngestRunListLimit = 25

// Store is a Neo4j/Aura-backed graph projection store implementation.
type Store struct {
	driver   neo4jdriver.DriverWithContext
	database string

	mu          sync.Mutex
	schemaReady bool
}

type Counts = graphstore.Counts
type Traversal = graphstore.Traversal
type IntegrityCheck = graphstore.IntegrityCheck
type PathPattern = graphstore.PathPattern
type Topology = graphstore.Topology
type IngestCheckpoint = graphstore.IngestCheckpoint
type IngestRun = graphstore.IngestRun
type IngestRunFilter = graphstore.IngestRunFilter

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
	if cfg.Neo4jPassword == "" {
		return nil, errors.New("neo4j password is required")
	}
	database := strings.TrimSpace(cfg.Neo4jDatabase)
	if database == "" {
		database = defaultDatabase
	}
	driver, err := neo4jdriver.NewDriverWithContext(uri, neo4jdriver.BasicAuth(username, cfg.Neo4jPassword, ""))
	if err != nil {
		return nil, fmt.Errorf("open neo4j: %w", err)
	}
	return &Store{driver: driver, database: database}, nil
}

// CloseContext closes the underlying driver.
func (s *Store) CloseContext(ctx context.Context) error {
	if s == nil || s.driver == nil {
		return nil
	}
	return s.driver.Close(ctx)
}

// Ping verifies that Neo4j can answer a trivial query.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.driver == nil {
		return errors.New("neo4j is not configured")
	}
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		value, err := queryOneValue(ctx, tx, "RETURN 1 AS ok", nil)
		if err != nil {
			return nil, err
		}
		if toInt64(value) != 1 {
			return nil, fmt.Errorf("unexpected neo4j ping result %v", value)
		}
		return nil, nil
	}); err != nil {
		return fmt.Errorf("query neo4j: %w", err)
	}
	return nil
}

// Counts returns the current number of projected nodes and relationships.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	if err := s.requireConfigured(); err != nil {
		return Counts{}, err
	}
	var counts Counts
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		var err error
		counts.Nodes, err = countQuery(ctx, tx, "MATCH (e:Entity) RETURN count(e)", nil)
		if err != nil {
			return nil, fmt.Errorf("count entity nodes: %w", err)
		}
		counts.Relations, err = countQuery(ctx, tx, "MATCH (:Entity)-[r:RELATION]->(:Entity) RETURN count(r)", nil)
		if err != nil {
			return nil, fmt.Errorf("count relation edges: %w", err)
		}
		return nil, nil
	}); err != nil {
		return Counts{}, err
	}
	return counts, nil
}

// SampleTraversals returns a bounded set of traversable two-hop paths from the graph.
func (s *Store) SampleTraversals(ctx context.Context, limit int) (_ []Traversal, err error) {
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	var traversals []Traversal
	query := fmt.Sprintf(`MATCH (src:Entity)-[left:RELATION]->(mid:Entity)-[right:RELATION]->(dst:Entity)
RETURN src.urn, src.label, left.relation, mid.urn, mid.label, right.relation, dst.urn, dst.label
ORDER BY src.urn, left.relation, mid.urn, right.relation, dst.urn LIMIT %d`, limit)
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		for result.Next(ctx) {
			record := result.Record()
			traversals = append(traversals, Traversal{
				FromURN:        stringValue(record.Values[0]),
				FromLabel:      stringValue(record.Values[1]),
				FirstRelation:  stringValue(record.Values[2]),
				ViaURN:         stringValue(record.Values[3]),
				ViaLabel:       stringValue(record.Values[4]),
				SecondRelation: stringValue(record.Values[5]),
				ToURN:          stringValue(record.Values[6]),
				ToLabel:        stringValue(record.Values[7]),
			})
		}
		return nil, result.Err()
	}); err != nil {
		return nil, fmt.Errorf("sample graph traversals: %w", err)
	}
	return traversals, nil
}

// PathPatterns returns bounded grouped two-hop path patterns from the graph.
func (s *Store) PathPatterns(ctx context.Context, limit int) (_ []PathPattern, err error) {
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	var patterns []PathPattern
	query := fmt.Sprintf(`MATCH (src:Entity)-[left:RELATION]->(mid:Entity)-[right:RELATION]->(dst:Entity)
RETURN src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type, count(*)
ORDER BY count(*) DESC, src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type LIMIT %d`, limit)
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, nil)
		if err != nil {
			return nil, err
		}
		for result.Next(ctx) {
			record := result.Record()
			patterns = append(patterns, PathPattern{
				FromType:       stringValue(record.Values[0]),
				FirstRelation:  stringValue(record.Values[1]),
				ViaType:        stringValue(record.Values[2]),
				SecondRelation: stringValue(record.Values[3]),
				ToType:         stringValue(record.Values[4]),
				Count:          toInt64(record.Values[5]),
			})
		}
		return nil, result.Err()
	}); err != nil {
		return nil, fmt.Errorf("query graph path patterns: %w", err)
	}
	return patterns, nil
}

// Topology returns connectivity-class counts for nodes in the graph.
func (s *Store) Topology(ctx context.Context) (Topology, error) {
	if err := s.requireConfigured(); err != nil {
		return Topology{}, err
	}
	var topology Topology
	queries := []struct {
		assign func(int64)
		query  string
	}{
		{func(v int64) { topology.Isolated = v }, "MATCH (e:Entity) WHERE NOT (e)-[:RELATION]-() RETURN count(e)"},
		{func(v int64) { topology.SourcesOnly = v }, "MATCH (e:Entity) WHERE NOT (:Entity)-[:RELATION]->(e) AND (e)-[:RELATION]->(:Entity) RETURN count(e)"},
		{func(v int64) { topology.SinksOnly = v }, "MATCH (e:Entity) WHERE (:Entity)-[:RELATION]->(e) AND NOT (e)-[:RELATION]->(:Entity) RETURN count(e)"},
		{func(v int64) { topology.Intermediates = v }, "MATCH (e:Entity) WHERE (:Entity)-[:RELATION]->(e) AND (e)-[:RELATION]->(:Entity) RETURN count(e)"},
	}
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		for _, item := range queries {
			value, err := countQuery(ctx, tx, item.query, nil)
			if err != nil {
				return nil, err
			}
			item.assign(value)
		}
		return nil, nil
	}); err != nil {
		return Topology{}, fmt.Errorf("query graph topology: %w", err)
	}
	return topology, nil
}

// IntegrityChecks returns a fixed set of graph invariant checks.
func (s *Store) IntegrityChecks(ctx context.Context) ([]IntegrityCheck, error) {
	if err := s.requireConfigured(); err != nil {
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
		"MATCH (src:Entity)-[r:RELATION]->(dst:Entity) WHERE src.tenant_id <> dst.tenant_id OR src.tenant_id <> r.tenant_id OR dst.tenant_id <> r.tenant_id RETURN count(r)",
		"MATCH (e:Entity) WHERE coalesce(e.label, '') = '' RETURN count(e)",
		"MATCH (e:Entity) WHERE coalesce(e.entity_type, '') = '' RETURN count(e)",
		"MATCH (:Entity)-[r:RELATION]->(:Entity) WHERE coalesce(r.relation, '') = '' RETURN count(r)",
		"MATCH (src:Entity)-[r:RELATION]->(dst:Entity) WHERE src.urn = dst.urn RETURN count(r)",
	}
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		for i, query := range queries {
			actual, err := countQuery(ctx, tx, query, nil)
			if err != nil {
				return nil, err
			}
			checks[i].Actual = actual
			checks[i].Passed = actual == checks[i].Expected
		}
		return nil, nil
	}); err != nil {
		return nil, fmt.Errorf("query graph integrity checks: %w", err)
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
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	label := strings.TrimSpace(entity.Label)
	if label == "" {
		label = urn
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		attributes, err := s.mergedEntityAttributes(ctx, tx, urn, entity.Attributes)
		if err != nil {
			return nil, fmt.Errorf("load projected entity %q attributes: %w", urn, err)
		}
		attributesJSON, err := graphAttributesJSON(attributes)
		if err != nil {
			return nil, fmt.Errorf("marshal projected entity attributes: %w", err)
		}
		return consume(ctx, tx, `MERGE (e:Entity {urn: $urn})
SET e.tenant_id = $tenant_id,
    e.source_id = $source_id,
    e.entity_type = $entity_type,
    e.label = $label,
    e.attributes_json = $attributes_json`, map[string]any{
			"urn":             urn,
			"tenant_id":       tenantID,
			"source_id":       sourceID,
			"entity_type":     entityType,
			"label":           label,
			"attributes_json": attributesJSON,
		})
	})
	if err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	return nil
}

// UpsertProjectedLink upserts one normalized link in the graph store.
func (s *Store) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	fromURN, toURN, relation, tenantID, sourceID, err := validateProjectedLink(link)
	if err != nil {
		return err
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		attributes, err := s.mergedLinkAttributes(ctx, tx, fromURN, relation, toURN, link.Attributes)
		if err != nil {
			return nil, fmt.Errorf("load projected link %q %q %q attributes: %w", fromURN, relation, toURN, err)
		}
		attributesJSON, err := graphAttributesJSON(attributes)
		if err != nil {
			return nil, fmt.Errorf("marshal projected link attributes: %w", err)
		}
		return consume(ctx, tx, `MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
MERGE (src)-[r:RELATION {relation: $relation}]->(dst)
SET r.tenant_id = $tenant_id,
    r.source_id = $source_id,
    r.attributes_json = $attributes_json`, map[string]any{
			"from_urn":        fromURN,
			"to_urn":          toURN,
			"relation":        relation,
			"tenant_id":       tenantID,
			"source_id":       sourceID,
			"attributes_json": attributesJSON,
		})
	})
	if err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// DeleteProjectedLink removes one normalized link from the graph store.
func (s *Store) DeleteProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	fromURN, toURN, relation, _, _, err := validateProjectedLinkIdentity(link)
	if err != nil {
		return err
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err = s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn}) DELETE r`, map[string]any{
			"from_urn": fromURN,
			"to_urn":   toURN,
			"relation": relation,
		})
	})
	if err != nil {
		return fmt.Errorf("delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// GetEntityNeighborhood returns one bounded root-centered graph neighborhood.
func (s *Store) GetEntityNeighborhood(ctx context.Context, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	normalizedRootURN := strings.TrimSpace(rootURN)
	if normalizedRootURN == "" {
		return nil, errors.New("root urn is required")
	}
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	neighborhood := &ports.EntityNeighborhood{
		Neighbors: []*ports.NeighborhoodNode{},
		Relations: []*ports.NeighborhoodRelation{},
	}
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		root, err := lookupNeighborhoodNode(ctx, tx, normalizedRootURN)
		if err != nil {
			return nil, err
		}
		neighborhood.Root = root
		if limit <= 0 {
			return nil, nil
		}
		neighbors := make(map[string]*ports.NeighborhoodNode)
		relations := make(map[string]*ports.NeighborhoodRelation)
		remaining, err := collectNeighborhoodRows(ctx, tx, `MATCH (root:Entity {urn: $root_urn})-[r:RELATION]->(neighbor:Entity)
RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label,
       root.urn AS from_urn, r.relation AS relation_type, neighbor.urn AS to_urn, coalesce(r.attributes_json, '{}') AS attributes_json
ORDER BY neighbor.urn, r.relation LIMIT $limit`, map[string]any{"root_urn": normalizedRootURN, "limit": limit}, limit, neighbors, relations)
		if err != nil {
			return nil, err
		}
		if remaining > 0 {
			if _, err := collectNeighborhoodRows(ctx, tx, `MATCH (neighbor:Entity)-[r:RELATION]->(root:Entity {urn: $root_urn})
RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label,
       neighbor.urn AS from_urn, r.relation AS relation_type, root.urn AS to_urn, coalesce(r.attributes_json, '{}') AS attributes_json
ORDER BY neighbor.urn, r.relation LIMIT $limit`, map[string]any{"root_urn": normalizedRootURN, "limit": remaining}, remaining, neighbors, relations); err != nil {
				return nil, err
			}
		}
		neighborhood.Neighbors = neighborhoodNodes(neighbors)
		neighborhood.Relations = neighborhoodRelations(relations)
		return nil, nil
	}); err != nil {
		return nil, err
	}
	return neighborhood, nil
}

// GetIngestCheckpoint returns one persisted graph ingest checkpoint.
func (s *Store) GetIngestCheckpoint(ctx context.Context, id string) (IngestCheckpoint, bool, error) {
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return IngestCheckpoint{}, false, errors.New("ingest checkpoint id is required")
	}
	if err := s.requireConfigured(); err != nil {
		return IngestCheckpoint{}, false, err
	}
	var checkpoint IngestCheckpoint
	var found bool
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `MATCH (c:IngestCheckpoint {id: $id})
RETURN c.id, c.source_id, coalesce(c.tenant_id, ''), coalesce(c.config_hash, ''), coalesce(c.cursor_opaque, ''),
       coalesce(c.checkpoint_opaque, ''), coalesce(c.completed, false), coalesce(c.pages_read, 0), coalesce(c.events_read, 0), coalesce(c.updated_at, '')`, map[string]any{"id": normalizedID})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		record := result.Record()
		checkpoint = IngestCheckpoint{
			ID:               stringValue(record.Values[0]),
			SourceID:         stringValue(record.Values[1]),
			TenantID:         stringValue(record.Values[2]),
			ConfigHash:       stringValue(record.Values[3]),
			CursorOpaque:     stringValue(record.Values[4]),
			CheckpointOpaque: stringValue(record.Values[5]),
			Completed:        boolValue(record.Values[6]),
			PagesRead:        toInt64(record.Values[7]),
			EventsRead:       toInt64(record.Values[8]),
			UpdatedAt:        stringValue(record.Values[9]),
		}
		found = true
		return nil, result.Err()
	}); err != nil {
		return IngestCheckpoint{}, false, fmt.Errorf("query ingest checkpoint %q: %w", normalizedID, err)
	}
	return checkpoint, found, nil
}

// PutIngestCheckpoint upserts one durable graph ingest checkpoint.
func (s *Store) PutIngestCheckpoint(ctx context.Context, checkpoint IngestCheckpoint) error {
	checkpoint.ID = strings.TrimSpace(checkpoint.ID)
	if checkpoint.ID == "" {
		return errors.New("ingest checkpoint id is required")
	}
	checkpoint.SourceID = strings.TrimSpace(checkpoint.SourceID)
	if checkpoint.SourceID == "" {
		return errors.New("ingest checkpoint source id is required")
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MERGE (c:IngestCheckpoint {id: $id})
SET c.source_id = $source_id,
    c.tenant_id = $tenant_id,
    c.config_hash = $config_hash,
    c.cursor_opaque = $cursor_opaque,
    c.checkpoint_opaque = $checkpoint_opaque,
    c.completed = $completed,
    c.pages_read = $pages_read,
    c.events_read = $events_read,
    c.updated_at = $updated_at`, map[string]any{
			"id":                checkpoint.ID,
			"source_id":         checkpoint.SourceID,
			"tenant_id":         strings.TrimSpace(checkpoint.TenantID),
			"config_hash":       strings.TrimSpace(checkpoint.ConfigHash),
			"cursor_opaque":     strings.TrimSpace(checkpoint.CursorOpaque),
			"checkpoint_opaque": strings.TrimSpace(checkpoint.CheckpointOpaque),
			"completed":         checkpoint.Completed,
			"pages_read":        checkpoint.PagesRead,
			"events_read":       checkpoint.EventsRead,
			"updated_at":        strings.TrimSpace(checkpoint.UpdatedAt),
		})
	})
	if err != nil {
		return fmt.Errorf("upsert ingest checkpoint %q: %w", checkpoint.ID, err)
	}
	return nil
}

// PutIngestRun upserts one operational graph ingest run.
func (s *Store) PutIngestRun(ctx context.Context, run IngestRun) error {
	run.ID = strings.TrimSpace(run.ID)
	if run.ID == "" {
		return errors.New("ingest run id is required")
	}
	run.Status = strings.TrimSpace(run.Status)
	if run.Status == "" {
		return errors.New("ingest run status is required")
	}
	if !validIngestRunStatus(run.Status) {
		return fmt.Errorf("unsupported ingest run status %q", run.Status)
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MERGE (r:IngestRun {id: $id})
SET r.runtime_id = $runtime_id,
    r.source_id = $source_id,
    r.tenant_id = $tenant_id,
    r.checkpoint_id = $checkpoint_id,
    r.status = $status,
    r.trigger = $trigger,
    r.pages_read = $pages_read,
    r.events_read = $events_read,
    r.entities_projected = $entities_projected,
    r.links_projected = $links_projected,
    r.graph_nodes_before = $graph_nodes_before,
    r.graph_links_before = $graph_links_before,
    r.graph_nodes_after = $graph_nodes_after,
    r.graph_links_after = $graph_links_after,
    r.started_at = $started_at,
    r.finished_at = $finished_at,
    r.error_message = $error_message`, map[string]any{
			"id":                 run.ID,
			"runtime_id":         strings.TrimSpace(run.RuntimeID),
			"source_id":          strings.TrimSpace(run.SourceID),
			"tenant_id":          strings.TrimSpace(run.TenantID),
			"checkpoint_id":      strings.TrimSpace(run.CheckpointID),
			"status":             run.Status,
			"trigger":            strings.TrimSpace(run.Trigger),
			"pages_read":         run.PagesRead,
			"events_read":        run.EventsRead,
			"entities_projected": run.EntitiesProjected,
			"links_projected":    run.LinksProjected,
			"graph_nodes_before": run.GraphNodesBefore,
			"graph_links_before": run.GraphLinksBefore,
			"graph_nodes_after":  run.GraphNodesAfter,
			"graph_links_after":  run.GraphLinksAfter,
			"started_at":         strings.TrimSpace(run.StartedAt),
			"finished_at":        strings.TrimSpace(run.FinishedAt),
			"error_message":      strings.TrimSpace(run.Error),
		})
	})
	if err != nil {
		return fmt.Errorf("upsert ingest run %q: %w", run.ID, err)
	}
	return nil
}

// GetIngestRun returns one operational graph ingest run.
func (s *Store) GetIngestRun(ctx context.Context, id string) (IngestRun, bool, error) {
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return IngestRun{}, false, errors.New("ingest run id is required")
	}
	if err := s.requireConfigured(); err != nil {
		return IngestRun{}, false, err
	}
	var run IngestRun
	var found bool
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, ingestRunReturnQuery("MATCH (r:IngestRun {id: $id})"), map[string]any{"id": normalizedID})
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		var scanErr error
		run, scanErr = scanIngestRunRecord(result.Record())
		if scanErr != nil {
			return nil, scanErr
		}
		found = true
		return nil, result.Err()
	}); err != nil {
		return IngestRun{}, false, fmt.Errorf("query ingest run %q: %w", normalizedID, err)
	}
	return run, found, nil
}

// ListIngestRuns returns recent operational graph ingest runs.
func (s *Store) ListIngestRuns(ctx context.Context, filter IngestRunFilter) (_ []IngestRun, err error) {
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit == 0 {
		limit = defaultIngestRunListLimit
	}
	if limit < 0 || limit > 500 {
		return nil, fmt.Errorf("ingest run limit must be between 1 and 500")
	}
	where := make([]string, 0, 2)
	params := map[string]any{}
	if runtimeID := strings.TrimSpace(filter.RuntimeID); runtimeID != "" {
		where = append(where, "r.runtime_id = $runtime_id")
		params["runtime_id"] = runtimeID
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		if !validIngestRunStatus(status) {
			return nil, fmt.Errorf("unsupported ingest run status %q", status)
		}
		where = append(where, "r.status = $status")
		params["status"] = status
	}
	prefix := "MATCH (r:IngestRun)"
	if len(where) > 0 {
		prefix += " WHERE " + strings.Join(where, " AND ")
	}
	query := ingestRunReturnQuery(prefix) + fmt.Sprintf(" ORDER BY coalesce(r.started_at, '') DESC, r.id DESC LIMIT %d", limit)
	var runs []IngestRun
	if _, err := s.read(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		for result.Next(ctx) {
			run, err := scanIngestRunRecord(result.Record())
			if err != nil {
				return nil, err
			}
			runs = append(runs, run)
		}
		return nil, result.Err()
	}); err != nil {
		return nil, fmt.Errorf("list ingest runs: %w", err)
	}
	return runs, nil
}

func (s *Store) requireConfigured() error {
	if s == nil || s.driver == nil {
		return errors.New("neo4j is not configured")
	}
	return nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	if err := s.requireConfigured(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schemaReady {
		return nil
	}
	statements := []string{
		"CREATE CONSTRAINT cerebro_entity_urn IF NOT EXISTS FOR (e:Entity) REQUIRE e.urn IS UNIQUE",
		"CREATE CONSTRAINT cerebro_checkpoint_id IF NOT EXISTS FOR (c:IngestCheckpoint) REQUIRE c.id IS UNIQUE",
		"CREATE CONSTRAINT cerebro_ingest_run_id IF NOT EXISTS FOR (r:IngestRun) REQUIRE r.id IS UNIQUE",
	}
	if _, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		for _, statement := range statements {
			if _, err := consume(ctx, tx, statement, nil); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}); err != nil {
		return fmt.Errorf("ensure neo4j schema: %w", err)
	}
	s.schemaReady = true
	return nil
}

func (s *Store) read(ctx context.Context, work neo4jdriver.ManagedTransactionWork) (any, error) {
	session := s.driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: s.database})
	defer func() { _ = session.Close(ctx) }()
	return session.ExecuteRead(ctx, work)
}

func (s *Store) write(ctx context.Context, work neo4jdriver.ManagedTransactionWork) (any, error) {
	session := s.driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: s.database})
	defer func() { _ = session.Close(ctx) }()
	return session.ExecuteWrite(ctx, work)
}

func consume(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any) (any, error) {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return nil, err
	}
	_, err = result.Consume(ctx)
	return nil, err
}

func queryOneValue(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any) (any, error) {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return nil, err
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("query returned no rows")
	}
	values := result.Record().Values
	if len(values) == 0 {
		return nil, errors.New("query returned no values")
	}
	return values[0], result.Err()
}

func countQuery(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any) (int64, error) {
	value, err := queryOneValue(ctx, tx, query, params)
	if err != nil {
		return 0, err
	}
	return toInt64(value), nil
}

func validateProjectedLink(link *ports.ProjectedLink) (fromURN string, toURN string, relation string, tenantID string, sourceID string, err error) {
	fromURN, toURN, relation, _, _, err = validateProjectedLinkIdentity(link)
	if err != nil {
		return "", "", "", "", "", err
	}
	tenantID = strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return "", "", "", "", "", errors.New("projected link tenant id is required")
	}
	sourceID = strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return "", "", "", "", "", errors.New("projected link source id is required")
	}
	return fromURN, toURN, relation, tenantID, sourceID, nil
}

func validateProjectedLinkIdentity(link *ports.ProjectedLink) (fromURN string, toURN string, relation string, tenantID string, sourceID string, err error) {
	if link == nil {
		return "", "", "", "", "", errors.New("projected link is required")
	}
	fromURN = strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return "", "", "", "", "", errors.New("projected link from urn is required")
	}
	toURN = strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return "", "", "", "", "", errors.New("projected link to urn is required")
	}
	relation = strings.TrimSpace(link.Relation)
	if relation == "" {
		return "", "", "", "", "", errors.New("projected link relation is required")
	}
	return fromURN, toURN, relation, strings.TrimSpace(link.TenantID), strings.TrimSpace(link.SourceID), nil
}

func (s *Store) mergedEntityAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, urn string, incoming map[string]string) (map[string]string, error) {
	value, found, err := queryOptionalValue(ctx, tx, "MATCH (e:Entity {urn: $urn}) RETURN coalesce(e.attributes_json, '{}')", map[string]any{"urn": urn})
	if err != nil {
		return nil, err
	}
	if !found {
		return mergeGraphAttributes(nil, incoming), nil
	}
	existing, err := graphAttributesFromJSON(stringValue(value))
	if err != nil {
		return nil, err
	}
	return mergeGraphAttributes(existing, incoming), nil
}

func (s *Store) mergedLinkAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, fromURN string, relation string, toURN string, incoming map[string]string) (map[string]string, error) {
	value, found, err := queryOptionalValue(ctx, tx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn})
RETURN coalesce(r.attributes_json, '{}')`, map[string]any{"from_urn": fromURN, "relation": relation, "to_urn": toURN})
	if err != nil {
		return nil, err
	}
	if !found {
		return mergeGraphAttributes(nil, incoming), nil
	}
	existing, err := graphAttributesFromJSON(stringValue(value))
	if err != nil {
		return nil, err
	}
	return mergeGraphAttributes(existing, incoming), nil
}

func queryOptionalValue(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any) (any, bool, error) {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return nil, false, err
	}
	if !result.Next(ctx) {
		return nil, false, result.Err()
	}
	values := result.Record().Values
	if len(values) == 0 {
		return nil, false, errors.New("query returned no values")
	}
	return values[0], true, result.Err()
}

func lookupNeighborhoodNode(ctx context.Context, tx neo4jdriver.ManagedTransaction, rootURN string) (*ports.NeighborhoodNode, error) {
	result, err := tx.Run(ctx, "MATCH (e:Entity {urn: $urn}) RETURN e.urn, e.entity_type, e.label", map[string]any{"urn": rootURN})
	if err != nil {
		return nil, fmt.Errorf("query graph root %q: %w", rootURN, err)
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("query graph root %q: %w", rootURN, err)
		}
		return nil, fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, rootURN)
	}
	record := result.Record()
	return &ports.NeighborhoodNode{
		URN:        stringValue(record.Values[0]),
		EntityType: stringValue(record.Values[1]),
		Label:      stringValue(record.Values[2]),
	}, result.Err()
}

func collectNeighborhoodRows(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any, remaining int, neighbors map[string]*ports.NeighborhoodNode, relations map[string]*ports.NeighborhoodRelation) (int, error) {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return remaining, fmt.Errorf("query graph neighborhood: %w", err)
	}
	for result.Next(ctx) {
		record := result.Record()
		neighbor := &ports.NeighborhoodNode{
			URN:        stringValue(record.Values[0]),
			EntityType: stringValue(record.Values[1]),
			Label:      stringValue(record.Values[2]),
		}
		attributes, err := decodeGraphAttributes(stringValue(record.Values[6]))
		if err != nil {
			return remaining, fmt.Errorf("decode graph neighborhood relation attributes: %w", err)
		}
		relation := &ports.NeighborhoodRelation{
			FromURN:    stringValue(record.Values[3]),
			Relation:   stringValue(record.Values[4]),
			ToURN:      stringValue(record.Values[5]),
			Attributes: attributes,
		}
		neighbors[neighbor.URN] = neighbor
		relations[relation.FromURN+"|"+relation.Relation+"|"+relation.ToURN] = relation
		remaining--
		if remaining == 0 {
			break
		}
	}
	return remaining, result.Err()
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

func graphAttributesFromJSON(raw string) (map[string]string, error) {
	attributes := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return attributes, nil
	}
	if err := json.Unmarshal([]byte(raw), &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}

func mergeGraphAttributes(existing map[string]string, incoming map[string]string) map[string]string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(incoming))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range incoming {
		merged[key] = value
	}
	return merged
}

func decodeGraphAttributes(payload string) (map[string]string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" || trimmed == "{}" {
		return nil, nil
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(trimmed), &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}

func neighborhoodNodes(values map[string]*ports.NeighborhoodNode) []*ports.NeighborhoodNode {
	nodes := make([]*ports.NeighborhoodNode, 0, len(values))
	for _, node := range values {
		nodes = append(nodes, node)
	}
	slices.SortFunc(nodes, func(left *ports.NeighborhoodNode, right *ports.NeighborhoodNode) int {
		switch {
		case left.URN < right.URN:
			return -1
		case left.URN > right.URN:
			return 1
		default:
			return 0
		}
	})
	return nodes
}

func neighborhoodRelations(values map[string]*ports.NeighborhoodRelation) []*ports.NeighborhoodRelation {
	relations := make([]*ports.NeighborhoodRelation, 0, len(values))
	for _, relation := range values {
		relations = append(relations, relation)
	}
	slices.SortFunc(relations, func(left *ports.NeighborhoodRelation, right *ports.NeighborhoodRelation) int {
		leftKey := left.FromURN + "|" + left.Relation + "|" + left.ToURN
		rightKey := right.FromURN + "|" + right.Relation + "|" + right.ToURN
		switch {
		case leftKey < rightKey:
			return -1
		case leftKey > rightKey:
			return 1
		default:
			return 0
		}
	})
	return relations
}

func ingestRunReturnQuery(prefix string) string {
	return prefix + ` RETURN r.id,
       coalesce(r.runtime_id, ''),
       coalesce(r.source_id, ''),
       coalesce(r.tenant_id, ''),
       coalesce(r.checkpoint_id, ''),
       coalesce(r.status, ''),
       coalesce(r.trigger, ''),
       coalesce(r.pages_read, 0),
       coalesce(r.events_read, 0),
       coalesce(r.entities_projected, 0),
       coalesce(r.links_projected, 0),
       coalesce(r.graph_nodes_before, 0),
       coalesce(r.graph_links_before, 0),
       coalesce(r.graph_nodes_after, 0),
       coalesce(r.graph_links_after, 0),
       coalesce(r.started_at, ''),
       coalesce(r.finished_at, ''),
       coalesce(r.error_message, '')`
}

func scanIngestRunRecord(record *neo4jdriver.Record) (IngestRun, error) {
	if len(record.Values) < 18 {
		return IngestRun{}, fmt.Errorf("ingest run record has %d values, want 18", len(record.Values))
	}
	return IngestRun{
		ID:                stringValue(record.Values[0]),
		RuntimeID:         stringValue(record.Values[1]),
		SourceID:          stringValue(record.Values[2]),
		TenantID:          stringValue(record.Values[3]),
		CheckpointID:      stringValue(record.Values[4]),
		Status:            stringValue(record.Values[5]),
		Trigger:           stringValue(record.Values[6]),
		PagesRead:         toInt64(record.Values[7]),
		EventsRead:        toInt64(record.Values[8]),
		EntitiesProjected: toInt64(record.Values[9]),
		LinksProjected:    toInt64(record.Values[10]),
		GraphNodesBefore:  toInt64(record.Values[11]),
		GraphLinksBefore:  toInt64(record.Values[12]),
		GraphNodesAfter:   toInt64(record.Values[13]),
		GraphLinksAfter:   toInt64(record.Values[14]),
		StartedAt:         stringValue(record.Values[15]),
		FinishedAt:        stringValue(record.Values[16]),
		Error:             stringValue(record.Values[17]),
	}, nil
}

func validIngestRunStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case graphstore.IngestRunStatusRunning, graphstore.IngestRunStatusCompleted, graphstore.IngestRunStatusFailed:
		return true
	default:
		return false
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func toInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int8:
		return int64(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		return int64(typed)
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}
