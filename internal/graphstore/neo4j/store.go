package neo4j

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	neo4jconfig "github.com/neo4j/neo4j-go-driver/v5/neo4j/config"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
	"github.com/writer/cerebro/internal/telemetry"
)

const defaultIngestRunListLimit = 25
const maxAttributeMergeRetries = 5
const defaultProjectionCleanupLimit = 1000

// Neo4j driver pool tuning. Aura reaps idle server-side connections, so a
// connection that has been parked in the pool past Aura's idle window fails
// the next borrow with a connectivity error. Recycling connections well under
// that window (rather than the driver default of one hour) keeps the pool warm
// with live sockets. The acquisition timeout fails fast if the pool is ever
// saturated instead of letting a borrow hang for the full caller deadline.
const (
	neo4jMaxConnectionLifetime        = 30 * time.Minute
	neo4jConnectionAcquisitionTimeout = 60 * time.Second
	neo4jMaxConnectionPoolSize        = 100
)
const mergeEntityAndLoadAttributesQuery = `MERGE (e:Entity {urn: $urn})
ON CREATE SET e.attributes_json = '{}', e.attributes_version = 0
SET e.tenant_id = $tenant_id,
    e.source_id = $source_id,
    e.runtime_id = CASE WHEN $runtime_id <> '' THEN $runtime_id ELSE coalesce(e.runtime_id, '') END,
    e.entity_type = $entity_type,
    e.label = CASE WHEN $label <> $urn THEN $label ELSE coalesce(e.label, $label) END
RETURN coalesce(e.attributes_json, '{}'), coalesce(e.attributes_version, 0)`

var errConcurrentAttributeMerge = errors.New("concurrent attribute merge")
var errProjectionAssertionMigrationScopeRequired = errors.New("tenant_id and relations are required for projected link assertion migration")
var mutatingCypherPattern = regexp.MustCompile(`(?i)\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|LOAD\s+CSV)\b|\bCALL\s+(DB|APOC)\.`)
var procedureCallPattern = regexp.MustCompile(`(?i)\bCALL\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(`)
var escapedProcedureCallPattern = regexp.MustCompile("(?i)\\bCALL\\s+`")

// Keep this list in parity with SAFE_PROCEDURES in the Rust static validator.
var readOnlyAPOCProcedures = map[string]struct{}{
	"apoc.coll.elements":       {},
	"apoc.coll.pairwithoffset": {},
	"apoc.coll.partition":      {},
	"apoc.coll.split":          {},
	"apoc.coll.ziptorows":      {},
	"apoc.neighbors.athop":     {},
	"apoc.neighbors.byhop":     {},
	"apoc.neighbors.tohop":     {},
	"apoc.path.expandconfig":   {},
	"apoc.path.subgraphnodes":  {},
	"apoc.paths.tojsontree":    {},
}

// Store is a Neo4j/Aura-backed graph projection store implementation.
type Store struct {
	driver       neo4jdriver.DriverWithContext
	database     string
	queryTimeout time.Duration

	projectionBatchSize        int
	projectionWriteConcurrency int
	writeSlots                 chan struct{}

	schemaMu    sync.Mutex
	schemaReady bool
}

type Counts = graphstore.Counts
type RelationCounts = graphstore.RelationCounts
type Traversal = graphstore.Traversal
type IntegrityCheck = graphstore.IntegrityCheck
type PathPattern = graphstore.PathPattern
type Topology = graphstore.Topology
type IngestCheckpoint = graphstore.IngestCheckpoint
type IngestRun = graphstore.IngestRun
type IngestRunFilter = graphstore.IngestRunFilter

func suppressedPathParams() map[string]any {
	return map[string]any{
		"suppressed_relation_pairs": graphstore.SuppressedTwoHopRelationPairKeys(),
		"suppressed_relations":      graphstore.SuppressedTwoHopRelations(),
	}
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
	if cfg.Neo4jPassword == "" {
		return nil, errors.New("neo4j password is required")
	}
	database := strings.TrimSpace(cfg.Neo4jDatabase)
	driver, err := neo4jdriver.NewDriverWithContext(uri, neo4jdriver.BasicAuth(username, cfg.Neo4jPassword, ""), func(c *neo4jconfig.Config) {
		c.MaxConnectionLifetime = neo4jMaxConnectionLifetime
		c.ConnectionAcquisitionTimeout = neo4jConnectionAcquisitionTimeout
		c.MaxConnectionPoolSize = neo4jMaxConnectionPoolSize
	})
	if err != nil {
		return nil, fmt.Errorf("open neo4j: %w", err)
	}
	projectionBatchSize := cfg.Neo4jProjectionBatchSize
	if projectionBatchSize <= 0 {
		projectionBatchSize = defaultProjectionUpsertBatchSize
	}
	projectionWriteConcurrency := cfg.Neo4jProjectionWriteConcurrency
	if projectionWriteConcurrency <= 0 {
		projectionWriteConcurrency = defaultProjectionWriteConcurrency
	}
	if projectionWriteConcurrency > neo4jMaxConnectionPoolSize {
		projectionWriteConcurrency = neo4jMaxConnectionPoolSize
	}
	return &Store{
		driver:                     driver,
		database:                   database,
		queryTimeout:               cfg.Neo4jQueryTimeout,
		projectionBatchSize:        projectionBatchSize,
		projectionWriteConcurrency: projectionWriteConcurrency,
		writeSlots:                 make(chan struct{}, projectionWriteConcurrency),
	}, nil
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
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

// RelationCounts returns exact totals for the requested projected relation names.
func (s *Store) RelationCounts(ctx context.Context, relations []string) (_ RelationCounts, err error) {
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	if len(relations) == 0 {
		return RelationCounts{}, nil
	}
	counts := make(RelationCounts, len(relations))
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `UNWIND $relations AS relation
OPTIONAL MATCH ()-[r:RELATION]->()
WHERE r.relation = relation
RETURN relation, count(r)
ORDER BY relation`, map[string]any{"relations": relations})
		if err != nil {
			return nil, err
		}
		for result.Next(ctx) {
			record := result.Record()
			counts[stringValue(record.Values[0])] = toInt64(record.Values[1])
		}
		return nil, result.Err()
	}); err != nil {
		return nil, fmt.Errorf("count graph relations: %w", err)
	}
	for _, relation := range relations {
		if _, ok := counts[relation]; !ok {
			counts[relation] = 0
		}
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
	query := fmt.Sprintf(`MATCH (src:Entity)-[left:RELATION]->(mid:Entity)
WHERE NOT (left.relation IN $suppressed_relations)
MATCH (mid)-[right:RELATION]->(dst:Entity)
WHERE NOT (right.relation IN $suppressed_relations)
  AND NOT ((left.relation + '|' + right.relation) IN $suppressed_relation_pairs)
RETURN src.urn, src.label, left.relation, mid.urn, mid.label, right.relation, dst.urn, dst.label
ORDER BY src.urn, left.relation, mid.urn, right.relation, dst.urn LIMIT %d`, limit)
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		traversals = traversals[:0]
		result, err := tx.Run(ctx, query, suppressedPathParams())
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
	query := fmt.Sprintf(`MATCH (src:Entity)-[left:RELATION]->(mid:Entity)
WHERE NOT (left.relation IN $suppressed_relations)
MATCH (mid)-[right:RELATION]->(dst:Entity)
WHERE NOT (right.relation IN $suppressed_relations)
  AND NOT ((left.relation + '|' + right.relation) IN $suppressed_relation_pairs)
RETURN src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type, count(*)
ORDER BY count(*) DESC, src.entity_type, left.relation, mid.entity_type, right.relation, dst.entity_type LIMIT %d`, limit)
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		patterns = patterns[:0]
		result, err := tx.Run(ctx, query, suppressedPathParams())
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
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
	checks, queries := integrityCheckDefinitions()
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
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

// RepairOpenFindingPrimaryLinks restores missing has_finding edges for open findings whose primary resource node exists.
func (s *Store) RepairOpenFindingPrimaryLinks(ctx context.Context, request graphstore.OpenFindingPrimaryLinkRepairRequest) (graphstore.OpenFindingPrimaryLinkRepairResult, error) {
	if err := s.requireConfigured(); err != nil {
		return graphstore.OpenFindingPrimaryLinkRepairResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return graphstore.OpenFindingPrimaryLinkRepairResult{}, err
	}
	limit := int64(request.Limit)
	if limit <= 0 {
		limit = 25
	}
	params := map[string]any{"limit": limit}
	result := graphstore.OpenFindingPrimaryLinkRepairResult{DryRun: request.DryRun}
	query := `MATCH (finding:Entity {entity_type: 'finding'})
WITH finding, coalesce(finding.attributes_json, '') AS attrs
WHERE attrs CONTAINS '"status":"open"' AND attrs CONTAINS '"primary_resource_urn":"'
WITH finding, split(split(attrs, '"primary_resource_urn":"')[1], '"')[0] AS primary_urn
WHERE primary_urn <> ''
MATCH (resource:Entity {tenant_id: finding.tenant_id, urn: primary_urn})
WHERE NOT EXISTS { MATCH (resource)-[:RELATION {relation: 'has_finding'}]->(finding) }
WITH resource, finding
ORDER BY finding.urn
LIMIT $limit`
	if request.DryRun {
		value, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			return queryOneValue(ctx, tx, query+`
RETURN count(finding)`, params)
		})
		if err != nil {
			return graphstore.OpenFindingPrimaryLinkRepairResult{}, fmt.Errorf("query open finding primary link repair candidates: %w", err)
		}
		result.LinksMatched = uint32FromInt64(toInt64(value))
		return result, nil
	}
	value, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return queryOneValue(ctx, tx, query+`
MERGE (resource)-[r:RELATION {relation: 'has_finding'}]->(finding)
ON CREATE SET r.attributes_json = '{}', r.attributes_version = 0
SET r.tenant_id = finding.tenant_id,
    r.source_id = coalesce(finding.source_id, ''),
    r.runtime_id = coalesce(finding.runtime_id, '')
RETURN count(r)`, params)
	})
	if err != nil {
		return graphstore.OpenFindingPrimaryLinkRepairResult{}, fmt.Errorf("repair open finding primary links: %w", err)
	}
	result.LinksMatched = uint32FromInt64(toInt64(value))
	result.LinksCreated = result.LinksMatched
	return result, nil
}

const defaultEntityTypedPropertyBackfillBatchSize = 500

// BackfillEntityTypedProperties promotes the typed boolean properties onto Entity
// nodes that predate the promotion and still carry NULL values for them, deriving
// each from the node's stored attributes_json with the exact same code the projection
// write path uses (graphAttributesFromJSON + projectionmeta.DerivedEntityProperties),
// so the backfilled values can never drift from a re-projection. It is idempotent: a
// node is only revisited until its typed properties are concrete booleans, so each
// batch shrinks the candidate set and the loop terminates. With DryRun it only counts
// the entities that still need the backfill.
func (s *Store) BackfillEntityTypedProperties(ctx context.Context, request graphstore.BackfillEntityTypedPropertiesRequest) (graphstore.BackfillEntityTypedPropertiesResult, error) {
	if err := s.requireConfigured(); err != nil {
		return graphstore.BackfillEntityTypedPropertiesResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return graphstore.BackfillEntityTypedPropertiesResult{}, err
	}
	batchSize := int64(request.BatchSize)
	if batchSize <= 0 {
		batchSize = defaultEntityTypedPropertyBackfillBatchSize
	}
	nullPredicate := entityMissingTypedPropertiesPredicate()
	result := graphstore.BackfillEntityTypedPropertiesResult{DryRun: request.DryRun}

	if request.DryRun {
		value, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			return queryOneValue(ctx, tx, fmt.Sprintf("MATCH (e:Entity) WHERE %s RETURN count(e)", nullPredicate), nil)
		})
		if err != nil {
			return graphstore.BackfillEntityTypedPropertiesResult{}, fmt.Errorf("count entity typed-property backfill candidates: %w", err)
		}
		result.EntitiesMatched = uint32FromInt64(toInt64(value))
		return result, nil
	}

	readCypher := fmt.Sprintf("MATCH (e:Entity) WHERE %s RETURN e.urn, coalesce(e.attributes_json, '') LIMIT $limit", nullPredicate)
	const writeCypher = `UNWIND $rows AS row
MATCH (e:Entity {urn: row.urn})
SET e += row.typed_properties
RETURN count(e)`
	for {
		processed, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
			readResult, err := tx.Run(ctx, readCypher, map[string]any{"limit": batchSize})
			if err != nil {
				return int64(0), err
			}
			type candidate struct {
				urn   string
				attrs string
			}
			var candidates []candidate
			for readResult.Next(ctx) {
				values := readResult.Record().Values
				candidates = append(candidates, candidate{urn: stringValue(values[0]), attrs: stringValue(values[1])})
			}
			if err := readResult.Err(); err != nil {
				return int64(0), err
			}
			if len(candidates) == 0 {
				return int64(0), nil
			}
			rows := make([]map[string]any, 0, len(candidates))
			for _, c := range candidates {
				attributes, err := graphAttributesFromJSON(c.attrs)
				if err != nil {
					return int64(0), fmt.Errorf("decode attributes_json for %q: %w", c.urn, err)
				}
				rows = append(rows, map[string]any{
					"urn":              c.urn,
					"typed_properties": entityTypedPropertyParams(projectionmeta.DerivedEntityProperties(attributes)),
				})
			}
			return countQuery(ctx, tx, writeCypher, map[string]any{"rows": rows})
		})
		if err != nil {
			return graphstore.BackfillEntityTypedPropertiesResult{}, fmt.Errorf("backfill entity typed properties: %w", err)
		}
		written := toInt64(processed)
		if written == 0 {
			break
		}
		result.Batches++
		result.EntitiesUpdated += uint32FromInt64(written)
	}
	result.EntitiesMatched = result.EntitiesUpdated
	return result, nil
}

// entityMissingTypedPropertiesPredicate matches Entity nodes left with NULL typed properties from
// before the typed-property promotion. It is shared by the backfill candidate scan and the
// integrity check so the "must be zero once backfilled" invariant cannot drift. Bound to `e`.
func entityMissingTypedPropertiesPredicate() string {
	return fmt.Sprintf("e.%s IS NULL OR e.%s IS NULL OR e.%s IS NULL",
		projectionmeta.PropertyInternetExposed,
		projectionmeta.PropertyPrivilegedIdentity,
		projectionmeta.PropertyMFADisabled)
}

func integrityCheckDefinitions() ([]IntegrityCheck, []string) {
	checks := []IntegrityCheck{
		{Name: "tenant_mismatched_relations", Expected: 0},
		{Name: "blank_entity_labels", Expected: 0},
		{Name: "blank_entity_types", Expected: 0},
		{Name: "blank_relation_types", Expected: 0},
		{Name: "self_referential_relations", Expected: 0},
		{Name: "github_code_repositories_without_owner_link", Expected: 0},
		{Name: "aws_public_endpoints_without_instance_link", Expected: 0},
		{Name: "open_findings_missing_primary_has_finding_edge", Expected: 0},
		{Name: "github_workflow_job_runners_projected_as_assets", Expected: 0},
		{Name: "sentinelone_activity_events_projected_as_assets", Expected: 0},
		{Name: "ephemeral_event_entities_projected_as_inventory", Expected: 0},
		{Name: "entities_missing_typed_properties", Expected: 0},
	}
	queries := []string{
		"MATCH (src:Entity)-[r:RELATION]->(dst:Entity) WHERE src.tenant_id <> dst.tenant_id OR src.tenant_id <> r.tenant_id OR dst.tenant_id <> r.tenant_id RETURN count(r)",
		"MATCH (e:Entity) WHERE coalesce(e.label, '') = '' RETURN count(e)",
		"MATCH (e:Entity) WHERE coalesce(e.entity_type, '') = '' RETURN count(e)",
		"MATCH (:Entity)-[r:RELATION]->(:Entity) WHERE coalesce(r.relation, '') = '' RETURN count(r)",
		"MATCH (src:Entity)-[r:RELATION]->(dst:Entity) WHERE src.urn = dst.urn RETURN count(r)",
		"MATCH (e:Entity) WHERE e.source_id = 'github' AND e.entity_type = 'github.code.repository' AND coalesce(e.attributes_json, '') CONTAINS '\"owner_login\":\"' AND NOT coalesce(e.attributes_json, '') CONTAINS '\"owner_login\":\"\"' AND NOT EXISTS { MATCH (e)-[:RELATION {relation: 'belongs_to'}]->(:Entity {entity_type: 'github.org'}) } RETURN count(e)",
		"MATCH (e:Entity) WHERE e.entity_type IN ['aws.elastic.ip', 'aws.network.interface'] AND ((coalesce(e.attributes_json, '') CONTAINS '\"attached_instance_id\":\"' AND NOT coalesce(e.attributes_json, '') CONTAINS '\"attached_instance_id\":\"\"') OR (coalesce(e.attributes_json, '') CONTAINS '\"associated_instance_id\":\"' AND NOT coalesce(e.attributes_json, '') CONTAINS '\"associated_instance_id\":\"\"')) AND NOT EXISTS { MATCH (e)-[:RELATION {relation: 'attached_to'}]->(:Entity {entity_type: 'aws.ec2.instance'}) } AND NOT EXISTS { MATCH (e)-[:RELATION {relation: 'associated_with'}]->(:Entity {entity_type: 'aws.ec2.instance'}) } RETURN count(e)",
		"MATCH (finding:Entity {entity_type: 'finding'}) WITH finding, coalesce(finding.attributes_json, '') AS attrs WHERE attrs CONTAINS '\"status\":\"open\"' AND attrs CONTAINS '\"primary_resource_urn\":\"' WITH finding, split(split(attrs, '\"primary_resource_urn\":\"')[1], '\"')[0] AS primary_urn WHERE primary_urn <> '' MATCH (resource:Entity {tenant_id: finding.tenant_id, urn: primary_urn}) WHERE NOT EXISTS { MATCH (resource)-[:RELATION {relation: 'has_finding'}]->(finding) } RETURN count(finding)",
		"MATCH (e:Entity {entity_type: 'github.runner'}) WHERE coalesce(e.attributes_json, '') CONTAINS '\"action\":\"workflows.' RETURN count(e)",
		"MATCH (e:Entity {entity_type: 'sentinelone.activity'}) RETURN count(e)",
		"MATCH (e:Entity) WHERE coalesce(e.attributes_json, '') CONTAINS '\"projection_class\":\"ephemeral_event\"' RETURN count(e)",
		fmt.Sprintf("MATCH (e:Entity) WHERE %s RETURN count(e)", entityMissingTypedPropertiesPredicate()),
	}
	return checks, queries
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
	if err := ports.ValidateProjectedEntityTenantScope(entity); err != nil {
		return err
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
	params := map[string]any{
		"urn":         urn,
		"tenant_id":   tenantID,
		"source_id":   sourceID,
		"runtime_id":  strings.TrimSpace(entity.RuntimeID),
		"entity_type": entityType,
		"label":       label,
	}
	incomingAttributes := projectionmeta.ApplyEntityMetadata(entityType, entity.Attributes)
	for attempt := 0; attempt < maxAttributeMergeRetries; attempt++ {
		_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
			attributesJSON, version, err := mergeEntityAndLoadAttributes(ctx, tx, params)
			if err != nil {
				return nil, fmt.Errorf("load projected entity %q attributes: %w", urn, err)
			}
			existing, err := graphAttributesFromJSON(attributesJSON)
			if err != nil {
				return nil, fmt.Errorf("decode projected entity attributes: %w", err)
			}
			mergedAttributes := mergeGraphAttributes(existing, incomingAttributes)
			mergedJSON, err := graphAttributesJSON(mergedAttributes)
			if err != nil {
				return nil, fmt.Errorf("marshal projected entity attributes: %w", err)
			}
			typedProperties := entityTypedPropertyParams(projectionmeta.DerivedEntityProperties(mergedAttributes))
			updated, err := updateEntityAttributes(ctx, tx, urn, version, mergedJSON, typedProperties)
			if err != nil {
				return nil, err
			}
			if !updated {
				return nil, errConcurrentAttributeMerge
			}
			return nil, nil
		})
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConcurrentAttributeMerge) {
			return fmt.Errorf("upsert projected entity %q: %w", urn, err)
		}
	}
	return fmt.Errorf("upsert projected entity %q: %w", urn, errConcurrentAttributeMerge)
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
	params := map[string]any{
		"from_urn":          fromURN,
		"to_urn":            toURN,
		"relation":          relation,
		"tenant_id":         tenantID,
		"source_id":         sourceID,
		"runtime_id":        strings.TrimSpace(link.RuntimeID),
		"reconciliation_id": projectedLinkReconciliationID(link.Attributes),
	}
	for attempt := 0; attempt < maxAttributeMergeRetries; attempt++ {
		_, err = s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
			current, found, err := mergeLinkAndLoadAttributes(ctx, tx, params)
			if err != nil {
				return nil, fmt.Errorf("load projected link %q %q %q attributes: %w", fromURN, relation, toURN, err)
			}
			if !found {
				return nil, nil
			}
			existingLogical, err := graphAttributesFromJSON(current.logicalAttributesJSON)
			if err != nil {
				return nil, fmt.Errorf("decode projected logical link attributes: %w", err)
			}
			existingAssertion, err := graphAttributesFromJSON(current.assertionAttributesJSON)
			if err != nil {
				return nil, fmt.Errorf("decode projected link assertion attributes: %w", err)
			}
			logicalJSON, err := graphAttributesJSON(mergeGraphAttributes(existingLogical, link.Attributes))
			if err != nil {
				return nil, fmt.Errorf("marshal projected logical link attributes: %w", err)
			}
			assertionJSON, err := graphAttributesJSON(mergeGraphAttributes(existingAssertion, link.Attributes))
			if err != nil {
				return nil, fmt.Errorf("marshal projected link assertion attributes: %w", err)
			}
			updated, err := updateLinkAttributes(ctx, tx, params, current, logicalJSON, assertionJSON)
			if err != nil {
				return nil, err
			}
			if !updated {
				return nil, errConcurrentAttributeMerge
			}
			return nil, nil
		})
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConcurrentAttributeMerge) {
			return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
		}
	}
	return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, errConcurrentAttributeMerge)
}

// defaultProjectionUpsertBatchSize bounds how many entities or links are written per
// UNWIND transaction. Batching collapses the two round-trips per element of the
// per-item upsert path (merge/load attributes, then version-checked update) into
// two round-trips per batch, which is the dominant cost of graph ingest against
// a remote Aura instance.
const defaultProjectionUpsertBatchSize = 500

// defaultProjectionWriteConcurrency allows multiple independent graph writes to
// share the driver's connection pool instead of serializing every write behind a
// process-wide mutex. Attribute-version checks and transient retry handling keep
// overlapping writes safe.
const defaultProjectionWriteConcurrency = 4

// mergeProjectedEntitiesQuery is the batched counterpart of
// mergeEntityAndLoadAttributesQuery: it MERGEs every entity in the batch and
// returns each node's current attributes_json/version so the caller can deep-merge
// client-side before the version-checked write. The label clause mirrors the
// per-item query so existing labels survive fallback (urn-equal) labels.
const mergeProjectedEntitiesQuery = `UNWIND $rows AS row
MERGE (e:Entity {urn: row.urn})
ON CREATE SET e.attributes_json = '{}', e.attributes_version = 0
SET e.tenant_id = row.tenant_id,
    e.source_id = row.source_id,
    e.runtime_id = CASE WHEN row.runtime_id <> '' THEN row.runtime_id ELSE coalesce(e.runtime_id, '') END,
    e.entity_type = row.entity_type,
    e.label = CASE WHEN row.label <> row.urn THEN row.label ELSE coalesce(e.label, row.label) END
RETURN row.urn AS urn, coalesce(e.attributes_json, '{}') AS attributes_json, coalesce(e.attributes_version, 0) AS attributes_version`

// updateProjectedEntitiesQuery is the batched counterpart of updateEntityAttributes.
// The version guard is redundant within a single transaction (the MERGE above
// write-locks each node for the batch's duration) but is retained so the on-disk
// write semantics and monotonic version increment match the per-item path exactly.
const updateProjectedEntitiesQuery = `UNWIND $rows AS row
MATCH (e:Entity {urn: row.urn})
WHERE coalesce(e.attributes_version, 0) = row.attributes_version
SET e.attributes_json = row.attributes_json,
    e.attributes_version = row.next_attributes_version,
    e += row.typed_properties
RETURN count(e)`

// mergeProjectedLinksQuery is the batched counterpart of mergeLinkAndLoadAttributes.
// Rows whose endpoints do not both exist are dropped by the MATCH and therefore
// never returned, preserving the per-item rule that a link is only materialized
// when both endpoints exist. The relation_lock bump mirrors the per-item write so
// concurrent relationship creation against the same source node stays serialized.
const mergeProjectedLinksQuery = `UNWIND $rows AS row
MATCH (src:Entity {urn: row.from_urn}), (dst:Entity {urn: row.to_urn})
SET src.relation_lock = coalesce(src.relation_lock, 0) + 1
MERGE (src)-[r:RELATION {relation: row.relation}]->(dst)
ON CREATE SET r.attributes_json = '{}', r.attributes_version = 0, r.assertion_managed = true, r.assertion_quarantined = false
WITH src, dst, r, row,
     coalesce(r.assertion_managed, false) AS was_assertion_managed,
     CASE WHEN coalesce(r.tenant_id, '') <> '' THEN r.tenant_id ELSE row.tenant_id END AS legacy_tenant_id,
     coalesce(r.source_id, '') AS legacy_source_id,
     coalesce(r.runtime_id, '') AS legacy_runtime_id
WITH src, dst, r, row, legacy_tenant_id, legacy_source_id, legacy_runtime_id,
     NOT was_assertion_managed AS preserve_legacy_logical
SET r.tenant_id = CASE WHEN preserve_legacy_logical THEN legacy_tenant_id ELSE row.tenant_id END,
    r.source_id = CASE WHEN preserve_legacy_logical THEN legacy_source_id ELSE row.source_id END,
    r.runtime_id = CASE WHEN preserve_legacy_logical THEN legacy_runtime_id ELSE row.runtime_id END,
    r.assertion_managed = NOT preserve_legacy_logical,
    r.assertion_quarantined = preserve_legacy_logical
MERGE (src)-[a:RELATION_ASSERTION {
    relation: row.relation,
    tenant_id: row.tenant_id,
    source_id: row.source_id,
    runtime_id: row.runtime_id
}]->(dst)
ON CREATE SET a.attributes_json = '{}', a.attributes_version = 0
SET a.projection_reconciliation_id = row.reconciliation_id
RETURN row.from_urn AS from_urn,
       row.relation AS relation,
       row.to_urn AS to_urn,
       row.tenant_id AS tenant_id,
       row.source_id AS source_id,
       row.runtime_id AS runtime_id,
       coalesce(r.attributes_json, '{}') AS logical_attributes_json,
       coalesce(r.attributes_version, 0) AS logical_attributes_version,
       coalesce(a.attributes_json, '{}') AS assertion_attributes_json,
       coalesce(a.attributes_version, 0) AS assertion_attributes_version,
       preserve_legacy_logical AS preserve_legacy_logical`

// updateProjectedLinksQuery is the batched counterpart of updateLinkAttributes.
const updateProjectedLinksQuery = `UNWIND $rows AS row
MATCH (:Entity {urn: row.from_urn})-[r:RELATION {relation: row.relation}]->(:Entity {urn: row.to_urn})
WHERE coalesce(r.attributes_version, 0) = row.attributes_version
SET r.attributes_json = row.attributes_json,
    r.attributes_version = row.next_attributes_version,
    r.tenant_id = row.tenant_id,
    r.source_id = row.source_id,
    r.runtime_id = row.runtime_id,
    r.projection_reconciliation_id = row.reconciliation_id,
    r.assertion_managed = true,
    r.assertion_quarantined = false
RETURN count(r)`

const updateProjectedLinkAssertionsQuery = `UNWIND $rows AS row
MATCH (:Entity {urn: row.from_urn})-[a:RELATION_ASSERTION {
    relation: row.relation,
    tenant_id: row.tenant_id,
    source_id: row.source_id,
    runtime_id: row.runtime_id
}]->(:Entity {urn: row.to_urn})
WHERE coalesce(a.attributes_version, 0) = row.attributes_version
SET a.attributes_json = row.attributes_json,
    a.attributes_version = row.next_attributes_version,
    a.projection_reconciliation_id = row.reconciliation_id
RETURN count(a)`

type loadedAttributeRow struct {
	attributesJSON string
	version        int64
}

type loadedProjectedLinkRow struct {
	logicalAttributesJSON   string
	logicalVersion          int64
	assertionAttributesJSON string
	assertionVersion        int64
	preserveLegacyLogical   bool
}

type preparedProjectedEntity struct {
	urn        string
	tenantID   string
	sourceID   string
	runtimeID  string
	entityType string
	label      string
	attributes map[string]string
}

type preparedProjectedLink struct {
	fromURN    string
	toURN      string
	relation   string
	tenantID   string
	sourceID   string
	runtimeID  string
	attributes map[string]string
}

// UpsertProjectedEntities upserts normalized entities in batches. It preserves
// the exact semantics of UpsertProjectedEntity (tenant-scope validation, entity
// metadata application, attribute deep-merge, typed-property derivation, and the
// monotonic attributes_version) while collapsing the per-entity round-trips into
// two round-trips per batch. Entities are coalesced by URN and written in URN
// order so concurrent batches acquire node locks in a stable order.
func (s *Store) UpsertProjectedEntities(ctx context.Context, entities []*ports.ProjectedEntity) error {
	prepared, err := prepareProjectedEntities(entities)
	if err != nil {
		return err
	}
	if len(prepared) == 0 {
		return nil
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	for _, chunk := range chunkSlice(prepared, s.projectionBatchSizeOrDefault()) {
		if err := s.upsertProjectedEntityChunk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// UpsertProjectedLinks upserts normalized links in batches, mirroring
// UpsertProjectedLink (tenant-scope validation, attribute deep-merge, monotonic
// attributes_version, and materializing a link only when both endpoints exist).
func (s *Store) UpsertProjectedLinks(ctx context.Context, links []*ports.ProjectedLink) error {
	prepared, err := prepareProjectedLinks(links)
	if err != nil {
		return err
	}
	if len(prepared) == 0 {
		return nil
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	for _, chunk := range chunkSlice(prepared, s.projectionBatchSizeOrDefault()) {
		if err := s.upsertProjectedLinkChunk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertProjectedEntityChunk(ctx context.Context, chunk []*preparedProjectedEntity) error {
	for attempt := 0; attempt < maxAttributeMergeRetries; attempt++ {
		err := s.writeProjectedEntityChunk(ctx, chunk)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConcurrentAttributeMerge) {
			return fmt.Errorf("upsert projected entities: %w", err)
		}
	}
	return fmt.Errorf("upsert projected entities: %w", errConcurrentAttributeMerge)
}

func (s *Store) writeProjectedEntityChunk(ctx context.Context, chunk []*preparedProjectedEntity) error {
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		mergeRows := make([]map[string]any, 0, len(chunk))
		for _, entity := range chunk {
			mergeRows = append(mergeRows, map[string]any{
				"urn":         entity.urn,
				"tenant_id":   entity.tenantID,
				"source_id":   entity.sourceID,
				"runtime_id":  entity.runtimeID,
				"entity_type": entity.entityType,
				"label":       entity.label,
			})
		}
		loaded, err := loadAttributeRows(ctx, tx, mergeProjectedEntitiesQuery, mergeRows, entityAttributeRowKey)
		if err != nil {
			return nil, fmt.Errorf("load projected entity attributes: %w", err)
		}
		updateRows := make([]map[string]any, 0, len(chunk))
		for _, entity := range chunk {
			current, ok := loaded[entity.urn]
			if !ok {
				return nil, fmt.Errorf("merge projected entity %q returned no attributes", entity.urn)
			}
			existing, err := graphAttributesFromJSON(current.attributesJSON)
			if err != nil {
				return nil, fmt.Errorf("decode projected entity %q attributes: %w", entity.urn, err)
			}
			merged := mergeGraphAttributes(existing, entity.attributes)
			mergedJSON, err := graphAttributesJSON(merged)
			if err != nil {
				return nil, fmt.Errorf("marshal projected entity %q attributes: %w", entity.urn, err)
			}
			updateRows = append(updateRows, map[string]any{
				"urn":                     entity.urn,
				"attributes_version":      current.version,
				"next_attributes_version": current.version + 1,
				"attributes_json":         mergedJSON,
				"typed_properties":        entityTypedPropertyParams(projectionmeta.DerivedEntityProperties(merged)),
			})
		}
		updated, err := countQuery(ctx, tx, updateProjectedEntitiesQuery, map[string]any{"rows": updateRows})
		if err != nil {
			return nil, err
		}
		if updated != int64(len(updateRows)) {
			return nil, errConcurrentAttributeMerge
		}
		return nil, nil
	})
	return err
}

func (s *Store) upsertProjectedLinkChunk(ctx context.Context, chunk []*preparedProjectedLink) error {
	for attempt := 0; attempt < maxAttributeMergeRetries; attempt++ {
		err := s.writeProjectedLinkChunk(ctx, chunk)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConcurrentAttributeMerge) {
			return fmt.Errorf("upsert projected links: %w", err)
		}
	}
	return fmt.Errorf("upsert projected links: %w", errConcurrentAttributeMerge)
}

func (s *Store) writeProjectedLinkChunk(ctx context.Context, chunk []*preparedProjectedLink) error {
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		mergeRows := make([]map[string]any, 0, len(chunk))
		for _, link := range chunk {
			mergeRows = append(mergeRows, map[string]any{
				"from_urn":          link.fromURN,
				"to_urn":            link.toURN,
				"relation":          link.relation,
				"tenant_id":         link.tenantID,
				"source_id":         link.sourceID,
				"runtime_id":        link.runtimeID,
				"reconciliation_id": projectedLinkReconciliationID(link.attributes),
			})
		}
		loaded, err := loadProjectedLinkRows(ctx, tx, mergeRows)
		if err != nil {
			return nil, fmt.Errorf("load projected link attributes: %w", err)
		}
		assertionUpdateRows := make([]map[string]any, 0, len(loaded))
		type logicalUpdate struct {
			link       *preparedProjectedLink
			version    int64
			attributes map[string]string
			preserve   bool
		}
		logicalUpdates := make([]*logicalUpdate, 0, len(loaded))
		logicalIndex := make(map[string]*logicalUpdate, len(loaded))
		for _, link := range chunk {
			key := projectedLinkAssertionKey(link.fromURN, link.relation, link.toURN, link.tenantID, link.sourceID, link.runtimeID)
			current, ok := loaded[key]
			if !ok {
				continue
			}
			existingAssertion, err := graphAttributesFromJSON(current.assertionAttributesJSON)
			if err != nil {
				return nil, fmt.Errorf("decode projected link assertion %q attributes: %w", key, err)
			}
			assertionJSON, err := graphAttributesJSON(mergeGraphAttributes(existingAssertion, link.attributes))
			if err != nil {
				return nil, fmt.Errorf("marshal projected link assertion %q attributes: %w", key, err)
			}
			assertionUpdateRows = append(assertionUpdateRows, map[string]any{
				"from_urn":                link.fromURN,
				"to_urn":                  link.toURN,
				"relation":                link.relation,
				"tenant_id":               link.tenantID,
				"source_id":               link.sourceID,
				"runtime_id":              link.runtimeID,
				"reconciliation_id":       projectedLinkReconciliationID(link.attributes),
				"attributes_version":      current.assertionVersion,
				"next_attributes_version": current.assertionVersion + 1,
				"attributes_json":         assertionJSON,
			})

			logicalKey := projectedLinkKey(link.fromURN, link.relation, link.toURN)
			logical := logicalIndex[logicalKey]
			if logical == nil {
				existingLogical, err := graphAttributesFromJSON(current.logicalAttributesJSON)
				if err != nil {
					return nil, fmt.Errorf("decode projected logical link %q attributes: %w", logicalKey, err)
				}
				logical = &logicalUpdate{link: link, version: current.logicalVersion, attributes: existingLogical, preserve: current.preserveLegacyLogical}
				logicalIndex[logicalKey] = logical
				logicalUpdates = append(logicalUpdates, logical)
			}
			if !logical.preserve {
				logical.attributes = mergeGraphAttributes(logical.attributes, link.attributes)
			}
		}
		if len(assertionUpdateRows) == 0 {
			return nil, nil
		}
		logicalUpdateRows := make([]map[string]any, 0, len(logicalUpdates))
		for _, logical := range logicalUpdates {
			if logical.preserve {
				continue
			}
			attributesJSON, err := graphAttributesJSON(logical.attributes)
			if err != nil {
				return nil, fmt.Errorf("marshal projected logical link %q attributes: %w", projectedLinkKey(logical.link.fromURN, logical.link.relation, logical.link.toURN), err)
			}
			logicalUpdateRows = append(logicalUpdateRows, map[string]any{
				"from_urn":                logical.link.fromURN,
				"to_urn":                  logical.link.toURN,
				"relation":                logical.link.relation,
				"tenant_id":               logical.link.tenantID,
				"source_id":               logical.link.sourceID,
				"runtime_id":              logical.link.runtimeID,
				"reconciliation_id":       projectedLinkReconciliationID(logical.link.attributes),
				"attributes_version":      logical.version,
				"next_attributes_version": logical.version + 1,
				"attributes_json":         attributesJSON,
			})
		}
		if len(logicalUpdateRows) != 0 {
			updated, err := countQuery(ctx, tx, updateProjectedLinksQuery, map[string]any{"rows": logicalUpdateRows})
			if err != nil {
				return nil, err
			}
			if updated != int64(len(logicalUpdateRows)) {
				return nil, errConcurrentAttributeMerge
			}
		}
		updated, err := countQuery(ctx, tx, updateProjectedLinkAssertionsQuery, map[string]any{"rows": assertionUpdateRows})
		if err != nil {
			return nil, err
		}
		if updated != int64(len(assertionUpdateRows)) {
			return nil, errConcurrentAttributeMerge
		}
		return nil, nil
	})
	return err
}

func loadAttributeRows(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, rows []map[string]any, key func([]any) string) (map[string]loadedAttributeRow, error) {
	result, err := tx.Run(ctx, query, map[string]any{"rows": rows})
	if err != nil {
		return nil, err
	}
	loaded := make(map[string]loadedAttributeRow, len(rows))
	for result.Next(ctx) {
		values := result.Record().Values
		loaded[key(values)] = loadedAttributeRow{
			attributesJSON: stringValue(values[len(values)-2]),
			version:        toInt64(values[len(values)-1]),
		}
	}
	return loaded, result.Err()
}

func loadProjectedLinkRows(ctx context.Context, tx neo4jdriver.ManagedTransaction, rows []map[string]any) (map[string]loadedProjectedLinkRow, error) {
	result, err := tx.Run(ctx, mergeProjectedLinksQuery, map[string]any{"rows": rows})
	if err != nil {
		return nil, err
	}
	loaded := make(map[string]loadedProjectedLinkRow, len(rows))
	for result.Next(ctx) {
		values := result.Record().Values
		key := projectedLinkAssertionKey(
			stringValue(values[0]),
			stringValue(values[1]),
			stringValue(values[2]),
			stringValue(values[3]),
			stringValue(values[4]),
			stringValue(values[5]),
		)
		loaded[key] = loadedProjectedLinkRow{
			logicalAttributesJSON:   stringValue(values[6]),
			logicalVersion:          toInt64(values[7]),
			assertionAttributesJSON: stringValue(values[8]),
			assertionVersion:        toInt64(values[9]),
			preserveLegacyLogical:   boolValue(values[10]),
		}
	}
	return loaded, result.Err()
}

func entityAttributeRowKey(values []any) string {
	return stringValue(values[0])
}

func projectedLinkKey(fromURN string, relation string, toURN string) string {
	return fromURN + "|" + relation + "|" + toURN
}

func projectedLinkAssertionKey(fromURN string, relation string, toURN string, tenantID string, sourceID string, runtimeID string) string {
	return projectedLinkKey(fromURN, relation, toURN) + "|" + tenantID + "|" + sourceID + "|" + runtimeID
}

func projectedLinkReconciliationID(attributes map[string]string) string {
	return strings.TrimSpace(attributes["projection_reconciliation_id"])
}

const reconcileProjectedLogicalLinksQuery = `UNWIND $rows AS row
MATCH (src:Entity {urn: row.from_urn})-[logical:RELATION {relation: row.relation}]->(dst:Entity {urn: row.to_urn})
WHERE logical.tenant_id = row.tenant_id
CALL {
  WITH src, dst, row
  OPTIONAL MATCH (src)-[candidate:RELATION_ASSERTION {relation: row.relation}]->(dst)
  WHERE candidate.tenant_id = row.tenant_id
  WITH candidate
  ORDER BY candidate.source_id, candidate.runtime_id, candidate.attributes_json, elementId(candidate)
  RETURN head(collect(candidate)) AS survivor
}
WITH logical, survivor, coalesce(logical.assertion_managed, false) AS can_rehydrate
FOREACH (_ IN CASE WHEN survivor IS NOT NULL AND can_rehydrate THEN [1] ELSE [] END |
  SET logical.tenant_id = survivor.tenant_id,
      logical.source_id = survivor.source_id,
      logical.runtime_id = survivor.runtime_id,
      logical.attributes_json = coalesce(survivor.attributes_json, '{}'),
      logical.attributes_version = coalesce(logical.attributes_version, 0) + 1,
      logical.projection_reconciliation_id = coalesce(survivor.projection_reconciliation_id, ''),
      logical.assertion_managed = true,
      logical.assertion_quarantined = false
)
FOREACH (_ IN CASE WHEN survivor IS NULL AND coalesce(logical.assertion_managed, false) THEN [1] ELSE [] END |
  DELETE logical
)
RETURN count(*)`

func reconcileProjectedLogicalLinks(ctx context.Context, tx neo4jdriver.ManagedTransaction, rows []map[string]any) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := consume(ctx, tx, reconcileProjectedLogicalLinksQuery, map[string]any{"rows": rows})
	return err
}

func prepareProjectedEntities(entities []*ports.ProjectedEntity) ([]*preparedProjectedEntity, error) {
	prepared := make([]*preparedProjectedEntity, 0, len(entities))
	index := make(map[string]*preparedProjectedEntity, len(entities))
	for _, entity := range entities {
		if entity == nil {
			return nil, errors.New("projected entity is required")
		}
		urn := strings.TrimSpace(entity.URN)
		if urn == "" {
			return nil, errors.New("projected entity urn is required")
		}
		tenantID := strings.TrimSpace(entity.TenantID)
		if tenantID == "" {
			return nil, errors.New("projected entity tenant id is required")
		}
		sourceID := strings.TrimSpace(entity.SourceID)
		if sourceID == "" {
			return nil, errors.New("projected entity source id is required")
		}
		entityType := strings.TrimSpace(entity.EntityType)
		if entityType == "" {
			return nil, errors.New("projected entity type is required")
		}
		if err := ports.ValidateProjectedEntityTenantScope(entity); err != nil {
			return nil, err
		}
		label := strings.TrimSpace(entity.Label)
		if label == "" {
			label = urn
		}
		incoming := projectionmeta.ApplyEntityMetadata(entityType, entity.Attributes)
		if existing, ok := index[urn]; ok {
			existing.tenantID = tenantID
			existing.sourceID = sourceID
			existing.runtimeID = strings.TrimSpace(entity.RuntimeID)
			existing.entityType = entityType
			existing.label = label
			existing.attributes = mergeGraphAttributes(existing.attributes, incoming)
			continue
		}
		entry := &preparedProjectedEntity{
			urn:        urn,
			tenantID:   tenantID,
			sourceID:   sourceID,
			runtimeID:  strings.TrimSpace(entity.RuntimeID),
			entityType: entityType,
			label:      label,
			attributes: incoming,
		}
		index[urn] = entry
		prepared = append(prepared, entry)
	}
	slices.SortFunc(prepared, func(left *preparedProjectedEntity, right *preparedProjectedEntity) int {
		return strings.Compare(left.urn, right.urn)
	})
	return prepared, nil
}

func prepareProjectedLinks(links []*ports.ProjectedLink) ([]*preparedProjectedLink, error) {
	prepared := make([]*preparedProjectedLink, 0, len(links))
	index := make(map[string]*preparedProjectedLink, len(links))
	for _, link := range links {
		fromURN, toURN, relation, tenantID, sourceID, err := validateProjectedLink(link)
		if err != nil {
			return nil, err
		}
		runtimeID := strings.TrimSpace(link.RuntimeID)
		key := projectedLinkAssertionKey(fromURN, relation, toURN, tenantID, sourceID, runtimeID)
		if existing, ok := index[key]; ok {
			existing.attributes = mergeGraphAttributes(existing.attributes, link.Attributes)
			continue
		}
		entry := &preparedProjectedLink{
			fromURN:    fromURN,
			toURN:      toURN,
			relation:   relation,
			tenantID:   tenantID,
			sourceID:   sourceID,
			runtimeID:  runtimeID,
			attributes: mergeGraphAttributes(nil, link.Attributes),
		}
		index[key] = entry
		prepared = append(prepared, entry)
	}
	slices.SortFunc(prepared, func(left *preparedProjectedLink, right *preparedProjectedLink) int {
		if cmp := strings.Compare(left.fromURN, right.fromURN); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.relation, right.relation); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.toURN, right.toURN); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.tenantID, right.tenantID); cmp != 0 {
			return cmp
		}
		if cmp := strings.Compare(left.sourceID, right.sourceID); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.runtimeID, right.runtimeID)
	})
	return prepared, nil
}

func chunkSlice[T any](items []T, size int) [][]T {
	if size <= 0 {
		size = len(items)
	}
	if len(items) == 0 {
		return nil
	}
	chunks := make([][]T, 0, (len(items)+size-1)/size)
	for start := 0; start < len(items); start += size {
		end := start + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[start:end])
	}
	return chunks
}

// DeleteProjectedLink retracts one source-runtime assertion when tenant and
// source provenance are present. A blank runtime is an exact blank-runtime
// identity, not a wildcard. Identity-less deletes are a fail-closed no-op;
// they never remove assertions or uncovered legacy relationships.
func (s *Store) DeleteProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	fromURN, toURN, relation, err := validateProjectedLinkIdentity(link)
	if err != nil {
		return err
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	tenantID := strings.TrimSpace(link.TenantID)
	sourceID := strings.TrimSpace(link.SourceID)
	runtimeID := strings.TrimSpace(link.RuntimeID)
	if tenantID != "" {
		if err := ports.ValidateProjectedLinkTenantScope(link); err != nil {
			return err
		}
	}
	_, err = s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		params := map[string]any{
			"from_urn":   fromURN,
			"to_urn":     toURN,
			"relation":   relation,
			"tenant_id":  tenantID,
			"source_id":  sourceID,
			"runtime_id": runtimeID,
		}
		if tenantID == "" || sourceID == "" {
			return nil, nil
		}
		value, err := queryOneValue(ctx, tx, `MATCH (src:Entity {urn: $from_urn})-[assertion:RELATION_ASSERTION {
    relation: $relation,
    tenant_id: $tenant_id,
    source_id: $source_id,
    runtime_id: $runtime_id
}]->(dst:Entity {urn: $to_urn})
WITH src, dst, assertion
DELETE assertion
RETURN count(*)`, params)
		if err != nil {
			return nil, err
		}
		if toInt64(value) == 0 {
			return nil, nil
		}
		return nil, reconcileProjectedLogicalLinks(ctx, tx, []map[string]any{{
			"from_urn": fromURN, "relation": relation, "to_urn": toURN, "tenant_id": tenantID,
		}})
	})
	if err != nil {
		return fmt.Errorf("delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// DeleteProjectedLinks retracts source-runtime assertions in one transaction and
// reconciles each affected logical relationship after all assertions are gone.
func (s *Store) DeleteProjectedLinks(ctx context.Context, links []*ports.ProjectedLink) error {
	rows := make([]map[string]any, 0, len(links))
	seen := map[string]struct{}{}
	for _, link := range links {
		fromURN, toURN, relation, err := validateProjectedLinkIdentity(link)
		if err != nil {
			return err
		}
		tenantID := strings.TrimSpace(link.TenantID)
		sourceID := strings.TrimSpace(link.SourceID)
		runtimeID := strings.TrimSpace(link.RuntimeID)
		if tenantID != "" {
			if err := ports.ValidateProjectedLinkTenantScope(link); err != nil {
				return err
			}
		}
		if tenantID == "" || sourceID == "" {
			continue
		}
		key := strings.Join([]string{fromURN, relation, toURN, tenantID, sourceID, runtimeID}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		rows = append(rows, map[string]any{
			"from_urn": fromURN, "to_urn": toURN, "relation": relation,
			"tenant_id": tenantID, "source_id": sourceID, "runtime_id": runtimeID,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, `UNWIND $rows AS row
MATCH (src:Entity {urn: row.from_urn})-[assertion:RELATION_ASSERTION {
    relation: row.relation,
    tenant_id: row.tenant_id,
    source_id: row.source_id,
    runtime_id: row.runtime_id
}]->(dst:Entity {urn: row.to_urn})
DELETE assertion
RETURN DISTINCT row.from_urn, row.relation, row.to_urn, row.tenant_id`, map[string]any{"rows": rows})
		if err != nil {
			return nil, err
		}
		affected := make([]map[string]any, 0, len(rows))
		for result.Next(ctx) {
			record := result.Record()
			affected = append(affected, map[string]any{
				"from_urn": stringValue(record.Values[0]), "relation": stringValue(record.Values[1]),
				"to_urn": stringValue(record.Values[2]), "tenant_id": stringValue(record.Values[3]),
			})
		}
		if err := result.Err(); err != nil {
			return nil, err
		}
		return nil, reconcileProjectedLogicalLinks(ctx, tx, affected)
	})
	if err != nil {
		return fmt.Errorf("delete projected links: %w", err)
	}
	return nil
}

// DeleteProjectedEntity removes only an isolated entity. The identity-less API
// cannot safely choose among source-runtime assertions, so shared or legacy
// graph facts must be retracted through their scoped link APIs first.
func (s *Store) DeleteProjectedEntity(ctx context.Context, urn string) error {
	normalizedURN := strings.TrimSpace(urn)
	if normalizedURN == "" {
		return errors.New("projected entity urn is required")
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `MATCH (e:Entity {urn: $urn})
WHERE NOT (e)-[:RELATION]-()
  AND NOT (e)-[:RELATION_ASSERTION]-()
DELETE e`, map[string]any{"urn": normalizedURN})
	})
	if err != nil {
		return fmt.Errorf("delete projected entity %q: %w", normalizedURN, err)
	}
	return nil
}

// DeleteProjectedEntities removes isolated entities with one UNWIND query.
func (s *Store) DeleteProjectedEntities(ctx context.Context, urns []string) error {
	normalized := make([]string, 0, len(urns))
	seen := map[string]struct{}{}
	for _, urn := range urns {
		urn = strings.TrimSpace(urn)
		if urn == "" {
			return errors.New("projected entity urn is required")
		}
		if _, ok := seen[urn]; ok {
			continue
		}
		seen[urn] = struct{}{}
		normalized = append(normalized, urn)
	}
	if len(normalized) == 0 {
		return nil
	}
	if err := s.requireConfigured(); err != nil {
		return err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	_, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return consume(ctx, tx, `UNWIND $urns AS urn
MATCH (e:Entity {urn: urn})
WHERE NOT (e)-[:RELATION]-()
  AND NOT (e)-[:RELATION_ASSERTION]-()
DELETE e`, map[string]any{"urns": normalized})
	})
	if err != nil {
		return fmt.Errorf("delete projected entities: %w", err)
	}
	return nil
}

// CleanupProjectedEntities removes only assertions in the requested
// tenant/source/runtime scope, reconciles their logical links, and deletes an
// entity only when no logical link or assertion still references it.
func (s *Store) CleanupProjectedEntities(ctx context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	if err := s.requireConfigured(); err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	limit := int64(request.Limit)
	if limit <= 0 {
		limit = defaultProjectionCleanupLimit
	}
	tenantID := strings.TrimSpace(request.TenantID)
	sourceID := strings.TrimSpace(request.SourceID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	findingID := strings.TrimSpace(request.FindingID)
	entityTypes := normalizeCleanupEntityTypes(request.EntityTypes)
	urnPrefixes := normalizeCleanupValues(request.URNPrefixes)
	if tenantID == "" && sourceID == "" && runtimeID == "" && findingID == "" && len(entityTypes) == 0 && len(urnPrefixes) == 0 {
		return ports.ProjectionCleanupResult{}, errors.New("projection cleanup scope is required")
	}
	conditions := make([]string, 0, 8)
	params := map[string]any{"limit": limit, "entity_types": entityTypes, "urn_prefixes": urnPrefixes}
	if tenantID != "" {
		conditions = append(conditions, "e.tenant_id = $tenant_id")
		params["tenant_id"] = tenantID
	}
	if sourceID != "" {
		conditions = append(conditions, "e.source_id = $source_id")
		params["source_id"] = sourceID
	}
	if runtimeID != "" {
		conditions = append(conditions, "coalesce(e.runtime_id, '') = $runtime_id")
		params["runtime_id"] = runtimeID
	}
	if findingID != "" {
		conditions = append(conditions, "coalesce(e.attributes_json, '') CONTAINS $finding_id_fragment")
		params["finding_id_fragment"] = fmt.Sprintf("%q:%q", "finding_id", findingID)
	}
	if len(entityTypes) != 0 {
		conditions = append(conditions, "e.entity_type IN $entity_types")
	}
	if len(urnPrefixes) != 0 {
		conditions = append(conditions, "any(prefix IN $urn_prefixes WHERE e.urn STARTS WITH prefix)")
	}
	if request.OnlyIsolated && findingID == "" {
		conditions = append(conditions, "NOT (e)-[:RELATION]-()", "NOT (e)-[:RELATION_ASSERTION]-()")
	}
	candidateQuery := `MATCH (e:Entity)
WHERE ` + strings.Join(conditions, " AND ") + `
RETURN e.urn
ORDER BY e.urn
LIMIT $limit`
	loadCandidates := func(ctx context.Context, tx neo4jdriver.ManagedTransaction) ([]string, error) {
		result, err := tx.Run(ctx, candidateQuery, params)
		if err != nil {
			return nil, err
		}
		var urns []string
		for result.Next(ctx) {
			urns = append(urns, stringValue(result.Record().Values[0]))
		}
		return urns, result.Err()
	}
	assertionScopeComplete := tenantID != "" && sourceID != ""
	assertionParams := map[string]any{
		"tenant_id": tenantID, "source_id": sourceID, "runtime_id": runtimeID,
	}
	countAssertions := func(ctx context.Context, tx neo4jdriver.ManagedTransaction, urns []string) (int64, error) {
		if !assertionScopeComplete || len(urns) == 0 {
			return 0, nil
		}
		assertionParams["urns"] = urns
		value, err := queryOneValue(ctx, tx, `UNWIND $urns AS urn
MATCH (candidate:Entity {urn: urn})
MATCH (src:Entity)-[assertion:RELATION_ASSERTION]->(dst:Entity)
WHERE (src = candidate OR dst = candidate)
  AND assertion.tenant_id = $tenant_id
  AND assertion.source_id = $source_id
  AND assertion.runtime_id = $runtime_id
RETURN count(DISTINCT assertion)`, assertionParams)
		return toInt64(value), err
	}
	if request.DryRun {
		var urns []string
		var links int64
		if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			var err error
			urns, err = loadCandidates(ctx, tx)
			if err != nil {
				return nil, err
			}
			links, err = countAssertions(ctx, tx, urns)
			return nil, err
		}); err != nil {
			return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
		}
		return ports.ProjectionCleanupResult{
			EntitiesMatched: uint32FromInt64(int64(len(urns))),
			LinksMatched:    uint32FromInt64(links),
		}, nil
	}

	var matchedEntities, deletedEntities, deletedAssertions int64
	if _, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		urns, err := loadCandidates(ctx, tx)
		if err != nil {
			return nil, err
		}
		matchedEntities = int64(len(urns))
		if len(urns) == 0 {
			return nil, nil
		}
		if assertionScopeComplete {
			assertionParams["urns"] = urns
			result, err := tx.Run(ctx, `UNWIND $urns AS urn
MATCH (candidate:Entity {urn: urn})
MATCH (src:Entity)-[assertion:RELATION_ASSERTION]->(dst:Entity)
WHERE (src = candidate OR dst = candidate)
  AND assertion.tenant_id = $tenant_id
  AND assertion.source_id = $source_id
  AND assertion.runtime_id = $runtime_id
WITH DISTINCT src, dst, assertion, assertion.relation AS relation
DELETE assertion
RETURN src.urn, relation, dst.urn`, assertionParams)
			if err != nil {
				return nil, err
			}
			affectedRows := make([]map[string]any, 0)
			for result.Next(ctx) {
				values := result.Record().Values
				deletedAssertions++
				affectedRows = append(affectedRows, map[string]any{
					"from_urn": stringValue(values[0]), "relation": stringValue(values[1]),
					"to_urn": stringValue(values[2]), "tenant_id": tenantID,
				})
			}
			if err := result.Err(); err != nil {
				return nil, err
			}
			if err := reconcileProjectedLogicalLinks(ctx, tx, affectedRows); err != nil {
				return nil, err
			}
		}
		value, err := queryOneValue(ctx, tx, `UNWIND $urns AS urn
MATCH (entity:Entity {urn: urn})
WHERE NOT (entity)-[:RELATION]-()
  AND NOT (entity)-[:RELATION_ASSERTION]-()
WITH collect(entity) AS victims
FOREACH (entity IN victims | DELETE entity)
RETURN size(victims)`, map[string]any{"urns": urns})
		if err != nil {
			return nil, err
		}
		deletedEntities = toInt64(value)
		return nil, nil
	}); err != nil {
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	return ports.ProjectionCleanupResult{
		EntitiesMatched: uint32FromInt64(matchedEntities),
		LinksMatched:    uint32FromInt64(deletedAssertions),
		EntitiesDeleted: uint32FromInt64(deletedEntities),
		LinksDeleted:    uint32FromInt64(deletedAssertions),
	}, nil
}

// CleanupEndpointOwnerIDLinks removes stale endpoint owner_id/user_id canonical identity links.
func (s *Store) CleanupEndpointOwnerIDLinks(ctx context.Context, request ports.ProjectionLinkCleanupRequest) (ports.ProjectionLinkCleanupResult, error) {
	if err := s.requireConfigured(); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	params, conditions, err := endpointOwnerIDLinkCleanupParams(request)
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	query := endpointOwnerIDLinkCleanupQuery(conditions, request.DryRun)
	if request.DryRun {
		var matched int64
		if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			value, err := queryOneValue(ctx, tx, query, params)
			if err != nil {
				return nil, err
			}
			matched = toInt64(value)
			return nil, nil
		}); err != nil {
			return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
		}
		return ports.ProjectionLinkCleanupResult{LinksMatched: uint32FromInt64(matched)}, nil
	}
	var deleted int64
	if _, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		affectedRows := make([]map[string]any, 0)
		for result.Next(ctx) {
			values := result.Record().Values
			deleted++
			affectedRows = append(affectedRows, map[string]any{
				"from_urn": stringValue(values[0]), "relation": stringValue(values[1]),
				"to_urn": stringValue(values[2]), "tenant_id": stringValue(params["tenant_id"]),
			})
		}
		if err := result.Err(); err != nil {
			return nil, err
		}
		return nil, reconcileProjectedLogicalLinks(ctx, tx, affectedRows)
	}); err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	return ports.ProjectionLinkCleanupResult{LinksMatched: uint32FromInt64(deleted), LinksDeleted: uint32FromInt64(deleted)}, nil
}

// CountProjectedLinksMissingAssertions reports material logical relationships
// that do not have assertion coverage for the same tenant, endpoints, and
// relation. Callers can use a non-zero count as a migration coverage gate.
func (s *Store) CountProjectedLinksMissingAssertions(ctx context.Context, tenantID string, relations []string) (uint32, error) {
	tenantID = strings.TrimSpace(tenantID)
	relations = normalizeCleanupValues(relations)
	if tenantID == "" || len(relations) == 0 {
		return 0, errProjectionAssertionMigrationScopeRequired
	}
	if err := s.requireConfigured(); err != nil {
		return 0, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return 0, err
	}
	var missing int64
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		value, err := queryOneValue(ctx, tx, `MATCH (src:Entity)-[logical:RELATION]->(dst:Entity)
WHERE logical.tenant_id = $tenant_id
  AND logical.relation IN $relations
  AND (
    coalesce(logical.assertion_managed, false) = false
    OR NOT EXISTS {
      MATCH (src)-[assertion:RELATION_ASSERTION {relation: logical.relation}]->(dst)
      WHERE assertion.tenant_id = $tenant_id
    }
  )
RETURN count(logical)`, map[string]any{
			"tenant_id": tenantID,
			"relations": relations,
		})
		if err != nil {
			return nil, err
		}
		missing = toInt64(value)
		return nil, nil
	}); err != nil {
		return 0, fmt.Errorf("count projected links missing assertions: %w", err)
	}
	return uint32FromInt64(missing), nil
}

// MigrateProjectedLinkAssertions quarantines legacy logical relationships.
// Their last-writer source/runtime properties cannot prove that no other
// runtime asserted the same fact, so only a clean graph rebuild may establish
// complete assertion coverage for them.
func (s *Store) MigrateProjectedLinkAssertions(ctx context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	relations := normalizeCleanupValues(request.Relations)
	if tenantID == "" || len(relations) == 0 {
		return ports.ProjectionAssertionMigrationResult{}, errProjectionAssertionMigrationScopeRequired
	}
	if err := s.requireConfigured(); err != nil {
		return ports.ProjectionAssertionMigrationResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return ports.ProjectionAssertionMigrationResult{}, err
	}
	limit := int64(request.Limit)
	if limit <= 0 {
		limit = defaultProjectionCleanupLimit
	}
	params := map[string]any{"tenant_id": tenantID, "relations": relations, "limit": limit}
	candidateQuery := `MATCH ()-[logical:RELATION]->()
WHERE logical.tenant_id = $tenant_id
  AND logical.relation IN $relations
  AND coalesce(logical.assertion_managed, false) = false
WITH logical
ORDER BY elementId(logical)
LIMIT $limit
RETURN count(logical)`
	if request.DryRun {
		var quarantined int64
		if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			value, err := queryOneValue(ctx, tx, candidateQuery, params)
			quarantined = toInt64(value)
			return nil, err
		}); err != nil {
			return ports.ProjectionAssertionMigrationResult{}, fmt.Errorf("migrate projected link assertions: %w", err)
		}
		return ports.ProjectionAssertionMigrationResult{
			LinksMatched:     uint32FromInt64(quarantined),
			LinksQuarantined: uint32FromInt64(quarantined),
		}, nil
	}
	var quarantined int64
	if _, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		value, err := queryOneValue(ctx, tx, `MATCH ()-[logical:RELATION]->()
WHERE logical.tenant_id = $tenant_id
  AND logical.relation IN $relations
  AND coalesce(logical.assertion_managed, false) = false
WITH logical
ORDER BY elementId(logical)
LIMIT $limit
SET logical.assertion_managed = false,
    logical.assertion_quarantined = true
RETURN count(logical)`, params)
		if err != nil {
			return nil, err
		}
		quarantined = toInt64(value)
		return nil, nil
	}); err != nil {
		return ports.ProjectionAssertionMigrationResult{}, fmt.Errorf("migrate projected link assertions: %w", err)
	}
	return ports.ProjectionAssertionMigrationResult{
		LinksMatched:     uint32FromInt64(quarantined),
		LinksQuarantined: uint32FromInt64(quarantined),
	}, nil
}

// CleanupProjectedRuntimeLinks removes stale source-runtime assertions from one
// authoritative projection pass. The shared logical relationship is retained
// while any assertion remains and is removed only when its last assertion is
// deleted. Legacy logical relationships without assertion coverage are counted
// as matched but deliberately left untouched.
func (s *Store) CleanupProjectedRuntimeLinks(ctx context.Context, request ports.ProjectionRuntimeLinkReconciliationRequest) (ports.ProjectionLinkCleanupResult, error) {
	if err := s.requireConfigured(); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	if err := s.ensureSchema(ctx); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	tenantID := strings.TrimSpace(request.TenantID)
	sourceID := strings.TrimSpace(request.SourceID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	reconciliationID := strings.TrimSpace(request.ReconciliationID)
	relations := normalizeCleanupValues(request.Relations)
	if tenantID == "" || sourceID == "" || runtimeID == "" || reconciliationID == "" || len(relations) == 0 {
		return ports.ProjectionLinkCleanupResult{}, errors.New("tenant_id, source_id, runtime_id, reconciliation_id, and relations are required for runtime link reconciliation")
	}
	limit := int64(request.Limit)
	if limit <= 0 {
		limit = defaultProjectionCleanupLimit
	}
	params := map[string]any{
		"tenant_id":         tenantID,
		"source_id":         sourceID,
		"runtime_id":        runtimeID,
		"relations":         relations,
		"reconciliation_id": reconciliationID,
		"limit":             limit,
	}
	legacyCountQuery := `MATCH (src:Entity)-[legacy:RELATION]->(dst:Entity)
WHERE legacy.tenant_id = $tenant_id
  AND legacy.source_id = $source_id
  AND coalesce(legacy.runtime_id, '') = $runtime_id
  AND legacy.relation IN $relations
  AND coalesce(legacy.assertion_managed, false) = false
  AND NOT EXISTS {
    MATCH (src)-[covered:RELATION_ASSERTION {relation: legacy.relation}]->(dst)
    WHERE covered.tenant_id = $tenant_id
  }
RETURN count(legacy)`
	staleCountQuery := `MATCH ()-[stale:RELATION_ASSERTION]->()
WHERE stale.tenant_id = $tenant_id
  AND stale.source_id = $source_id
  AND stale.runtime_id = $runtime_id
  AND stale.relation IN $relations
  AND coalesce(stale.projection_reconciliation_id, '') <> $reconciliation_id
WITH stale
ORDER BY elementId(stale)
LIMIT $limit
RETURN count(stale)`
	countMatches := func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (int64, int64, error) {
		legacyValue, err := queryOneValue(ctx, tx, legacyCountQuery, params)
		if err != nil {
			return 0, 0, err
		}
		staleValue, err := queryOneValue(ctx, tx, staleCountQuery, params)
		if err != nil {
			return 0, 0, err
		}
		return toInt64(legacyValue), toInt64(staleValue), nil
	}
	if request.DryRun {
		var legacy, stale int64
		if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
			var err error
			legacy, stale, err = countMatches(ctx, tx)
			return nil, err
		}); err != nil {
			return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup projected runtime links: %w", err)
		}
		return ports.ProjectionLinkCleanupResult{LinksMatched: uint32FromInt64(legacy + stale)}, nil
	}

	var legacy, deleted int64
	if _, err := s.write(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		legacyValue, err := queryOneValue(ctx, tx, legacyCountQuery, params)
		if err != nil {
			return nil, err
		}
		legacy = toInt64(legacyValue)
		result, err := tx.Run(ctx, `MATCH (src:Entity)-[stale:RELATION_ASSERTION]->(dst:Entity)
WHERE stale.tenant_id = $tenant_id
  AND stale.source_id = $source_id
  AND stale.runtime_id = $runtime_id
  AND stale.relation IN $relations
  AND coalesce(stale.projection_reconciliation_id, '') <> $reconciliation_id
WITH src, dst, stale, stale.relation AS relation
ORDER BY elementId(stale)
LIMIT $limit
DELETE stale
RETURN src.urn, relation, dst.urn`, params)
		if err != nil {
			return nil, err
		}
		affectedRows := make([]map[string]any, 0)
		affected := make(map[string]struct{})
		for result.Next(ctx) {
			values := result.Record().Values
			fromURN := stringValue(values[0])
			relation := stringValue(values[1])
			toURN := stringValue(values[2])
			deleted++
			key := projectedLinkKey(fromURN, relation, toURN)
			if _, ok := affected[key]; ok {
				continue
			}
			affected[key] = struct{}{}
			affectedRows = append(affectedRows, map[string]any{
				"from_urn":  fromURN,
				"relation":  relation,
				"to_urn":    toURN,
				"tenant_id": tenantID,
			})
		}
		if err := result.Err(); err != nil {
			return nil, err
		}
		return nil, reconcileProjectedLogicalLinks(ctx, tx, affectedRows)
	}); err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup projected runtime links: %w", err)
	}
	return ports.ProjectionLinkCleanupResult{
		LinksMatched: uint32FromInt64(legacy + deleted),
		LinksDeleted: uint32FromInt64(deleted),
	}, nil
}

func endpointOwnerIDLinkCleanupQuery(conditions []string, dryRun bool) string {
	query := `MATCH (e:Entity)-[logical:RELATION]->(target:Entity)
WHERE ` + strings.Join(conditions, " AND ") + `
  AND EXISTS {
    MATCH (e)-[replacement:RELATION {relation: 'has_identifier'}]->(replacementTarget:Entity)
    WHERE replacement.tenant_id = logical.tenant_id
      AND replacement.source_id IN $source_ids
      AND any(stalePrefix IN $stale_prefixes WHERE target.urn STARTS WITH stalePrefix
        AND any(replacementPrefix IN $replacement_prefixes WHERE replacementTarget.urn STARTS WITH replacementPrefix
          AND substring(target.urn, size(stalePrefix)) = substring(replacementTarget.urn, size(replacementPrefix))))
  }
MATCH (e)-[stale:RELATION_ASSERTION {relation: logical.relation}]->(target)
WHERE stale.tenant_id = $tenant_id
  AND stale.source_id IN $source_ids
  AND stale.runtime_id = $runtime_id
WITH stale, e, target, logical.relation AS relation
ORDER BY e.urn, relation, target.urn, elementId(stale)
LIMIT $limit`
	if dryRun {
		return query + `
RETURN count(stale)`
	}
	return query + `
DELETE stale
RETURN e.urn, relation, target.urn`
}

func endpointOwnerIDLinkCleanupParams(request ports.ProjectionLinkCleanupRequest) (map[string]any, []string, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, nil, errors.New("tenant_id is required for endpoint owner-id link cleanup")
	}
	sourceIDs := endpointOwnerIDCleanupSources(request.SourceID)
	if len(sourceIDs) == 0 {
		return nil, nil, errors.New("unsupported endpoint owner-id cleanup source")
	}
	stalePrefixes, replacementPrefixes := endpointOwnerIDCleanupPrefixes(tenantID, sourceIDs)
	limit := int64(request.Limit)
	if limit <= 0 {
		limit = defaultProjectionCleanupLimit
	}
	conditions := []string{
		"e.tenant_id = $tenant_id",
		"logical.tenant_id = $tenant_id",
		"e.source_id IN $source_ids",
		"e.entity_type IN $endpoint_entity_types",
		"logical.relation IN $stale_relations",
		"any(stalePrefix IN $stale_prefixes WHERE target.urn STARTS WITH stalePrefix)",
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	params := map[string]any{
		"tenant_id":             tenantID,
		"source_ids":            sourceIDs,
		"endpoint_entity_types": []string{"kolide.device", "kandji.device"},
		"stale_relations":       []string{"owned_by", "represents_identity", "has_identifier"},
		"stale_prefixes":        stalePrefixes,
		"replacement_prefixes":  replacementPrefixes,
		"runtime_id":            runtimeID,
		"limit":                 limit,
	}
	return params, conditions, nil
}

func endpointOwnerIDCleanupSources(sourceID string) []string {
	source := strings.ToLower(strings.TrimSpace(sourceID))
	switch source {
	case "":
		return []string{"kolide", "kandji"}
	case "kolide", "kandji":
		return []string{source}
	default:
		return nil
	}
}

func endpointOwnerIDCleanupPrefixes(tenantID string, sources []string) ([]string, []string) {
	stalePrefixes := []string{
		fmt.Sprintf("urn:cerebro:%s:identity:login:", tenantID),
		fmt.Sprintf("urn:cerebro:%s:identifier:login:", tenantID),
	}
	replacementPrefixes := make([]string, 0, len(sources)*2)
	for _, source := range sources {
		replacementPrefixes = append(replacementPrefixes,
			fmt.Sprintf("urn:cerebro:%s:endpoint_identifier:%s_owner_id:", tenantID, source),
			fmt.Sprintf("urn:cerebro:%s:endpoint_identifier:%s_user_id:", tenantID, source),
		)
	}
	return stalePrefixes, replacementPrefixes
}

// GetEntityNeighborhood retains the bounded compatibility read used by
// explicit legacy rollback and shadow verification. Rust remains the default
// product-read authority; callers reach this method only through a configured
// compatibility mode.
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		neighborhood = &ports.EntityNeighborhood{
			Neighbors: []*ports.NeighborhoodNode{},
			Relations: []*ports.NeighborhoodRelation{},
		}
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

// GetEntityNeighborhoods retains the batched compatibility read used by
// explicit legacy rollback and shadow verification. It preserves the same
// per-root edge ordering as GetEntityNeighborhood while collapsing frontier
// expansion into three read queries instead of three queries per root.
func (s *Store) GetEntityNeighborhoods(ctx context.Context, rootURNs []string, limit int) (map[string]*ports.EntityNeighborhood, error) {
	roots := normalizeNeighborhoodRootURNs(rootURNs)
	if len(roots) == 0 {
		return map[string]*ports.EntityNeighborhood{}, nil
	}
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	neighborhoods := make(map[string]*ports.EntityNeighborhood, len(roots))
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		accumulators := make(map[string]*neighborhoodAccumulator, len(roots))
		result, err := tx.Run(ctx, `MATCH (e:Entity)
WHERE e.urn IN $root_urns
RETURN e.urn, e.entity_type, e.label`, map[string]any{"root_urns": roots})
		if err != nil {
			return nil, fmt.Errorf("query graph roots: %w", err)
		}
		for result.Next(ctx) {
			record := result.Record()
			root := &ports.NeighborhoodNode{
				URN:        stringValue(record.Values[0]),
				EntityType: stringValue(record.Values[1]),
				Label:      stringValue(record.Values[2]),
			}
			accumulators[root.URN] = &neighborhoodAccumulator{
				neighborhood: &ports.EntityNeighborhood{
					Root:      root,
					Neighbors: []*ports.NeighborhoodNode{},
					Relations: []*ports.NeighborhoodRelation{},
				},
				neighbors: make(map[string]*ports.NeighborhoodNode),
				relations: make(map[string]*ports.NeighborhoodRelation),
				remaining: limit,
			}
		}
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("query graph roots: %w", err)
		}
		presentRoots := make([]string, 0, len(roots))
		for _, rootURN := range roots {
			if accumulators[rootURN] != nil {
				presentRoots = append(presentRoots, rootURN)
			}
		}
		if limit > 0 && len(presentRoots) > 0 {
			params := map[string]any{"root_urns": presentRoots, "limit": limit}
			if err := collectBatchedNeighborhoodRows(ctx, tx, outgoingNeighborhoodBatchQuery, params, accumulators); err != nil {
				return nil, err
			}
			incomingRootsByLimit := make(map[int][]string)
			for _, rootURN := range presentRoots {
				remaining := accumulators[rootURN].remaining
				if remaining > 0 {
					incomingRootsByLimit[remaining] = append(incomingRootsByLimit[remaining], rootURN)
				}
			}
			incomingLimits := make([]int, 0, len(incomingRootsByLimit))
			for remaining := range incomingRootsByLimit {
				incomingLimits = append(incomingLimits, remaining)
			}
			slices.Sort(incomingLimits)
			for _, remaining := range incomingLimits {
				params := map[string]any{"root_urns": incomingRootsByLimit[remaining], "limit": remaining}
				if err := collectBatchedNeighborhoodRows(ctx, tx, incomingNeighborhoodBatchQuery, params, accumulators); err != nil {
					return nil, err
				}
			}
		}
		for _, rootURN := range presentRoots {
			accumulator := accumulators[rootURN]
			accumulator.neighborhood.Neighbors = neighborhoodNodes(accumulator.neighbors)
			accumulator.neighborhood.Relations = neighborhoodRelations(accumulator.relations)
			neighborhoods[rootURN] = accumulator.neighborhood
		}
		return nil, nil
	}); err != nil {
		return nil, err
	}
	return neighborhoods, nil
}

// ExecuteReadCypher runs one bounded read-only Cypher query and returns its rows.
//
// The store enforces a row cap to keep graph rules from accidentally pulling unbounded result
// sets that would stall the orchestrator; callers may request a smaller cap via RowLimit but
// the absolute upper bound is ports.MaxCypherQueryRows.
func (s *Store) ExecuteReadCypher(ctx context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	query := strings.TrimSpace(request.Query)
	if query == "" {
		return nil, errors.New("cypher query is required")
	}
	if err := validateReadOnlyCypher(query); err != nil {
		return nil, err
	}
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	rowLimit := request.RowLimit
	if rowLimit <= 0 || rowLimit > ports.MaxCypherQueryRows {
		rowLimit = ports.MaxCypherQueryRows
	}
	var rows []ports.CypherRow
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		rows = nil
		result, err := tx.Run(ctx, query, request.Params)
		if err != nil {
			return nil, err
		}
		keys, err := result.Keys()
		if err != nil {
			return nil, err
		}
		for result.Next(ctx) {
			if len(rows) >= rowLimit {
				break
			}
			record := result.Record()
			values := make(map[string]any, len(keys))
			for i, key := range keys {
				if i >= len(record.Values) {
					break
				}
				values[key] = record.Values[i]
			}
			rows = append(rows, ports.CypherRow{Values: values})
		}
		return nil, result.Err()
	}); err != nil {
		return nil, fmt.Errorf("execute read cypher: %w", err)
	}
	return rows, nil
}

// ExplainReadCypher returns the Neo4j execution plan for one read-only Cypher query.
func (s *Store) ExplainReadCypher(ctx context.Context, request ports.CypherQueryRequest) (*ports.CypherPlan, error) {
	query := strings.TrimSpace(request.Query)
	if query == "" {
		return nil, errors.New("cypher query is required")
	}
	if err := validateReadOnlyCypher(query); err != nil {
		return nil, err
	}
	if err := s.requireConfigured(); err != nil {
		return nil, err
	}
	var plan *ports.CypherPlan
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, "EXPLAIN "+query, request.Params)
		if err != nil {
			return nil, err
		}
		summary, err := result.Consume(ctx)
		if err != nil {
			return nil, err
		}
		if root := cypherPlanNode(summary.Plan()); root != nil {
			plan = &ports.CypherPlan{Root: root}
		}
		return nil, nil
	}); err != nil {
		return nil, fmt.Errorf("explain read cypher: %w", err)
	}
	return plan, nil
}

func cypherPlanNode(plan neo4jdriver.Plan) *ports.CypherPlanNode {
	if plan == nil {
		return nil
	}
	children := plan.Children()
	node := &ports.CypherPlanNode{
		Operator:  plan.Operator(),
		Arguments: clonePlanArguments(plan.Arguments()),
		Children:  make([]ports.CypherPlanNode, 0, len(children)),
	}
	for _, child := range children {
		if childNode := cypherPlanNode(child); childNode != nil {
			node.Children = append(node.Children, *childNode)
		}
	}
	return node
}

func clonePlanArguments(arguments map[string]any) map[string]any {
	if len(arguments) == 0 {
		return nil
	}
	clone := make(map[string]any, len(arguments))
	for key, value := range arguments {
		clone[key] = value
	}
	return clone
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		checkpoint = IngestCheckpoint{}
		found = false
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
    r.checkpoint_cursor = $checkpoint_cursor,
    r.checkpoint_complete = $checkpoint_complete,
    r.status = $status,
    r.trigger = $trigger,
    r.pages_read = $pages_read,
    r.events_read = $events_read,
    r.entities_projected = $entities_projected,
    r.links_projected = $links_projected,
	 r.material_link_reconciliation_requested = $material_link_reconciliation_requested,
	 r.material_link_reconciliation_supported = $material_link_reconciliation_supported,
	 r.material_link_reconciliation_completed = $material_link_reconciliation_completed,
	 r.projection_reconciliation_id = $projection_reconciliation_id,
	 r.stale_material_links_deleted = $stale_material_links_deleted,
    r.graph_nodes_before = $graph_nodes_before,
    r.graph_links_before = $graph_links_before,
    r.graph_nodes_after = $graph_nodes_after,
    r.graph_links_after = $graph_links_after,
    r.started_at = $started_at,
    r.finished_at = $finished_at,
    r.error_message = $error_message`, map[string]any{
			"id":                                     run.ID,
			"runtime_id":                             strings.TrimSpace(run.RuntimeID),
			"source_id":                              strings.TrimSpace(run.SourceID),
			"tenant_id":                              strings.TrimSpace(run.TenantID),
			"checkpoint_id":                          strings.TrimSpace(run.CheckpointID),
			"checkpoint_cursor":                      strings.TrimSpace(run.CheckpointCursor),
			"checkpoint_complete":                    run.CheckpointComplete,
			"status":                                 run.Status,
			"trigger":                                strings.TrimSpace(run.Trigger),
			"pages_read":                             run.PagesRead,
			"events_read":                            run.EventsRead,
			"entities_projected":                     run.EntitiesProjected,
			"links_projected":                        run.LinksProjected,
			"material_link_reconciliation_requested": run.MaterialLinkReconciliationRequested,
			"material_link_reconciliation_supported": run.MaterialLinkReconciliationSupported,
			"material_link_reconciliation_completed": run.MaterialLinkReconciliationCompleted,
			"projection_reconciliation_id":           strings.TrimSpace(run.ProjectionReconciliationID),
			"stale_material_links_deleted":           run.StaleMaterialLinksDeleted,
			"graph_nodes_before":                     run.GraphNodesBefore,
			"graph_links_before":                     run.GraphLinksBefore,
			"graph_nodes_after":                      run.GraphNodesAfter,
			"graph_links_after":                      run.GraphLinksAfter,
			"started_at":                             strings.TrimSpace(run.StartedAt),
			"finished_at":                            strings.TrimSpace(run.FinishedAt),
			"error_message":                          strings.TrimSpace(run.Error),
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
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		run = IngestRun{}
		found = false
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
	query, params, err := ingestRunListQuery(filter, limit)
	if err != nil {
		return nil, err
	}
	var runs []IngestRun
	if _, err := s.read(ctx, func(ctx context.Context, tx neo4jdriver.ManagedTransaction) (any, error) {
		runs = runs[:0]
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

func ingestRunListQuery(filter IngestRunFilter, limit int) (string, map[string]any, error) {
	where := make([]string, 0, 2)
	params := map[string]any{}
	runtimeIDs := normalizedNonEmptyStrings(append(slices.Clone(filter.RuntimeIDs), filter.RuntimeID))
	status := strings.TrimSpace(filter.Status)
	if status != "" && !validIngestRunStatus(status) {
		return "", nil, fmt.Errorf("unsupported ingest run status %q", status)
	}
	if filter.LatestByRuntime && len(runtimeIDs) > 0 {
		params["runtime_ids"] = runtimeIDs
		statusPredicate := ""
		if status != "" {
			params["status"] = status
			statusPredicate = "\nWHERE r.status = $status"
		}
		query := `
UNWIND $runtime_ids AS runtime_id
CALL {
  WITH runtime_id
  MATCH (r:IngestRun {runtime_id: runtime_id})` + statusPredicate + `
  RETURN r
  ORDER BY r.started_at DESC, r.id DESC
  LIMIT 1
}
` + ingestRunReturnQuery("WITH r") + fmt.Sprintf(" ORDER BY r.started_at DESC, r.id DESC LIMIT %d", limit)
		return query, params, nil
	}
	if len(runtimeIDs) == 1 {
		where = append(where, "r.runtime_id = $runtime_id")
		params["runtime_id"] = runtimeIDs[0]
	} else if len(runtimeIDs) > 1 {
		where = append(where, "r.runtime_id IN $runtime_ids")
		params["runtime_ids"] = runtimeIDs
	}
	if status != "" {
		where = append(where, "r.status = $status")
		params["status"] = status
	}
	prefix := "MATCH (r:IngestRun)"
	if len(where) > 0 {
		prefix += " WHERE " + strings.Join(where, " AND ")
	}
	query := ingestRunReturnQuery(prefix) + fmt.Sprintf(" ORDER BY coalesce(r.started_at, '') DESC, r.id DESC LIMIT %d", limit)
	if filter.LatestByRuntime {
		query = prefix + `
WITH coalesce(r.runtime_id, r.id) AS runtime_key, r
ORDER BY runtime_key ASC, coalesce(r.started_at, '') DESC, r.id DESC
WITH runtime_key, collect(r)[0] AS r
` + ingestRunReturnQuery("WITH r") + fmt.Sprintf(" ORDER BY coalesce(r.started_at, '') DESC, r.id DESC LIMIT %d", limit)
	}
	return query, params, nil
}

func normalizedNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
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
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.schemaReady {
		return nil
	}
	statements := neo4jSchemaStatements()
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

func neo4jSchemaStatements() []string {
	return []string{
		"CREATE CONSTRAINT cerebro_entity_urn IF NOT EXISTS FOR (e:Entity) REQUIRE e.urn IS UNIQUE",
		"CREATE CONSTRAINT cerebro_checkpoint_id IF NOT EXISTS FOR (c:IngestCheckpoint) REQUIRE c.id IS UNIQUE",
		"CREATE CONSTRAINT cerebro_ingest_run_id IF NOT EXISTS FOR (r:IngestRun) REQUIRE r.id IS UNIQUE",
		"CREATE INDEX cerebro_ingest_run_runtime IF NOT EXISTS FOR (r:IngestRun) ON (r.runtime_id)",
		"CREATE INDEX cerebro_ingest_run_runtime_started IF NOT EXISTS FOR (r:IngestRun) ON (r.runtime_id, r.started_at)",
		"CREATE INDEX cerebro_entity_tenant_runtime IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.runtime_id)",
		"CREATE INDEX cerebro_entity_tenant_type IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.entity_type)",
		"CREATE INDEX cerebro_entity_tenant_source IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.source_id)",
		"CREATE INDEX cerebro_entity_tenant_source_type IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.source_id, e.entity_type)",
		"CREATE INDEX cerebro_entity_tenant_label IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.label)",
		"CREATE INDEX cerebro_entity_tenant_internet_exposed IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.internet_exposed)",
		"CREATE INDEX cerebro_entity_tenant_privileged_identity IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.is_privileged_identity)",
		"CREATE INDEX cerebro_entity_tenant_mfa_disabled IF NOT EXISTS FOR (e:Entity) ON (e.tenant_id, e.mfa_disabled)",
		"CREATE INDEX cerebro_relation_tenant_runtime IF NOT EXISTS FOR ()-[r:RELATION]-() ON (r.tenant_id, r.runtime_id)",
		"CREATE INDEX cerebro_relation_tenant_relation IF NOT EXISTS FOR ()-[r:RELATION]-() ON (r.tenant_id, r.relation)",
		"CREATE INDEX cerebro_relation_assertion_tenant_runtime IF NOT EXISTS FOR ()-[a:RELATION_ASSERTION]-() ON (a.tenant_id, a.runtime_id)",
		"CREATE INDEX cerebro_relation_assertion_identity IF NOT EXISTS FOR ()-[a:RELATION_ASSERTION]-() ON (a.tenant_id, a.relation, a.source_id, a.runtime_id)",
		"CREATE FULLTEXT INDEX cerebro_entity_inventory_fulltext IF NOT EXISTS FOR (e:Entity) ON EACH [e.urn, e.label, e.entity_type, e.attributes_json]",
	}
}

func (s *Store) projectionBatchSizeOrDefault() int {
	if s != nil && s.projectionBatchSize > 0 {
		return s.projectionBatchSize
	}
	return defaultProjectionUpsertBatchSize
}

func (s *Store) acquireWriteSlot(ctx context.Context) (func(), error) {
	if s == nil || s.writeSlots == nil {
		return func() {}, nil
	}
	select {
	case s.writeSlots <- struct{}{}:
		return func() { <-s.writeSlots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Store) read(ctx context.Context, work func(context.Context, neo4jdriver.ManagedTransaction) (any, error)) (any, error) {
	attrs := neo4jTelemetryAttrs("read", s.database, s.queryTimeout)
	if s.queryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.queryTimeout)
		defer cancel()
	}
	started := time.Now()
	ctx, span := telemetry.StartQuiet(ctx, "neo4j.read", attrs)
	session := s.driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: s.database})
	defer func() { _ = session.Close(ctx) }()
	result, err := session.ExecuteRead(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		return work(ctx, tx)
	})
	if err != nil {
		recordNeo4jOperation(ctx, s.database, "read", "failed", telemetry.ErrorKind(err), time.Since(started))
		neo4jTelemetryError(ctx, span, s.database, "read", err)
		return nil, err
	}
	recordNeo4jOperation(ctx, s.database, "read", "completed", "", time.Since(started))
	neo4jAnnotateMain(ctx, s.database, "read", "completed")
	telemetry.EndQuiet(span, "completed", telemetry.Attrs())
	return result, nil
}

func (s *Store) write(ctx context.Context, work neo4jdriver.ManagedTransactionWork) (any, error) {
	release, err := s.acquireWriteSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	started := time.Now()
	ctx, span := telemetry.StartQuiet(ctx, "neo4j.write", neo4jTelemetryAttrs("write", s.database, 0))
	session := s.driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: s.database})
	defer func() { _ = session.Close(ctx) }()
	result, err := session.ExecuteWrite(ctx, work)
	if err != nil {
		recordNeo4jOperation(ctx, s.database, "write", "failed", telemetry.ErrorKind(err), time.Since(started))
		neo4jTelemetryError(ctx, span, s.database, "write", err)
		return nil, err
	}
	recordNeo4jOperation(ctx, s.database, "write", "completed", "", time.Since(started))
	neo4jAnnotateMain(ctx, s.database, "write", "completed")
	telemetry.EndQuiet(span, "completed", telemetry.Attrs())
	return result, nil
}

func recordNeo4jOperation(ctx context.Context, database string, operation string, status string, errorKind string, duration time.Duration) {
	observability.RecordNeo4jOperation(ctx, observability.Neo4jOperationMetrics{
		Operation:          operation,
		Status:             status,
		ErrorKind:          errorKind,
		Duration:           duration,
		DatabaseConfigured: strings.TrimSpace(database) != "",
	})
}

func neo4jTelemetryAttrs(operation string, database string, timeout time.Duration) telemetry.Attributes {
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "graphstore.neo4j"},
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "db.system.name", Value: "neo4j"},
		telemetry.Field{Key: "db.namespace", Value: strings.TrimSpace(database)},
	)
	if timeout > 0 {
		attrs = attrs.WithField(telemetry.Field{Key: "timeout_ms", Value: timeout.Milliseconds()})
	}
	return attrs
}

func neo4jTelemetryError(ctx context.Context, span *telemetry.Span, database string, operation string, err error) {
	neo4jAnnotateMain(ctx, database, operation, "failed")
	attrs := telemetry.Attrs(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	telemetry.CaptureError(ctx, "neo4j.error", err, telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "graphstore.neo4j"},
		telemetry.Field{Key: "operation", Value: operation},
		telemetry.Field{Key: "db.namespace", Value: strings.TrimSpace(database)},
	))
	telemetry.End(span, "failed", attrs)
}

func neo4jAnnotateMain(ctx context.Context, database string, operation string, status string) {
	telemetry.IncrementMain(ctx, "db.neo4j.operation.count", 1)
	if operation == "read" {
		telemetry.IncrementMain(ctx, "db.neo4j.read.count", 1)
	}
	if operation == "write" {
		telemetry.IncrementMain(ctx, "db.neo4j.write.count", 1)
	}
	if status == "failed" {
		telemetry.IncrementMain(ctx, "db.neo4j.error.count", 1)
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "db.neo4j.last_database", Value: strings.TrimSpace(database)},
		telemetry.Field{Key: "db.neo4j.last_operation", Value: strings.TrimSpace(operation)},
		telemetry.Field{Key: "db.neo4j.last_status", Value: strings.TrimSpace(status)},
		telemetry.Field{Key: "db.system.name", Value: "neo4j"},
		telemetry.Field{Key: "db.namespace", Value: strings.TrimSpace(database)},
	)
	telemetry.AnnotateMain(ctx, attrs)
	telemetry.AnnotateMainDependency(ctx, "db.neo4j", "graphstore.neo4j", operation, status, attrs)
}

func consume(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any) (any, error) {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return nil, err
	}
	_, err = result.Consume(ctx)
	return nil, err
}

func validateReadOnlyCypher(query string) error {
	code := stripCypherNonCode(query)
	if escapedProcedureCallPattern.MatchString(stripCypherNonCodePreservingIdentifiers(query)) {
		return errors.New("read cypher must use an unescaped allowlisted procedure name")
	}
	if err := validateBoundedAPOCProcedureCalls(query); err != nil {
		return err
	}
	code = maskReadOnlyAPOCProcedureCalls(code)
	if match := mutatingCypherPattern.FindString(code); match != "" {
		return fmt.Errorf("read cypher must not contain mutating clause %q", strings.TrimSpace(match))
	}
	return nil
}

func maskReadOnlyAPOCProcedureCalls(query string) string {
	masked := []byte(query)
	for _, match := range procedureCallPattern.FindAllStringSubmatchIndex(query, -1) {
		if len(match) < 4 || match[2] < 0 || match[3] < 0 {
			continue
		}
		name := strings.ToLower(query[match[2]:match[3]])
		if _, ok := readOnlyAPOCProcedures[name]; !ok {
			continue
		}
		for index := match[0]; index < match[3]; index++ {
			if masked[index] != '\n' && masked[index] != '\r' {
				masked[index] = ' '
			}
		}
	}
	return string(masked)
}

func stripCypherNonCode(query string) string {
	return stripCypherNonCodeWithIdentifiers(query, false)
}

func stripCypherNonCodePreservingIdentifiers(query string) string {
	return stripCypherNonCodeWithIdentifiers(query, true)
}

func stripCypherNonCodeWithIdentifiers(query string, preserveIdentifiers bool) string {
	var out strings.Builder
	out.Grow(len(query))
	for i := 0; i < len(query); {
		if i+1 < len(query) && query[i] == '/' && query[i+1] == '/' {
			i = writeCypherMaskedUntilNewline(&out, query, i)
			continue
		}
		if i+1 < len(query) && query[i] == '/' && query[i+1] == '*' {
			i = writeCypherMaskedBlockComment(&out, query, i)
			continue
		}
		switch query[i] {
		case '`':
			if preserveIdentifiers {
				i = writeCypherQuoted(&out, query, i, query[i])
			} else {
				i = writeCypherMaskedQuoted(&out, query, i, query[i])
			}
		case '\'', '"':
			i = writeCypherMaskedQuoted(&out, query, i, query[i])
		default:
			out.WriteByte(query[i])
			i++
		}
	}
	return out.String()
}

func writeCypherQuoted(out *strings.Builder, query string, start int, quote byte) int {
	for i := start; i < len(query); i++ {
		out.WriteByte(query[i])
		if i == start || query[i] != quote {
			continue
		}
		if i+1 < len(query) && query[i+1] == quote {
			i++
			out.WriteByte(query[i])
			continue
		}
		return i + 1
	}
	return len(query)
}

func writeCypherMaskedUntilNewline(out *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		if query[i] == '\n' {
			out.WriteByte('\n')
			return i + 1
		}
		out.WriteByte(' ')
	}
	return len(query)
}

func writeCypherMaskedBlockComment(out *strings.Builder, query string, start int) int {
	for i := start; i < len(query); i++ {
		if query[i] == '\n' {
			out.WriteByte('\n')
		} else {
			out.WriteByte(' ')
		}
		if i > start && query[i-1] == '*' && query[i] == '/' {
			return i + 1
		}
	}
	return len(query)
}

func writeCypherMaskedQuoted(out *strings.Builder, query string, start int, quote byte) int {
	out.WriteByte(' ')
	for i := start + 1; i < len(query); i++ {
		if query[i] == '\n' {
			out.WriteByte('\n')
		} else {
			out.WriteByte(' ')
		}
		if query[i] == '\\' && quote != '`' && i+1 < len(query) {
			i++
			if query[i] == '\n' {
				out.WriteByte('\n')
			} else {
				out.WriteByte(' ')
			}
			continue
		}
		if query[i] != quote {
			continue
		}
		if i+1 < len(query) && query[i+1] == quote {
			i++
			out.WriteByte(' ')
			continue
		}
		return i + 1
	}
	return len(query)
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
	fromURN, toURN, relation, err = validateProjectedLinkIdentity(link)
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
	if err := ports.ValidateProjectedLinkTenantScope(link); err != nil {
		return "", "", "", "", "", err
	}
	return fromURN, toURN, relation, tenantID, sourceID, nil
}

func validateProjectedLinkIdentity(link *ports.ProjectedLink) (fromURN string, toURN string, relation string, err error) {
	if link == nil {
		return "", "", "", errors.New("projected link is required")
	}
	fromURN = strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return "", "", "", errors.New("projected link from urn is required")
	}
	toURN = strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return "", "", "", errors.New("projected link to urn is required")
	}
	relation = strings.TrimSpace(link.Relation)
	if relation == "" {
		return "", "", "", errors.New("projected link relation is required")
	}
	return fromURN, toURN, relation, nil
}

func normalizeCleanupEntityTypes(values []string) []string {
	return normalizeCleanupValues(values)
}

func normalizeCleanupValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func mergeEntityAndLoadAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, params map[string]any) (string, int64, error) {
	result, err := tx.Run(ctx, mergeEntityAndLoadAttributesQuery, params)
	if err != nil {
		return "", 0, err
	}
	if !result.Next(ctx) {
		if err := result.Err(); err != nil {
			return "", 0, err
		}
		return "", 0, errors.New("entity merge returned no rows")
	}
	values := result.Record().Values
	return stringValue(values[0]), toInt64(values[1]), result.Err()
}

// entityTypedPropertyParams maps the derived typed properties onto the node
// property names backing the range indexes and the rule predicates. Building the
// map here (rather than in projectionmeta) keeps the exported derivation API
// strongly typed.
func entityTypedPropertyParams(properties projectionmeta.EntityTypedProperties) map[string]any {
	return map[string]any{
		projectionmeta.PropertyInternetExposed:    properties.InternetExposed,
		projectionmeta.PropertyPrivilegedIdentity: properties.PrivilegedIdentity,
		projectionmeta.PropertyMFADisabled:        properties.MFADisabled,
	}
}

func updateEntityAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, urn string, version int64, attributesJSON string, typedProperties map[string]any) (bool, error) {
	updated, err := countQuery(ctx, tx, `MATCH (e:Entity {urn: $urn})
WHERE coalesce(e.attributes_version, 0) = $attributes_version
SET e.attributes_json = $attributes_json,
    e.attributes_version = $next_attributes_version,
    e += $typed_properties
RETURN count(e)`, map[string]any{
		"urn":                     urn,
		"attributes_version":      version,
		"next_attributes_version": version + 1,
		"attributes_json":         attributesJSON,
		"typed_properties":        typedProperties,
	})
	if err != nil {
		return false, err
	}
	return updated == 1, nil
}

func mergeLinkAndLoadAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, params map[string]any) (loadedProjectedLinkRow, bool, error) {
	result, err := tx.Run(ctx, `MATCH (src:Entity {urn: $from_urn}), (dst:Entity {urn: $to_urn})
SET src.relation_lock = coalesce(src.relation_lock, 0) + 1
MERGE (src)-[r:RELATION {relation: $relation}]->(dst)
ON CREATE SET r.attributes_json = '{}', r.attributes_version = 0, r.assertion_managed = true, r.assertion_quarantined = false
WITH src, dst, r,
     coalesce(r.assertion_managed, false) AS was_assertion_managed,
     CASE WHEN coalesce(r.tenant_id, '') <> '' THEN r.tenant_id ELSE $tenant_id END AS legacy_tenant_id,
     coalesce(r.source_id, '') AS legacy_source_id,
     coalesce(r.runtime_id, '') AS legacy_runtime_id
WITH src, dst, r, legacy_tenant_id, legacy_source_id, legacy_runtime_id,
     NOT was_assertion_managed AS preserve_legacy_logical
SET r.tenant_id = CASE WHEN preserve_legacy_logical THEN legacy_tenant_id ELSE $tenant_id END,
	r.source_id = CASE WHEN preserve_legacy_logical THEN legacy_source_id ELSE $source_id END,
	r.runtime_id = CASE WHEN preserve_legacy_logical THEN legacy_runtime_id ELSE $runtime_id END,
	r.assertion_managed = NOT preserve_legacy_logical,
	r.assertion_quarantined = preserve_legacy_logical
MERGE (src)-[a:RELATION_ASSERTION {
    relation: $relation,
    tenant_id: $tenant_id,
    source_id: $source_id,
    runtime_id: $runtime_id
}]->(dst)
ON CREATE SET a.attributes_json = '{}', a.attributes_version = 0
SET a.projection_reconciliation_id = $reconciliation_id
RETURN coalesce(r.attributes_json, '{}'),
       coalesce(r.attributes_version, 0),
       coalesce(a.attributes_json, '{}'),
       coalesce(a.attributes_version, 0),
       preserve_legacy_logical`, params)
	if err != nil {
		return loadedProjectedLinkRow{}, false, err
	}
	if !result.Next(ctx) {
		return loadedProjectedLinkRow{}, false, result.Err()
	}
	values := result.Record().Values
	return loadedProjectedLinkRow{
		logicalAttributesJSON:   stringValue(values[0]),
		logicalVersion:          toInt64(values[1]),
		assertionAttributesJSON: stringValue(values[2]),
		assertionVersion:        toInt64(values[3]),
		preserveLegacyLogical:   boolValue(values[4]),
	}, true, result.Err()
}

func updateLinkAttributes(ctx context.Context, tx neo4jdriver.ManagedTransaction, params map[string]any, current loadedProjectedLinkRow, logicalAttributesJSON string, assertionAttributesJSON string) (bool, error) {
	params["logical_attributes_version"] = current.logicalVersion
	params["next_logical_attributes_version"] = current.logicalVersion + 1
	params["logical_attributes_json"] = logicalAttributesJSON
	params["assertion_attributes_version"] = current.assertionVersion
	params["next_assertion_attributes_version"] = current.assertionVersion + 1
	params["assertion_attributes_json"] = assertionAttributesJSON
	params["preserve_legacy_logical"] = current.preserveLegacyLogical
	updated, err := countQuery(ctx, tx, `MATCH (:Entity {urn: $from_urn})-[r:RELATION {relation: $relation}]->(:Entity {urn: $to_urn})
MATCH (:Entity {urn: $from_urn})-[a:RELATION_ASSERTION {
    relation: $relation,
    tenant_id: $tenant_id,
    source_id: $source_id,
    runtime_id: $runtime_id
}]->(:Entity {urn: $to_urn})
WHERE coalesce(r.attributes_version, 0) = $logical_attributes_version
  AND coalesce(a.attributes_version, 0) = $assertion_attributes_version
SET r.attributes_json = CASE WHEN $preserve_legacy_logical THEN r.attributes_json ELSE $logical_attributes_json END,
	r.attributes_version = CASE WHEN $preserve_legacy_logical THEN r.attributes_version ELSE $next_logical_attributes_version END,
	r.tenant_id = CASE WHEN $preserve_legacy_logical THEN r.tenant_id ELSE $tenant_id END,
	r.source_id = CASE WHEN $preserve_legacy_logical THEN r.source_id ELSE $source_id END,
	r.runtime_id = CASE WHEN $preserve_legacy_logical THEN r.runtime_id ELSE $runtime_id END,
	r.projection_reconciliation_id = CASE WHEN $preserve_legacy_logical THEN r.projection_reconciliation_id ELSE $reconciliation_id END,
	r.assertion_managed = CASE WHEN $preserve_legacy_logical THEN false ELSE true END,
	r.assertion_quarantined = $preserve_legacy_logical,
	a.attributes_json = $assertion_attributes_json,
	a.attributes_version = $next_assertion_attributes_version,
	a.projection_reconciliation_id = $reconciliation_id
RETURN count(a)`, params)
	if err != nil {
		return false, err
	}
	return updated == 1, nil
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

type neighborhoodAccumulator struct {
	neighborhood *ports.EntityNeighborhood
	neighbors    map[string]*ports.NeighborhoodNode
	relations    map[string]*ports.NeighborhoodRelation
	remaining    int
}

const outgoingNeighborhoodBatchQuery = `UNWIND $root_urns AS root_urn
MATCH (root:Entity {urn: root_urn})
CALL {
  WITH root
  MATCH (root)-[r:RELATION]->(neighbor:Entity)
  RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label,
         root.urn AS from_urn, r.relation AS relation_type, neighbor.urn AS to_urn, coalesce(r.attributes_json, '{}') AS attributes_json
  ORDER BY neighbor.urn, r.relation
  LIMIT $limit
}
RETURN root_urn, neighbor_urn, neighbor_type, neighbor_label, from_urn, relation_type, to_urn, attributes_json
ORDER BY root_urn, neighbor_urn, relation_type`

const incomingNeighborhoodBatchQuery = `UNWIND $root_urns AS root_urn
MATCH (root:Entity {urn: root_urn})
CALL {
  WITH root
  MATCH (neighbor:Entity)-[r:RELATION]->(root)
  RETURN neighbor.urn AS neighbor_urn, neighbor.entity_type AS neighbor_type, neighbor.label AS neighbor_label,
         neighbor.urn AS from_urn, r.relation AS relation_type, root.urn AS to_urn, coalesce(r.attributes_json, '{}') AS attributes_json
  ORDER BY neighbor.urn, r.relation
  LIMIT $limit
}
RETURN root_urn, neighbor_urn, neighbor_type, neighbor_label, from_urn, relation_type, to_urn, attributes_json
ORDER BY root_urn, neighbor_urn, relation_type`

func normalizeNeighborhoodRootURNs(rootURNs []string) []string {
	roots := make([]string, 0, len(rootURNs))
	seen := make(map[string]bool, len(rootURNs))
	for _, raw := range rootURNs {
		rootURN := strings.TrimSpace(raw)
		if rootURN == "" || seen[rootURN] {
			continue
		}
		seen[rootURN] = true
		roots = append(roots, rootURN)
	}
	return roots
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

func collectBatchedNeighborhoodRows(ctx context.Context, tx neo4jdriver.ManagedTransaction, query string, params map[string]any, accumulators map[string]*neighborhoodAccumulator) error {
	result, err := tx.Run(ctx, query, params)
	if err != nil {
		return fmt.Errorf("query graph neighborhoods: %w", err)
	}
	for result.Next(ctx) {
		record := result.Record()
		rootURN := stringValue(record.Values[0])
		accumulator := accumulators[rootURN]
		if accumulator == nil || accumulator.remaining <= 0 {
			continue
		}
		neighbor := &ports.NeighborhoodNode{
			URN:        stringValue(record.Values[1]),
			EntityType: stringValue(record.Values[2]),
			Label:      stringValue(record.Values[3]),
		}
		attributes, err := decodeGraphAttributes(stringValue(record.Values[7]))
		if err != nil {
			return fmt.Errorf("decode graph neighborhood relation attributes: %w", err)
		}
		relation := &ports.NeighborhoodRelation{
			FromURN:    stringValue(record.Values[4]),
			Relation:   stringValue(record.Values[5]),
			ToURN:      stringValue(record.Values[6]),
			Attributes: attributes,
		}
		accumulator.neighbors[neighbor.URN] = neighbor
		accumulator.relations[relation.FromURN+"|"+relation.Relation+"|"+relation.ToURN] = relation
		accumulator.remaining--
	}
	return result.Err()
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
	incomingIsOlderObservation := graphIncomingObservationIsOlder(existing, incoming)
	if !incomingIsOlderObservation && graphIncomingObservationIsNewer(existing, incoming) {
		for key := range merged {
			if graphAttributeCoupledToObservationTime(key) {
				delete(merged, key)
			}
		}
	}
	for key, value := range incoming {
		if incomingIsOlderObservation && graphAttributeCoupledToObservationTime(key) {
			continue
		}
		merged[key] = mergeAttributeValue(key, merged[key], value)
	}
	return merged
}

func graphIncomingObservationIsOlder(existing map[string]string, incoming map[string]string) bool {
	existingAt := strings.TrimSpace(existing["at"])
	incomingAt := strings.TrimSpace(incoming["at"])
	if existingAt == "" {
		return false
	}
	if incomingAt == "" {
		return true
	}
	existingT, errExisting := time.Parse(time.RFC3339, existingAt)
	incomingT, errIncoming := time.Parse(time.RFC3339, incomingAt)
	if errExisting != nil || errIncoming != nil {
		return false
	}
	return incomingT.Before(existingT)
}

func graphIncomingObservationIsNewer(existing map[string]string, incoming map[string]string) bool {
	existingAt := strings.TrimSpace(existing["at"])
	incomingAt := strings.TrimSpace(incoming["at"])
	if existingAt == "" || incomingAt == "" {
		return false
	}
	existingT, errExisting := time.Parse(time.RFC3339, existingAt)
	incomingT, errIncoming := time.Parse(time.RFC3339, incomingAt)
	if errExisting != nil || errIncoming != nil {
		return false
	}
	return incomingT.After(existingT)
}

func graphAttributeCoupledToObservationTime(key string) bool {
	switch key {
	case "action", "actor_type", "classification", "client_ip", "event_id", "event_type", "grant_type", "incident_status", "mitigation_status", "oauth_event_category", "outcome_reason", "outcome_result", "programmatic_access_type", "source_event_id", "source_runtime_id", "transaction_id", "transport_protocol_name":
		return true
	default:
		return false
	}
}

// mergeAttributeValue lets specific attribute keys override the default
// last-write-wins merge. The `at` key carries the "most recent observed
// action" timestamp (RFC3339 UTC) for relations like `acted_on`. Some sources
// — notably GitHub audit logs — paginate newest-first, so a later batch may
// replay older pages after newer ones have already landed. Last-write-wins
// would let that older page silently overwrite the newer timestamp, which
// would in turn cause the deprovisioned-Okta-active-in-GitHub rule to read
// the edge as stale and auto-resolve a finding that should still be open.
// We take chronological max instead so once the edge has seen a recent
// action, no subsequent older event can pull the timestamp backward.
func mergeAttributeValue(key, existing, incoming string) string {
	if key != "at" {
		return incoming
	}
	if strings.TrimSpace(existing) == "" {
		return incoming
	}
	if strings.TrimSpace(incoming) == "" {
		return existing
	}
	existingT, errExisting := time.Parse(time.RFC3339, existing)
	incomingT, errIncoming := time.Parse(time.RFC3339, incoming)
	if errExisting != nil || errIncoming != nil {
		return incoming
	}
	if incomingT.Before(existingT) {
		return existing
	}
	return incoming
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
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	relations := make([]*ports.NeighborhoodRelation, 0, len(keys))
	for _, key := range keys {
		relations = append(relations, values[key])
	}
	return relations
}

func ingestRunReturnQuery(prefix string) string {
	return prefix + ` RETURN r.id,
       coalesce(r.runtime_id, ''),
       coalesce(r.source_id, ''),
       coalesce(r.tenant_id, ''),
       coalesce(r.checkpoint_id, ''),
       coalesce(r.checkpoint_cursor, ''),
       r.checkpoint_complete,
       coalesce(r.status, ''),
       coalesce(r.trigger, ''),
       coalesce(r.pages_read, 0),
       coalesce(r.events_read, 0),
       coalesce(r.entities_projected, 0),
       coalesce(r.links_projected, 0),
	   coalesce(r.material_link_reconciliation_requested, false),
	   coalesce(r.material_link_reconciliation_supported, false),
	   coalesce(r.material_link_reconciliation_completed, false),
	   coalesce(r.projection_reconciliation_id, ''),
	   coalesce(r.stale_material_links_deleted, 0),
       coalesce(r.graph_nodes_before, 0),
       coalesce(r.graph_links_before, 0),
       coalesce(r.graph_nodes_after, 0),
       coalesce(r.graph_links_after, 0),
       coalesce(r.started_at, ''),
       coalesce(r.finished_at, ''),
       coalesce(r.error_message, '')`
}

func scanIngestRunRecord(record *neo4jdriver.Record) (IngestRun, error) {
	if len(record.Values) != 20 && len(record.Values) < 25 {
		return IngestRun{}, fmt.Errorf("ingest run record has %d values, want 20 (legacy) or 25", len(record.Values))
	}
	run := IngestRun{
		ID:                      stringValue(record.Values[0]),
		RuntimeID:               stringValue(record.Values[1]),
		SourceID:                stringValue(record.Values[2]),
		TenantID:                stringValue(record.Values[3]),
		CheckpointID:            stringValue(record.Values[4]),
		CheckpointCursor:        stringValue(record.Values[5]),
		CheckpointComplete:      boolValue(record.Values[6]),
		CheckpointCompleteKnown: record.Values[6] != nil,
		Status:                  stringValue(record.Values[7]),
		Trigger:                 stringValue(record.Values[8]),
		PagesRead:               toInt64(record.Values[9]),
		EventsRead:              toInt64(record.Values[10]),
		EntitiesProjected:       toInt64(record.Values[11]),
		LinksProjected:          toInt64(record.Values[12]),
	}
	if len(record.Values) == 20 {
		run.GraphNodesBefore = toInt64(record.Values[13])
		run.GraphLinksBefore = toInt64(record.Values[14])
		run.GraphNodesAfter = toInt64(record.Values[15])
		run.GraphLinksAfter = toInt64(record.Values[16])
		run.StartedAt = stringValue(record.Values[17])
		run.FinishedAt = stringValue(record.Values[18])
		run.Error = stringValue(record.Values[19])
		return run, nil
	}
	run.MaterialLinkReconciliationRequested = boolValue(record.Values[13])
	run.MaterialLinkReconciliationSupported = boolValue(record.Values[14])
	run.MaterialLinkReconciliationCompleted = boolValue(record.Values[15])
	run.ProjectionReconciliationID = stringValue(record.Values[16])
	run.StaleMaterialLinksDeleted = toInt64(record.Values[17])
	run.GraphNodesBefore = toInt64(record.Values[18])
	run.GraphLinksBefore = toInt64(record.Values[19])
	run.GraphNodesAfter = toInt64(record.Values[20])
	run.GraphLinksAfter = toInt64(record.Values[21])
	run.StartedAt = stringValue(record.Values[22])
	run.FinishedAt = stringValue(record.Values[23])
	run.Error = stringValue(record.Values[24])
	return run, nil
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
		return uint64ToInt64(uint64(typed))
	case uint8:
		return int64(typed)
	case uint16:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		return uint64ToInt64(typed)
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func uint32FromInt64(value int64) uint32 {
	if value <= 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value)
}

func uint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}
