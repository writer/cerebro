package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	configpkg "github.com/writer/cerebro/internal/config"
	graphstoreneo4j "github.com/writer/cerebro/internal/graphstore/neo4j"
	"github.com/writer/cerebro/internal/ports"
)

func openNeo4jLiveGraphStore(t *testing.T, ctx context.Context) *graphstoreneo4j.Store {
	t.Helper()
	cfg := configpkg.GraphStoreConfig{
		Neo4jURI:      strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_URI")),
		Neo4jUsername: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_USERNAME")),
		Neo4jPassword: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_PASSWORD")),
		Neo4jDatabase: strings.TrimSpace(os.Getenv("CEREBRO_NEO4J_DATABASE")),
	}
	if cfg.Neo4jURI == "" || cfg.Neo4jUsername == "" || cfg.Neo4jPassword == "" {
		t.Skip("set CEREBRO_NEO4J_URI, CEREBRO_NEO4J_USERNAME, and CEREBRO_NEO4J_PASSWORD to run Neo4j-backed live graph tests")
	}
	store, err := graphstoreneo4j.Open(cfg)
	if err != nil {
		t.Fatalf("open Neo4j graph store: %v", err)
	}
	if err := store.Ping(ctx); err != nil {
		_ = store.CloseContext(ctx)
		t.Fatalf("ping Neo4j graph store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.CloseContext(ctx)
	})
	resetNeo4jLiveGraph(t, ctx, cfg)
	return store
}

// readNeo4jLiveNeighborhood keeps legacy Neo4j-only integration fixtures
// working through the retained raw-Cypher compatibility boundary. Product
// neighborhood reads must use the Rust authority adapter.
func readNeo4jLiveNeighborhood(ctx context.Context, store ports.RawCypherQueryStore, rootURN string, limit int) (*ports.EntityNeighborhood, error) {
	rootRows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: `MATCH (root:Entity {urn: $root_urn})
RETURN root.urn AS urn, root.entity_type AS entity_type, root.label AS label
LIMIT 1`,
		Params:   map[string]any{"root_urn": rootURN},
		RowLimit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(rootRows) == 0 {
		return nil, fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, rootURN)
	}
	neighborhood := &ports.EntityNeighborhood{
		Root: &ports.NeighborhoodNode{
			URN:        liveCypherString(rootRows[0].Values["urn"]),
			EntityType: liveCypherString(rootRows[0].Values["entity_type"]),
			Label:      liveCypherString(rootRows[0].Values["label"]),
		},
		Neighbors: []*ports.NeighborhoodNode{},
		Relations: []*ports.NeighborhoodRelation{},
	}
	if limit <= 0 {
		return neighborhood, nil
	}
	rows, err := store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: `MATCH (root:Entity {urn: $root_urn})-[relation:RELATION]-(neighbor:Entity)
RETURN neighbor.urn AS neighbor_urn,
       neighbor.entity_type AS neighbor_type,
       neighbor.label AS neighbor_label,
       startNode(relation).urn AS from_urn,
       relation.relation AS relation_type,
       endNode(relation).urn AS to_urn,
       coalesce(relation.attributes_json, '{}') AS attributes_json
ORDER BY neighbor.urn, relation.relation
LIMIT $limit`,
		Params:   map[string]any{"root_urn": rootURN, "limit": limit},
		RowLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	neighbors := make(map[string]*ports.NeighborhoodNode, len(rows))
	for _, row := range rows {
		neighbor := &ports.NeighborhoodNode{
			URN:        liveCypherString(row.Values["neighbor_urn"]),
			EntityType: liveCypherString(row.Values["neighbor_type"]),
			Label:      liveCypherString(row.Values["neighbor_label"]),
		}
		neighbors[neighbor.URN] = neighbor
		attributes := map[string]string{}
		if err := json.Unmarshal([]byte(liveCypherString(row.Values["attributes_json"])), &attributes); err != nil {
			return nil, fmt.Errorf("decode live graph relation attributes: %w", err)
		}
		neighborhood.Relations = append(neighborhood.Relations, &ports.NeighborhoodRelation{
			FromURN:    liveCypherString(row.Values["from_urn"]),
			Relation:   liveCypherString(row.Values["relation_type"]),
			ToURN:      liveCypherString(row.Values["to_urn"]),
			Attributes: attributes,
		})
	}
	for _, neighbor := range neighbors {
		neighborhood.Neighbors = append(neighborhood.Neighbors, neighbor)
	}
	return neighborhood, nil
}

func liveCypherString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func resetNeo4jLiveGraph(t *testing.T, ctx context.Context, cfg configpkg.GraphStoreConfig) {
	t.Helper()
	driver, err := neo4jdriver.NewDriverWithContext(
		cfg.Neo4jURI,
		neo4jdriver.BasicAuth(cfg.Neo4jUsername, cfg.Neo4jPassword, ""),
	)
	if err != nil {
		t.Fatalf("open Neo4j reset driver: %v", err)
	}
	defer func() { _ = driver.Close(ctx) }()

	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: strings.TrimSpace(cfg.Neo4jDatabase)})
	defer func() { _ = session.Close(ctx) }()
	if _, err := session.ExecuteWrite(ctx, func(tx neo4jdriver.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx, "MATCH (n) WHERE n:Entity OR n:IngestCheckpoint OR n:IngestRun DETACH DELETE n", nil)
		if err != nil {
			return nil, err
		}
		_, err = result.Consume(ctx)
		return nil, err
	}); err != nil {
		t.Fatalf("reset Neo4j live graph database: %v", err)
	}
}
