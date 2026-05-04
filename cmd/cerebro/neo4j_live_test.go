package main

import (
	"context"
	"os"
	"strings"
	"testing"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

	configpkg "github.com/writer/cerebro/internal/config"
	graphstoreneo4j "github.com/writer/cerebro/internal/graphstore/neo4j"
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
		_ = store.CloseContext(context.Background())
	})
	resetNeo4jLiveGraph(t, ctx, cfg)
	return store
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
	defer func() { _ = driver.Close(context.Background()) }()

	session := driver.NewSession(ctx, neo4jdriver.SessionConfig{DatabaseName: strings.TrimSpace(cfg.Neo4jDatabase)})
	defer func() { _ = session.Close(context.Background()) }()
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
