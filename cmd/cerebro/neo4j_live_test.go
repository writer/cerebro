package main

import (
	"context"
	"os"
	"strings"
	"testing"

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
	return store
}
