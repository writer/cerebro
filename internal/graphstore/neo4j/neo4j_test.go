package neo4j

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestOpenRejectsMissingURI(t *testing.T) {
	if _, err := Open(config.GraphStoreConfig{Driver: config.GraphStoreDriverNeo4j}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
}

func TestCloseNilStore(t *testing.T) {
	var store *Store
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestUpsertProjectedEntityRejectsNilEntity(t *testing.T) {
	store := &Store{}
	if err := store.UpsertProjectedEntity(context.Background(), nil); err == nil {
		t.Fatal("UpsertProjectedEntity() error = nil, want non-nil")
	}
}

func TestUpsertProjectedLinkRejectsMissingFromURN(t *testing.T) {
	store := &Store{}
	err := store.UpsertProjectedLink(context.Background(), &ports.ProjectedLink{
		TenantID: "writer",
		SourceID: "github",
		Relation: "belongs_to",
		ToURN:    "urn:cerebro:writer:github_repo:writer/cerebro",
	})
	if err == nil {
		t.Fatal("UpsertProjectedLink() error = nil, want non-nil")
	}
}

func TestOpenAndPingLive(t *testing.T) {
	store, _ := newLiveTestStore(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

func newLiveTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	if os.Getenv("CEREBRO_RUN_NEO4J_E2E") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_E2E=1 to run live Neo4j e2e tests")
	}
	cfg := config.GraphStoreConfig{
		Driver:        config.GraphStoreDriverNeo4j,
		Neo4jURI:      os.Getenv("CEREBRO_NEO4J_URI"),
		Neo4jUsername: os.Getenv("CEREBRO_NEO4J_USERNAME"),
		Neo4jPassword: os.Getenv("CEREBRO_NEO4J_PASSWORD"),
		Neo4jDatabase: os.Getenv("CEREBRO_NEO4J_DATABASE"),
	}
	store, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	})
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	tenantID := fmt.Sprintf("neo4j-test-%d", time.Now().UnixNano())
	cleanupLiveTestData(t, store, tenantID)
	t.Cleanup(func() {
		cleanupLiveTestData(t, store, tenantID)
	})
	return store, tenantID
}

func cleanupLiveTestData(t *testing.T, store *Store, tenantID string) {
	t.Helper()
	if err := store.write(context.Background(),
		"MATCH (n:entity) WHERE n.tenant_id = $tenant_id OR n.urn STARTS WITH $urn_prefix DETACH DELETE n",
		map[string]any{
			"tenant_id":  tenantID,
			"urn_prefix": "urn:cerebro:" + tenantID + ":",
		},
	); err != nil {
		t.Fatalf("cleanup live Neo4j test data: %v", err)
	}
}
