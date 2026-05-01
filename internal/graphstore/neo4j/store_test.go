package neo4j

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

func TestOpenRejectsIncompleteConfig(t *testing.T) {
	if _, err := Open(config.GraphStoreConfig{}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
	if _, err := Open(config.GraphStoreConfig{Neo4jURI: "bolt://127.0.0.1:7687"}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
	if _, err := Open(config.GraphStoreConfig{Neo4jURI: "bolt://127.0.0.1:7687", Neo4jUsername: "neo4j"}); err == nil {
		t.Fatal("Open() error = nil, want non-nil")
	}
}

func TestNeo4jDockerProjectionAndQueries(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_NEO4J_DOCKER") != "1" {
		t.Skip("set CEREBRO_RUN_NEO4J_DOCKER=1 to run Neo4j Docker integration test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	port := freePort(t)
	name := fmt.Sprintf("cerebro-neo4j-test-%d", time.Now().UnixNano())
	password := "test-password"
	image := os.Getenv("CEREBRO_NEO4J_DOCKER_IMAGE")
	if image == "" {
		image = "neo4j:5"
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "-d", "--rm", "--name", name,
		"-e", "NEO4J_AUTH=neo4j/"+password,
		"-p", fmt.Sprintf("127.0.0.1:%d:7687", port),
		image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run neo4j: %v\n%s", err, string(output))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	store := waitForStore(t, ctx, config.GraphStoreConfig{
		Neo4jURI:      fmt.Sprintf("bolt://127.0.0.1:%d", port),
		Neo4jUsername: "neo4j",
		Neo4jPassword: password,
	})
	defer func() { _ = store.CloseContext(context.Background()) }()

	user := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_user:alice",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github_user",
		Label:      "alice",
		Attributes: map[string]string{"login": "alice"},
	}
	repo := &ports.ProjectedEntity{
		URN:        "urn:cerebro:writer:github_repository:writer/cerebro",
		TenantID:   "writer",
		SourceID:   "github",
		EntityType: "github_repository",
		Label:      "writer/cerebro",
	}
	if err := store.UpsertProjectedEntity(ctx, user); err != nil {
		t.Fatalf("UpsertProjectedEntity(user) error = %v", err)
	}
	if err := store.UpsertProjectedEntity(ctx, repo); err != nil {
		t.Fatalf("UpsertProjectedEntity(repo) error = %v", err)
	}
	if err := store.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: "writer", SourceID: "github", FromURN: user.URN, Relation: "maintains", ToURN: repo.URN,
		Attributes: map[string]string{"role": "admin"},
	}); err != nil {
		t.Fatalf("UpsertProjectedLink() error = %v", err)
	}

	counts, err := store.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts.Nodes != 2 || counts.Relations != 1 {
		t.Fatalf("Counts() = %#v, want 2 nodes and 1 relation", counts)
	}
	neighborhood, err := store.GetEntityNeighborhood(ctx, user.URN, 5)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood() error = %v", err)
	}
	if neighborhood.Root == nil || neighborhood.Root.URN != user.URN || len(neighborhood.Neighbors) != 1 || len(neighborhood.Relations) != 1 {
		t.Fatalf("GetEntityNeighborhood() = %#v", neighborhood)
	}
	patterns, err := store.PathPatterns(ctx, 5)
	if err != nil {
		t.Fatalf("PathPatterns() error = %v", err)
	}
	if len(patterns) != 0 {
		t.Fatalf("PathPatterns() = %#v, want no two-hop patterns", patterns)
	}
	checks, err := store.IntegrityChecks(ctx)
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	for _, check := range checks {
		if !check.Passed {
			t.Fatalf("IntegrityChecks() contains failure: %#v", checks)
		}
	}

	checkpoint := graphstore.IngestCheckpoint{ID: "checkpoint-1", SourceID: "github", TenantID: "writer", Completed: true, PagesRead: 2}
	if err := store.PutIngestCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("PutIngestCheckpoint() error = %v", err)
	}
	gotCheckpoint, ok, err := store.GetIngestCheckpoint(ctx, checkpoint.ID)
	if err != nil || !ok || gotCheckpoint.ID != checkpoint.ID || !gotCheckpoint.Completed {
		t.Fatalf("GetIngestCheckpoint() = %#v, %v, %v", gotCheckpoint, ok, err)
	}
	run := graphstore.IngestRun{ID: "run-1", RuntimeID: "runtime", Status: graphstore.IngestRunStatusCompleted, StartedAt: "2026-05-01T00:00:00Z"}
	if err := store.PutIngestRun(ctx, run); err != nil {
		t.Fatalf("PutIngestRun() error = %v", err)
	}
	runs, err := store.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: "runtime", Status: graphstore.IngestRunStatusCompleted, Limit: 10})
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID {
		t.Fatalf("ListIngestRuns() = %#v, %v", runs, err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForStore(t *testing.T, ctx context.Context, cfg config.GraphStoreConfig) *Store {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		store, err := Open(cfg)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		if err := store.Ping(ctx); err == nil {
			return store
		} else {
			lastErr = err
		}
		_ = store.CloseContext(context.Background())
		select {
		case <-ctx.Done():
			t.Fatalf("context done waiting for neo4j: %v", ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
	if lastErr == nil || errors.Is(lastErr, context.DeadlineExceeded) || strings.TrimSpace(lastErr.Error()) == "" {
		t.Fatal("neo4j did not become ready")
	}
	t.Fatalf("neo4j did not become ready: %v", lastErr)
	return nil
}
