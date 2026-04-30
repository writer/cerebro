package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	kuzudb "github.com/kuzudb/go-kuzu"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	configpkg "github.com/writer/cerebro/internal/config"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceregistry"
)

type ghAPIPull struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	User    struct {
		Login string `json:"login"`
	} `json:"user"`
}

type githubSourcePayload struct {
	Number     int    `json:"number"`
	Repository string `json:"repository"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	Author     string `json:"author"`
}

func TestGitHubLocalEndToEndWithGHCLI(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_GITHUB_LOCAL_E2E") != "1" {
		t.Skip("set CEREBRO_RUN_GITHUB_LOCAL_E2E=1 to run the live GitHub local e2e flow")
	}

	ctx := context.Background()
	config, err := prepareSourceConfigWithCLI(ctx, githubSourceID, "read", map[string]string{
		"per_page": "5",
		"state":    "all",
	}, execGitHubLocalCLI{})
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}

	registry, err := sourceregistry.Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
	}
	response, err := sourceops.New(registry).Read(ctx, &cerebrov1.ReadSourceRequest{
		SourceId: githubSourceID,
		Config:   config,
	})
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(response.GetEvents()) == 0 {
		t.Fatal("Read().Events = 0, want at least 1 live pull-request event")
	}

	var payload githubSourcePayload
	if err := json.Unmarshal(response.GetEvents()[0].GetPayload(), &payload); err != nil {
		t.Fatalf("unmarshal source payload: %v", err)
	}
	if payload.Number == 0 {
		t.Fatal("source payload number = 0, want non-zero")
	}
	pull, err := readGitHubPullWithGHCLI(ctx, config["owner"], config["repo"], payload.Number)
	if err != nil {
		t.Fatalf("readGitHubPullWithGHCLI(%d) error = %v", payload.Number, err)
	}
	if payload.Number != pull.Number {
		t.Fatalf("source payload number = %d, want %d", payload.Number, pull.Number)
	}
	if payload.Title != pull.Title {
		t.Fatalf("source payload title = %q, want %q", payload.Title, pull.Title)
	}
	if payload.URL != pull.HTMLURL {
		t.Fatalf("source payload url = %q, want %q", payload.URL, pull.HTMLURL)
	}
	if payload.Author != pull.User.Login {
		t.Fatalf("source payload author = %q, want %q", payload.Author, pull.User.Login)
	}

	graphPath := filepath.Join(t.TempDir(), "graph")
	store, err := graphstorekuzu.Open(configpkg.GraphStoreConfig{
		Driver:   configpkg.GraphStoreDriverKuzu,
		KuzuPath: graphPath,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}
	}()

	projector := sourceprojection.New(nil, store)
	for _, event := range response.GetEvents() {
		if _, err := projector.Project(ctx, event); err != nil {
			t.Fatalf("Project(%q) error = %v", event.GetId(), err)
		}
	}

	db, err := sql.Open(kuzudb.Name, "kuzu://"+filepath.ToSlash(graphPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("db.Close() error = %v", closeErr)
		}
	}()

	nodeCount := graphCount(t, db, "MATCH (entity:entity) RETURN COUNT(entity)")
	authoredCount := graphCount(t, db, "MATCH (:entity)-[r:relation]->(:entity) WHERE r.relation = 'authored' RETURN COUNT(r)")
	if nodeCount == 0 {
		t.Fatal("projected graph node count = 0, want non-zero")
	}
	if authoredCount == 0 {
		t.Fatal("projected authored link count = 0, want non-zero")
	}

	t.Logf(
		"validated live github flow owner=%s repo=%s first_pr=%d events=%d graph_nodes=%d authored_links=%d",
		config["owner"],
		config["repo"],
		payload.Number,
		len(response.GetEvents()),
		nodeCount,
		authoredCount,
	)
}

func readGitHubPullWithGHCLI(ctx context.Context, owner string, repo string, number int) (ghAPIPull, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number)
	output, err := exec.CommandContext(ctx, "gh", "api", path).Output()
	if err != nil {
		return ghAPIPull{}, fmt.Errorf("read github pull with gh cli: %w", err)
	}
	var pull ghAPIPull
	if err := json.Unmarshal(output, &pull); err != nil {
		return ghAPIPull{}, fmt.Errorf("decode github pull from gh cli: %w", err)
	}
	return pull, nil
}

func graphCount(t *testing.T, db *sql.DB, query string) int64 {
	t.Helper()
	var count int64
	if err := db.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatalf("QueryRowContext(%q) error = %v", query, err)
	}
	return count
}
