package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	configpkg "github.com/writer/cerebro/internal/config"
	graphstorekuzu "github.com/writer/cerebro/internal/graphstore/kuzu"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceops"
	"github.com/writer/cerebro/internal/sourceprojection"
	"github.com/writer/cerebro/internal/sourceregistry"
)

func TestAWSGitHubKuzuSharedIdentityLiveE2E(t *testing.T) {
	if os.Getenv("CEREBRO_RUN_AWS_GITHUB_KUZU_E2E") != "1" {
		t.Skip("set CEREBRO_RUN_AWS_GITHUB_KUZU_E2E=1 to run the live AWS/GitHub Kuzu e2e flow")
	}
	ctx := context.Background()
	sharedEmail := requiredEnv(t, "CEREBRO_AWS_GITHUB_SHARED_EMAIL")
	tenantID := envOrDefault("CEREBRO_AWS_GITHUB_TENANT_ID", "writer")
	pageLimit := uint32EnvOrDefault(t, "CEREBRO_AWS_GITHUB_PAGE_LIMIT", 1)

	registry, err := sourceregistry.Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v", err)
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
	sourceService := sourceops.New(registry)

	githubConfig, err := prepareSourceConfigWithCLI(ctx, githubSourceID, "read", map[string]string{
		"family":   "audit",
		"include":  "all",
		"order":    "desc",
		"owner":    envOrDefault("CEREBRO_GITHUB_OWNER", "WriterInternal"),
		"per_page": "5",
		"phrase":   requiredEnv(t, "CEREBRO_GITHUB_AUDIT_PHRASE"),
	}, execGitHubLocalCLI{})
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}
	githubResult, err := ingestGraph(ctx, sourceService, projector, store, graphIngestOptions{
		SourceID:     githubSourceID,
		SourceConfig: githubConfig,
		TenantID:     tenantID,
		PageLimit:    pageLimit,
	})
	if err != nil {
		t.Fatalf("ingest github audit: %v", err)
	}
	if githubResult.EventsRead == 0 {
		t.Fatal("github audit ingest read zero events")
	}

	awsResult, err := ingestGraph(ctx, sourceService, projector, store, graphIngestOptions{
		SourceID: "aws",
		SourceConfig: map[string]string{
			"account_id":   requiredEnv(t, "CEREBRO_AWS_ACCOUNT_ID"),
			"family":       "cloudtrail",
			"lookup_key":   "Username",
			"lookup_value": sharedEmail,
			"per_page":     "5",
			"profile":      envOrDefault("CEREBRO_AWS_PROFILE", ""),
			"region":       envOrDefault("CEREBRO_AWS_REGION", "us-east-1"),
		},
		TenantID:  tenantID,
		PageLimit: pageLimit,
	})
	if err != nil {
		t.Fatalf("ingest aws cloudtrail: %v", err)
	}
	if awsResult.EventsRead == 0 {
		t.Fatal("aws cloudtrail ingest read zero events")
	}

	assertIntegrityChecksPass(t, store)
	counts, err := store.Counts(ctx)
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts.Nodes == 0 || counts.Relations == 0 {
		t.Fatalf("graph counts = %#v, want non-zero nodes and relations", counts)
	}
	identityURN := "urn:cerebro:" + tenantID + ":identity:email:" + strings.ToLower(sharedEmail)
	neighborhood, err := store.GetEntityNeighborhood(ctx, identityURN, 50)
	if err != nil {
		t.Fatalf("GetEntityNeighborhood(%q) error = %v", identityURN, err)
	}
	if !hasIdentityRelationFrom(neighborhood, identityURN, "github.user") {
		t.Fatalf("identity neighborhood missing github.user relation: %#v", neighborhood.Relations)
	}
	if !hasIdentityRelationFrom(neighborhood, identityURN, "aws.user") {
		t.Fatalf("identity neighborhood missing aws.user relation: %#v", neighborhood.Relations)
	}
	t.Logf("validated live AWS/GitHub Kuzu identity path email=%s nodes=%d relations=%d", sharedEmail, counts.Nodes, counts.Relations)
}

func hasIdentityRelationFrom(neighborhood *ports.EntityNeighborhood, identityURN string, entityType string) bool {
	if neighborhood == nil {
		return false
	}
	nodeTypes := map[string]string{}
	if neighborhood.Root != nil {
		nodeTypes[neighborhood.Root.URN] = neighborhood.Root.EntityType
	}
	for _, node := range neighborhood.Neighbors {
		if node != nil {
			nodeTypes[node.URN] = node.EntityType
		}
	}
	for _, relation := range neighborhood.Relations {
		if relation == nil || relation.ToURN != identityURN || relation.Relation != "represents_identity" {
			continue
		}
		if nodeTypes[relation.FromURN] == entityType {
			return true
		}
	}
	return false
}

func assertIntegrityChecksPass(t *testing.T, store *graphstorekuzu.Store) {
	t.Helper()
	checks, err := store.IntegrityChecks(context.Background())
	if err != nil {
		t.Fatalf("IntegrityChecks() error = %v", err)
	}
	for _, check := range checks {
		if !check.Passed {
			t.Fatalf("integrity check %q failed: actual=%d expected=%d", check.Name, check.Actual, check.Expected)
		}
	}
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}

func envOrDefault(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func uint32EnvOrDefault(t *testing.T, key string, fallback uint32) uint32 {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		t.Fatalf("parse %s: %v", key, err)
	}
	if parsed == 0 {
		t.Fatalf("%s must be greater than zero", key)
	}
	return uint32(parsed)
}
