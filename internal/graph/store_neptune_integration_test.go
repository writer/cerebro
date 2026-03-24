//go:build integration
// +build integration

package graph

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/neptunedata"
)

var (
	neptuneIntegrationEnsureIndexesOnce sync.Once
	neptuneIntegrationEnsureIndexesErr  error
)

func TestNeptuneGraphStoreIntegrationCRUDSoftDeleteAndDecoding(t *testing.T) {
	store, ctx := newNeptuneIntegrationStore(t)
	prefix := neptuneIntegrationPrefix(t)
	now := time.Now().UTC().Round(time.Second)

	service := &Node{
		ID:         prefix + "service",
		Kind:       NodeKindService,
		Name:       "Integration Service",
		TenantID:   prefix + "tenant",
		Properties: map[string]any{"critical": true},
		Tags:       map[string]string{"env": "integration"},
		CreatedAt:  now,
		UpdatedAt:  now,
		Version:    1,
	}
	database := &Node{
		ID:        prefix + "database",
		Kind:      NodeKindDatabase,
		Name:      "Integration Database",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}
	edge := &Edge{
		ID:       prefix + "edge",
		Source:   service.ID,
		Target:   database.ID,
		Kind:     EdgeKindCalls,
		Effect:   EdgeEffectAllow,
		Priority: 50,
		Properties: map[string]any{
			"path": "/query",
		},
		CreatedAt: now,
		Version:   1,
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = store.DeleteNode(cleanupCtx, service.ID)
		_ = store.DeleteNode(cleanupCtx, database.ID)
	})

	if err := store.UpsertNode(ctx, service); err != nil {
		t.Fatalf("UpsertNode(service) error = %v", err)
	}
	if err := store.UpsertNode(ctx, database); err != nil {
		t.Fatalf("UpsertNode(database) error = %v", err)
	}
	if err := store.UpsertEdge(ctx, edge); err != nil {
		t.Fatalf("UpsertEdge() error = %v", err)
	}

	neptuneIntegrationWait(t, ctx, "service node becomes queryable", func(waitCtx context.Context) (bool, error) {
		node, ok, err := store.LookupNode(waitCtx, service.ID)
		if err != nil {
			return false, err
		}
		if !ok || node == nil {
			return false, nil
		}
		return strings.TrimSpace(node.ID) == service.ID, nil
	})
	neptuneIntegrationWait(t, ctx, "edge becomes queryable", func(waitCtx context.Context) (bool, error) {
		got, ok, err := store.LookupEdge(waitCtx, edge.ID)
		if err != nil {
			return false, err
		}
		if !ok || got == nil {
			return false, nil
		}
		return strings.TrimSpace(got.ID) == edge.ID, nil
	})

	gotNode, ok, err := store.LookupNode(ctx, service.ID)
	if err != nil {
		t.Fatalf("LookupNode() error = %v", err)
	}
	if !ok || gotNode == nil {
		t.Fatalf("LookupNode() = (%#v, %v), want present node", gotNode, ok)
	}
	if got := strings.TrimSpace(gotNode.TenantID); got != service.TenantID {
		t.Fatalf("LookupNode() tenant_id = %q, want %q", got, service.TenantID)
	}
	if critical, _ := gotNode.Properties["critical"].(bool); !critical {
		t.Fatalf("LookupNode() properties = %#v, want critical=true", gotNode.Properties)
	}
	if got := strings.TrimSpace(gotNode.Tags["env"]); got != "integration" {
		t.Fatalf("LookupNode() tags = %#v, want env=integration", gotNode.Tags)
	}

	gotEdge, ok, err := store.LookupEdge(ctx, edge.ID)
	if err != nil {
		t.Fatalf("LookupEdge() error = %v", err)
	}
	if !ok || gotEdge == nil {
		t.Fatalf("LookupEdge() = (%#v, %v), want present edge", gotEdge, ok)
	}
	if strings.TrimSpace(gotEdge.Source) != service.ID || strings.TrimSpace(gotEdge.Target) != database.ID {
		t.Fatalf("LookupEdge() endpoints = (%q -> %q), want (%q -> %q)", gotEdge.Source, gotEdge.Target, service.ID, database.ID)
	}
	if got := strings.TrimSpace(propertyString(gotEdge.Properties, "path")); got != "/query" {
		t.Fatalf("LookupEdge() properties = %#v, want path=/query", gotEdge.Properties)
	}

	nodesByKind, err := store.LookupNodesByKind(ctx, NodeKindService, NodeKindDatabase)
	if err != nil {
		t.Fatalf("LookupNodesByKind() error = %v", err)
	}
	if got := filterNodeIDsByPrefix(nodesByKind, prefix); !slices.Equal(got, []string{database.ID, service.ID}) {
		t.Fatalf("LookupNodesByKind() filtered ids = %#v, want %#v", got, []string{database.ID, service.ID})
	}

	outEdges, err := store.LookupOutEdges(ctx, service.ID)
	if err != nil {
		t.Fatalf("LookupOutEdges() error = %v", err)
	}
	if got := filterEdgeIDsByPrefix(outEdges, prefix); !slices.Equal(got, []string{edge.ID}) {
		t.Fatalf("LookupOutEdges() filtered ids = %#v, want %#v", got, []string{edge.ID})
	}

	if err := store.DeleteNode(ctx, service.ID); err != nil {
		t.Fatalf("DeleteNode() error = %v", err)
	}

	neptuneIntegrationWait(t, ctx, "deleted service node is filtered out", func(waitCtx context.Context) (bool, error) {
		node, ok, err := store.LookupNode(waitCtx, service.ID)
		return err == nil && !ok && node == nil, err
	})
	neptuneIntegrationWait(t, ctx, "deleted edge is filtered out", func(waitCtx context.Context) (bool, error) {
		got, ok, err := store.LookupEdge(waitCtx, edge.ID)
		return err == nil && !ok && got == nil, err
	})
	neptuneIntegrationWait(t, ctx, "deleted service node is absent from kind lookup", func(waitCtx context.Context) (bool, error) {
		nodes, err := store.LookupNodesByKind(waitCtx, NodeKindService, NodeKindDatabase)
		if err != nil {
			return false, err
		}
		return slices.Equal(filterNodeIDsByPrefix(nodes, prefix), []string{database.ID}), nil
	})
	neptuneIntegrationWait(t, ctx, "deleted service edges are absent from out-edge lookup", func(waitCtx context.Context) (bool, error) {
		edges, err := store.LookupOutEdges(waitCtx, service.ID)
		if err != nil {
			return false, err
		}
		return len(filterEdgeIDsByPrefix(edges, prefix)) == 0, nil
	})
}

func TestNeptuneGraphStoreIntegrationBatchUpserts(t *testing.T) {
	store, ctx := newNeptuneIntegrationStore(t)
	prefix := neptuneIntegrationPrefix(t)
	now := time.Now().UTC().Round(time.Second)

	serviceA := &Node{
		ID:        prefix + "service-a",
		Kind:      NodeKindService,
		Name:      "Integration Service A",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}
	serviceB := &Node{
		ID:        prefix + "service-b",
		Kind:      NodeKindService,
		Name:      "Integration Service B",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}
	database := &Node{
		ID:        prefix + "database",
		Kind:      NodeKindDatabase,
		Name:      "Integration Database",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, nodeID := range []string{serviceA.ID, serviceB.ID, database.ID} {
			_ = store.DeleteNode(cleanupCtx, nodeID)
		}
	})

	if err := store.UpsertNodesBatch(ctx, []*Node{serviceA, nil, serviceB, database}); err != nil {
		t.Fatalf("UpsertNodesBatch() error = %v", err)
	}

	edgeA := &Edge{
		ID:        prefix + "edge-a",
		Source:    serviceA.ID,
		Target:    database.ID,
		Kind:      EdgeKindCalls,
		Effect:    EdgeEffectAllow,
		Priority:  50,
		CreatedAt: now,
		Version:   1,
	}
	edgeB := &Edge{
		ID:        prefix + "edge-b",
		Source:    serviceB.ID,
		Target:    database.ID,
		Kind:      EdgeKindDependsOn,
		Effect:    EdgeEffectAllow,
		Priority:  50,
		CreatedAt: now,
		Version:   1,
	}

	if err := store.UpsertEdgesBatch(ctx, []*Edge{edgeA, nil, edgeB}); err != nil {
		t.Fatalf("UpsertEdgesBatch() error = %v", err)
	}

	neptuneIntegrationWait(t, ctx, "batch nodes become queryable by kind", func(waitCtx context.Context) (bool, error) {
		nodes, err := store.LookupNodesByKind(waitCtx, NodeKindService, NodeKindDatabase)
		if err != nil {
			return false, err
		}
		return slices.Equal(filterNodeIDsByPrefix(nodes, prefix), []string{database.ID, serviceA.ID, serviceB.ID}), nil
	})
	neptuneIntegrationWait(t, ctx, "batch edges become queryable by destination", func(waitCtx context.Context) (bool, error) {
		edges, err := store.LookupInEdges(waitCtx, database.ID)
		if err != nil {
			return false, err
		}
		return slices.Equal(filterEdgeIDsByPrefix(edges, prefix), []string{edgeA.ID, edgeB.ID}), nil
	})

	if err := store.DeleteEdge(ctx, edgeA.ID); err != nil {
		t.Fatalf("DeleteEdge() error = %v", err)
	}
	neptuneIntegrationWait(t, ctx, "deleted batch edge is filtered out", func(waitCtx context.Context) (bool, error) {
		edges, err := store.LookupInEdges(waitCtx, database.ID)
		if err != nil {
			return false, err
		}
		return slices.Equal(filterEdgeIDsByPrefix(edges, prefix), []string{edgeB.ID}), nil
	})
}

func TestNeptuneGraphStoreIntegrationSchemaEnforcementAndEdgeValidation(t *testing.T) {
	store, ctx := newNeptuneIntegrationStore(t)
	prefix := neptuneIntegrationPrefix(t)
	now := time.Now().UTC().Round(time.Second)

	invalidNode := &Node{
		ID:        prefix + "invalid-node",
		Kind:      NodeKind(" unknown_kind "),
		Name:      "Invalid Node",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}
	var nodeValidationErr *SchemaValidationError
	if err := store.UpsertNode(ctx, invalidNode); !errors.As(err, &nodeValidationErr) {
		t.Fatalf("UpsertNode(invalid) error = %v, want SchemaValidationError", err)
	}

	source := &Node{
		ID:        prefix + "service",
		Kind:      NodeKindService,
		Name:      "Validation Source",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}
	target := &Node{
		ID:        prefix + "database",
		Kind:      NodeKindDatabase,
		Name:      "Validation Target",
		TenantID:  prefix + "tenant",
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = store.DeleteNode(cleanupCtx, source.ID)
		_ = store.DeleteNode(cleanupCtx, target.ID)
	})

	if err := store.UpsertNodesBatch(ctx, []*Node{source, target}); err != nil {
		t.Fatalf("UpsertNodesBatch(valid nodes) error = %v", err)
	}

	invalidEdge := &Edge{
		ID:        prefix + "invalid-edge",
		Source:    source.ID,
		Target:    target.ID,
		Kind:      EdgeKind(" unknown_edge "),
		Effect:    EdgeEffectAllow,
		Priority:  50,
		CreatedAt: now,
		Version:   1,
	}
	var edgeValidationErr *SchemaValidationError
	if err := store.UpsertEdge(ctx, invalidEdge); !errors.As(err, &edgeValidationErr) {
		t.Fatalf("UpsertEdge(invalid kind) error = %v, want SchemaValidationError", err)
	}

	missingTargetEdge := &Edge{
		ID:        prefix + "missing-target",
		Source:    source.ID,
		Target:    prefix + "missing-database",
		Kind:      EdgeKindCalls,
		Effect:    EdgeEffectAllow,
		Priority:  50,
		CreatedAt: now,
		Version:   1,
	}
	edgeValidationErr = nil
	if err := store.UpsertEdge(ctx, missingTargetEdge); !errors.As(err, &edgeValidationErr) {
		t.Fatalf("UpsertEdge(missing target) error = %v, want SchemaValidationError", err)
	}

	got, ok, err := store.LookupEdge(ctx, missingTargetEdge.ID)
	if err != nil {
		t.Fatalf("LookupEdge(missing target edge) error = %v", err)
	}
	if ok || got != nil {
		t.Fatalf("LookupEdge(missing target edge) = (%#v, %v), want absent edge", got, ok)
	}
}

func newNeptuneIntegrationStore(t *testing.T) (*NeptuneGraphStore, context.Context) {
	t.Helper()

	if strings.TrimSpace(os.Getenv("CEREBRO_LIVE_NEPTUNE")) != "1" {
		t.Skip("set CEREBRO_LIVE_NEPTUNE=1 to run Neptune graph store integration tests")
	}

	endpoint := strings.TrimSpace(firstNonEmptyEnv("CEREBRO_TEST_NEPTUNE_ENDPOINT", "GRAPH_STORE_NEPTUNE_ENDPOINT"))
	if endpoint == "" {
		t.Skip("set CEREBRO_TEST_NEPTUNE_ENDPOINT or GRAPH_STORE_NEPTUNE_ENDPOINT for Neptune graph store integration tests")
	}

	region := strings.TrimSpace(firstNonEmptyEnv("CEREBRO_TEST_NEPTUNE_REGION", "GRAPH_STORE_NEPTUNE_REGION", "AWS_REGION"))
	if region == "" {
		region = "us-east-1"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Fatalf("load aws config for Neptune integration test: %v", err)
	}

	client := neptunedata.NewFromConfig(awsCfg, func(options *neptunedata.Options) {
		options.BaseEndpoint = aws.String(endpoint)
	})
	store := NewNeptuneGraphStore(NewNeptuneDataExecutor(client))

	neptuneIntegrationEnsureIndexesOnce.Do(func() {
		neptuneIntegrationEnsureIndexesErr = store.EnsureIndexes(ctx)
	})
	if neptuneIntegrationEnsureIndexesErr != nil {
		t.Fatalf("EnsureIndexes() error = %v", neptuneIntegrationEnsureIndexesErr)
	}

	return store, ctx
}

func neptuneIntegrationWait(t *testing.T, ctx context.Context, description string, check func(context.Context) (bool, error)) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ok, err := check(ctx)
		if err != nil {
			t.Fatalf("%s: %v", description, err)
		}
		if ok {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: context canceled: %v", description, ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatalf("timeout waiting for %s", description)
}

func neptuneIntegrationPrefix(t *testing.T) string {
	t.Helper()

	name := strings.ToLower(strings.TrimSpace(t.Name()))
	name = strings.NewReplacer("/", "-", " ", "-", "_", "-").Replace(name)
	return fmt.Sprintf("itest:%s:%d:", name, time.Now().UTC().UnixNano())
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func filterNodeIDsByPrefix(nodes []*Node, prefix string) []string {
	filtered := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		id := strings.TrimSpace(node.ID)
		if strings.HasPrefix(id, prefix) {
			filtered = append(filtered, id)
		}
	}
	slices.Sort(filtered)
	return filtered
}

func filterEdgeIDsByPrefix(edges []*Edge, prefix string) []string {
	filtered := make([]string, 0, len(edges))
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		id := strings.TrimSpace(edge.ID)
		if strings.HasPrefix(id, prefix) {
			filtered = append(filtered, id)
		}
	}
	slices.Sort(filtered)
	return filtered
}

func propertyString(properties map[string]any, key string) string {
	if len(properties) == 0 {
		return ""
	}
	if value, ok := properties[strings.TrimSpace(key)].(string); ok {
		return value
	}
	return ""
}
