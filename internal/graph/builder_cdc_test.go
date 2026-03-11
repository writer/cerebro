package graph

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type cdcRoutingSource struct {
	mu        sync.Mutex
	latest    time.Time
	events    []map[string]any
	routes    map[string]*QueryResult
	queryHits map[string]int
}

var _ DataSource = (*cdcRoutingSource)(nil)

func newCDCRoutingSource() *cdcRoutingSource {
	return &cdcRoutingSource{
		routes:    make(map[string]*QueryResult),
		queryHits: make(map[string]int),
	}
}

func (s *cdcRoutingSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	_ = ctx
	_ = args
	lower := strings.ToLower(query)

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.Contains(lower, "select max(event_time)") && strings.Contains(lower, "from cdc_events") {
		s.queryHits["has_changes"]++
		if s.latest.IsZero() {
			return &QueryResult{Rows: []map[string]any{{"latest": time.Time{}}}, Count: 1}, nil
		}
		return &QueryResult{Rows: []map[string]any{{"latest": s.latest}}, Count: 1}, nil
	}

	if strings.Contains(lower, "select event_id") && strings.Contains(lower, "from cdc_events") {
		s.queryHits["cdc_events"]++
		rows := make([]map[string]any, 0, len(s.events))
		rows = append(rows, s.events...)
		return &QueryResult{Rows: rows, Count: len(rows)}, nil
	}

	for needle, result := range s.routes {
		if strings.Contains(lower, needle) {
			s.queryHits[needle]++
			if result == nil {
				return &QueryResult{Rows: []map[string]any{}}, nil
			}
			return result, nil
		}
	}

	return &QueryResult{Rows: []map[string]any{}}, nil
}

func TestBuilderApplyChanges_UpsertsAndRemovesNodes(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})
	builder.Graph().AddNode(&Node{ID: "arn:aws:s3:::existing-bucket", Kind: NodeKindBucket, Provider: "aws", Account: "111111111111", Properties: map[string]any{"public": false}})
	builder.Graph().AddNode(&Node{ID: "arn:aws:iam::111111111111:role/old-role", Kind: NodeKindRole, Provider: "aws", Account: "111111111111"})

	base := time.Now().UTC().Add(-1 * time.Minute)
	source.events = []map[string]any{
		{
			"event_id":    "evt-1",
			"table_name":  "aws_s3_buckets",
			"resource_id": "arn:aws:s3:::new-public-bucket",
			"change_type": "added",
			"provider":    "aws",
			"region":      "us-east-1",
			"account_id":  "111111111111",
			"payload": map[string]any{
				"arn":                 "arn:aws:s3:::new-public-bucket",
				"name":                "new-public-bucket",
				"account_id":          "111111111111",
				"region":              "us-east-1",
				"block_public_acls":   false,
				"block_public_policy": false,
			},
			"event_time": base.Add(5 * time.Second),
		},
		{
			"event_id":    "evt-2",
			"table_name":  "aws_s3_buckets",
			"resource_id": "arn:aws:s3:::existing-bucket",
			"change_type": "modified",
			"provider":    "aws",
			"region":      "us-east-1",
			"account_id":  "111111111111",
			"payload": map[string]any{
				"arn":                 "arn:aws:s3:::existing-bucket",
				"name":                "existing-bucket",
				"account_id":          "111111111111",
				"region":              "us-east-1",
				"block_public_acls":   true,
				"block_public_policy": true,
			},
			"event_time": base.Add(10 * time.Second),
		},
		{
			"event_id":    "evt-3",
			"table_name":  "aws_iam_roles",
			"resource_id": "arn:aws:iam::111111111111:role/old-role",
			"change_type": "removed",
			"provider":    "aws",
			"event_time":  base.Add(15 * time.Second),
		},
	}

	summary, err := builder.ApplyChanges(context.Background(), base)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	if summary.EventsProcessed != 3 {
		t.Fatalf("expected 3 events processed, got %d", summary.EventsProcessed)
	}
	if summary.NodesAdded != 1 {
		t.Fatalf("expected 1 node added, got %d", summary.NodesAdded)
	}
	if summary.NodesUpdated != 1 {
		t.Fatalf("expected 1 node updated, got %d", summary.NodesUpdated)
	}
	if summary.NodesRemoved != 1 {
		t.Fatalf("expected 1 node removed, got %d", summary.NodesRemoved)
	}
	if summary.Mode != GraphMutationModeIncremental {
		t.Fatalf("expected incremental mode, got %q", summary.Mode)
	}

	if _, ok := builder.Graph().GetNode("arn:aws:s3:::new-public-bucket"); !ok {
		t.Fatal("expected new bucket node to exist")
	}
	if _, ok := builder.Graph().GetNode("arn:aws:iam::111111111111:role/old-role"); ok {
		t.Fatal("expected removed role to be hidden from active graph")
	}
	if deleted, ok := builder.Graph().GetNodeIncludingDeleted("arn:aws:iam::111111111111:role/old-role"); !ok || deleted.DeletedAt == nil {
		t.Fatal("expected removed role to be soft-deleted")
	}

	internetEdges := builder.Graph().GetOutEdges("internet")
	foundExposure := false
	for _, edge := range internetEdges {
		if edge.Target == "arn:aws:s3:::new-public-bucket" && edge.Kind == EdgeKindExposedTo {
			foundExposure = true
			break
		}
	}
	if !foundExposure {
		t.Fatal("expected internet exposure edge for new public bucket")
	}

	if got := builder.LastMutation(); got.EventsProcessed != summary.EventsProcessed || got.NodesRemoved != summary.NodesRemoved {
		t.Fatalf("expected last mutation to match summary, got %+v", got)
	}

	if len(summary.Tables) != 2 || summary.Tables[0] != "aws_iam_roles" || summary.Tables[1] != "aws_s3_buckets" {
		t.Fatalf("unexpected mutated table list: %v", summary.Tables)
	}
}

func TestBuilderApplyChanges_EdgeOnlyTableChangeRebuildsEdges(t *testing.T) {
	source := newCDCRoutingSource()
	source.routes["from aws_iam_policy_versions"] = &QueryResult{Rows: []map[string]any{{
		"policy_arn": "arn:aws:iam::111111111111:policy/S3FullAccess",
		"document": `{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": "s3:*",
				"Resource": "*"
			}]
		}`,
	}}}
	source.routes["from aws_iam_user_attached_policies"] = &QueryResult{Rows: []map[string]any{{
		"user_arn":   "arn:aws:iam::111111111111:user/alice",
		"policy_arn": "arn:aws:iam::111111111111:policy/S3FullAccess",
	}}}

	builder := NewBuilder(source, nil)
	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})
	builder.Graph().AddNode(&Node{ID: "arn:aws:iam::111111111111:user/alice", Kind: NodeKindUser, Provider: "aws", Account: "111111111111", Name: "alice"})
	builder.Graph().AddNode(&Node{ID: "arn:aws:s3:::sensitive-data", Kind: NodeKindBucket, Provider: "aws", Account: "111111111111", Name: "sensitive-data"})

	since := time.Now().UTC().Add(-2 * time.Minute)
	source.events = []map[string]any{{
		"event_id":    "evt-policy-1",
		"table_name":  "aws_iam_user_attached_policies",
		"resource_id": "arn:aws:iam::111111111111:user/alice",
		"change_type": "modified",
		"provider":    "aws",
		"event_time":  since.Add(5 * time.Second),
	}}

	summary, err := builder.ApplyChanges(context.Background(), since)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}
	if summary.EventsProcessed != 1 {
		t.Fatalf("expected 1 event processed, got %d", summary.EventsProcessed)
	}
	if summary.NodesAdded != 0 || summary.NodesUpdated != 0 || summary.NodesRemoved != 0 {
		t.Fatalf("expected no node-level changes for edge-only table, got %+v", summary)
	}

	edges := builder.Graph().GetOutEdges("arn:aws:iam::111111111111:user/alice")
	found := false
	for _, edge := range edges {
		if edge.Target == "arn:aws:s3:::sensitive-data" && edge.Kind == EdgeKindCanAdmin {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected policy-derived edge from alice to sensitive-data, got %d edges", len(edges))
	}
}

func TestBuilderHasChanges_UsesCDCEventTime(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	if !builder.HasChanges(context.Background()) {
		t.Fatal("expected HasChanges to fail-open when last build time is zero")
	}

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	source.latest = time.Now().UTC().Add(-1 * time.Minute)
	if builder.HasChanges(context.Background()) {
		t.Fatal("expected HasChanges=false when latest CDC event is older than last build")
	}

	source.latest = time.Now().UTC().Add(1 * time.Minute)
	if !builder.HasChanges(context.Background()) {
		t.Fatal("expected HasChanges=true when latest CDC event is newer than last build")
	}
}
