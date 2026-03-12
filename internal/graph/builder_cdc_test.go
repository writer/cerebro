package graph

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type cdcRoutingSource struct {
	mu           sync.Mutex
	latest       time.Time
	events       []map[string]any
	routes       map[string]*QueryResult
	queryHits    map[string]int
	blockNeedle  string
	blockStart   chan struct{}
	blockRelease chan struct{}
	blockOnce    sync.Once
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

	if s.blockNeedle != "" && strings.Contains(lower, s.blockNeedle) {
		s.blockOnce.Do(func() {
			if s.blockStart != nil {
				close(s.blockStart)
			}
		})
		select {
		case <-s.blockRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

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

func TestBuilderApplyChanges_UsesCopyOnWriteSwap(t *testing.T) {
	source := newCDCRoutingSource()
	source.blockNeedle = "from aws_iam_policy_versions"
	source.blockStart = make(chan struct{})
	source.blockRelease = make(chan struct{})

	builder := NewBuilder(source, nil)
	live := builder.Graph()
	live.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})
	live.AddNode(&Node{ID: "arn:aws:s3:::existing-bucket", Kind: NodeKindBucket, Provider: "aws", Account: "111111111111", Name: "existing-bucket"})
	live.AddEdge(&Edge{Source: "internet", Target: "arn:aws:s3:::existing-bucket", Kind: EdgeKindExposedTo})
	live.BuildIndex()

	base := time.Now().UTC().Add(-1 * time.Minute)
	source.events = []map[string]any{{
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
	}}

	done := make(chan error, 1)
	go func() {
		_, err := builder.ApplyChanges(context.Background(), base)
		done <- err
	}()

	select {
	case <-source.blockStart:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for incremental edge rebuild to start")
	}

	if _, ok := builder.Graph().GetNode("arn:aws:s3:::new-public-bucket"); ok {
		t.Fatal("expected live graph to remain unchanged until incremental swap completes")
	}
	oldEdges := builder.Graph().GetOutEdges("internet")
	if len(oldEdges) != 1 || oldEdges[0].Target != "arn:aws:s3:::existing-bucket" {
		t.Fatalf("expected live graph edges to remain readable during incremental rebuild, got %#v", oldEdges)
	}

	close(source.blockRelease)
	if err := <-done; err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode("arn:aws:s3:::new-public-bucket"); !ok {
		t.Fatal("expected swapped graph to contain incrementally added node")
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

func TestBuilderApplyChanges_NoopPreservesWatermark(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	previous := time.Now().UTC().Add(-2 * time.Minute).Round(time.Second)
	builder.lastBuildTime = previous

	summary, err := builder.ApplyChanges(context.Background(), previous)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	if summary.EventsProcessed != 0 {
		t.Fatalf("expected no events processed, got %d", summary.EventsProcessed)
	}
	if !summary.Until.Equal(previous) {
		t.Fatalf("expected noop summary to preserve watermark %s, got %s", previous, summary.Until)
	}
	if !builder.lastBuildTime.Equal(previous) {
		t.Fatalf("expected builder watermark to remain %s, got %s", previous, builder.lastBuildTime)
	}
}

func TestBuilderApplyChanges_DoesNotRegressWatermarkOnHistoricalReplay(t *testing.T) {
	source := newCDCRoutingSource()
	builder := NewBuilder(source, nil)

	current := time.Now().UTC().Add(-1 * time.Minute).Round(time.Second)
	historical := current.Add(-30 * time.Second)
	builder.lastBuildTime = current
	source.events = []map[string]any{{
		"event_id":    "evt-historical-1",
		"table_name":  "aws_s3_buckets",
		"resource_id": "arn:aws:s3:::historical-bucket",
		"change_type": "added",
		"provider":    "aws",
		"region":      "us-east-1",
		"account_id":  "111111111111",
		"payload": map[string]any{
			"arn":        "arn:aws:s3:::historical-bucket",
			"name":       "historical-bucket",
			"account_id": "111111111111",
			"region":     "us-east-1",
		},
		"event_time": historical.Add(5 * time.Second),
	}}

	summary, err := builder.ApplyChanges(context.Background(), historical)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}

	if !summary.Until.Equal(current) {
		t.Fatalf("expected summary watermark to remain at %s, got %s", current, summary.Until)
	}
	if !builder.lastBuildTime.Equal(current) {
		t.Fatalf("expected builder watermark to remain at %s, got %s", current, builder.lastBuildTime)
	}
	if _, ok := builder.Graph().GetNode("arn:aws:s3:::historical-bucket"); !ok {
		t.Fatal("expected historical node to be applied while preserving watermark")
	}
}

func TestBuilderApplyChanges_KubernetesEventsMaterializeTypedNodesAndEdges(t *testing.T) {
	source := newCDCRoutingSource()
	source.routes["from k8s_core_pods"] = &QueryResult{Rows: []map[string]any{{
		"_cq_id":               "prod-cluster/pod/payments/payments-api",
		"name":                 "payments-api",
		"namespace":            "payments",
		"cluster_name":         "prod-cluster",
		"service_account_name": "payments-sa",
	}}}
	source.routes["from k8s_rbac_service_account_bindings"] = &QueryResult{Rows: []map[string]any{{
		"cluster_name":              "prod-cluster",
		"binding_kind":              "ClusterRoleBinding",
		"binding_name":              "payments-admins",
		"binding_namespace":         "",
		"service_account_name":      "payments-sa",
		"service_account_namespace": "payments",
		"role_ref_kind":             "ClusterRole",
		"role_ref_name":             "cluster-admin",
		"role_ref_api_group":        "rbac.authorization.k8s.io",
	}}}

	builder := NewBuilder(source, nil)
	builder.Graph().AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Provider: "external", Name: "Internet", Risk: RiskCritical})

	base := time.Now().UTC().Add(-1 * time.Minute)
	source.events = []map[string]any{
		{
			"event_id":    "evt-k8s-pod-1",
			"table_name":  "k8s_core_pods",
			"resource_id": "prod-cluster/pod/payments/payments-api",
			"change_type": "added",
			"provider":    "k8s",
			"account_id":  "prod-cluster",
			"payload": map[string]any{
				"_cq_id":               "prod-cluster/pod/payments/payments-api",
				"uid":                  "pod-uid-1",
				"name":                 "payments-api",
				"namespace":            "payments",
				"cluster_name":         "prod-cluster",
				"service_account_name": "payments-sa",
				"spec": map[string]any{
					"automount_service_account_token": true,
					"uses_host_path_volume":           true,
					"containers": []any{
						map[string]any{
							"name": "app",
							"security_context": map[string]any{
								"privileged":  true,
								"run_as_user": float64(0),
							},
						},
					},
				},
			},
			"event_time": base.Add(5 * time.Second),
		},
		{
			"event_id":    "evt-k8s-sa-1",
			"table_name":  "k8s_core_service_accounts",
			"resource_id": "prod-cluster/serviceaccount/payments/payments-sa",
			"change_type": "added",
			"provider":    "k8s",
			"account_id":  "prod-cluster",
			"payload": map[string]any{
				"_cq_id":                          "prod-cluster/serviceaccount/payments/payments-sa",
				"uid":                             "sa-uid-1",
				"name":                            "payments-sa",
				"namespace":                       "payments",
				"cluster_name":                    "prod-cluster",
				"automount_service_account_token": true,
			},
			"event_time": base.Add(10 * time.Second),
		},
		{
			"event_id":    "evt-k8s-role-1",
			"table_name":  "k8s_rbac_cluster_roles",
			"resource_id": "prod-cluster/clusterrole/cluster-admin",
			"change_type": "added",
			"provider":    "k8s",
			"account_id":  "prod-cluster",
			"payload": map[string]any{
				"_cq_id":       "prod-cluster/clusterrole/cluster-admin",
				"uid":          "cr-uid-1",
				"name":         "cluster-admin",
				"cluster_name": "prod-cluster",
				"rules": []any{
					map[string]any{"resources": []any{"secrets"}, "verbs": []any{"*"}},
				},
			},
			"event_time": base.Add(15 * time.Second),
		},
		{
			"event_id":    "evt-k8s-configmap-1",
			"table_name":  "k8s_core_configmaps",
			"resource_id": "prod-cluster/configmap/payments/payments-config",
			"change_type": "added",
			"provider":    "k8s",
			"account_id":  "prod-cluster",
			"payload": map[string]any{
				"_cq_id":           "prod-cluster/configmap/payments/payments-config",
				"uid":              "cfg-uid-1",
				"name":             "payments-config",
				"namespace":        "payments",
				"cluster_name":     "prod-cluster",
				"immutable":        true,
				"data_keys":        []any{"LOG_LEVEL"},
				"binary_data_keys": []any{},
			},
			"event_time": base.Add(20 * time.Second),
		},
		{
			"event_id":    "evt-k8s-pv-1",
			"table_name":  "k8s_core_persistent_volumes",
			"resource_id": "prod-cluster/persistentvolume/payments-pv",
			"change_type": "added",
			"provider":    "k8s",
			"account_id":  "prod-cluster",
			"payload": map[string]any{
				"_cq_id":             "prod-cluster/persistentvolume/payments-pv",
				"uid":                "pv-uid-1",
				"name":               "payments-pv",
				"cluster_name":       "prod-cluster",
				"storage_class_name": "gp3",
				"phase":              "Bound",
			},
			"event_time": base.Add(25 * time.Second),
		},
	}

	summary, err := builder.ApplyChanges(context.Background(), base)
	if err != nil {
		t.Fatalf("ApplyChanges failed: %v", err)
	}
	if summary.NodesAdded != 5 {
		t.Fatalf("expected 5 k8s nodes added, got %+v", summary)
	}

	for _, id := range []string{
		"prod-cluster/pod/payments/payments-api",
		"prod-cluster/serviceaccount/payments/payments-sa",
		"prod-cluster/clusterrole/cluster-admin",
		"prod-cluster/configmap/payments/payments-config",
		"prod-cluster/persistentvolume/payments-pv",
	} {
		if _, ok := builder.Graph().GetNode(id); !ok {
			t.Fatalf("expected node %q to exist after CDC apply", id)
		}
	}

	assertHasEdge(t, builder.Graph(), "prod-cluster/pod/payments/payments-api", "prod-cluster/serviceaccount/payments/payments-sa", EdgeKindCanAssume)
	assertHasEdge(t, builder.Graph(), "prod-cluster/serviceaccount/payments/payments-sa", "prod-cluster/clusterrole/cluster-admin", EdgeKindCanAssume)
}

func TestCDCNodeID_KubernetesPrefersTypedIDOverLegacyFallback(t *testing.T) {
	payload := map[string]any{
		"name":         "cluster-admin",
		"cluster_name": "prod-cluster",
	}

	got := cdcNodeID("k8s_rbac_cluster_roles", payload, "prod-cluster/cluster-admin")
	if got != "prod-cluster/clusterrole/cluster-admin" {
		t.Fatalf("expected typed kubernetes id, got %q", got)
	}
}
