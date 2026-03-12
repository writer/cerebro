package graph

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockDataSource implements DataSource for testing
type mockDataSource struct {
	results map[string]*QueryResult
}

var _ DataSource = (*mockDataSource)(nil)

func newMockDataSource() *mockDataSource {
	return &mockDataSource{
		results: make(map[string]*QueryResult),
	}
}

func (m *mockDataSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	// Return empty result if no mock data configured
	if result, ok := m.results[query]; ok {
		return result, nil
	}
	return &QueryResult{Rows: []map[string]any{}}, nil
}

func (m *mockDataSource) setResult(query string, result *QueryResult) {
	m.results[query] = result
}

type blockingBuildSource struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingBuildSource) Query(ctx context.Context, query string, args ...any) (*QueryResult, error) {
	_ = args
	if strings.Contains(strings.ToLower(query), "information_schema.tables") {
		s.once.Do(func() { close(s.started) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &QueryResult{Rows: []map[string]any{}}, nil
}

func TestBuilder_BuildWithMockData(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Set up mock IAM users
	source.setResult(`
		SELECT arn, user_name, account_id, password_last_used, tags
		FROM aws_iam_users
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:user/alice",
				"user_name":  "alice",
				"account_id": "111111111111",
			},
			{
				"arn":        "arn:aws:iam::111111111111:user/bob",
				"user_name":  "bob",
				"account_id": "111111111111",
			},
		},
	})

	// Set up mock IAM roles
	source.setResult(`
		SELECT arn, role_name, account_id, assume_role_policy_document, description
		FROM aws_iam_roles
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:role/AdminRole",
				"role_name":  "AdminRole",
				"account_id": "111111111111",
				"assume_role_policy_document": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::111111111111:user/alice"},
						"Action": "sts:AssumeRole"
					}]
				}`,
			},
		},
	})

	// Set up mock IAM groups
	source.setResult(`
		SELECT arn, group_name, account_id
		FROM aws_iam_groups
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:group/Developers",
				"group_name": "Developers",
				"account_id": "111111111111",
			},
		},
	})

	// Set up mock S3 buckets
	source.setResult(`
		SELECT arn, name, account_id, region, block_public_acls, block_public_policy, versioning_status
		FROM aws_s3_buckets
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":                 "arn:aws:s3:::sensitive-data",
				"name":                "sensitive-data",
				"account_id":          "111111111111",
				"region":              "us-east-1",
				"block_public_acls":   true,
				"block_public_policy": true,
			},
			{
				"arn":                 "arn:aws:s3:::public-website",
				"name":                "public-website",
				"account_id":          "111111111111",
				"region":              "us-east-1",
				"block_public_acls":   false,
				"block_public_policy": false,
			},
		},
	})

	// Set up mock policies
	source.setResult(`
		SELECT arn, name, document FROM aws_iam_policies
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":  "arn:aws:iam::111111111111:policy/S3FullAccess",
				"name": "S3FullAccess",
				"document": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Action": "s3:*",
						"Resource": "*"
					}]
				}`,
			},
		},
	})

	// Set up mock role attached policies
	source.setResult(`
		SELECT role_arn, policy_arn FROM aws_iam_role_attached_policies
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"role_arn":   "arn:aws:iam::111111111111:role/AdminRole",
				"policy_arn": "arn:aws:iam::111111111111:policy/S3FullAccess",
			},
		},
	})

	// Set up mock trust policy query for buildTrustEdges
	source.setResult(`
		SELECT arn, account_id, assume_role_policy_document
		FROM aws_iam_roles
		WHERE assume_role_policy_document IS NOT NULL
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:role/AdminRole",
				"account_id": "111111111111",
				"assume_role_policy_document": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::111111111111:user/alice"},
						"Action": "sts:AssumeRole"
					}]
				}`,
			},
		},
	})

	builder := NewBuilder(source, logger)
	err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	g := builder.Graph()

	// Verify nodes
	if g.NodeCount() < 5 {
		t.Errorf("expected at least 5 nodes, got %d", g.NodeCount())
	}

	// Verify alice user node
	alice, ok := g.GetNode("arn:aws:iam::111111111111:user/alice")
	if !ok {
		t.Error("alice user node not found")
	} else if alice.Kind != NodeKindUser {
		t.Errorf("alice should be a user, got %s", alice.Kind)
	}

	// Verify admin role node
	adminRole, ok := g.GetNode("arn:aws:iam::111111111111:role/AdminRole")
	if !ok {
		t.Error("AdminRole node not found")
	} else if adminRole.Kind != NodeKindRole {
		t.Errorf("AdminRole should be a role, got %s", adminRole.Kind)
	}

	// Verify public bucket has high risk
	publicBucket, ok := g.GetNode("arn:aws:s3:::public-website")
	if !ok {
		t.Error("public-website bucket not found")
	} else if publicBucket.Risk != RiskHigh {
		t.Errorf("public bucket should have high risk, got %s", publicBucket.Risk)
	}
	if _, ok := g.GetNode("bucket_public_access_block:arn-aws-s3-public-website"); !ok {
		t.Error("expected normalized bucket public-access-block subresource")
	}
	if _, ok := g.GetNode("claim:arn-aws-s3-public-website:public-access:normalized"); !ok {
		t.Error("expected normalized bucket public_access claim")
	}

	// Verify internet node exists
	_, ok = g.GetNode("internet")
	if !ok {
		t.Error("internet node not found")
	}

	// Verify trust edge exists (alice can assume AdminRole)
	aliceEdges := g.GetOutEdges("arn:aws:iam::111111111111:user/alice")
	foundTrustEdge := false
	for _, e := range aliceEdges {
		if e.Target == "arn:aws:iam::111111111111:role/AdminRole" && e.Kind == EdgeKindCanAssume {
			foundTrustEdge = true
			break
		}
	}
	if !foundTrustEdge {
		t.Error("expected trust edge from alice to AdminRole")
	}
}

func TestBuilder_BuildReturnsContextErrorWhenCanceled(t *testing.T) {
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	builder := NewBuilder(source, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := builder.Build(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestBuilder_BuildUsesCopyOnWriteSwap(t *testing.T) {
	source := &blockingBuildSource{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))
	builder.Graph().AddNode(&Node{ID: "service:live", Kind: NodeKindService, Name: "live"})

	done := make(chan error, 1)
	go func() {
		done <- builder.Build(context.Background())
	}()

	select {
	case <-source.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for build to start")
	}

	if _, ok := builder.Graph().GetNode("service:live"); !ok {
		t.Fatal("expected live graph to remain readable until rebuilt graph swaps in")
	}

	close(source.release)
	if err := <-done; err != nil {
		t.Fatalf("build failed: %v", err)
	}

	if _, ok := builder.Graph().GetNode("service:live"); ok {
		t.Fatal("expected rebuilt graph to replace previous live node")
	}
	if _, ok := builder.Graph().GetNode("internet"); !ok {
		t.Fatal("expected rebuilt graph to contain internet node")
	}
}

func TestBuilder_BuildPreservesSchemaValidationMode(t *testing.T) {
	source := newMockDataSource()
	builder := NewBuilder(source, slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})))
	builder.Graph().SetSchemaValidationMode(SchemaValidationEnforce)

	if err := builder.Build(context.Background()); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if got := builder.Graph().SchemaValidationMode(); got != SchemaValidationEnforce {
		t.Fatalf("expected schema validation mode %q, got %q", SchemaValidationEnforce, got)
	}
}

func TestNormalizeRelID(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/TestRole"
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"plain", arn, arn},
		{"json-string-lower", `{"arn":"` + arn + `"}`, arn},
		{"json-string-upper", `{"Arn":"` + arn + `"}`, arn},
		{"map-string", "map[Arn:" + arn + "]", arn},
		{"map-value", map[string]any{"Arn": arn}, arn},
		{"byte-json", []byte(`{"arn":"` + arn + `"}`), arn},
	}

	for _, tc := range tests {
		if got := normalizeRelID(tc.input); got != tc.want {
			t.Errorf("%s: normalizeRelID(%v) = %q, want %q", tc.name, tc.input, got, tc.want)
		}
	}
}

func TestBuilder_EmptyDataSource(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	builder := NewBuilder(source, logger)
	err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build with empty data should not error: %v", err)
	}

	g := builder.Graph()
	// Should have internet node at minimum
	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node (internet), got %d", g.NodeCount())
	}
}

func TestBuilder_PublicTrustPolicy(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Role with public trust (wildcard principal)
	source.setResult(`
		SELECT arn, role_name, account_id, assume_role_policy_document, description
		FROM aws_iam_roles
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:role/PublicRole",
				"role_name":  "PublicRole",
				"account_id": "111111111111",
				"assume_role_policy_document": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}]
				}`,
			},
		},
	})

	source.setResult(`
		SELECT arn, account_id, assume_role_policy_document
		FROM aws_iam_roles
		WHERE assume_role_policy_document IS NOT NULL
	`, &QueryResult{
		Rows: []map[string]any{
			{
				"arn":        "arn:aws:iam::111111111111:role/PublicRole",
				"account_id": "111111111111",
				"assume_role_policy_document": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "sts:AssumeRole"
					}]
				}`,
			},
		},
	})

	builder := NewBuilder(source, logger)
	err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	g := builder.Graph()

	// Verify internet can assume the public role
	internetEdges := g.GetOutEdges("internet")
	foundPublicTrust := false
	for _, e := range internetEdges {
		if e.Target == "arn:aws:iam::111111111111:role/PublicRole" && e.Kind == EdgeKindCanAssume {
			foundPublicTrust = true
			if e.Risk != RiskCritical {
				t.Errorf("public trust edge should have critical risk, got %s", e.Risk)
			}
			break
		}
	}
	if !foundPublicTrust {
		t.Error("expected public trust edge from internet to PublicRole")
	}
}

func TestIsValidPublicIP(t *testing.T) {
	valid := []string{
		"54.239.28.85",
		"203.0.113.1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"::1",
		"0.0.0.0",
	}
	for _, ip := range valid {
		if !isValidPublicIP(ip) {
			t.Errorf("isValidPublicIP(%q) = false, want true", ip)
		}
	}

	invalid := []string{
		"",
		"N/A",
		"none",
		"null",
		"  ",
		"not-an-ip",
		"0 results",
		"version 2",
		"192.168.1.",
		"abc.def.ghi.jkl",
	}
	for _, ip := range invalid {
		if isValidPublicIP(ip) {
			t.Errorf("isValidPublicIP(%q) = true, want false", ip)
		}
	}
}

func TestIsNodePublic(t *testing.T) {
	tests := []struct {
		name   string
		node   *Node
		public bool
	}{
		{
			name:   "explicit public=true",
			node:   &Node{ID: "db1", Kind: NodeKindDatabase, Properties: map[string]any{"public": true}},
			public: true,
		},
		{
			name:   "explicit public=false",
			node:   &Node{ID: "db2", Kind: NodeKindDatabase, Properties: map[string]any{"public": false}},
			public: false,
		},
		{
			name:   "valid public_ip",
			node:   &Node{ID: "i1", Kind: NodeKindInstance, Properties: map[string]any{"public_ip": "54.239.28.85"}},
			public: true,
		},
		{
			name:   "placeholder public_ip N/A",
			node:   &Node{ID: "i2", Kind: NodeKindInstance, Properties: map[string]any{"public_ip": "N/A"}},
			public: false,
		},
		{
			name:   "empty public_ip",
			node:   &Node{ID: "i3", Kind: NodeKindInstance, Properties: map[string]any{"public_ip": ""}},
			public: false,
		},
		{
			name:   "iam_policy allUsers",
			node:   &Node{ID: "b1", Kind: NodeKindBucket, Properties: map[string]any{"iam_policy": `{"bindings":[{"members":["allUsers"]}]}`}},
			public: true,
		},
		{
			name:   "iam_policy allAuthenticatedUsers",
			node:   &Node{ID: "b2", Kind: NodeKindBucket, Properties: map[string]any{"iam_policy": `{"bindings":[{"members":["allAuthenticatedUsers"]}]}`}},
			public: true,
		},
		{
			name:   "iam_policy private only",
			node:   &Node{ID: "b3", Kind: NodeKindBucket, Properties: map[string]any{"iam_policy": `{"bindings":[{"members":["user:a@b.com"]}]}`}},
			public: false,
		},
		{
			name:   "ip_addresses 0.0.0.0/0",
			node:   &Node{ID: "sg1", Kind: NodeKindNetwork, Properties: map[string]any{"ip_addresses": "[0.0.0.0/0]"}},
			public: true,
		},
		{
			name:   "ip_addresses private only",
			node:   &Node{ID: "sg2", Kind: NodeKindNetwork, Properties: map[string]any{"ip_addresses": "[10.0.0.0/8]"}},
			public: false,
		},
		{
			name:   "ingress INGRESS_TRAFFIC_ALL",
			node:   &Node{ID: "fn1", Kind: NodeKindFunction, Properties: map[string]any{"ingress": "INGRESS_TRAFFIC_ALL"}},
			public: true,
		},
		{
			name:   "ingress internal only",
			node:   &Node{ID: "fn2", Kind: NodeKindFunction, Properties: map[string]any{"ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}},
			public: false,
		},
		{
			name:   "no properties",
			node:   &Node{ID: "x1", Kind: NodeKindInstance, Properties: map[string]any{}},
			public: false,
		},
		{
			name:   "nil properties",
			node:   &Node{ID: "x2", Kind: NodeKindInstance},
			public: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isNodePublic(tc.node)
			if got != tc.public {
				t.Errorf("isNodePublic() = %v, want %v", got, tc.public)
			}
		})
	}
}

func TestBuilder_GCPIAMEdgesFromMembers(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`, &QueryResult{
		Rows: []map[string]any{{
			"id":               "instance-1",
			"name":             "instance-1",
			"project_id":       "proj-1",
			"zone":             "us-central1-a",
			"status":           "RUNNING",
			"service_accounts": []any{},
		}},
	})

	source.setResult(`SELECT project_id, member, roles FROM gcp_iam_members`, &QueryResult{
		Rows: []map[string]any{{
			"project_id": "proj-1",
			"member":     "user:alice@example.com",
			"roles": []any{
				map[string]any{"name": "roles/owner"},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	edges := builder.Graph().GetOutEdges("user:alice@example.com")
	found := false
	for _, edge := range edges {
		if edge.Target == "instance-1" && edge.Kind == EdgeKindCanAdmin {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected admin edge from user:alice@example.com to instance-1")
	}
}

func TestBuilder_GCPIAMEdgesFallbackToPolicies(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`, &QueryResult{
		Rows: []map[string]any{{
			"id":               "instance-2",
			"name":             "instance-2",
			"project_id":       "proj-2",
			"zone":             "us-central1-a",
			"status":           "RUNNING",
			"service_accounts": []any{},
		}},
	})

	source.setResult(`SELECT project_id, bindings FROM gcp_iam_policies`, &QueryResult{
		Rows: []map[string]any{{
			"project_id": "proj-2",
			"bindings": []any{
				map[string]any{
					"role":    "roles/viewer",
					"members": []any{"user:bob@example.com"},
				},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	edges := builder.Graph().GetOutEdges("user:bob@example.com")
	found := false
	for _, edge := range edges {
		if edge.Target == "instance-2" && edge.Kind == EdgeKindCanRead {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected read edge from user:bob@example.com to instance-2")
	}
}

func TestBuilder_GCPIAMServiceAccountMemberResolvesToNodeID(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT unique_id, email, project_id, display_name FROM gcp_iam_service_accounts`, &QueryResult{
		Rows: []map[string]any{{
			"unique_id":    "sa-uid-1",
			"email":        "app-sa@proj-1.iam.gserviceaccount.com",
			"project_id":   "proj-1",
			"display_name": "app-sa",
		}},
	})

	source.setResult(`SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`, &QueryResult{
		Rows: []map[string]any{{
			"id":               "instance-1",
			"name":             "instance-1",
			"project_id":       "proj-1",
			"zone":             "us-central1-a",
			"status":           "RUNNING",
			"service_accounts": []any{},
		}},
	})

	source.setResult(`SELECT project_id, member, roles FROM gcp_iam_members`, &QueryResult{
		Rows: []map[string]any{{
			"project_id": "proj-1",
			"member":     "serviceAccount:app-sa@proj-1.iam.gserviceaccount.com",
			"roles": []any{
				map[string]any{"name": "roles/owner"},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	edges := builder.Graph().GetOutEdges("sa-uid-1")
	found := false
	for _, edge := range edges {
		if edge.Target == "instance-1" && edge.Kind == EdgeKindCanAdmin {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected admin edge from sa-uid-1 to instance-1")
	}
}

func TestBuilder_GCPInstanceServiceAccountEdgeResolvesToNodeID(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT unique_id, email, project_id, display_name FROM gcp_iam_service_accounts`, &QueryResult{
		Rows: []map[string]any{{
			"unique_id":    "sa-uid-3",
			"email":        "runtime-sa@proj-3.iam.gserviceaccount.com",
			"project_id":   "proj-3",
			"display_name": "runtime-sa",
		}},
	})

	source.setResult(`SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`, &QueryResult{
		Rows: []map[string]any{{
			"id":         "instance-3",
			"name":       "instance-3",
			"project_id": "proj-3",
			"zone":       "us-central1-a",
			"status":     "RUNNING",
			"service_accounts": []any{
				map[string]any{"email": "runtime-sa@proj-3.iam.gserviceaccount.com"},
			},
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	edges := builder.Graph().GetOutEdges("instance-3")
	found := false
	for _, edge := range edges {
		if edge.Target == "sa-uid-3" && edge.Kind == EdgeKindCanAssume {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected instance-3 runs_as edge to sa-uid-3")
	}
}
