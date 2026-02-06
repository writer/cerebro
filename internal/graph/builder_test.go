package graph

import (
	"context"
	"log/slog"
	"os"
	"testing"
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
