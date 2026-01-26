package graph

import (
	"testing"
)

func TestToxicCombinationEngine_NewEngine(t *testing.T) {
	engine := NewToxicCombinationEngine()
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(engine.rules) == 0 {
		t.Error("expected rules to be registered")
	}
}

func TestToxicCombinationEngine_Analyze_EmptyGraph(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	results := engine.Analyze(g)
	if len(results) != 0 {
		t.Errorf("expected no results for empty graph, got %d", len(results))
	}
}

func TestToxicCombination_PrivilegedPodWithHostPath(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add a privileged pod with host path
	g.AddNode(&Node{
		ID:       "pod-1",
		Kind:     NodeKindPod,
		Name:     "privileged-pod",
		Provider: "kubernetes",
		Properties: map[string]any{
			"privileged":        true,
			"host_path_volumes": true,
			"run_as_root":       true,
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-K8S-001-pod-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			if tc.Score < 90 {
				t.Errorf("expected score >= 90 for privileged+hostPath+root, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-K8S-001 toxic combination")
	}
}

func TestToxicCombination_PrivilegedPodWithHostPath_NotPrivileged(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add a non-privileged pod
	g.AddNode(&Node{
		ID:       "pod-1",
		Kind:     NodeKindPod,
		Name:     "normal-pod",
		Provider: "kubernetes",
		Properties: map[string]any{
			"privileged":        false,
			"host_path_volumes": true,
		},
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-K8S-001-pod-1" {
			t.Error("should not detect TC-K8S-001 for non-privileged pod")
		}
	}
}

func TestToxicCombination_RBACWildcardSecrets(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add a ClusterRole with wildcard on secrets
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindClusterRole,
		Name:     "overprivileged-role",
		Provider: "kubernetes",
		Properties: map[string]any{
			"rules": []any{
				map[string]any{
					"resources": []any{"secrets"},
					"verbs":     []any{"*"},
				},
			},
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-K8S-002-role-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-K8S-002 toxic combination")
	}
}

func TestToxicCombination_ServiceAccountClusterAdmin(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add service account
	g.AddNode(&Node{
		ID:       "sa-1",
		Kind:     NodeKindServiceAccount,
		Name:     "admin-sa",
		Provider: "kubernetes",
	})

	// Add cluster-admin role
	g.AddNode(&Node{
		ID:       "cluster-admin",
		Kind:     NodeKindClusterRole,
		Name:     "cluster-admin",
		Provider: "kubernetes",
	})

	// Add edge from SA to cluster-admin
	g.AddEdge(&Edge{
		ID:     "sa-1-to-cluster-admin",
		Source: "sa-1",
		Target: "cluster-admin",
		Kind:   EdgeKindCanAssume,
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-K8S-003-sa-1" {
			found = true
			if tc.Score < 90 {
				t.Errorf("expected high score for cluster-admin SA, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-K8S-003 toxic combination")
	}
}

func TestToxicCombination_GitHubActionsOIDCOverprivileged(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add AWS role trusting GitHub Actions
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindRole,
		Name:     "github-deploy-role",
		Provider: "aws",
		Properties: map[string]any{
			"trust_policy": `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}]}`,
		},
	})

	// Add admin edge
	g.AddNode(&Node{
		ID:       "resource-1",
		Kind:     NodeKindBucket,
		Name:     "sensitive-bucket",
		Provider: "aws",
	})
	g.AddEdge(&Edge{
		ID:     "role-1-admin",
		Source: "role-1",
		Target: "resource-1",
		Kind:   EdgeKindCanAdmin,
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-CICD-001-role-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			// Weak condition (repo:*) should give higher score
			if tc.Score < 90 {
				t.Errorf("expected high score for weak OIDC condition, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-CICD-001 toxic combination")
	}
}

func TestToxicCombination_IMDSv1WithSensitiveRole(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add EC2 instance with IMDSv1
	g.AddNode(&Node{
		ID:       "instance-1",
		Kind:     NodeKindInstance,
		Name:     "web-server",
		Provider: "aws",
		Properties: map[string]any{
			"imdsv2_required": false,
			"http_tokens":     "optional",
		},
	})

	// Add role with sensitive permissions
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindRole,
		Name:     "instance-role",
		Provider: "aws",
		Properties: map[string]any{
			"actions": []any{"secretsmanager:GetSecretValue", "iam:PassRole"},
		},
	})

	// Link instance to role
	g.AddEdge(&Edge{
		ID:     "instance-role-edge",
		Source: "instance-1",
		Target: "role-1",
		Kind:   EdgeKindCanAssume,
	})

	// Add admin edge from role
	g.AddNode(&Node{
		ID:       "secret-1",
		Kind:     NodeKindSecret,
		Name:     "db-credentials",
		Provider: "aws",
	})
	g.AddEdge(&Edge{
		ID:     "role-admin-edge",
		Source: "role-1",
		Target: "secret-1",
		Kind:   EdgeKindCanAdmin,
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-AWS-001-instance-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-AWS-001 toxic combination")
	}
}

func TestToxicCombination_IMDSv2Required_NoDetection(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add EC2 instance with IMDSv2 required
	g.AddNode(&Node{
		ID:       "instance-1",
		Kind:     NodeKindInstance,
		Name:     "secure-server",
		Provider: "aws",
		Properties: map[string]any{
			"imdsv2_required": true,
			"http_tokens":     "required",
		},
	})

	// Add role with sensitive permissions
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindRole,
		Name:     "instance-role",
		Provider: "aws",
	})
	g.AddEdge(&Edge{
		ID:     "instance-role-edge",
		Source: "instance-1",
		Target: "role-1",
		Kind:   EdgeKindCanAssume,
	})
	g.AddEdge(&Edge{
		ID:     "role-admin-edge",
		Source: "role-1",
		Target: "some-resource",
		Kind:   EdgeKindCanAdmin,
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-AWS-001-instance-1" {
			t.Error("should not detect TC-AWS-001 when IMDSv2 is required")
		}
	}
}

func TestToxicCombination_S3PublicBucketWithSensitiveData(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add public S3 bucket with sensitive data
	g.AddNode(&Node{
		ID:       "bucket-1",
		Kind:     NodeKindBucket,
		Name:     "customer-data-bucket",
		Provider: "aws",
		Properties: map[string]any{
			"public_access":       true,
			"block_public_access": false,
			"data_classification": "confidential",
			"contains_pii":        true,
			"encrypted":           false,
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-AWS-002-bucket-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			// Unencrypted should give higher score
			if tc.Score < 95 {
				t.Errorf("expected very high score for unencrypted public bucket, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-AWS-002 toxic combination")
	}
}

func TestToxicCombination_S3PrivateBucket_NoDetection(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add private S3 bucket
	g.AddNode(&Node{
		ID:       "bucket-1",
		Kind:     NodeKindBucket,
		Name:     "private-bucket",
		Provider: "aws",
		Properties: map[string]any{
			"public_access":       false,
			"block_public_access": true,
			"data_classification": "confidential",
		},
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-AWS-002-bucket-1" {
			t.Error("should not detect TC-AWS-002 for private bucket")
		}
	}
}

func TestToxicCombination_LambdaVPCSecretsAccess(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add Lambda in VPC with secrets access
	g.AddNode(&Node{
		ID:       "lambda-1",
		Kind:     NodeKindFunction,
		Name:     "data-processor",
		Provider: "aws",
		Properties: map[string]any{
			"vpc_config":          true,
			"vpc_id":              "vpc-123",
			"has_internet_egress": true,
			"has_nat_gateway":     true,
		},
	})

	// Add role with secrets access
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindRole,
		Name:     "lambda-role",
		Provider: "aws",
		Properties: map[string]any{
			"actions": []any{"secretsmanager:GetSecretValue"},
		},
	})
	g.AddEdge(&Edge{
		ID:     "lambda-role-edge",
		Source: "lambda-1",
		Target: "role-1",
		Kind:   EdgeKindCanAssume,
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-AWS-003-lambda-1" {
			found = true
			if tc.Severity != SeverityHigh {
				t.Errorf("expected high severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-AWS-003 toxic combination")
	}
}

func TestToxicCombination_EKSNodeRoleECRPush(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add EKS node role with ECR push
	g.AddNode(&Node{
		ID:       "role-1",
		Kind:     NodeKindRole,
		Name:     "eks-node-role",
		Provider: "aws",
		Properties: map[string]any{
			"name":         "eks-node-role",
			"trust_policy": `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			"actions":      []any{"ecr:PutImage", "ecr:BatchCheckLayerAvailability"},
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-CICD-002-role-1" {
			found = true
			if tc.Severity != SeverityHigh {
				t.Errorf("expected high severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-CICD-002 toxic combination")
	}
}

func TestToxicCombination_Deduplication(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add multiple similar nodes
	for i := 0; i < 3; i++ {
		g.AddNode(&Node{
			ID:       "pod-1", // Same ID
			Kind:     NodeKindPod,
			Name:     "privileged-pod",
			Provider: "kubernetes",
			Properties: map[string]any{
				"privileged":        true,
				"host_path_volumes": true,
			},
		})
	}

	results := engine.Analyze(g)

	count := 0
	for _, tc := range results {
		if tc.ID == "TC-K8S-001-pod-1" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected deduplication to produce 1 result, got %d", count)
	}
}

func TestToxicCombination_SortedByScore(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add pods with different severity
	g.AddNode(&Node{
		ID:       "pod-low",
		Kind:     NodeKindPod,
		Name:     "low-risk-pod",
		Provider: "kubernetes",
		Properties: map[string]any{
			"privileged":        true,
			"host_path_volumes": true,
			"run_as_root":       false,
		},
	})
	g.AddNode(&Node{
		ID:       "pod-high",
		Kind:     NodeKindPod,
		Name:     "high-risk-pod",
		Provider: "kubernetes",
		Properties: map[string]any{
			"privileged":        true,
			"host_path_volumes": true,
			"run_as_root":       true,
		},
	})

	results := engine.Analyze(g)

	if len(results) < 2 {
		t.Skip("not enough results to test sorting")
	}

	// Results should be sorted by score descending
	for i := 1; i < len(results); i++ {
		if results[i].Score > results[i-1].Score {
			t.Error("results should be sorted by score descending")
		}
	}
}

func TestToxicCombinationRule_Fields(t *testing.T) {
	engine := NewToxicCombinationEngine()

	for _, rule := range engine.rules {
		if rule.ID == "" {
			t.Error("rule ID should not be empty")
		}
		if rule.Name == "" {
			t.Errorf("rule %s should have a name", rule.ID)
		}
		if rule.Description == "" {
			t.Errorf("rule %s should have a description", rule.ID)
		}
		if rule.Severity == "" {
			t.Errorf("rule %s should have a severity", rule.ID)
		}
		if rule.Detector == nil {
			t.Errorf("rule %s should have a detector function", rule.ID)
		}
	}
}

func TestToxicCombination_RemediationSteps(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	g.AddNode(&Node{
		ID:       "pod-1",
		Kind:     NodeKindPod,
		Name:     "test-pod",
		Provider: "kubernetes",
		Properties: map[string]any{
			"privileged":        true,
			"host_path_volumes": true,
		},
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-K8S-001-pod-1" {
			if len(tc.Remediation) == 0 {
				t.Error("toxic combination should have remediation steps")
			}
			for _, step := range tc.Remediation {
				if step.Action == "" {
					t.Error("remediation step should have an action")
				}
				if step.Priority == 0 {
					t.Error("remediation step should have a priority")
				}
				if step.Effort == "" {
					t.Error("remediation step should have an effort estimate")
				}
			}
			break
		}
	}
}

// GCP Tests

func TestToxicCombination_GCPServiceAccountKeyExposed(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add GCP service account with user-managed keys and elevated permissions
	g.AddNode(&Node{
		ID:       "sa-1",
		Kind:     NodeKindServiceAccount,
		Name:     "admin-sa@project.iam.gserviceaccount.com",
		Provider: "gcp",
		Properties: map[string]any{
			"has_user_managed_keys": true,
			"key_count":             2,
			"oldest_key_age_days":   120,
			"roles":                 []any{"roles/owner"},
		},
	})

	// Add admin edge
	g.AddNode(&Node{
		ID:       "resource-1",
		Kind:     NodeKindBucket,
		Name:     "sensitive-bucket",
		Provider: "gcp",
	})
	g.AddEdge(&Edge{
		ID:     "sa-admin-edge",
		Source: "sa-1",
		Target: "resource-1",
		Kind:   EdgeKindCanAdmin,
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-GCP-001-sa-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			// Old key should increase score
			if tc.Score < 90 {
				t.Errorf("expected high score for old key, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-GCP-001 toxic combination")
	}
}

func TestToxicCombination_GCPPublicGCSBucket(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add public GCS bucket with sensitive name
	g.AddNode(&Node{
		ID:       "bucket-1",
		Kind:     NodeKindBucket,
		Name:     "company-backup-bucket",
		Provider: "gcp",
		Properties: map[string]any{
			"all_users_access": true,
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-GCP-002-bucket-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			// allUsers should give highest score
			if tc.Score < 95 {
				t.Errorf("expected very high score for allUsers access, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-GCP-002 toxic combination")
	}
}

func TestToxicCombination_GCPComputeDefaultSA(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add GCE instance with default SA and cloud-platform scope
	g.AddNode(&Node{
		ID:       "instance-1",
		Kind:     NodeKindInstance,
		Name:     "web-server",
		Provider: "gcp",
		Properties: map[string]any{
			"service_account_email":  "123456789-compute@developer.gserviceaccount.com",
			"service_account_scopes": []any{"https://www.googleapis.com/auth/cloud-platform"},
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-GCP-003-instance-1" {
			found = true
			if tc.Severity != SeverityHigh {
				t.Errorf("expected high severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-GCP-003 toxic combination")
	}
}

// Azure Tests

func TestToxicCombination_AzureManagedIdentityOverprivileged(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add Azure managed identity with Owner at subscription scope
	g.AddNode(&Node{
		ID:       "mi-1",
		Kind:     NodeKindServiceAccount,
		Name:     "app-managed-identity",
		Provider: "azure",
		Properties: map[string]any{
			"identity_type": "SystemAssigned",
			"role_assignments": []any{
				map[string]any{
					"role_definition_name": "Owner",
					"scope":                "/subscriptions/12345678-1234-1234-1234-123456789012",
				},
			},
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-AZURE-001-mi-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-AZURE-001 toxic combination")
	}
}

func TestToxicCombination_AzureManagedIdentity_ResourceGroupScope_NoDetection(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add Azure managed identity with Owner at resource group scope (acceptable)
	g.AddNode(&Node{
		ID:       "mi-1",
		Kind:     NodeKindServiceAccount,
		Name:     "app-managed-identity",
		Provider: "azure",
		Properties: map[string]any{
			"identity_type": "SystemAssigned",
			"role_assignments": []any{
				map[string]any{
					"role_definition_name": "Owner",
					"scope":                "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg",
				},
			},
		},
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-AZURE-001-mi-1" {
			t.Error("should not detect TC-AZURE-001 for resource group scoped role")
		}
	}
}

func TestToxicCombination_AzurePublicStorageBlob(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add public Azure blob container with sensitive name
	g.AddNode(&Node{
		ID:       "container-1",
		Kind:     NodeKindBucket,
		Name:     "internal-backup-container",
		Provider: "azure",
		Properties: map[string]any{
			"public_access":            "container",
			"allow_blob_public_access": true,
		},
	})

	results := engine.Analyze(g)

	found := false
	for _, tc := range results {
		if tc.ID == "TC-AZURE-002-container-1" {
			found = true
			if tc.Severity != SeverityCritical {
				t.Errorf("expected critical severity, got %s", tc.Severity)
			}
			// Container-level access should give higher score
			if tc.Score < 90 {
				t.Errorf("expected high score for container-level access, got %f", tc.Score)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find TC-AZURE-002 toxic combination")
	}
}

func TestToxicCombination_AzurePrivateBlob_NoDetection(t *testing.T) {
	engine := NewToxicCombinationEngine()
	g := New()

	// Add private Azure blob container
	g.AddNode(&Node{
		ID:       "container-1",
		Kind:     NodeKindBucket,
		Name:     "internal-backup-container",
		Provider: "azure",
		Properties: map[string]any{
			"public_access":            "",
			"allow_blob_public_access": false,
		},
	})

	results := engine.Analyze(g)

	for _, tc := range results {
		if tc.ID == "TC-AZURE-002-container-1" {
			t.Error("should not detect TC-AZURE-002 for private blob container")
		}
	}
}

func TestToxicCombination_MultiCloudRuleCount(t *testing.T) {
	engine := NewToxicCombinationEngine()

	// Count rules by cloud provider
	awsCount := 0
	gcpCount := 0
	azureCount := 0
	k8sCount := 0
	cicdCount := 0

	for _, rule := range engine.rules {
		switch {
		case len(rule.ID) >= 6 && rule.ID[:6] == "TC-AWS":
			awsCount++
		case len(rule.ID) >= 6 && rule.ID[:6] == "TC-GCP":
			gcpCount++
		case len(rule.ID) >= 8 && rule.ID[:8] == "TC-AZURE":
			azureCount++
		case len(rule.ID) >= 6 && rule.ID[:6] == "TC-K8S":
			k8sCount++
		case len(rule.ID) >= 7 && rule.ID[:7] == "TC-CICD":
			cicdCount++
		}
	}

	// Verify we have multi-cloud coverage
	if awsCount < 3 {
		t.Errorf("expected at least 3 AWS rules, got %d", awsCount)
	}
	if gcpCount < 3 {
		t.Errorf("expected at least 3 GCP rules, got %d", gcpCount)
	}
	if azureCount < 2 {
		t.Errorf("expected at least 2 Azure rules, got %d", azureCount)
	}
	if k8sCount < 4 {
		t.Errorf("expected at least 4 K8s rules, got %d", k8sCount)
	}
	if cicdCount < 2 {
		t.Errorf("expected at least 2 CI/CD rules, got %d", cicdCount)
	}

	t.Logf("Rule counts - AWS: %d, GCP: %d, Azure: %d, K8s: %d, CI/CD: %d",
		awsCount, gcpCount, azureCount, k8sCount, cicdCount)
}
