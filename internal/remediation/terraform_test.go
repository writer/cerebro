package remediation

import (
	"strings"
	"testing"
)

func TestRenderTerraformArtifact_RejectsUnsupportedContextForSecurityGroupIngress(t *testing.T) {
	_, err := renderTerraformArtifact(Action{Type: ActionRestrictPublicSecurityGroupIngress}, &Execution{})
	if err == nil {
		t.Fatal("expected unsupported terraform context error")
	}
	if !strings.Contains(err.Error(), "standalone Terraform security group rule resources") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformArtifact_RestrictPublicSecurityGroupIngressUsesRemovedBlockForStandaloneRule(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{Type: ActionRestrictPublicSecurityGroupIngress}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "sg-rule-123",
			"resource_name":     "public-ssh",
			"resource_type":     "security_group_rule",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.aws_security_group_rule.public_ssh",
			"matched_ports":     []string{"22"},
			"matched_cidrs":     []string{"0.0.0.0/0"},
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "module.platform.aws_security_group_rule.public_ssh" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if artifact.Summary != "Terraform removal patch for public ingress rule module.platform.aws_security_group_rule.public_ssh" {
		t.Fatalf("unexpected artifact summary: %#v", artifact.Summary)
	}
	if artifact.Path != "generated/terraform/platform/cerebro_remove_public_ingress_public_ssh.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if !strings.Contains(artifact.Content, "removed {") {
		t.Fatalf("expected removed block, got:\n%s", artifact.Content)
	}
	if !strings.Contains(artifact.Content, "from = module.platform.aws_security_group_rule.public_ssh") {
		t.Fatalf("expected removed block address, got:\n%s", artifact.Content)
	}
	if !strings.Contains(artifact.Content, "destroy = true") {
		t.Fatalf("expected removed block destroy lifecycle, got:\n%s", artifact.Content)
	}
	if artifact.StateReconciliation == nil || artifact.StateReconciliation.StateShow.Program != "terraform" {
		t.Fatalf("expected state reconciliation metadata, got %#v", artifact.StateReconciliation)
	}
	if len(artifact.StateReconciliation.Imports) != 0 {
		t.Fatalf("expected no import instructions for removed block artifact, got %#v", artifact.StateReconciliation.Imports)
	}
}

func TestRenderTerraformArtifact_RestrictPublicSecurityGroupIngressRejectsForEachRuleAddresses(t *testing.T) {
	_, err := renderTerraformArtifact(Action{Type: ActionRestrictPublicSecurityGroupIngress}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "sg-rule-123",
			"resource_type":     "security_group_rule",
			"resource_platform": "aws",
			"iac_state_id":      `module.platform.aws_vpc_security_group_ingress_rule.public["ssh_open"].id`,
		},
	})
	if err == nil {
		t.Fatal("expected for_each rule address rejection")
	}
	if !strings.Contains(err.Error(), "standalone Terraform security group rule resources") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformArtifact_RestrictPublicSecurityGroupIngressRejectsInlineSecurityGroupState(t *testing.T) {
	_, err := renderTerraformArtifact(Action{Type: ActionRestrictPublicSecurityGroupIngress}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "sg-123",
			"resource_type":     "security_group",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.aws_security_group.public",
		},
	})
	if err == nil {
		t.Fatal("expected inline security group state rejection")
	}
	if !strings.Contains(err.Error(), "standalone Terraform security group rule resources") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_InfersBucketNameFromARN(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id": "arn:aws:s3:::audit-logs",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ImportID != "audit-logs" {
		t.Fatalf("unexpected import id: %#v", artifact.ImportID)
	}
	if artifact.Path != "generated/terraform/aws/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if !strings.Contains(artifact.Content, `bucket = "audit-logs"`) {
		t.Fatalf("expected bucket reference in artifact content, got %q", artifact.Content)
	}
}

func TestActionDeliveryModeDefaultsToCatalogEntry(t *testing.T) {
	mode := actionDeliveryMode(Action{Type: ActionEnableBucketDefaultEncryption}, nil, CatalogEntry{
		DefaultDeliveryMode: DeliveryModeTerraform,
	})
	if mode != DeliveryModeTerraform {
		t.Fatalf("unexpected delivery mode: %s", mode)
	}
}

func TestActionDeliveryModeUsesProviderSpecificDefault(t *testing.T) {
	mode := actionDeliveryMode(Action{Type: ActionRestrictPublicStorageAccess}, &Execution{
		TriggerData: map[string]any{
			"resource_platform": "aws",
		},
	}, CatalogEntry{
		DefaultDeliveryMode: DeliveryModeRemoteApply,
		DefaultDeliveryModesByProvider: map[string]DeliveryMode{
			"aws": DeliveryModeTerraform,
		},
	})
	if mode != DeliveryModeTerraform {
		t.Fatalf("unexpected delivery mode: %s", mode)
	}
}

func TestRenderTerraformArtifact_EnableBucketDefaultEncryptionRejectsNonAWSProvider(t *testing.T) {
	_, err := renderTerraformArtifact(Action{
		Type: ActionEnableBucketDefaultEncryption,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_type":     "bucket",
			"resource_platform": "gcp",
		},
	})
	if err == nil {
		t.Fatal("expected non-aws provider rejection")
	}
	if !strings.Contains(err.Error(), "only implemented for aws buckets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_UsesIaCStateIDModulePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "module.platform.module.storage.aws_s3_bucket.audit_logs",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.Path != "generated/terraform/platform/storage/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if !strings.Contains(artifact.Content, `bucket = module.platform.module.storage.aws_s3_bucket.audit_logs.id`) {
		t.Fatalf("expected bucket reference from state id, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformArtifact_EnableBucketDefaultEncryptionEscapesLiteralStrings(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionEnableBucketDefaultEncryption,
		Config: map[string]string{
			"kms_master_key_id": `arn:aws:kms:::key/${literal}%{ if injected }`,
		},
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id": "bucket:audit-logs",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `kms_master_key_id = "arn:aws:kms:::key/$${literal}%%{ if injected }"`) {
		t.Fatalf("expected literal terraform markers to be escaped, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_DoesNotTreatRootStateIDAsModulePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "aws_s3_bucket.audit_logs",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.IaCModule != "" {
		t.Fatalf("expected empty inferred module for root state id, got %#v", artifact.IaCModule)
	}
	if artifact.Path != "generated/terraform/aws/cerebro_s3_bucket_default_encryption_audit_logs.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if !strings.Contains(artifact.Content, `bucket = aws_s3_bucket.audit_logs.id`) {
		t.Fatalf("expected root bucket reference from state id, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_UsesIaCFilePlacement(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "arn:aws:s3:::audit-logs",
			"resource_platform": "aws",
			"iac_file":          "infra/storage/main.tf",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.Path != "infra/storage/cerebro_s3_bucket_public_access_block_audit_logs.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if artifact.ResourceAddress != "aws_s3_bucket_public_access_block.audit_logs_public_access_block" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if artifact.ImportID != "audit-logs" {
		t.Fatalf("unexpected import id: %#v", artifact.ImportID)
	}
	if !strings.Contains(artifact.Content, `resource "aws_s3_bucket_public_access_block" "audit_logs_public_access_block"`) {
		t.Fatalf("expected public access block resource, got:\n%s", artifact.Content)
	}
	for _, want := range []string{
		`bucket = "audit-logs"`,
		`block_public_acls       = true`,
		`block_public_policy     = true`,
		`ignore_public_acls      = true`,
		`restrict_public_buckets = true`,
	} {
		if !strings.Contains(artifact.Content, want) {
			t.Fatalf("expected %q in artifact content, got:\n%s", want, artifact.Content)
		}
	}
	if artifact.StateReconciliation == nil {
		t.Fatal("expected structured state reconciliation guidance")
	}
	if artifact.StateReconciliation.StateShow.Program != "terraform" {
		t.Fatalf("unexpected state show program: %#v", artifact.StateReconciliation.StateShow)
	}
	if got := strings.Join(artifact.StateReconciliation.StateShow.Args, " "); got != "state show aws_s3_bucket_public_access_block.audit_logs_public_access_block" {
		t.Fatalf("unexpected state show args: %q", got)
	}
	if artifact.StateReconciliation.Plan.Program != "terraform" {
		t.Fatalf("unexpected plan program: %#v", artifact.StateReconciliation.Plan)
	}
	if got := strings.Join(artifact.StateReconciliation.Plan.Args, " "); got != "plan" {
		t.Fatalf("unexpected plan args: %q", got)
	}
	if len(artifact.StateReconciliation.Imports) != 1 {
		t.Fatalf("expected one import instruction, got %#v", artifact.StateReconciliation.Imports)
	}
	importInstruction := artifact.StateReconciliation.Imports[0]
	if importInstruction.To != "aws_s3_bucket_public_access_block.audit_logs_public_access_block" {
		t.Fatalf("unexpected import target: %#v", importInstruction)
	}
	if importInstruction.ID != "audit-logs" {
		t.Fatalf("unexpected import id: %#v", importInstruction)
	}
	if !strings.Contains(importInstruction.HCL, `to = aws_s3_bucket_public_access_block.audit_logs_public_access_block`) {
		t.Fatalf("expected import block target, got:\n%s", importInstruction.HCL)
	}
	if !strings.Contains(importInstruction.HCL, `id = "audit-logs"`) {
		t.Fatalf("expected import block id, got:\n%s", importInstruction.HCL)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_UsesIaCStateIDModulePath(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.module.storage.aws_s3_bucket.audit_logs",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.Path != "generated/terraform/platform/storage/cerebro_s3_bucket_public_access_block_audit_logs.tf" {
		t.Fatalf("unexpected artifact path: %#v", artifact.Path)
	}
	if artifact.IaCModule != "module.platform.module.storage" {
		t.Fatalf("unexpected inferred module: %#v", artifact.IaCModule)
	}
	if !strings.Contains(artifact.Content, `bucket = module.platform.module.storage.aws_s3_bucket.audit_logs.id`) {
		t.Fatalf("expected bucket reference from state id, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_ReusesExistingPublicAccessBlockResourceAddress(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.module.storage.aws_s3_bucket_public_access_block.existing_block",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "module.platform.module.storage.aws_s3_bucket_public_access_block.existing_block" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if !strings.Contains(artifact.Content, `resource "aws_s3_bucket_public_access_block" "existing_block"`) {
		t.Fatalf("expected existing resource label reuse, got:\n%s", artifact.Content)
	}
	if artifact.StateReconciliation == nil || len(artifact.StateReconciliation.Imports) != 1 {
		t.Fatalf("expected import guidance, got %#v", artifact.StateReconciliation)
	}
	if artifact.StateReconciliation.Imports[0].To != "module.platform.module.storage.aws_s3_bucket_public_access_block.existing_block" {
		t.Fatalf("unexpected import target: %#v", artifact.StateReconciliation.Imports[0])
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_DoesNotReuseForEachInstanceAsResourceLabel(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit.logs",
			"resource_platform": "aws",
			"iac_state_id":      `module.platform.module.storage.aws_s3_bucket_public_access_block.blocks["audit.logs"]`,
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "aws_s3_bucket_public_access_block.audit_logs_public_access_block" {
		t.Fatalf("expected generated resource address fallback, got %#v", artifact.ResourceAddress)
	}
	if strings.Contains(artifact.Content, `resource "aws_s3_bucket_public_access_block" "blocks["audit.logs"]"`) {
		t.Fatalf("unexpected invalid for_each instance resource label in content:\n%s", artifact.Content)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_DoesNotReuseForEachInstanceAsResourceLabelWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit.logs",
			"resource_platform": "aws",
			"iac_state_id":      `module.platform.module.storage.aws_s3_bucket_public_access_block.blocks["audit.logs"].id`,
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "aws_s3_bucket_public_access_block.audit_logs_public_access_block" {
		t.Fatalf("expected generated resource address fallback, got %#v", artifact.ResourceAddress)
	}
	if strings.Contains(artifact.Content, `resource "aws_s3_bucket_public_access_block" "blocks["audit.logs"]"`) {
		t.Fatalf("unexpected invalid for_each instance resource label in content:\n%s", artifact.Content)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_FallsBackToLiteralBucketWhenStateIDIsNonBucketResource(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.module.storage.aws_s3_bucket_public_access_block.audit_logs_public_access_block",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `bucket = "audit-logs"`) {
		t.Fatalf("expected literal bucket fallback when state id is not a bucket resource, got:\n%s", artifact.Content)
	}
}

func TestTerraformStateResourceAddress_PreservesForEachKeysWithDots(t *testing.T) {
	address, resourceType := terraformStateResourceAddress(`module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"]`)
	if resourceType != "aws_s3_bucket" {
		t.Fatalf("unexpected resource type: %q", resourceType)
	}
	if address != `module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"]` {
		t.Fatalf("unexpected resource address: %q", address)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_UsesStateReferenceForForEachKeyWithDots(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit.logs",
			"resource_platform": "aws",
			"iac_state_id":      `module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"]`,
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `bucket = module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"].id`) {
		t.Fatalf("expected bucket reference from for_each state id, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_UsesBucketReferenceWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "module.platform.module.storage.aws_s3_bucket.audit_logs.id",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `bucket = module.platform.module.storage.aws_s3_bucket.audit_logs.id`) {
		t.Fatalf("expected bucket reference reuse for attribute-path state id, got:\n%s", artifact.Content)
	}
	if strings.Contains(artifact.Content, `.id.id`) {
		t.Fatalf("unexpected duplicated id dereference in content:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_UsesBucketReferenceWhenForEachStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit.logs",
			"iac_state_id": `module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"].id`,
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `bucket = module.platform.module.storage.aws_s3_bucket.buckets["audit.logs"].id`) {
		t.Fatalf("expected bucket reference reuse for for_each attribute-path state id, got:\n%s", artifact.Content)
	}
	if strings.Contains(artifact.Content, `.id.id`) {
		t.Fatalf("unexpected duplicated id dereference in content:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_ReusesExistingEncryptionResourceAddress(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "module.platform.module.storage.aws_s3_bucket_server_side_encryption_configuration.existing_encryption",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "module.platform.module.storage.aws_s3_bucket_server_side_encryption_configuration.existing_encryption" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if !strings.Contains(artifact.Content, `resource "aws_s3_bucket_server_side_encryption_configuration" "existing_encryption"`) {
		t.Fatalf("expected existing encryption resource label reuse, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_RejectsNonAWSProvider(t *testing.T) {
	_, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_platform": "gcp",
		},
	})
	if err == nil {
		t.Fatal("expected non-aws provider rejection")
	}
	if !strings.Contains(err.Error(), "only implemented for aws") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_RejectsNonBucketResource(t *testing.T) {
	_, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:public-assets",
			"resource_type":     "database",
			"resource_platform": "aws",
		},
	})
	if err == nil {
		t.Fatal("expected non-bucket resource rejection")
	}
	if !strings.Contains(err.Error(), "resource_family=database") && !strings.Contains(err.Error(), "got database") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRenderTerraformRestrictPublicStorageAccessArtifact_ReusesExistingPublicAccessBlockAddressWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformArtifact(Action{
		Type: ActionRestrictPublicStorageAccess,
	}, &Execution{
		TriggerData: map[string]any{
			"resource_id":       "bucket:audit-logs",
			"resource_platform": "aws",
			"iac_state_id":      "module.platform.module.storage.aws_s3_bucket_public_access_block.existing_block.id",
		},
	})
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "module.platform.module.storage.aws_s3_bucket_public_access_block.existing_block" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if !strings.Contains(artifact.Content, `resource "aws_s3_bucket_public_access_block" "existing_block"`) {
		t.Fatalf("expected existing public-access-block resource label reuse, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_ReusesExistingEncryptionAddressWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "module.platform.module.storage.aws_s3_bucket_server_side_encryption_configuration.existing_encryption.id",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "module.platform.module.storage.aws_s3_bucket_server_side_encryption_configuration.existing_encryption" {
		t.Fatalf("unexpected resource address: %#v", artifact.ResourceAddress)
	}
	if !strings.Contains(artifact.Content, `resource "aws_s3_bucket_server_side_encryption_configuration" "existing_encryption"`) {
		t.Fatalf("expected existing encryption resource label reuse, got:\n%s", artifact.Content)
	}
}

func TestRenderTerraformBucketDefaultEncryptionArtifact_DoesNotReuseForEachInstanceAsResourceLabelWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit.logs",
			"iac_state_id": `module.platform.module.storage.aws_s3_bucket_server_side_encryption_configuration.configs["audit.logs"].id`,
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if artifact.ResourceAddress != "aws_s3_bucket_server_side_encryption_configuration.audit_logs_default_encryption" {
		t.Fatalf("expected generated resource address fallback, got %#v", artifact.ResourceAddress)
	}
	if strings.Contains(artifact.Content, `resource "aws_s3_bucket_server_side_encryption_configuration" "configs["audit.logs"]"`) {
		t.Fatalf("unexpected invalid for_each instance resource label in content:\n%s", artifact.Content)
	}
}
