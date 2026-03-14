package remediation

import (
	"strings"
	"testing"
)

func TestRenderTerraformArtifact_RejectsUnsupportedAction(t *testing.T) {
	_, err := renderTerraformArtifact(Action{Type: ActionRestrictPublicSecurityGroupIngress}, &Execution{})
	if err == nil {
		t.Fatal("expected unsupported terraform action error")
	}
	if !strings.Contains(err.Error(), "not implemented") {
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

func TestRenderTerraformBucketDefaultEncryptionArtifact_FallsBackToLiteralBucketWhenStateIDIsAttributePath(t *testing.T) {
	artifact, err := renderTerraformBucketDefaultEncryptionArtifact(&Execution{
		TriggerData: map[string]any{
			"resource_id":  "bucket:audit-logs",
			"iac_state_id": "module.platform.module.storage.aws_s3_bucket.audit_logs.id",
		},
	}, "AES256", "", false)
	if err != nil {
		t.Fatalf("render artifact: %v", err)
	}

	if !strings.Contains(artifact.Content, `bucket = "audit-logs"`) {
		t.Fatalf("expected literal bucket fallback for attribute-path state id, got:\n%s", artifact.Content)
	}
	if strings.Contains(artifact.Content, `.id.id`) {
		t.Fatalf("unexpected duplicated id reference in content:\n%s", artifact.Content)
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
