package remediation

import (
	"strings"
	"testing"
)

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
	mode := actionDeliveryMode(Action{Type: ActionEnableBucketDefaultEncryption}, CatalogEntry{
		DefaultDeliveryMode: DeliveryModeTerraform,
	})
	if mode != DeliveryModeTerraform {
		t.Fatalf("unexpected delivery mode: %s", mode)
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
}
