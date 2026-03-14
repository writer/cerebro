package remediation

import "testing"

func TestCatalogIncludesSafeCloudRemediations(t *testing.T) {
	entries := Catalog()
	if len(entries) < 2 {
		t.Fatalf("expected catalog entries, got %d", len(entries))
	}

	byAction := make(map[ActionType]CatalogEntry, len(entries))
	for _, entry := range entries {
		byAction[entry.ActionType] = entry
	}

	storage, ok := byAction[ActionRestrictPublicStorageAccess]
	if !ok {
		t.Fatal("expected public storage restriction catalog entry")
	}
	if !storage.SafeByDefault || !storage.SupportsDryRun || !storage.SupportsRollback {
		t.Fatalf("expected public storage entry to be safe dry-run rollback capable, got %+v", storage)
	}
	if storage.BlastRadius != BlastRadiusLow {
		t.Fatalf("expected public storage action blast radius to be low, got %s", storage.BlastRadius)
	}
	if got := storage.DefaultRemoteTools["aws"]; got != "aws.s3.block_public_access" {
		t.Fatalf("unexpected aws tool mapping: %q", got)
	}
	if storage.DefaultDeliveryMode != DeliveryModeRemoteApply {
		t.Fatalf("expected public storage default delivery mode to remain remote apply, got %s", storage.DefaultDeliveryMode)
	}
	if len(storage.SupportedDeliveryModes) != 2 || storage.SupportedDeliveryModes[0] != DeliveryModeRemoteApply || storage.SupportedDeliveryModes[1] != DeliveryModeTerraform {
		t.Fatalf("unexpected public storage supported delivery modes: %#v", storage.SupportedDeliveryModes)
	}

	accessKey, ok := byAction[ActionDisableStaleAccessKey]
	if !ok {
		t.Fatal("expected stale access key catalog entry")
	}
	if !accessKey.RequiresApproval {
		t.Fatal("expected stale access key remediation to require approval by default")
	}
	if got := accessKey.DefaultRemoteTools["gcp"]; got != "gcp.iam.disable_service_account_key" {
		t.Fatalf("unexpected gcp tool mapping: %q", got)
	}

	encryption, ok := byAction[ActionEnableBucketDefaultEncryption]
	if !ok {
		t.Fatal("expected bucket default encryption catalog entry")
	}
	if !encryption.SafeByDefault || !encryption.SupportsDryRun || !encryption.SupportsRollback {
		t.Fatalf("expected bucket encryption entry to be safe dry-run rollback capable, got %+v", encryption)
	}
	if encryption.BlastRadius != BlastRadiusLow {
		t.Fatalf("expected bucket encryption action blast radius to be low, got %s", encryption.BlastRadius)
	}
	if encryption.DefaultDeliveryMode != DeliveryModeTerraform {
		t.Fatalf("expected bucket encryption default delivery mode to be terraform, got %s", encryption.DefaultDeliveryMode)
	}
	if len(encryption.SupportedDeliveryModes) != 2 || encryption.SupportedDeliveryModes[0] != DeliveryModeTerraform || encryption.SupportedDeliveryModes[1] != DeliveryModeRemoteApply {
		t.Fatalf("unexpected supported delivery modes: %#v", encryption.SupportedDeliveryModes)
	}
	if got := encryption.DefaultRemoteTools["aws"]; got != "aws.s3.put_bucket_encryption" {
		t.Fatalf("unexpected aws bucket encryption tool mapping: %q", got)
	}

	ingress, ok := byAction[ActionRestrictPublicSecurityGroupIngress]
	if !ok {
		t.Fatal("expected public security group ingress catalog entry")
	}
	if !ingress.SafeByDefault || !ingress.SupportsDryRun || !ingress.SupportsRollback {
		t.Fatalf("expected ingress entry to be safe dry-run rollback capable, got %+v", ingress)
	}
	if ingress.BlastRadius != BlastRadiusLow {
		t.Fatalf("expected ingress action blast radius to be low, got %s", ingress.BlastRadius)
	}
	if got := ingress.DefaultRemoteTools["aws"]; got != "aws.ec2.revoke_security_group_ingress" {
		t.Fatalf("unexpected aws ingress tool mapping: %q", got)
	}
}
