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
}
