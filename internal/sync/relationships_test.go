package sync

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractReferenceID(t *testing.T) {
	t.Run("top level id", func(t *testing.T) {
		id := extractReferenceID(map[string]interface{}{"id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-a"})
		if id == "" {
			t.Fatalf("expected id")
		}
	})

	t.Run("nested properties id", func(t *testing.T) {
		id := extractReferenceID(map[string]interface{}{
			"properties": map[string]interface{}{"id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-b"},
		})
		if id == "" {
			t.Fatalf("expected id")
		}
	})

	t.Run("map string fallback", func(t *testing.T) {
		id := extractReferenceID("map[id:/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-c]")
		if id != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-c" {
			t.Fatalf("unexpected id: %s", id)
		}
	})
}

func TestExtractManagedDiskID(t *testing.T) {
	t.Run("managedDisk", func(t *testing.T) {
		id := extractManagedDiskID(map[string]interface{}{
			"managedDisk": map[string]interface{}{"id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-a"},
		})
		if id != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-a" {
			t.Fatalf("unexpected id: %s", id)
		}
	})

	t.Run("ManagedDisk", func(t *testing.T) {
		id := extractManagedDiskID(map[string]interface{}{
			"ManagedDisk": map[string]interface{}{"Id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-b"},
		})
		if id != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Compute/disks/disk-b" {
			t.Fatalf("unexpected id: %s", id)
		}
	})
}

func TestExtractSubnetReferenceID(t *testing.T) {
	id := extractSubnetReferenceID(map[string]interface{}{
		"properties": map[string]interface{}{
			"subnet": map[string]interface{}{"id": "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/subnet-a"},
		},
	})
	if id != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/virtualNetworks/vnet-a/subnets/subnet-a" {
		t.Fatalf("unexpected id: %s", id)
	}
}

func TestAzureResourceIDBuilders(t *testing.T) {
	serverID := azureSQLServerID("sub-a", "rg-a", "sql-a")
	if serverID != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Sql/servers/sql-a" {
		t.Fatalf("unexpected server id: %s", serverID)
	}

	containerID := azureStorageContainerID("sub-a", "rg-a", "acct-a", "container-a")
	if containerID != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/acct-a/blobServices/default/containers/container-a" {
		t.Fatalf("unexpected container id: %s", containerID)
	}
}

func TestIsMissingRelationshipSourceError(t *testing.T) {
	cases := []error{
		errors.New("SQL compilation error: Object does not exist"),
		errors.New("SQL compilation error: invalid identifier 'FOO'"),
		errors.New("does not exist or not authorized"),
	}

	for _, err := range cases {
		if !isMissingRelationshipSourceError(err) {
			t.Fatalf("expected missing-source classification for %q", err.Error())
		}
	}
}

func TestGCPAssetNodeType(t *testing.T) {
	if got := gcpAssetNodeType("compute.googleapis.com/Instance"); got != "gcp:compute:instance" {
		t.Fatalf("unexpected node type: %s", got)
	}
	if got := gcpAssetNodeType("invalid type"); got != "gcp:asset:invalid_type" {
		t.Fatalf("unexpected fallback node type: %s", got)
	}
}

func TestNormalizeGCPAssetRelationshipType(t *testing.T) {
	if got := normalizeGCPAssetRelationshipType("instance-to.instance group"); got != "INSTANCE_TO_INSTANCE_GROUP" {
		t.Fatalf("unexpected relationship type: %s", got)
	}
}

func TestExtractGCPKMSKeyID(t *testing.T) {
	if got := extractGCPKMSKeyID(map[string]interface{}{"kmsKey": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}); got != "projects/p/locations/l/keyRings/r/cryptoKeys/k" {
		t.Fatalf("unexpected key id: %s", got)
	}
	if got := extractGCPKMSKeyID("projects/p/locations/l/keyRings/r/cryptoKeys/k2"); got != "projects/p/locations/l/keyRings/r/cryptoKeys/k2" {
		t.Fatalf("unexpected key id: %s", got)
	}
}

func TestGCPAssetColumnExpression(t *testing.T) {
	columns := map[string]struct{}{
		"ASSET_TYPE": {},
	}

	if got := gcpAssetColumnExpression(columns, "asset_type"); got != "ASSET_TYPE" {
		t.Fatalf("expected ASSET_TYPE, got %q", got)
	}
	if got := gcpAssetColumnExpression(columns, "parent_asset_type"); got != "NULL AS PARENT_ASSET_TYPE" {
		t.Fatalf("expected NULL alias for missing column, got %q", got)
	}
}

func TestBuildGCPAssetInventoryQuery(t *testing.T) {
	t.Run("missing optional columns", func(t *testing.T) {
		query := buildGCPAssetInventoryQuery("GCP_SAMPLE_TABLE", map[string]struct{}{"_CQ_ID": {}})
		checks := []string{
			"SELECT _CQ_ID, NULL AS ASSET_TYPE, NULL AS PARENT_FULL_NAME, NULL AS PARENT_ASSET_TYPE, NULL AS KMS_KEYS, NULL AS RELATIONSHIPS",
			"FROM GCP_SAMPLE_TABLE",
			"WHERE _CQ_ID IS NOT NULL",
		}
		for _, check := range checks {
			if !strings.Contains(query, check) {
				t.Fatalf("expected query to contain %q, got %q", check, query)
			}
		}
	})

	t.Run("all optional columns present", func(t *testing.T) {
		query := buildGCPAssetInventoryQuery("GCP_SAMPLE_TABLE", map[string]struct{}{
			"_CQ_ID":            {},
			"ASSET_TYPE":        {},
			"PARENT_FULL_NAME":  {},
			"PARENT_ASSET_TYPE": {},
			"KMS_KEYS":          {},
			"RELATIONSHIPS":     {},
		})
		checks := []string{"ASSET_TYPE", "PARENT_FULL_NAME", "PARENT_ASSET_TYPE", "KMS_KEYS", "RELATIONSHIPS"}
		for _, check := range checks {
			if !strings.Contains(query, check) {
				t.Fatalf("expected query to contain %q, got %q", check, query)
			}
		}
		if strings.Contains(query, "NULL AS") {
			t.Fatalf("did not expect NULL aliases when all columns exist, got %q", query)
		}
	})
}
