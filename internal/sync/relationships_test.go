package sync

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/snowflake"
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

	if parent := azureParentResourceID("/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-a/ipConfigurations/ipconfig-a", "ipConfigurations"); parent != "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.Network/networkInterfaces/nic-a" {
		t.Fatalf("unexpected parent id: %s", parent)
	}
}

func TestAWSEKSClusterARN(t *testing.T) {
	arn := awsEKSClusterARN("us-east-1", "123456789012", "cluster-a")
	if arn != "arn:aws:eks:us-east-1:123456789012:cluster/cluster-a" {
		t.Fatalf("unexpected eks cluster arn: %s", arn)
	}

	if arn := awsEKSClusterARN("", "123456789012", "cluster-a"); arn != "" {
		t.Fatalf("expected empty arn when inputs are incomplete, got %s", arn)
	}
}

func TestAWSRDSHelpers(t *testing.T) {
	lookup := make(map[string]string)
	recordRDSLookup(lookup, "us-east-1", "Db-Primary", "arn:aws:rds:us-east-1:123456789012:db:db-primary")

	if got := lookupRDSResourceARN(lookup, "us-east-1", "db-primary"); got != "arn:aws:rds:us-east-1:123456789012:db:db-primary" {
		t.Fatalf("unexpected region-scoped lookup result: %s", got)
	}

	if got := lookupRDSResourceARN(lookup, "us-west-2", "DB-PRIMARY"); got != "arn:aws:rds:us-east-1:123456789012:db:db-primary" {
		t.Fatalf("unexpected fallback lookup result: %s", got)
	}

	if got := awsRDSARN("cluster", "us-east-1", "123456789012", "cluster-a"); got != "arn:aws:rds:us-east-1:123456789012:cluster:cluster-a" {
		t.Fatalf("unexpected rds arn: %s", got)
	}

	if got := awsRDSARN("cluster", "", "", "cluster-a"); got != "cluster-a" {
		t.Fatalf("expected identifier fallback when account/region missing, got %s", got)
	}
}

func TestResolveRDSEventSourceTarget(t *testing.T) {
	lookupBySourceType := map[string]map[string]string{
		"db-instance":                make(map[string]string),
		"db-option-group":            make(map[string]string),
		"db-cluster-parameter-group": make(map[string]string),
		"db-proxy":                   make(map[string]string),
	}
	recordRDSLookup(lookupBySourceType["db-instance"], "us-east-1", "db-primary", "arn:aws:rds:us-east-1:123456789012:db:db-primary")
	recordRDSLookup(lookupBySourceType["db-option-group"], "us-east-1", "og-main", "arn:aws:rds:us-east-1:123456789012:og:og-main")
	recordRDSLookup(lookupBySourceType["db-proxy"], "us-east-1", "proxy-main", "arn:aws:rds:us-east-1:123456789012:db-proxy:proxy-main")

	targetID, targetType := resolveRDSEventSourceTarget("db-instance", "us-east-1", "123456789012", "DB-PRIMARY", lookupBySourceType)
	if targetID != "arn:aws:rds:us-east-1:123456789012:db:db-primary" || targetType != "aws:rds:db_instance" {
		t.Fatalf("unexpected resolved instance target: %s (%s)", targetID, targetType)
	}

	targetID, targetType = resolveRDSEventSourceTarget("db-cluster", "us-east-1", "123456789012", "cluster-a", lookupBySourceType)
	if targetID != "arn:aws:rds:us-east-1:123456789012:cluster:cluster-a" || targetType != "aws:rds:db_cluster" {
		t.Fatalf("unexpected cluster fallback target: %s (%s)", targetID, targetType)
	}

	targetID, targetType = resolveRDSEventSourceTarget("db-option-group", "us-east-1", "123456789012", "OG-MAIN", lookupBySourceType)
	if targetID != "arn:aws:rds:us-east-1:123456789012:og:og-main" || targetType != "aws:rds:db_option_group" {
		t.Fatalf("unexpected option group target: %s (%s)", targetID, targetType)
	}

	targetID, targetType = resolveRDSEventSourceTarget("db-cluster-parameter-group", "us-east-1", "123456789012", "cluster-pg-a", lookupBySourceType)
	if targetID != "arn:aws:rds:us-east-1:123456789012:cluster-pg:cluster-pg-a" || targetType != "aws:rds:db_cluster_parameter_group" {
		t.Fatalf("unexpected cluster parameter group fallback target: %s (%s)", targetID, targetType)
	}

	targetID, targetType = resolveRDSEventSourceTarget("db-proxy", "us-east-1", "123456789012", "proxy-main", lookupBySourceType)
	if targetID != "arn:aws:rds:us-east-1:123456789012:db-proxy:proxy-main" || targetType != "aws:rds:db_proxy" {
		t.Fatalf("unexpected proxy target: %s (%s)", targetID, targetType)
	}

	targetID, targetType = resolveRDSEventSourceTarget("unknown", "us-east-1", "123456789012", "x", lookupBySourceType)
	if targetID != "" || targetType != "" {
		t.Fatalf("expected unknown source type to be ignored, got %s (%s)", targetID, targetType)
	}
}

func TestGetSliceAny(t *testing.T) {
	value := map[string]interface{}{
		"subnetIds": []interface{}{"subnet-1", "subnet-2"},
	}

	slice := getSliceAny(value, "SubnetIds", "subnetIds", "subnet_ids")
	if len(slice) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(slice))
	}

	if slice := getSliceAny(value, "missing"); slice != nil {
		t.Fatalf("expected nil for missing keys")
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

func TestAppendOktaGroupMembershipRelationships(t *testing.T) {
	t.Parallel()

	rels := appendOktaGroupMembershipRelationships(nil, []map[string]interface{}{
		{"group_id": "group-1", "user_id": "user-1"},
		{"group_id": "", "user_id": "user-2"},
	})

	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
	if rels[0].SourceID != "user-1" || rels[0].TargetID != "group-1" || rels[0].RelType != RelMemberOf {
		t.Fatalf("unexpected relationship: %+v", rels[0])
	}
}

func TestAppendOktaAppAssignmentRelationships(t *testing.T) {
	t.Parallel()

	rels := appendOktaAppAssignmentRelationships(nil, []map[string]interface{}{
		{"app_id": "app-1", "assignee_id": "user-1", "assignee_type": "USER"},
		{"app_id": "app-2", "assignee_id": "group-1", "assignee_type": "GROUP"},
		{"app_id": "app-3", "assignee_id": "other-1", "assignee_type": "ROLE"},
	})

	if len(rels) != 2 {
		t.Fatalf("expected 2 relationships, got %d", len(rels))
	}

	if rels[0].SourceType != "okta:user" || rels[0].TargetType != "okta:application" || rels[0].RelType != RelCanAccess {
		t.Fatalf("unexpected user assignment relationship: %+v", rels[0])
	}
	if rels[1].SourceType != "okta:group" || rels[1].TargetType != "okta:application" || rels[1].RelType != RelCanAccess {
		t.Fatalf("unexpected group assignment relationship: %+v", rels[1])
	}
}

func TestAppendOktaAdminRoleRelationships(t *testing.T) {
	t.Parallel()

	rels := appendOktaAdminRoleRelationships(nil, []map[string]interface{}{
		{"user_id": "user-1", "role_type": "SUPER_ADMIN", "role_label": "Super Admin"},
		{"user_id": "user-2", "role_type": "", "role_label": "Missing"},
	})

	if len(rels) != 1 {
		t.Fatalf("expected 1 relationship, got %d", len(rels))
	}
	if rels[0].SourceID != "user-1" || rels[0].TargetID != "okta_admin_role:super_admin" || rels[0].RelType != RelHasRole {
		t.Fatalf("unexpected relationship: %+v", rels[0])
	}

	props := map[string]interface{}{}
	if err := json.Unmarshal([]byte(rels[0].Properties), &props); err != nil {
		t.Fatalf("failed to parse relationship properties: %v", err)
	}
	if props["role_type"] != "SUPER_ADMIN" || props["role_label"] != "Super Admin" {
		t.Fatalf("unexpected relationship properties: %+v", props)
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

func TestGCPArtifactRelationshipHelpers(t *testing.T) {
	packageID := "projects/p/locations/us-central1/repositories/repo-a/packages/pkg-a"
	versionID := packageID + "/versions/1.0.0"

	if got := gcpArtifactPackageID(packageID, "", "", "", ""); got != packageID {
		t.Fatalf("expected package id from _cq_id, got %s", got)
	}

	if got := gcpArtifactVersionID(versionID, "", "", "", "", ""); got != versionID {
		t.Fatalf("expected version id from _cq_id, got %s", got)
	}

	if got := gcpArtifactRepositoryIDFromPackage(packageID, "", ""); got != "projects/p/locations/us-central1/repositories/repo-a" {
		t.Fatalf("unexpected repository id: %s", got)
	}

	if got := gcpArtifactPackageIDFromVersion(versionID, "", "", ""); got != packageID {
		t.Fatalf("unexpected package id from version: %s", got)
	}

	if got := gcpArtifactPackageID("", "", "p", "repo-a", "pkg-a"); got != "projects/p/locations/-/repositories/repo-a/packages/pkg-a" {
		t.Fatalf("unexpected package fallback id: %s", got)
	}

	if got := gcpArtifactVersionID("", "", "p", "repo-a", "pkg-a", "1.0.0"); got != "projects/p/locations/-/repositories/repo-a/packages/pkg-a/versions/1.0.0" {
		t.Fatalf("unexpected version fallback id: %s", got)
	}

	if got := gcpArtifactRepositoryIDFromPackage("", "p", "repo-a"); got != "projects/p/locations/-/repositories/repo-a" {
		t.Fatalf("unexpected repository fallback id: %s", got)
	}

	if got := gcpArtifactPackageIDFromVersion("", "p", "repo-a", "pkg-a"); got != "projects/p/locations/-/repositories/repo-a/packages/pkg-a" {
		t.Fatalf("unexpected package fallback from version: %s", got)
	}

	if got := gcpArtifactPackageID("", "", "", "", ""); got != "" {
		t.Fatalf("expected empty id for missing package fields, got %s", got)
	}
}

func TestGCPArtifactImageRelationshipHelpers(t *testing.T) {
	imageName := "projects/p/locations/us-central1/repositories/repo-a/dockerImages/team/app@sha256:abcd"
	imageURI := "us-central1-docker.pkg.dev/p/repo-a/team/app@sha256:abcd"

	if got := gcpArtifactImageID(imageURI, "", ""); got != imageURI {
		t.Fatalf("expected image id from uri, got %s", got)
	}
	if got := gcpArtifactImageID("", imageURI, ""); got != imageURI {
		t.Fatalf("expected image id from _cq_id fallback, got %s", got)
	}
	if got := gcpArtifactImageID("", "", imageName); got != imageName {
		t.Fatalf("expected image id from name fallback, got %s", got)
	}

	if got := gcpArtifactRepositoryID("projects/p/locations/us-central1/repositories/repo-a", ""); got != "projects/p/locations/us-central1/repositories/repo-a" {
		t.Fatalf("unexpected repository id from repository column: %s", got)
	}
	if got := gcpArtifactRepositoryID("", imageName); got != "projects/p/locations/us-central1/repositories/repo-a" {
		t.Fatalf("unexpected repository id from image name: %s", got)
	}

	if got := gcpArtifactPackageIDFromImage(imageName); got != "projects/p/locations/us-central1/repositories/repo-a/packages/team/app" {
		t.Fatalf("unexpected package id from digest image: %s", got)
	}
	if got := gcpArtifactPackageIDFromImage("projects/p/locations/us-central1/repositories/repo-a/dockerImages/team/app:latest"); got != "projects/p/locations/us-central1/repositories/repo-a/packages/team/app" {
		t.Fatalf("unexpected package id from tagged image: %s", got)
	}
	if got := gcpArtifactPackageIDFromImage("projects/p/locations/us-central1/repositories/repo-a/dockerImages/team/app"); got != "projects/p/locations/us-central1/repositories/repo-a/packages/team/app" {
		t.Fatalf("unexpected package id from image without digest/tag: %s", got)
	}
	if got := gcpArtifactPackageIDFromImage("projects/p/locations/us-central1/repositories/repo-a"); got != "" {
		t.Fatalf("expected empty package id for non-image input, got %s", got)
	}
}

func TestPersistRelationships_UsesRunSyncTimeForFreshWrites(t *testing.T) {
	originalSchema := relationshipSchemaName
	originalBatch := relationshipQueryBatch
	t.Cleanup(func() {
		relationshipSchemaName = originalSchema
		relationshipQueryBatch = originalBatch
	})

	relationshipSchemaName = func(_ *snowflake.Client) string { return "RAW" }
	var capturedArgs []interface{}
	relationshipQueryBatch = func(_ context.Context, _ *snowflake.Client, _ string, args ...interface{}) error {
		capturedArgs = append([]interface{}(nil), args...)
		return nil
	}

	runSyncTime := time.Date(2026, 2, 24, 16, 0, 0, 0, time.UTC)
	rex := &RelationshipExtractor{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		runSyncTime: runSyncTime,
	}

	rels := []Relationship{{
		SourceID:   "arn:aws:iam::123456789012:role/test-role",
		SourceType: "aws:iam:role",
		TargetID:   "arn:aws:iam::123456789012:policy/test-policy",
		TargetType: "aws:iam:policy",
		RelType:    RelAttachedTo,
		Properties: "{}",
	}}

	total, err := rex.persistRelationships(context.Background(), rels)
	if err != nil {
		t.Fatalf("persist relationships: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 persisted relationship, got %d", total)
	}
	if len(capturedArgs) != 8 {
		t.Fatalf("expected 8 query args for one relationship, got %d", len(capturedArgs))
	}

	syncArg, ok := capturedArgs[7].(time.Time)
	if !ok {
		t.Fatalf("expected sync_time arg to be time.Time, got %T", capturedArgs[7])
	}
	if !syncArg.Equal(runSyncTime) {
		t.Fatalf("expected sync_time %s, got %s", runSyncTime, syncArg)
	}
}

func TestPersistRelationships_UsesCurrentTimeWhenRunSyncTimeMissing(t *testing.T) {
	originalSchema := relationshipSchemaName
	originalBatch := relationshipQueryBatch
	originalNow := relationshipNowUTC
	t.Cleanup(func() {
		relationshipSchemaName = originalSchema
		relationshipQueryBatch = originalBatch
		relationshipNowUTC = originalNow
	})

	relationshipSchemaName = func(_ *snowflake.Client) string { return "RAW" }
	fixedNow := time.Date(2026, 2, 24, 16, 5, 0, 0, time.UTC)
	relationshipNowUTC = func() time.Time { return fixedNow }

	var capturedArgs []interface{}
	relationshipQueryBatch = func(_ context.Context, _ *snowflake.Client, _ string, args ...interface{}) error {
		capturedArgs = append([]interface{}(nil), args...)
		return nil
	}

	rex := &RelationshipExtractor{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rels := []Relationship{{
		SourceID:   "arn:aws:iam::123456789012:role/test-role",
		SourceType: "aws:iam:role",
		TargetID:   "arn:aws:iam::123456789012:policy/test-policy",
		TargetType: "aws:iam:policy",
		RelType:    RelAttachedTo,
		Properties: "{}",
	}}

	total, err := rex.persistRelationships(context.Background(), rels)
	if err != nil {
		t.Fatalf("persist relationships: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 persisted relationship, got %d", total)
	}
	if len(capturedArgs) != 8 {
		t.Fatalf("expected 8 query args for one relationship, got %d", len(capturedArgs))
	}

	syncArg, ok := capturedArgs[7].(time.Time)
	if !ok {
		t.Fatalf("expected sync_time arg to be time.Time, got %T", capturedArgs[7])
	}
	if !syncArg.Equal(fixedNow) {
		t.Fatalf("expected sync_time %s, got %s", fixedNow, syncArg)
	}
}

func TestGCPSCCFindingID(t *testing.T) {
	findingName := "organizations/123/sources/456/findings/finding-a"

	if got := gcpSCCFindingID(findingName, ""); got != findingName {
		t.Fatalf("expected id from _cq_id, got %s", got)
	}
	if got := gcpSCCFindingID("", findingName); got != findingName {
		t.Fatalf("expected id from name fallback, got %s", got)
	}
	if got := gcpSCCFindingID("", ""); got != "" {
		t.Fatalf("expected empty id when values are missing, got %s", got)
	}
}

func TestGCPStorageAndTopicIDHelpers(t *testing.T) {
	if got := gcpStorageBucketID("bucket-a"); got != "projects/_/buckets/bucket-a" {
		t.Fatalf("unexpected bucket id from name: %s", got)
	}
	if got := gcpStorageBucketID("projects/p/buckets/bucket-a"); got != "projects/p/buckets/bucket-a" {
		t.Fatalf("unexpected bucket id from full path: %s", got)
	}

	if got := gcpStorageObjectID("obj-id", "", "", ""); got != "obj-id" {
		t.Fatalf("unexpected object id from _cq_id: %s", got)
	}
	if got := gcpStorageObjectID("", "https://storage.googleapis.com/storage/v1/b/bucket-a/o/object-a", "", ""); got != "https://storage.googleapis.com/storage/v1/b/bucket-a/o/object-a" {
		t.Fatalf("unexpected object id from self_link: %s", got)
	}
	if got := gcpStorageObjectID("", "", "bucket-a", "path/object-a"); got != "projects/_/buckets/bucket-a/objects/path/object-a" {
		t.Fatalf("unexpected object id from bucket+name: %s", got)
	}

	if got := gcpPubSubTopicID("projects/p/topics/topic-a", "", ""); got != "projects/p/topics/topic-a" {
		t.Fatalf("unexpected topic id from _cq_id: %s", got)
	}
	if got := gcpPubSubTopicID("", "p", "topic-a"); got != "projects/p/topics/topic-a" {
		t.Fatalf("unexpected topic id from fallback fields: %s", got)
	}

	endpointName := "projects/p/locations/us-central1/endpoints/ep-a"
	if got := gcpIDSEndpointID(endpointName, ""); got != endpointName {
		t.Fatalf("unexpected endpoint id from _cq_id: %s", got)
	}
	if got := gcpIDSEndpointID("", endpointName); got != endpointName {
		t.Fatalf("unexpected endpoint id from name fallback: %s", got)
	}
}

func TestGCPGKEIDHelpers(t *testing.T) {
	clusterPath := "projects/p/locations/us-central1/clusters/cluster-a"
	nodePoolPath := clusterPath + "/nodePools/pool-a"

	if got := gcpClusterID(clusterPath, "", "", "", ""); got != clusterPath {
		t.Fatalf("unexpected cluster id from _cq_id: %s", got)
	}
	if got := gcpClusterID("", "", "p", "us-central1", "cluster-a"); got != clusterPath {
		t.Fatalf("unexpected cluster fallback id: %s", got)
	}

	if got := gcpNodePoolID(nodePoolPath, "", "", "", "", ""); got != nodePoolPath {
		t.Fatalf("unexpected node pool id from _cq_id: %s", got)
	}
	if got := gcpNodePoolID("", "", "p", "us-central1", "cluster-a", "pool-a"); got != nodePoolPath {
		t.Fatalf("unexpected node pool fallback id: %s", got)
	}
}

func TestGCPIAMAndLoggingHelpers(t *testing.T) {
	if got := gcpProjectPath("p"); got != "projects/p" {
		t.Fatalf("unexpected project path: %s", got)
	}
	if got := gcpServiceAccountID("", "", "p", "sa@p.iam.gserviceaccount.com"); got != "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com" {
		t.Fatalf("unexpected service account fallback id: %s", got)
	}

	if id, typ := gcpIAMPrincipal("serviceAccount:sa@p.iam.gserviceaccount.com", "", "", "p"); id != "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com" || typ != "gcp:iam:service_account" {
		t.Fatalf("unexpected service account principal: %s (%s)", id, typ)
	}
	if id, typ := gcpIAMPrincipal("user:alice@example.com", "", "", ""); id != "alice@example.com" || typ != "gcp:iam:user" {
		t.Fatalf("unexpected user principal: %s (%s)", id, typ)
	}
	if id, typ := gcpIAMPrincipal("group:eng@example.com", "", "", ""); id != "eng@example.com" || typ != "gcp:iam:group" {
		t.Fatalf("unexpected group principal: %s (%s)", id, typ)
	}
	if id, typ := gcpIAMPrincipal("allUsers", "", "", ""); id != "allUsers" || typ != "gcp:iam:principal" {
		t.Fatalf("unexpected public principal: %s (%s)", id, typ)
	}

	if got := gcpLoggingSinkID("", "p", "sink-a"); got != "projects/p/sinks/sink-a" {
		t.Fatalf("unexpected sink id: %s", got)
	}

	if id, typ := gcpLoggingDestinationID("storage.googleapis.com/my-bucket"); id != "projects/_/buckets/my-bucket" || typ != "gcp:storage:bucket" {
		t.Fatalf("unexpected storage destination: %s (%s)", id, typ)
	}
	if id, typ := gcpLoggingDestinationID("pubsub.googleapis.com/projects/p/topics/topic-a"); id != "projects/p/topics/topic-a" || typ != "gcp:pubsub:topic" {
		t.Fatalf("unexpected pubsub destination: %s (%s)", id, typ)
	}
	if id, typ := gcpLoggingDestinationID("bigquery.googleapis.com/projects/p/datasets/ds"); id != "projects/p/datasets/ds" || typ != "gcp:bigquery:dataset" {
		t.Fatalf("unexpected bigquery destination: %s (%s)", id, typ)
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
