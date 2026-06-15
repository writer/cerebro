package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "gcp" {
		t.Fatalf("Spec().Id = %q, want gcp", source.Spec().Id)
	}
}

func TestCheckRequiresProjectAndAuth(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want missing project_id error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"project_id": "writer-prod"})); err == nil {
		t.Fatal("Check() error = nil, want missing token error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"project_id": "writer-prod", "wif_audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws"})); err == nil {
		t.Fatal("Check() error = nil, want missing WIF service account error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"project_id": "writer-prod", "wif_service_account_email": "scanner@writer-iam.iam.gserviceaccount.com"})); err == nil {
		t.Fatal("Check() error = nil, want missing WIF audience error")
	}
}

func TestGCPPullFromRecordsPreservesNextCursorWithoutEvents(t *testing.T) {
	pull, err := gcpPullFromRecords[string](nil, "next-page", nil)
	if err != nil {
		t.Fatalf("gcpPullFromRecords() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if got := pull.NextCursor.GetOpaque(); got != "next-page" {
		t.Fatalf("NextCursor = %q, want next-page", got)
	}
}

func TestNewFixtureReplaysGCPFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyAssetMetadata, kind: "asset.data_sensitivity"},
		{family: familyArtifactImage, config: map[string]string{"artifact_repository": "projects/writer-prod/locations/us/repositories/app"}, kind: "gcp.artifact_registry_image"},
		{family: familyArtifactRepo, kind: "gcp.artifact_registry_repository"},
		{family: familyServiceAcct, kind: "gcp.service_account"},
		{family: familyCloudFunction, kind: "gcp.cloud_function"},
		{family: familyCloudIDSEndpoint, kind: "gcp.cloud_ids_endpoint"},
		{family: familyCloudRunService, kind: "gcp.cloud_run_service"},
		{family: familyCloudSQLInstance, kind: "gcp.cloud_sql_instance"},
		{family: familyComputeDisk, kind: "gcp.compute_disk"},
		{family: familyComputeFirewall, kind: "gcp.compute_firewall"},
		{family: familyComputeInstance, kind: "gcp.compute_instance"},
		{family: familyComputeNetwork, kind: "gcp.compute_network"},
		{family: familyComputeSubnetwork, kind: "gcp.compute_subnetwork"},
		{family: familyDNSManagedZone, kind: "gcp.dns_managed_zone"},
		{family: familyGCSBucket, kind: "gcp.gcs_bucket"},
		{family: familyGKECluster, kind: "gcp.gke_cluster"},
		{family: familyGKENodePool, kind: "gcp.gke_node_pool"},
		{family: familyGroup, config: map[string]string{"customer_id": "C01"}, kind: "gcp.group"},
		{family: familyGroupMember, config: map[string]string{"group_key": "security@writer.com"}, kind: "gcp.group_membership"},
		{family: familyKMSKey, config: map[string]string{"location": "us", "key_ring": "prod"}, kind: "gcp.kms_key"},
		{family: familyLoggingSink, kind: "gcp.logging_project_sink"},
		{family: familyResourceExposure, kind: "gcp.resource_exposure"},
		{family: familyRoleAssign, kind: "gcp.iam_role_assignment"},
		{family: familyEffectivePermission, kind: "gcp.effective_permission"},
		{family: familySAImpersonation, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_impersonation"},
		{family: familySecret, kind: "gcp.secret_manager_secret"},
		{family: familyAudit, kind: "gcp.audit"},
		{family: familySAKey, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_key"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"project_id": "writer-prod", "family": tt.family, "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
		})
	}
}

func TestReadLiveGCPServiceAccountPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyServiceAcct, "project_id": "writer-prod", "token": "test-token"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(service_account) error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(service_account) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["email"]; got != "sa@writer-prod.iam.gserviceaccount.com" {
		t.Fatalf("email = %q, want service account email", got)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover(service_account) error = %v", err)
	}
	if len(urns) != 1 {
		t.Fatalf("len(Discover(service_account)) = %d, want 1", len(urns))
	}
	if got := urns[0].String(); got != "urn:cerebro:writer-prod:gcp_service_account:sa@writer-prod.iam.gserviceaccount.com" {
		t.Fatalf("Discover(service_account) urn = %q, want email-based service account urn", got)
	}
}

func TestReadLiveGCPUsesWIFTokenSource(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	calls := 0
	source.tokenSourceFactory = func(_ context.Context, settings settings) (oauth2.TokenSource, error) {
		calls++
		if settings.wifAudience == "" {
			t.Fatal("wifAudience is empty")
		}
		if settings.wifServiceAccount != "scanner@writer-iam.iam.gserviceaccount.com" {
			t.Fatalf("wifServiceAccount = %q", settings.wifServiceAccount)
		}
		return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"}), nil
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":                  server.URL,
		"family":                    familyServiceAcct,
		"project_id":                "writer-prod",
		"wif_audience":              "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws",
		"wif_service_account_email": "scanner@writer-iam.iam.gserviceaccount.com",
		"wif_aws_region":            "us-east-1",
	})
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(service_account) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if calls != 1 {
		t.Fatalf("token source factory calls = %d, want 1", calls)
	}
	if _, err := source.Discover(context.Background(), cfg); err != nil {
		t.Fatalf("Discover(service_account) error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("token source factory calls after cache = %d, want 1", calls)
	}
}

func TestReadLiveGCPRoleAndAuditPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: familyRoleAssign, kind: "gcp.iam_role_assignment"},
		{family: familyEffectivePermission, kind: "gcp.effective_permission"},
		{family: familyAudit, kind: "gcp.audit"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
		})
	}
}

func TestReadLiveGCPAssetMetadataPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyAssetMetadata, "project_id": "writer-prod", "token": "test-token"}), nil)
	if err != nil {
		t.Fatalf("Read(asset_metadata) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "asset.data_sensitivity" {
		t.Fatalf("kind = %q, want asset.data_sensitivity", event.Kind)
	}
	if got := event.Attributes["resource_provider"]; got != "gcp" {
		t.Fatalf("resource_provider = %q, want gcp", got)
	}
	if got := event.Attributes["data_classification"]; got != "restricted" {
		t.Fatalf("data_classification = %q, want restricted", got)
	}
}

func TestReadLiveGCPTypedCloudResourceFamiliesPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: familyComputeInstance, kind: "gcp.compute_instance", attr: "service_account_email", want: "vm@writer-prod.iam.gserviceaccount.com"},
		{family: familyGKECluster, kind: "gcp.gke_cluster", attr: "network_tags", want: "gke"},
		{family: familyCloudIDSEndpoint, kind: "gcp.cloud_ids_endpoint", attr: "severity", want: "HIGH"},
		{family: familyCloudRunService, kind: "gcp.cloud_run_service", attr: "internet_exposed", want: "true"},
		{family: familyCloudFunction, kind: "gcp.cloud_function", attr: "runtime_identity", want: "fn@writer-prod.iam.gserviceaccount.com"},
		{family: familyCloudSQLInstance, kind: "gcp.cloud_sql_instance", attr: "backup_enabled", want: "true"},
		{family: familyComputeNetwork, kind: "gcp.compute_network", attr: "routing_mode", want: "REGIONAL"},
		{family: familyComputeSubnetwork, kind: "gcp.compute_subnetwork", attr: "ip_cidr_range", want: "10.0.0.0/24"},
		{family: familyComputeFirewall, kind: "gcp.compute_firewall", attr: "source_ranges", want: "0.0.0.0/0"},
		{family: familyComputeDisk, kind: "gcp.compute_disk", attr: "disk_type", want: "pd-balanced"},
		{family: familyDNSManagedZone, kind: "gcp.dns_managed_zone", attr: "dnssec_enabled", want: "true"},
		{family: familyGKENodePool, kind: "gcp.gke_node_pool", attr: "auto_upgrade", want: "true"},
		{family: familyGCSBucket, kind: "gcp.gcs_bucket", attr: "versioning_enabled", want: "true"},
		{family: familySecret, kind: "gcp.secret_manager_secret", attr: "rotation_enabled", want: "true"},
		{family: familyKMSKey, config: map[string]string{"location": "us", "key_ring": "prod"}, kind: "gcp.kms_key", attr: "protection_level", want: "HSM"},
		{family: familyLoggingSink, kind: "gcp.logging_project_sink", attr: "exclusions_count", want: "1"},
		{family: familyArtifactRepo, kind: "gcp.artifact_registry_repository", attr: "immutable_tags", want: "true"},
		{family: familyArtifactImage, config: map[string]string{"artifact_repository": "projects/writer-prod/locations/us/repositories/app"}, kind: "gcp.artifact_registry_image", attr: "digest", want: "sha256:abc"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestReadLiveGCPRegionalComputeDiskKeepsRegionOutOfZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/compute/v1/projects/writer-prod/aggregated/disks" {
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"disks": []map[string]any{{
			"id":       "disk-1",
			"name":     "regional-disk",
			"selfLink": "projects/writer-prod/regions/us-central1/disks/regional-disk",
			"type":     "projects/writer-prod/regions/us-central1/diskTypes/pd-balanced",
			"status":   "READY",
			"sizeGb":   "100",
		}}}}})
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyComputeDisk,
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyComputeDisk, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["region"]; got != "us-central1" {
		t.Fatalf("region = %q, want us-central1", got)
	}
	if got := pull.Events[0].Attributes["zone"]; got != "" {
		t.Fatalf("zone = %q, want empty", got)
	}
}

func TestReadLiveGCPDisabledOptionalServicesReturnEmpty(t *testing.T) {
	for _, tt := range []struct {
		family string
		path   string
	}{
		{family: familyGKECluster, path: "/v1/projects/writer-prod/locations/-/clusters"},
		{family: familyCloudIDSEndpoint, path: "/v1/projects/writer-prod/locations/-/endpoints"},
		{family: familyCloudRunService, path: "/v2/projects/writer-prod/locations/-/services"},
		{family: familyCloudFunction, path: "/v2/projects/writer-prod/locations/-/functions"},
		{family: familyDNSManagedZone, path: "/dns/v1/projects/writer-prod/managedZones"},
		{family: familySecret, path: "/v1/projects/writer-prod/secrets"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					http.NotFound(w, r)
					return
				}
				w.WriteHeader(http.StatusForbidden)
				writeJSON(t, w, map[string]any{"error": map[string]any{
					"code":    403,
					"message": "Example API has not been used in project before or it is disabled.",
					"status":  "PERMISSION_DENIED",
					"details": []map[string]any{{"reason": "SERVICE_DISABLED"}},
				}})
			}))
			defer server.Close()
			source, err := newLiveTestSource()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"})
			if err := source.Check(context.Background(), cfg); err != nil {
				t.Fatalf("Check(%s) error = %v", tt.family, err)
			}
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 0 {
				t.Fatalf("len(events) = %d, want 0", len(pull.Events))
			}
		})
	}
}

func TestReadLiveGCPServiceAccountKeyPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":              server.URL,
		"family":                familySAKey,
		"project_id":            "writer-prod",
		"service_account_email": "sa@writer-prod.iam.gserviceaccount.com",
		"token":                 "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(service_account_key) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["credential_type"]; got != "gcp_service_account_key" {
		t.Fatalf("credential_type = %q, want gcp_service_account_key", got)
	}
}

func TestReadLiveGCPExposureAndImpersonationPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: familyResourceExposure, kind: "gcp.resource_exposure", attr: "internet_exposed", want: "true"},
		{family: familySAImpersonation, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_impersonation", attr: "relationship", want: "can_impersonate"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestReadLiveGCPGroupMembershipResolvesGroupKeys(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, groupKey := range []string{"security@writer.com", "groups/abc"} {
		t.Run(groupKey, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url":  server.URL,
				"family":    familyGroupMember,
				"group_key": groupKey,
				"token":     "test-token",
			}), nil)
			if err != nil {
				t.Fatalf("Read(group_membership) error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Attributes["member_email"]; got != "admin@writer.com" {
				t.Fatalf("member_email = %q, want admin@writer.com", got)
			}
		})
	}
}

func newLiveTestSource() (*Source, error) {
	source, err := New()
	if err != nil {
		return nil, err
	}
	source.allowLoopbackBaseURL = true
	source.client = source.safeClient()
	return source, nil
}

func newGCPAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
			return
		}
		switch r.URL.Path {
		case "/v1/projects/writer-prod/serviceAccounts":
			writeJSON(t, w, map[string]any{"accounts": []map[string]any{{"name": "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com", "email": "sa@writer-prod.iam.gserviceaccount.com", "uniqueId": "sa-1", "displayName": "Prod SA"}}})
		case "/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys":
			writeJSON(t, w, map[string]any{"keys": []map[string]any{{"name": "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1", "keyType": "USER_MANAGED", "validAfterTime": "2026-04-23T00:00:00Z"}}})
		case "/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"user:admin@writer.com"}}}})
		case "/compute/v1/projects/writer-prod/global/networks":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "net-1", "name": "default", "selfLink": "projects/writer-prod/global/networks/default", "description": "default network", "autoCreateSubnetworks": false, "routingConfig": map[string]string{"routingMode": "REGIONAL"}, "labels": map[string]string{"env": "prod"}}}})
		case "/compute/v1/projects/writer-prod/global/firewalls":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "fw-1", "name": "allow-web", "network": "global/networks/default", "direction": "INGRESS", "sourceRanges": []string{"0.0.0.0/0"}, "allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}}}})
		case "/v1/groups:lookup":
			if got := r.URL.Query().Get("groupKey.id"); got != "security@writer.com" {
				t.Fatalf("groupKey.id = %q, want security@writer.com", got)
			}
			writeJSON(t, w, map[string]any{"name": "groups/abc", "groupKey": map[string]any{"id": "security@writer.com"}})
		case "/v1/groups/abc/memberships":
			writeJSON(t, w, map[string]any{"memberships": []map[string]any{{"name": "groups/abc/memberships/member-1", "preferredMemberKey": map[string]any{"id": "user:admin@writer.com"}, "roles": []map[string]any{{"name": "MEMBER"}}}}})
		case "/v1/projects/writer-prod:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/owner", "members": []string{"serviceAccount:sa@writer-prod.iam.gserviceaccount.com"}}}})
		case "/v1/projects/writer-prod:searchAllResources":
			writeJSON(t, w, map[string]any{"results": []map[string]any{{"name": "//storage.googleapis.com/projects/_/buckets/data", "assetType": "storage.googleapis.com/Bucket", "displayName": "data", "location": "us", "labels": map[string]string{"data_classification": "restricted", "owner": "security@writer.com", "tier": "critical", "pii": "true", "env": "prod"}}}})
		case "/compute/v1/projects/writer-prod/aggregated/instances":
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"instances": []map[string]any{{"id": "123456789", "name": "web-1", "zone": "projects/writer-prod/zones/us-central1-a", "machineType": "projects/writer-prod/zones/us-central1-a/machineTypes/e2-medium", "status": "RUNNING", "labels": map[string]string{"env": "prod"}, "tags": map[string]any{"items": []string{"web"}}, "networkInterfaces": []map[string]any{{"network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default", "networkIP": "10.0.0.5", "accessConfigs": []map[string]any{{"type": "ONE_TO_ONE_NAT", "natIP": "34.1.2.3"}}}}, "serviceAccounts": []map[string]any{{"email": "vm@writer-prod.iam.gserviceaccount.com"}}, "disks": []map[string]any{{"boot": true, "diskEncryptionKey": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/vm"}}}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/subnetworks":
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"subnetworks": []map[string]any{{"id": "subnet-1", "name": "default", "selfLink": "projects/writer-prod/regions/us-central1/subnetworks/default", "network": "projects/writer-prod/global/networks/default", "region": "projects/writer-prod/regions/us-central1", "ipCidrRange": "10.0.0.0/24", "privateIpGoogleAccess": true, "purpose": "PRIVATE", "stackType": "IPV4_ONLY", "labels": map[string]string{"env": "prod"}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/disks":
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"disks": []map[string]any{{"id": "disk-1", "name": "web-1", "selfLink": "projects/writer-prod/zones/us-central1-a/disks/web-1", "zone": "projects/writer-prod/zones/us-central1-a", "type": "projects/writer-prod/zones/us-central1-a/diskTypes/pd-balanced", "status": "READY", "sizeGb": "100", "users": []string{"projects/writer-prod/zones/us-central1-a/instances/web-1"}, "labels": map[string]string{"env": "prod"}, "diskEncryptionKey": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/disk"}}}}}})
		case "/dns/v1/projects/writer-prod/managedZones":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("dns maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"managedZones": []map[string]any{{"id": "zone-1", "name": "prod-zone", "dnsName": "writer.example.", "description": "prod public zone", "nameServers": []string{"ns-cloud-a1.googledomains.com."}, "creationTime": "2026-04-23T00:00:00Z", "dnssecConfig": map[string]string{"state": "on", "nonExistence": "nsec3"}, "visibility": "public", "labels": map[string]string{"env": "prod"}, "cloudLoggingConfig": map[string]bool{"enableLogging": true}}}})
		case "/v1/projects/writer-prod/locations/-/clusters":
			if got := r.URL.Query().Get("pageSize"); got != "" {
				t.Fatalf("gke pageSize = %q, want omitted", got)
			}
			writeJSON(t, w, map[string]any{"clusters": []map[string]any{{"name": "prod", "selfLink": "https://container.googleapis.com/v1/projects/writer-prod/locations/us-central1/clusters/prod", "location": "us-central1", "endpoint": "35.1.2.3", "status": "RUNNING", "network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default", "currentMasterVersion": "1.30.1", "resourceLabels": map[string]string{"env": "prod"}, "nodeConfig": map[string]any{"serviceAccount": "gke@writer-prod.iam.gserviceaccount.com", "tags": []string{"gke"}}, "masterAuthorizedNetworksConfig": map[string]any{"enabled": true, "cidrBlocks": []map[string]string{{"cidrBlock": "0.0.0.0/0"}}}, "databaseEncryption": map[string]string{"state": "ENCRYPTED", "keyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/gke"}}}})
		case "/v1/projects/writer-prod/locations/us-central1/clusters/prod/nodePools":
			writeJSON(t, w, map[string]any{"nodePools": []map[string]any{{"name": "default-pool", "selfLink": "https://container.googleapis.com/v1/projects/writer-prod/locations/us-central1/clusters/prod/nodePools/default-pool", "version": "1.30.1", "status": "RUNNING", "locations": []string{"us-central1-a"}, "initialNodeCount": 3, "config": map[string]any{"machineType": "e2-standard-4", "diskType": "pd-balanced", "diskSizeGb": 100, "imageType": "COS_CONTAINERD", "serviceAccount": "gke@writer-prod.iam.gserviceaccount.com", "tags": []string{"gke"}, "labels": map[string]string{"env": "prod"}, "workloadMetadataConfig": map[string]string{"mode": "GKE_METADATA"}, "shieldedInstanceConfig": map[string]bool{"enableSecureBoot": true, "enableIntegrityMonitoring": true}, "bootDiskKmsKey": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/gke"}, "management": map[string]bool{"autoRepair": true, "autoUpgrade": true}, "autoscaling": map[string]any{"enabled": true, "minNodeCount": 1, "maxNodeCount": 5}}}})
		case "/v1/projects/writer-prod/locations/-/endpoints":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("cloud ids pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"endpoints": []map[string]any{{"name": "projects/writer-prod/locations/us-central1-a/endpoints/prod-ids", "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "labels": map[string]string{"env": "prod"}, "network": "projects/writer-prod/global/networks/default", "endpointForwardingRule": "https://www.googleapis.com/compute/v1/projects/writer-prod/regions/us-central1/forwardingRules/prod-ids-ilb", "endpointIp": "10.3.0.5", "description": "prod ids endpoint", "severity": "HIGH", "threatExceptions": []string{"12345"}, "state": "READY", "trafficLogs": true}}})
		case "/v2/projects/writer-prod/locations/-/services":
			writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/services/api", "uid": "run-1", "uri": "https://api.run.app", "ingress": "INGRESS_TRAFFIC_ALL", "labels": map[string]string{"env": "prod"}, "template": map[string]any{"serviceAccount": "run@writer-prod.iam.gserviceaccount.com", "containers": []map[string]string{{"image": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc"}}, "vpcAccess": map[string]string{"connector": "projects/writer-prod/locations/us-central1/connectors/serverless"}}}}})
		case "/v2/projects/writer-prod/locations/-/functions":
			writeJSON(t, w, map[string]any{"functions": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/functions/ingest", "state": "ACTIVE", "environment": "GEN_2", "labels": map[string]string{"env": "prod"}, "serviceConfig": map[string]string{"serviceAccountEmail": "fn@writer-prod.iam.gserviceaccount.com", "uri": "https://ingest.cloudfunctions.net", "ingressSettings": "ALLOW_ALL", "vpcConnector": "projects/writer-prod/locations/us-central1/connectors/serverless"}}}})
		case "/sql/v1beta4/projects/writer-prod/instances":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"name": "prod-sql", "selfLink": "https://sqladmin.googleapis.com/sql/v1beta4/projects/writer-prod/instances/prod-sql", "region": "us-central1", "gceZone": "us-central1-a", "databaseVersion": "POSTGRES_15", "state": "RUNNABLE", "serviceAccountEmailAddress": "sql@writer-prod.iam.gserviceaccount.com", "settings": map[string]any{"userLabels": map[string]string{"env": "prod"}, "storageAutoResize": true, "deletionProtectionEnabled": true, "backupConfiguration": map[string]any{"enabled": true, "pointInTimeRecoveryEnabled": true, "startTime": "03:00"}, "ipConfiguration": map[string]any{"ipv4Enabled": true, "privateNetwork": "projects/writer-prod/global/networks/default", "authorizedNetworks": []map[string]string{{"name": "all", "value": "0.0.0.0/0"}}}}, "ipAddresses": []map[string]string{{"type": "PRIMARY", "ipAddress": "35.2.3.4"}, {"type": "PRIVATE", "ipAddress": "10.10.0.3"}}, "diskEncryptionConfiguration": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/sql"}}}})
		case "/storage/v1/b":
			if got := r.URL.Query().Get("project"); got != "writer-prod" {
				t.Fatalf("storage project = %q, want writer-prod", got)
			}
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data", "name": "data", "location": "US", "storageClass": "STANDARD", "labels": map[string]string{"env": "prod"}, "encryption": map[string]string{"defaultKmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/storage"}, "versioning": map[string]bool{"enabled": true}, "iamConfiguration": map[string]any{"uniformBucketLevelAccess": map[string]bool{"enabled": true}, "publicAccessPrevention": "enforced"}}}})
		case "/v1/projects/writer-prod/secrets":
			writeJSON(t, w, map[string]any{"secrets": []map[string]any{{"name": "projects/writer-prod/secrets/api-key", "labels": map[string]string{"env": "prod"}, "expireTime": "2027-04-23T00:00:00Z", "replication": map[string]any{"userManaged": map[string]any{"replicas": []map[string]any{{"location": "us-central1", "customerManagedEncryption": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/secrets"}}}}}, "rotation": map[string]string{"nextRotationTime": "2026-05-23T00:00:00Z", "rotationPeriod": "2592000s"}}}})
		case "/v1/projects/writer-prod/locations/us/keyRings/prod/cryptoKeys":
			writeJSON(t, w, map[string]any{"cryptoKeys": []map[string]any{{"name": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/app", "purpose": "ENCRYPT_DECRYPT", "nextRotationTime": "2026-05-23T00:00:00Z", "rotationPeriod": "2592000s", "labels": map[string]string{"env": "prod"}, "versionTemplate": map[string]string{"protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}, "primary": map[string]string{"name": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/app/cryptoKeyVersions/1", "state": "ENABLED", "protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}}})
		case "/v2/projects/writer-prod/sinks":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("logging sink pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"sinks": []map[string]any{{"name": "security-sink", "resourceName": "projects/writer-prod/sinks/security-sink", "description": "security export", "destination": "bigquery.googleapis.com/projects/writer-prod/datasets/security_logs", "filter": "severity>=ERROR", "disabled": false, "writerIdentity": "serviceAccount:writer-prod@gcp-sa-logging.iam.gserviceaccount.com", "includeChildren": false, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "exclusions": []map[string]any{{"name": "debug", "filter": "severity<ERROR", "disabled": false}}, "bigqueryOptions": map[string]bool{"usePartitionedTables": true, "usesTimestampColumnPartitioning": true}}}})
		case "/v1/projects/writer-prod/locations/-/repositories":
			writeJSON(t, w, map[string]any{"repositories": []map[string]any{{"name": "projects/writer-prod/locations/us/repositories/app", "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/artifacts", "labels": map[string]string{"env": "prod"}, "dockerConfig": map[string]bool{"immutableTags": true}}}})
		case "/v1/projects/writer-prod/locations/us/repositories/app/dockerImages":
			writeJSON(t, w, map[string]any{"dockerImages": []map[string]any{{"name": "projects/writer-prod/locations/us/repositories/app/dockerImages/us-docker.pkg.dev%2Fwriter-prod%2Fapp%2Fapi@sha256:abc", "uri": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc", "tags": []string{"latest", "prod"}, "imageSizeBytes": "12345", "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "uploadTime": "2026-04-23T00:00:00Z"}}})
		case "/v2/entries:list":
			writeJSON(t, w, map[string]any{"entries": []map[string]any{{"insertId": "audit-1", "timestamp": "2026-04-23T00:00:00Z", "protoPayload": map[string]any{"methodName": "SetIamPolicy", "serviceName": "cloudresourcemanager.googleapis.com", "resourceName": "projects/writer-prod", "authenticationInfo": map[string]any{"principalEmail": "admin@writer.com"}}, "resource": map[string]any{"type": "project", "labels": map[string]string{"project_id": "writer-prod"}}}}})
		default:
			http.NotFound(w, r)
		}
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
