package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/gcpcloud"
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
	pull, err := gcpcloud.PullFromRecords[string](nil, "next-page", nil)
	if err != nil {
		t.Fatalf("gcpcloud.PullFromRecords() error = %v", err)
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
		{family: familyAIDataset, kind: "gcp.aiplatform_dataset"},
		{family: familyAIEndpoint, kind: "gcp.aiplatform_endpoint"},
		{family: familyArtifactImage, config: map[string]string{"artifact_repository": "projects/writer-prod/locations/us/repositories/app"}, kind: "gcp.artifact_registry_image"},
		{family: familyArtifactRepo, kind: "gcp.artifact_registry_repository"},
		{family: familyBigQueryDataset, kind: "gcp.bigquery_dataset"},
		{family: familyBigQueryTable, kind: "gcp.bigquery_table"},
		{family: familyBigtableInstance, kind: "gcp.bigtable_instance"},
		{family: familyBigtableTable, kind: "gcp.bigtable_table"},
		{family: familyCertificateManagerCertificate, kind: "gcp.certificate_manager_certificate"},
		{family: familyCertificateManagerCertificateMap, kind: "gcp.certificate_manager_certificate_map"},
		{family: familyCertificateManagerCertificateMapEntry, kind: "gcp.certificate_manager_certificate_map_entry"},
		{family: familyCertificateManagerDNSAuthorization, kind: "gcp.certificate_manager_dns_authorization"},
		{family: familyServiceAcct, kind: "gcp.service_account"},
		{family: familyCloudFunction, kind: "gcp.cloud_function"},
		{family: familyCloudIDSEndpoint, kind: "gcp.cloud_ids_endpoint"},
		{family: familyCloudSchedulerJob, kind: "gcp.cloud_scheduler_job"},
		{family: familyCloudRunRevision, kind: "gcp.cloud_run_revision"},
		{family: familyCloudRunService, kind: "gcp.cloud_run_service"},
		{family: familyCloudSQLDatabase, kind: "gcp.cloud_sql_database"},
		{family: familyCloudSQLInstance, kind: "gcp.cloud_sql_instance"},
		{family: familyCloudSQLUser, kind: "gcp.cloud_sql_user"},
		{family: familyContainerRegistry, kind: "gcp.container_registry"},
		{family: familyContainerVuln, kind: "gcp.container_vulnerability"},
		{family: familyComputeBackendService, kind: "gcp.compute_backend_service"},
		{family: familyComputeAddress, kind: "gcp.compute_address"},
		{family: familyComputeBackendBucket, kind: "gcp.compute_backend_bucket"},
		{family: familyComputeDisk, kind: "gcp.compute_disk"},
		{family: familyComputeExternalVPNGateway, kind: "gcp.compute_external_vpn_gateway"},
		{family: familyComputeFirewall, kind: "gcp.compute_firewall"},
		{family: familyComputeForwardingRule, kind: "gcp.compute_forwarding_rule"},
		{family: familyComputeHealthCheck, kind: "gcp.compute_health_check"},
		{family: familyComputeInstance, kind: "gcp.compute_instance"},
		{family: familyComputeInstanceGroup, kind: "gcp.compute_instance_group"},
		{family: familyComputeInstanceGroupMgr, kind: "gcp.compute_instance_group_manager"},
		{family: familyComputeInstanceTemplate, kind: "gcp.compute_instance_template"},
		{family: familyComputeInterconnect, kind: "gcp.compute_interconnect"},
		{family: familyComputeInterconnectAttachment, kind: "gcp.compute_interconnect_attachment"},
		{family: familyComputeNetworkEndpointGroup, kind: "gcp.compute_network_endpoint_group"},
		{family: familyComputeNetworkFirewallPolicy, kind: "gcp.compute_network_firewall_policy"},
		{family: familyComputeNetwork, kind: "gcp.compute_network"},
		{family: familyComputePacketMirroring, kind: "gcp.compute_packet_mirroring"},
		{family: familyComputeRoute, kind: "gcp.compute_route"},
		{family: familyComputeRouter, kind: "gcp.compute_router"},
		{family: familyComputeSecurityPolicy, kind: "gcp.compute_security_policy"},
		{family: familyComputeSSLCertificate, kind: "gcp.compute_ssl_certificate"},
		{family: familyComputeSSLPolicy, kind: "gcp.compute_ssl_policy"},
		{family: familyComputeSubnetwork, kind: "gcp.compute_subnetwork"},
		{family: familyComputeTargetGRPCProxy, kind: "gcp.compute_target_grpc_proxy"},
		{family: familyComputeTargetHTTPProxy, kind: "gcp.compute_target_http_proxy"},
		{family: familyComputeTargetHTTPSProxy, kind: "gcp.compute_target_https_proxy"},
		{family: familyComputeTargetSSLProxy, kind: "gcp.compute_target_ssl_proxy"},
		{family: familyComputeTargetTCPProxy, kind: "gcp.compute_target_tcp_proxy"},
		{family: familyComputeTargetVPNGateway, kind: "gcp.compute_target_vpn_gateway"},
		{family: familyComputeURLMap, kind: "gcp.compute_url_map"},
		{family: familyComputeVPNGateway, kind: "gcp.compute_vpn_gateway"},
		{family: familyComputeVPNTunnel, kind: "gcp.compute_vpn_tunnel"},
		{family: familyDNSManagedZone, kind: "gcp.dns_managed_zone"},
		{family: familyDNSRecordSet, kind: "gcp.dns_record_set"},
		{family: familyGCSBucket, kind: "gcp.gcs_bucket"},
		{family: familyGCSObject, kind: "gcp.gcs_object"},
		{family: familyGKECluster, kind: "gcp.gke_cluster"},
		{family: familyGKENodePool, kind: "gcp.gke_node_pool"},
		{family: familyGroup, config: map[string]string{"customer_id": "C01"}, kind: "gcp.group"},
		{family: familyGroupMember, config: map[string]string{"group_key": "security@writer.com"}, kind: "gcp.group_membership"},
		{family: familyKMSKey, config: map[string]string{"location": "us", "key_ring": "prod"}, kind: "gcp.kms_key"},
		{family: familyLoggingMetric, kind: "gcp.logging_metric"},
		{family: familyLoggingSink, kind: "gcp.logging_project_sink"},
		{family: familyMonitoringAlertPolicy, kind: "gcp.monitoring_alert_policy"},
		{family: familyMonitoringNotificationChannel, kind: "gcp.monitoring_notification_channel"},
		{family: familyOrgPolicy, kind: "gcp.org_policy"},
		{family: familyPubSubSubscription, kind: "gcp.pubsub_subscription"},
		{family: familyPubSubTopic, kind: "gcp.pubsub_topic"},
		{family: familyResourceExposure, kind: "gcp.resource_exposure"},
		{family: familyResourceProject, kind: "gcp.resourcemanager_project"},
		{family: familyRoleAssign, kind: "gcp.iam_role_assignment"},
		{family: familyEffectivePermission, kind: "gcp.effective_permission"},
		{family: familySAImpersonation, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_impersonation"},
		{family: familySecret, kind: "gcp.secret_manager_secret"},
		{family: familySecretVersion, kind: "gcp.secret_manager_version"},
		{family: familySecurityCenterFinding, kind: "gcp.security_center_finding"},
		{family: familyAudit, kind: "gcp.audit"},
		{family: familyServiceUsageService, kind: "gcp.service_usage_service"},
		{family: familySpannerDatabase, kind: "gcp.spanner_database"},
		{family: familySpannerInstance, kind: "gcp.spanner_instance"},
		{family: familyVPCAccessConnector, kind: "gcp.vpc_access_connector"},
		{family: familyWorkloadIdentityPool, kind: "gcp.workload_identity_pool"},
		{family: familyWorkloadIdentityProvider, kind: "gcp.workload_identity_provider"},
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
		{family: familyAIDataset, config: map[string]string{"location": "us-central1"}, kind: "gcp.aiplatform_dataset", attr: "public", want: "true"},
		{family: familyAIEndpoint, config: map[string]string{"location": "us-central1"}, kind: "gcp.aiplatform_endpoint", attr: "deployed_models_count", want: "1"},
		{family: familyComputeInstance, kind: "gcp.compute_instance", attr: "service_account_email", want: "vm@writer-prod.iam.gserviceaccount.com"},
		{family: familyGKECluster, kind: "gcp.gke_cluster", attr: "network_tags", want: "gke"},
		{family: familyBigQueryDataset, kind: "gcp.bigquery_dataset", attr: "kms_key_name", want: "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/bq"},
		{family: familyBigQueryTable, kind: "gcp.bigquery_table", attr: "require_partition_filter", want: "true"},
		{family: familyBigtableInstance, kind: "gcp.bigtable_instance", attr: "state", want: "READY"},
		{family: familyBigtableTable, kind: "gcp.bigtable_table", attr: "deletion_protection", want: "true"},
		{family: familyCertificateManagerCertificate, kind: "gcp.certificate_manager_certificate", attr: "managed_state", want: "ACTIVE"},
		{family: familyCertificateManagerCertificateMap, kind: "gcp.certificate_manager_certificate_map", attr: "target_https_proxies", want: "prod-https-proxy"},
		{family: familyCertificateManagerCertificateMapEntry, kind: "gcp.certificate_manager_certificate_map_entry", attr: "hostname", want: "app.writer.example"},
		{family: familyCertificateManagerDNSAuthorization, kind: "gcp.certificate_manager_dns_authorization", attr: "dns_record_type", want: "CNAME"},
		{family: familyCloudIDSEndpoint, kind: "gcp.cloud_ids_endpoint", attr: "threat_log_routed", want: "true"},
		{family: familyCloudSchedulerJob, kind: "gcp.cloud_scheduler_job", attr: "runtime_identity", want: "scheduler@writer-prod.iam.gserviceaccount.com"},
		{family: familyCloudRunRevision, kind: "gcp.cloud_run_revision", attr: "runtime_identity", want: "run@writer-prod.iam.gserviceaccount.com"},
		{family: familyCloudRunService, kind: "gcp.cloud_run_service", attr: "internet_exposed", want: "true"},
		{family: familyCloudFunction, kind: "gcp.cloud_function", attr: "runtime_identity", want: "fn@writer-prod.iam.gserviceaccount.com"},
		{family: familyCloudSQLDatabase, kind: "gcp.cloud_sql_database", attr: "charset", want: "UTF8"},
		{family: familyCloudSQLInstance, kind: "gcp.cloud_sql_instance", attr: "backup_enabled", want: "true"},
		{family: familyCloudSQLUser, kind: "gcp.cloud_sql_user", attr: "host", want: "%"},
		{family: familyContainerRegistry, kind: "gcp.container_registry", attr: "iam_bindings_count", want: "1"},
		{family: familyContainerVuln, kind: "gcp.container_vulnerability", attr: "vulnerability_id", want: "CVE-2026-4242"},
		{family: familyComputeAddress, kind: "gcp.compute_address", attr: "internet_exposed", want: "true"},
		{family: familyComputeBackendBucket, kind: "gcp.compute_backend_bucket", attr: "edge_security_policy", want: "prod-edge-armor"},
		{family: familyComputeBackendService, kind: "gcp.compute_backend_service", attr: "health_checks_count", want: "1"},
		{family: familyComputeExternalVPNGateway, kind: "gcp.compute_external_vpn_gateway", attr: "interface_ips", want: "198.51.100.10"},
		{family: familyComputeHealthCheck, kind: "gcp.compute_health_check", attr: "request_path", want: "/healthz"},
		{family: familyComputeInstanceGroup, kind: "gcp.compute_instance_group", attr: "named_ports", want: "http:80"},
		{family: familyComputeInstanceGroupMgr, kind: "gcp.compute_instance_group_manager", attr: "instance_template", want: "prod-template"},
		{family: familyComputeInstanceTemplate, kind: "gcp.compute_instance_template", attr: "service_account_email", want: "vm@writer-prod.iam.gserviceaccount.com"},
		{family: familyComputeInterconnect, kind: "gcp.compute_interconnect", attr: "operational_status", want: "OS_ACTIVE"},
		{family: familyComputeInterconnectAttachment, kind: "gcp.compute_interconnect_attachment", attr: "bandwidth", want: "BPS_10G"},
		{family: familyComputeNetworkEndpointGroup, kind: "gcp.compute_network_endpoint_group", attr: "network_endpoint_type", want: "GCE_VM_IP_PORT"},
		{family: familyComputeNetworkFirewallPolicy, kind: "gcp.compute_network_firewall_policy", attr: "rule_actions", want: "allow"},
		{family: familyComputeNetwork, kind: "gcp.compute_network", attr: "routing_mode", want: "REGIONAL"},
		{family: familyComputePacketMirroring, kind: "gcp.compute_packet_mirroring", attr: "collector_ilb", want: "ids-ilb"},
		{family: familyComputeRoute, kind: "gcp.compute_route", attr: "internet_egress", want: "true"},
		{family: familyComputeRouter, kind: "gcp.compute_router", attr: "nats", want: "prod-nat"},
		{family: familyComputeSecurityPolicy, kind: "gcp.compute_security_policy", attr: "rules_count", want: "3"},
		{family: familyComputeSSLCertificate, kind: "gcp.compute_ssl_certificate", attr: "managed_status", want: "ACTIVE"},
		{family: familyComputeSSLPolicy, kind: "gcp.compute_ssl_policy", attr: "min_tls_version", want: "TLS_1_2"},
		{family: familyComputeSubnetwork, kind: "gcp.compute_subnetwork", attr: "ip_cidr_range", want: "10.0.0.0/24"},
		{family: familyComputeTargetGRPCProxy, kind: "gcp.compute_target_grpc_proxy", attr: "validate_for_proxyless", want: "true"},
		{family: familyComputeTargetHTTPProxy, kind: "gcp.compute_target_http_proxy", attr: "url_map", want: "prod-url-map"},
		{family: familyComputeTargetHTTPSProxy, kind: "gcp.compute_target_https_proxy", attr: "ssl_certificates", want: "prod-cert"},
		{family: familyComputeTargetSSLProxy, kind: "gcp.compute_target_ssl_proxy", attr: "ssl_policy", want: "modern"},
		{family: familyComputeTargetTCPProxy, kind: "gcp.compute_target_tcp_proxy", attr: "backend_service", want: "prod-tcp-backend"},
		{family: familyComputeTargetVPNGateway, kind: "gcp.compute_target_vpn_gateway", attr: "tunnels", want: "classic-tunnel"},
		{family: familyComputeURLMap, kind: "gcp.compute_url_map", attr: "backend_services", want: "prod-backend,api-backend,canary-backend"},
		{family: familyComputeVPNGateway, kind: "gcp.compute_vpn_gateway", attr: "interface_ips", want: "203.0.113.31"},
		{family: familyComputeVPNTunnel, kind: "gcp.compute_vpn_tunnel", attr: "router", want: "prod-router"},
		{family: familyComputeFirewall, kind: "gcp.compute_firewall", attr: "source_ranges", want: "0.0.0.0/0"},
		{family: familyComputeForwardingRule, kind: "gcp.compute_forwarding_rule", attr: "internet_exposed", want: "true"},
		{family: familyComputeDisk, kind: "gcp.compute_disk", attr: "disk_type", want: "pd-balanced"},
		{family: familyDNSManagedZone, kind: "gcp.dns_managed_zone", attr: "dnssec_enabled", want: "true"},
		{family: familyDNSRecordSet, kind: "gcp.dns_record_set", attr: "records_count", want: "1"},
		{family: familyGKENodePool, kind: "gcp.gke_node_pool", attr: "auto_upgrade", want: "true"},
		{family: familyGCSBucket, kind: "gcp.gcs_bucket", attr: "versioning_enabled", want: "true"},
		{family: familyGCSObject, kind: "gcp.gcs_object", attr: "content_findings", want: "pii,secret"},
		{family: familySecret, kind: "gcp.secret_manager_secret", attr: "rotation_enabled", want: "true"},
		{family: familySecretVersion, kind: "gcp.secret_manager_version", attr: "enabled", want: "true"},
		{family: familyKMSKey, config: map[string]string{"location": "us", "key_ring": "prod"}, kind: "gcp.kms_key", attr: "protection_level", want: "HSM"},
		{family: familyLoggingMetric, kind: "gcp.logging_metric", attr: "metric_kind", want: "DELTA"},
		{family: familyLoggingSink, kind: "gcp.logging_project_sink", attr: "exclusions_count", want: "1"},
		{family: familyMonitoringAlertPolicy, kind: "gcp.monitoring_alert_policy", attr: "severity", want: "CRITICAL"},
		{family: familyMonitoringNotificationChannel, kind: "gcp.monitoring_notification_channel", attr: "channel_type", want: "email"},
		{family: familyMonitoringNotificationChannel, kind: "gcp.monitoring_notification_channel", attr: "updated_by", want: "secops@writer.com"},
		{family: familyOrgPolicy, kind: "gcp.org_policy", attr: "constraint", want: "iam.disableServiceAccountKeyCreation"},
		{family: familyPubSubSubscription, kind: "gcp.pubsub_subscription", attr: "dead_letter_topic_name", want: "dead-letter"},
		{family: familyPubSubTopic, kind: "gcp.pubsub_topic", attr: "kms_key_name", want: "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/pubsub"},
		{family: familyResourceProject, kind: "gcp.resourcemanager_project", attr: "enabled_services_count", want: "2"},
		{family: familyArtifactRepo, kind: "gcp.artifact_registry_repository", attr: "immutable_tags", want: "true"},
		{family: familyArtifactImage, config: map[string]string{"artifact_repository": "projects/writer-prod/locations/us/repositories/app"}, kind: "gcp.artifact_registry_image", attr: "digest", want: "sha256:abc"},
		{family: familyServiceUsageService, kind: "gcp.service_usage_service", attr: "service_name", want: "bigquery.googleapis.com"},
		{family: familySpannerDatabase, kind: "gcp.spanner_database", attr: "drop_protection_enabled", want: "true"},
		{family: familySpannerInstance, kind: "gcp.spanner_instance", attr: "processing_units", want: "100"},
		{family: familyVPCAccessConnector, kind: "gcp.vpc_access_connector", attr: "ip_cidr_range", want: "10.8.0.0/28"},
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

func TestReadLiveGCSObjectPaginatesWithinBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/storage/v1/b":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data", "name": "data", "location": "US"}}})
		case "/storage/v1/b/data/o":
			if got := r.URL.Query().Get("maxResults"); got != "1" {
				t.Fatalf("storage object maxResults = %q, want 1", got)
			}
			if got := r.URL.Query().Get("projection"); got != "full" {
				t.Fatalf("storage object projection = %q, want full", got)
			}
			switch r.URL.Query().Get("pageToken") {
			case "":
				writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data/first.bin/1", "name": "first.bin", "bucket": "data", "generation": "1", "contentType": "application/octet-stream"}}, "nextPageToken": "objects-2"})
			case "objects-2":
				writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data/second.bin/2", "name": "second.bin", "bucket": "data", "generation": "2", "contentType": "application/octet-stream"}}})
			default:
				t.Fatalf("unexpected storage object pageToken %q", r.URL.Query().Get("pageToken"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyGCSObject,
		"per_page":   "1",
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyGCSObject, err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["object_name"]; got != "first.bin" {
		t.Fatalf("first object_name = %q, want first.bin", got)
	}
	if got := pull.Events[1].Attributes["object_name"]; got != "second.bin" {
		t.Fatalf("second object_name = %q, want second.bin", got)
	}
}

func TestReadLiveGCSObjectInspectsContentWithoutPersistingSample(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyGCSObject,
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyGCSObject, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["content_inspected"]; got != "true" {
		t.Fatalf("content_inspected = %q, want true", got)
	}
	if got := event.Attributes["content_findings"]; got != "pii,secret" {
		t.Fatalf("content_findings = %q, want pii,secret", got)
	}
	if got := event.Attributes["content_contains_secrets"]; got != "true" {
		t.Fatalf("content_contains_secrets = %q, want true", got)
	}
	if got := event.Attributes["content_inspection_truncated"]; got != "false" {
		t.Fatalf("content_inspection_truncated = %q, want false", got)
	}
	payload := string(event.Payload)
	if strings.Contains(payload, "abcdefghijklmnopqrstuvwxyz") || strings.Contains(payload, "admin@example.com") {
		t.Fatalf("payload persisted raw object content sample: %s", payload)
	}
}

func TestReadLiveCloudIDSEndpointPaginatesLogSinkEnrichment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/projects/writer-prod/locations/-/endpoints":
			if got := r.URL.Query().Get("pageSize"); got != "1" {
				t.Fatalf("cloud ids pageSize = %q, want 1", got)
			}
			writeJSON(t, w, map[string]any{"endpoints": []map[string]any{{
				"name":                   "projects/writer-prod/locations/us-central1-a/endpoints/prod-ids",
				"network":                "projects/writer-prod/global/networks/default",
				"endpointForwardingRule": "https://www.googleapis.com/compute/v1/projects/writer-prod/regions/us-central1/forwardingRules/prod-ids-ilb",
				"endpointIp":             "10.3.0.5",
				"severity":               "HIGH",
				"state":                  "READY",
				"trafficLogs":            true,
			}}})
		case "/v2/projects/writer-prod/sinks":
			if got := r.URL.Query().Get("pageSize"); got != "1" {
				t.Fatalf("logging sink pageSize = %q, want 1", got)
			}
			switch r.URL.Query().Get("pageToken") {
			case "":
				writeJSON(t, w, map[string]any{"sinks": []map[string]any{{
					"name":        "ids-threat-other-endpoint",
					"destination": "pubsub.googleapis.com/projects/writer-prod/topics/security-alerts",
					"filter":      `resource.labels.id="prod-ids-extra" AND logName="projects/writer-prod/logs/ids.googleapis.com%2Fthreat"`,
				}}, "nextPageToken": "sinks-2"})
			case "sinks-2":
				writeJSON(t, w, map[string]any{"sinks": []map[string]any{{
					"name":        "ids-threat",
					"destination": "pubsub.googleapis.com/projects/writer-prod/topics/security-alerts",
					"filter":      `resource.labels.id="prod-ids" AND logName="projects/writer-prod/logs/ids.googleapis.com%2Fthreat"`,
				}}})
			default:
				t.Fatalf("unexpected logging sink pageToken %q", r.URL.Query().Get("pageToken"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyCloudIDSEndpoint,
		"per_page":   "1",
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyCloudIDSEndpoint, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	attributes := pull.Events[0].Attributes
	if got := attributes["log_sinks_count"]; got != "1" {
		t.Fatalf("log_sinks_count = %q, want 1", got)
	}
	if got := attributes["threat_log_routed"]; got != "true" {
		t.Fatalf("threat_log_routed = %q, want true", got)
	}
	if got := attributes["traffic_log_routed"]; got != "false" {
		t.Fatalf("traffic_log_routed = %q, want false", got)
	}
	if got := attributes["notification_configured"]; got != "true" {
		t.Fatalf("notification_configured = %q, want true", got)
	}
}

func TestReadLiveResourceManagerProjectPaginatesEnrichment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/projects/writer-prod":
			writeJSON(t, w, map[string]any{"projectNumber": "123", "projectId": "writer-prod", "name": "Writer Prod", "lifecycleState": "ACTIVE"})
		case "/v1/projects/123/services":
			if got := r.URL.Query().Get("pageSize"); got != "1" {
				t.Fatalf("service usage pageSize = %q, want 1", got)
			}
			if got := r.URL.Query().Get("filter"); got != "state:ENABLED" {
				t.Fatalf("service usage filter = %q, want state:ENABLED", got)
			}
			switch r.URL.Query().Get("pageToken") {
			case "":
				writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/123/services/bigquery.googleapis.com", "state": "ENABLED", "config": map[string]string{"name": "bigquery.googleapis.com"}}}, "nextPageToken": "services-2"})
			case "services-2":
				writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/123/services/aiplatform.googleapis.com", "state": "ENABLED", "config": map[string]string{"name": "aiplatform.googleapis.com"}}}})
			default:
				t.Fatalf("unexpected service usage pageToken %q", r.URL.Query().Get("pageToken"))
			}
		case "/v2/projects/writer-prod/policies":
			if got := r.URL.Query().Get("pageSize"); got != "1" {
				t.Fatalf("org policy pageSize = %q, want 1", got)
			}
			switch r.URL.Query().Get("pageToken") {
			case "":
				enforce := true
				writeJSON(t, w, map[string]any{"policies": []map[string]any{{"name": "projects/writer-prod/policies/iam.disableServiceAccountKeyCreation", "spec": map[string]any{"rules": []map[string]any{{"enforce": enforce}}}}}, "nextPageToken": "policies-2"})
			case "policies-2":
				writeJSON(t, w, map[string]any{"policies": []map[string]any{{"name": "projects/writer-prod/policies/constraints/storage.publicAccessPrevention", "spec": map[string]any{"rules": []map[string]any{{"denyAll": true}}}}}})
			default:
				t.Fatalf("unexpected org policy pageToken %q", r.URL.Query().Get("pageToken"))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyResourceProject,
		"per_page":   "1",
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyResourceProject, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["enabled_services_count"]; got != "2" {
		t.Fatalf("enabled_services_count = %q, want 2", got)
	}
	if got := pull.Events[0].Attributes["org_policies_count"]; got != "2" {
		t.Fatalf("org_policies_count = %q, want 2", got)
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
		{family: familyAIDataset, path: "/v1/projects/writer-prod/locations/-/datasets"},
		{family: familyAIEndpoint, path: "/v1/projects/writer-prod/locations/-/endpoints"},
		{family: familyBigQueryDataset, path: "/bigquery/v2/projects/writer-prod/datasets"},
		{family: familyBigtableInstance, path: "/v2/projects/writer-prod/instances"},
		{family: familyCertificateManagerCertificate, path: "/v1/projects/writer-prod/locations/-/certificates"},
		{family: familyCertificateManagerCertificateMap, path: "/v1/projects/writer-prod/locations/-/certificateMaps"},
		{family: familyCertificateManagerCertificateMapEntry, path: "/v1/projects/writer-prod/locations/-/certificateMaps"},
		{family: familyCertificateManagerDNSAuthorization, path: "/v1/projects/writer-prod/locations/-/dnsAuthorizations"},
		{family: familyGKECluster, path: "/v1/projects/writer-prod/locations/-/clusters"},
		{family: familyCloudIDSEndpoint, path: "/v1/projects/writer-prod/locations/-/endpoints"},
		{family: familyCloudRunService, path: "/v2/projects/writer-prod/locations/-/services"},
		{family: familyCloudFunction, path: "/v2/projects/writer-prod/locations/-/functions"},
		{family: familyContainerVuln, path: "/v1/projects/writer-prod/occurrences"},
		{family: familyDNSManagedZone, path: "/dns/v1/projects/writer-prod/managedZones"},
		{family: familyLoggingMetric, path: "/v2/projects/writer-prod/metrics"},
		{family: familyMonitoringAlertPolicy, path: "/v3/projects/writer-prod/alertPolicies"},
		{family: familyMonitoringNotificationChannel, path: "/v3/projects/writer-prod/notificationChannels"},
		{family: familySecret, path: "/v1/projects/writer-prod/secrets"},
		{family: familySecurityCenterFinding, path: "/v2/projects/writer-prod/sources/-/findings"},
		{family: familySpannerInstance, path: "/v1/projects/writer-prod/instances"},
		{family: familyVPCAccessConnector, path: "/v1/projects/writer-prod/locations/-/connectors"},
		{family: familyWorkloadIdentityPool, path: "/v1/projects/writer-prod/locations/global/workloadIdentityPools"},
		{family: familyWorkloadIdentityProvider, path: "/v1/projects/writer-prod/locations/global/workloadIdentityPools"},
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

func TestReadLiveGCPSecurityCoveragePreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		kind   string
		attr   string
		want   string
	}{
		{family: familySecurityCenterFinding, kind: "gcp.security_center_finding", attr: "severity", want: "HIGH"},
		{family: familyWorkloadIdentityPool, kind: "gcp.workload_identity_pool", attr: "pool_id", want: "github"},
		{family: familyWorkloadIdentityProvider, kind: "gcp.workload_identity_provider", attr: "provider_type", want: "oidc"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url":   server.URL,
				"family":     tt.family,
				"project_id": "writer-prod",
				"token":      "test-token",
			}), nil)
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

func TestReadLiveGCPWorkloadIdentityProviderPropagatesProviderErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/projects/writer-prod/locations/global/workloadIdentityPools":
			writeJSON(t, w, map[string]any{"workloadIdentityPools": []map[string]any{{"name": "projects/writer-prod/locations/global/workloadIdentityPools/github"}}})
		case "/v1/projects/writer-prod/locations/global/workloadIdentityPools/github/providers":
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(t, w, map[string]any{"error": map[string]any{"message": "provider backend unavailable"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":   server.URL,
		"family":     familyWorkloadIdentityProvider,
		"project_id": "writer-prod",
		"token":      "test-token",
	}), nil)
	if err == nil {
		t.Fatal("Read(workload_identity_provider) error = nil, want provider fetch error")
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
		case "/v1/projects/writer-prod/locations/global/workloadIdentityPools":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("workload identity pools pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"workloadIdentityPools": []map[string]any{{"name": "projects/writer-prod/locations/global/workloadIdentityPools/github", "displayName": "GitHub Actions", "description": "GitHub workload identities", "state": "ACTIVE", "disabled": false}}})
		case "/v1/projects/writer-prod/locations/global/workloadIdentityPools/github/providers":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("workload identity providers pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"workloadIdentityPoolProviders": []map[string]any{{"name": "projects/writer-prod/locations/global/workloadIdentityPools/github/providers/actions", "displayName": "GitHub Actions OIDC", "state": "ACTIVE", "disabled": false, "attributeMapping": map[string]string{"google.subject": "assertion.sub", "attribute.repository": "assertion.repository"}, "attributeCondition": `assertion.repository_owner=="writer"`, "oidc": map[string]any{"issuerUri": "https://token.actions.githubusercontent.com", "allowedAudiences": []string{"https://github.com/writer"}}}}})
		case "/compute/v1/projects/writer-prod/global/networks":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "net-1", "name": "default", "selfLink": "projects/writer-prod/global/networks/default", "description": "default network", "autoCreateSubnetworks": false, "routingConfig": map[string]string{"routingMode": "REGIONAL"}, "labels": map[string]string{"env": "prod"}}}})
		case "/compute/v1/projects/writer-prod/global/routes":
			requireQuery(t, r, "maxResults", "10", "compute routes")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "route-1", "name": "default-route-internet", "selfLink": "projects/writer-prod/global/routes/default-route-internet", "description": "default internet route", "network": "projects/writer-prod/global/networks/default", "destRange": "0.0.0.0/0", "priority": 1000, "tags": []string{"web"}, "nextHopGateway": "projects/writer-prod/global/gateways/default-internet-gateway", "routeType": "STATIC", "routeStatus": "ACTIVE", "creationTimestamp": "2026-04-23T00:00:00Z"}}})
		case "/compute/v1/projects/writer-prod/global/firewalls":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "fw-1", "name": "allow-web", "network": "global/networks/default", "direction": "INGRESS", "sourceRanges": []string{"0.0.0.0/0"}, "allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/forwardingRules":
			requireQuery(t, r, "maxResults", "10", "forwarding rules")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"forwardingRules": []map[string]any{{"id": "fr-1", "name": "prod-https", "selfLink": "projects/writer-prod/regions/us-central1/forwardingRules/prod-https", "description": "prod https frontend", "region": "projects/writer-prod/regions/us-central1", "IPAddress": "203.0.113.20", "IPProtocol": "TCP", "ipVersion": "IPV4", "loadBalancingScheme": "EXTERNAL_MANAGED", "portRange": "443-443", "ports": []string{"443"}, "networkTier": "PREMIUM", "target": "projects/writer-prod/regions/us-central1/targetHttpsProxies/prod-https-proxy", "network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default", "labels": map[string]string{"env": "prod"}}}}}})
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
		case "/v1/projects/writer-prod/locations/us-central1/datasets":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("vertex datasets pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"datasets": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/datasets/123", "displayName": "training", "metadataSchemaUri": "gs://google-cloud-aiplatform/schema/dataset/metadata/image_1.0.0.yaml", "labels": map[string]string{"env": "prod"}, "encryptionSpec": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/vertex"}, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z"}}})
		case "/v1/projects/writer-prod/locations/us-central1/datasets/123:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/aiplatform.viewer", "members": []string{"allUsers"}}, {"role": "roles/aiplatform.admin", "members": []string{"user:ml-admin@writer.com"}}}})
		case "/v1/projects/writer-prod/locations/us-central1/endpoints":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("vertex endpoints pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"endpoints": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/endpoints/456", "displayName": "prod-model", "labels": map[string]string{"env": "prod"}, "network": "projects/writer-prod/global/networks/default", "privateServiceConnectConfig": map[string]any{"enablePrivateServiceConnect": true, "projectAllowlist": []string{"writer-prod"}}, "deployedModels": []map[string]any{{"id": "deployed-1", "model": "projects/writer-prod/locations/us-central1/models/789", "displayName": "classifier", "serviceAccount": "vertex@writer-prod.iam.gserviceaccount.com", "enableAccessLogging": true, "enableContainerLogging": true, "machineSpec": map[string]any{"machineType": "n1-standard-4"}}}, "trafficSplit": map[string]int{"deployed-1": 100}, "encryptionSpec": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/vertex"}, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z"}}})
		case "/v1/projects/writer-prod/locations/us-central1/endpoints/456:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/aiplatform.user", "members": []string{"serviceAccount:vertex@writer-prod.iam.gserviceaccount.com"}}}})
		case "/bigquery/v2/projects/writer-prod/datasets":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("bigquery maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"datasets": []map[string]any{{"id": "writer-prod:analytics", "datasetReference": map[string]string{"projectId": "writer-prod", "datasetId": "analytics"}, "friendlyName": "Analytics", "location": "US", "labels": map[string]string{"env": "prod"}}}})
		case "/bigquery/v2/projects/writer-prod/datasets/analytics":
			writeJSON(t, w, map[string]any{"id": "writer-prod:analytics", "selfLink": "https://bigquery.googleapis.com/bigquery/v2/projects/writer-prod/datasets/analytics", "datasetReference": map[string]string{"projectId": "writer-prod", "datasetId": "analytics"}, "friendlyName": "Analytics", "description": "prod analytics dataset", "location": "US", "labels": map[string]string{"env": "prod"}, "access": []map[string]string{{"role": "READER", "specialGroup": "projectReaders"}, {"role": "OWNER", "userByEmail": "data-owner@writer.com"}}, "defaultEncryptionConfiguration": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/bq"}, "creationTime": "1770000000000", "lastModifiedTime": "1770003600000"})
		case "/bigquery/v2/projects/writer-prod/datasets/analytics/tables":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("bigquery table maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"tables": []map[string]any{{"id": "writer-prod:analytics.events", "tableReference": map[string]string{"projectId": "writer-prod", "datasetId": "analytics", "tableId": "events"}, "type": "TABLE", "labels": map[string]string{"env": "prod"}}}})
		case "/bigquery/v2/projects/writer-prod/datasets/analytics/tables/events":
			writeJSON(t, w, map[string]any{"id": "writer-prod:analytics.events", "selfLink": "https://bigquery.googleapis.com/bigquery/v2/projects/writer-prod/datasets/analytics/tables/events", "tableReference": map[string]string{"projectId": "writer-prod", "datasetId": "analytics", "tableId": "events"}, "friendlyName": "Events", "description": "prod event table", "type": "TABLE", "labels": map[string]string{"env": "prod"}, "schema": map[string]any{"fields": []map[string]string{{"name": "event_id", "type": "STRING"}}}, "timePartitioning": map[string]any{"type": "DAY", "field": "event_date", "expirationMs": "7776000000", "requirePartitionFilter": true}, "clustering": map[string]any{"fields": []string{"tenant_id", "event_type"}}, "encryptionConfiguration": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/bq"}, "creationTime": "1770000000000", "lastModifiedTime": "1770003600000", "expirationTime": "1800000000000", "numBytes": "4096", "numRows": "42"})
		case "/v2/projects/writer-prod/instances":
			writeJSON(t, w, map[string]any{"instances": []map[string]any{{"name": "projects/writer-prod/instances/prod-bt", "displayName": "prod-bt", "state": "READY", "type": "PRODUCTION", "labels": map[string]string{"env": "prod"}, "createTime": "2026-04-23T00:00:00Z", "satisfiesPzs": true}}})
		case "/v2/projects/writer-prod/instances/prod-bt/tables":
			if got := r.URL.Query().Get("view"); got != "FULL" {
				t.Fatalf("bigtable table view = %q, want FULL", got)
			}
			writeJSON(t, w, map[string]any{"tables": []map[string]any{{"name": "projects/writer-prod/instances/prod-bt/tables/events", "clusterStates": map[string]any{"prod-bt-c1": map[string]string{"replicationState": "READY"}}, "columnFamilies": map[string]any{"cf1": map[string]any{"gcRule": map[string]any{"maxNumVersions": 3}}}, "granularity": "MILLIS", "deletionProtection": true, "changeStreamConfig": map[string]string{"retentionPeriod": "604800s"}}}})
		case "/v1/projects/writer-prod/locations/-/certificates":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("certificate manager certificates pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"certificates": []map[string]any{{
				"name":        "projects/writer-prod/locations/global/certificates/prod-cert",
				"description": "prod managed certificate",
				"labels":      map[string]string{"env": "prod"},
				"managed": map[string]any{
					"domains":           []string{"app.writer.example"},
					"dnsAuthorizations": []string{"projects/writer-prod/locations/global/dnsAuthorizations/app-writer-example"},
					"state":             "ACTIVE",
					"authorizationAttemptInfo": []map[string]string{{
						"domain": "app.writer.example",
						"state":  "AUTHORIZED",
					}},
				},
				"sanDnsnames": []string{"app.writer.example"},
				"expireTime":  "2026-12-31T23:59:59Z",
				"scope":       "DEFAULT",
				"usedBy":      []map[string]string{{"name": "//certificatemanager.googleapis.com/projects/writer-prod/locations/global/certificateMaps/prod-map/certificateMapEntries/app"}},
				"createTime":  "2026-04-23T00:00:00Z",
				"updateTime":  "2026-04-24T00:00:00Z",
			}}})
		case "/v1/projects/writer-prod/locations/-/certificateMaps":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("certificate manager maps pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"certificateMaps": []map[string]any{{
				"name":        "projects/writer-prod/locations/global/certificateMaps/prod-map",
				"description": "prod certificate map",
				"labels":      map[string]string{"env": "prod"},
				"gclbTargets": []map[string]any{{
					"targetHttpsProxy": "//compute.googleapis.com/projects/writer-prod/global/targetHttpsProxies/prod-https-proxy",
					"ipConfigs":        []map[string]any{{"ipAddress": "203.0.113.20", "ports": []int{443}}},
				}},
				"createTime": "2026-04-23T00:00:00Z",
				"updateTime": "2026-04-24T00:00:00Z",
			}}})
		case "/v1/projects/writer-prod/locations/global/certificateMaps/prod-map/certificateMapEntries":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("certificate manager map entries pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"certificateMapEntries": []map[string]any{{
				"name":         "projects/writer-prod/locations/global/certificateMaps/prod-map/certificateMapEntries/app",
				"description":  "app hostname certificate",
				"labels":       map[string]string{"env": "prod"},
				"hostname":     "app.writer.example",
				"certificates": []string{"projects/writer-prod/locations/global/certificates/prod-cert"},
				"state":        "ACTIVE",
				"createTime":   "2026-04-23T00:00:00Z",
				"updateTime":   "2026-04-24T00:00:00Z",
			}}})
		case "/v1/projects/writer-prod/locations/-/dnsAuthorizations":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("certificate manager dns authorizations pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"dnsAuthorizations": []map[string]any{{
				"name":        "projects/writer-prod/locations/global/dnsAuthorizations/app-writer-example",
				"description": "app domain authorization",
				"labels":      map[string]string{"env": "prod"},
				"domain":      "app.writer.example",
				"dnsResourceRecord": map[string]string{
					"name": "_acme-challenge.app.writer.example.",
					"type": "CNAME",
					"data": "token.authorize.certificatemanager.goog.",
				},
				"type":       "FIXED_RECORD",
				"createTime": "2026-04-23T00:00:00Z",
				"updateTime": "2026-04-24T00:00:00Z",
			}}})
		case "/compute/v1/projects/writer-prod/aggregated/instances":
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"instances": []map[string]any{{"id": "123456789", "name": "web-1", "zone": "projects/writer-prod/zones/us-central1-a", "machineType": "projects/writer-prod/zones/us-central1-a/machineTypes/e2-medium", "status": "RUNNING", "labels": map[string]string{"env": "prod"}, "tags": map[string]any{"items": []string{"web"}}, "networkInterfaces": []map[string]any{{"network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default", "networkIP": "10.0.0.5", "accessConfigs": []map[string]any{{"type": "ONE_TO_ONE_NAT", "natIP": "34.1.2.3"}}}}, "serviceAccounts": []map[string]any{{"email": "vm@writer-prod.iam.gserviceaccount.com"}}, "disks": []map[string]any{{"boot": true, "diskEncryptionKey": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/vm"}}}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/instanceGroups":
			requireQuery(t, r, "maxResults", "10", "instance groups")
			requireQuery(t, r, "returnPartialSuccess", "true", "instance groups")
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"instanceGroups": []map[string]any{{
				"id": "ig-1", "name": "prod-mig", "selfLink": "projects/writer-prod/zones/us-central1-a/instanceGroups/prod-mig", "description": "prod backend group",
				"zone": "projects/writer-prod/zones/us-central1-a", "network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default",
				"namedPorts": []map[string]any{{"name": "http", "port": 80}}, "size": 3,
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/instanceGroupManagers":
			requireQuery(t, r, "maxResults", "10", "instance group managers")
			requireQuery(t, r, "returnPartialSuccess", "true", "instance group managers")
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"instanceGroupManagers": []map[string]any{{
				"id": "igm-1", "name": "prod-mig", "selfLink": "projects/writer-prod/zones/us-central1-a/instanceGroupManagers/prod-mig", "description": "prod managed backend",
				"zone": "projects/writer-prod/zones/us-central1-a", "baseInstanceName": "prod-web", "instanceTemplate": "projects/writer-prod/global/instanceTemplates/prod-template", "targetSize": 3,
				"namedPorts": []map[string]any{{"name": "http", "port": 80}}, "autoHealingPolicies": []map[string]any{{"healthCheck": "projects/writer-prod/global/healthChecks/prod-hc", "initialDelaySec": 60}},
				"currentActions": map[string]any{"none": 3}, "status": map[string]any{"isStable": true, "versionTarget": map[string]bool{"isReached": true}},
				"updatePolicy": map[string]string{"type": "PROACTIVE", "minimalAction": "REPLACE", "replacementMethod": "SUBSTITUTE"}, "distributionPolicy": map[string]any{"zones": []map[string]string{{"zone": "projects/writer-prod/zones/us-central1-a"}}},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/instanceTemplates":
			requireQuery(t, r, "maxResults", "10", "instance templates")
			requireQuery(t, r, "returnPartialSuccess", "true", "instance templates")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"instanceTemplates": []map[string]any{{
				"id": "it-1", "name": "prod-template", "selfLink": "projects/writer-prod/global/instanceTemplates/prod-template", "description": "prod backend template",
				"properties": map[string]any{
					"machineType": "e2-medium", "labels": map[string]string{"env": "prod"}, "tags": map[string]any{"items": []string{"web"}},
					"networkInterfaces": []map[string]any{{"network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default", "accessConfigs": []map[string]any{{"type": "ONE_TO_ONE_NAT"}}}},
					"serviceAccounts":   []map[string]any{{"email": "vm@writer-prod.iam.gserviceaccount.com"}}, "disks": []map[string]any{{"boot": true, "diskEncryptionKey": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/vm"}}},
					"shieldedInstanceConfig": map[string]bool{"enableSecureBoot": true, "enableIntegrityMonitoring": true},
				},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/networkEndpointGroups":
			requireQuery(t, r, "maxResults", "10", "network endpoint groups")
			requireQuery(t, r, "returnPartialSuccess", "true", "network endpoint groups")
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"networkEndpointGroups": []map[string]any{{
				"id": "neg-1", "name": "prod-neg", "selfLink": "projects/writer-prod/zones/us-central1-a/networkEndpointGroups/prod-neg", "description": "prod backend endpoints",
				"zone": "projects/writer-prod/zones/us-central1-a", "network": "projects/writer-prod/global/networks/default", "subnetwork": "projects/writer-prod/regions/us-central1/subnetworks/default",
				"networkEndpointType": "GCE_VM_IP_PORT", "defaultPort": 8080, "size": 3, "annotations": map[string]string{"env": "prod"},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/interconnectAttachments":
			requireQuery(t, r, "maxResults", "10", "interconnect attachments")
			requireQuery(t, r, "returnPartialSuccess", "true", "interconnect attachments")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"interconnectAttachments": []map[string]any{{
				"id": "ica-1", "name": "prod-vlan", "selfLink": "projects/writer-prod/regions/us-central1/interconnectAttachments/prod-vlan", "description": "prod dedicated interconnect",
				"region": "projects/writer-prod/regions/us-central1", "router": "projects/writer-prod/regions/us-central1/routers/prod-router", "interconnect": "projects/writer-prod/global/interconnects/prod-interconnect",
				"type": "DEDICATED", "adminEnabled": true, "operationalStatus": "OS_ACTIVE", "state": "ACTIVE", "bandwidth": "BPS_10G", "edgeAvailabilityDomain": "AVAILABILITY_DOMAIN_1",
				"vlanTag8021q": 1234, "mtu": 1500, "encryption": "IPSEC", "cloudRouterIpAddress": "169.254.10.1/29", "customerRouterIpAddress": "169.254.10.2/29",
				"ipsecInternalAddresses": []string{"projects/writer-prod/regions/us-central1/addresses/prod-ipsec"}, "satisfiesPzs": true, "labels": map[string]string{"env": "prod"},
			}}}}})
		case "/compute/v1/projects/writer-prod/global/externalVpnGateways":
			requireQuery(t, r, "maxResults", "10", "external vpn gateways")
			requireQuery(t, r, "returnPartialSuccess", "true", "external vpn gateways")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{
				"id": "evg-1", "name": "onprem", "selfLink": "projects/writer-prod/global/externalVpnGateways/onprem", "description": "onprem peer gateway",
				"redundancyType": "SINGLE_IP_INTERNALLY_REDUNDANT", "interfaces": []map[string]any{{"id": 0, "ipAddress": "198.51.100.10"}}, "labels": map[string]string{"env": "prod"},
			}}})
		case "/compute/v1/projects/writer-prod/global/interconnects":
			requireQuery(t, r, "maxResults", "10", "interconnects")
			requireQuery(t, r, "returnPartialSuccess", "true", "interconnects")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{
				"id": "ic-1", "name": "prod-interconnect", "selfLink": "projects/writer-prod/global/interconnects/prod-interconnect", "description": "prod dedicated interconnect",
				"location": "projects/writer-prod/global/interconnectLocations/iad-zone1-1", "linkType": "LINK_TYPE_ETHERNET_10G_LR", "interconnectType": "DEDICATED",
				"requestedLinkCount": 1, "provisionedLinkCount": 1, "adminEnabled": true, "operationalStatus": "OS_ACTIVE", "state": "ACTIVE",
				"interconnectAttachments": []string{"projects/writer-prod/regions/us-central1/interconnectAttachments/prod-vlan"}, "macsecEnabled": true, "satisfiesPzs": true, "labels": map[string]string{"env": "prod"},
			}}})
		case "/compute/v1/projects/writer-prod/aggregated/routers":
			requireQuery(t, r, "maxResults", "10", "routers")
			requireQuery(t, r, "returnPartialSuccess", "true", "routers")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"routers": []map[string]any{{
				"id": "router-1", "name": "prod-router", "selfLink": "projects/writer-prod/regions/us-central1/routers/prod-router", "description": "prod hybrid router",
				"region": "projects/writer-prod/regions/us-central1", "network": "projects/writer-prod/global/networks/default",
				"bgp":                         map[string]any{"asn": 64514, "advertiseMode": "CUSTOM", "advertisedGroups": []string{"ALL_SUBNETS"}, "keepaliveInterval": 20},
				"interfaces":                  []map[string]any{{"name": "if-vlan", "linkedInterconnectAttachment": "projects/writer-prod/regions/us-central1/interconnectAttachments/prod-vlan"}, {"name": "if-vpn", "linkedVpnTunnel": "projects/writer-prod/regions/us-central1/vpnTunnels/ha-tunnel"}},
				"bgpPeers":                    []map[string]any{{"name": "peer-onprem", "interfaceName": "if-vlan", "peerAsn": 65001, "peerIpAddress": "169.254.10.2", "ipAddress": "169.254.10.1", "advertiseMode": "DEFAULT"}},
				"nats":                        []map[string]any{{"name": "prod-nat", "natIpAllocateOption": "MANUAL_ONLY", "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS", "natIps": []string{"projects/writer-prod/regions/us-central1/addresses/prod-nat-ip"}, "logConfig": map[string]any{"enable": true, "filter": "ALL"}}},
				"encryptedInterconnectRouter": true,
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/firewallPolicies":
			requireQuery(t, r, "maxResults", "10", "network firewall policies")
			requireQuery(t, r, "returnPartialSuccess", "true", "network firewall policies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"firewallPolicies": []map[string]any{{
				"id": "nfp-1", "name": "prod-network-policy", "selfLink": "projects/writer-prod/global/firewallPolicies/prod-network-policy", "description": "prod network firewall policy",
				"displayName": "Prod network firewall", "shortName": "prod-network-policy", "policyType": "NETWORK", "ruleTupleCount": 1,
				"rules":        []map[string]any{{"ruleName": "allow-web", "priority": 1000, "action": "allow", "direction": "INGRESS", "enableLogging": true, "targetResources": []string{"projects/writer-prod/global/networks/default"}, "match": map[string]any{"srcIpRanges": []string{"10.0.0.0/8"}, "layer4Configs": []map[string]any{{"ipProtocol": "tcp", "ports": []string{"443"}}}}}},
				"associations": []map[string]any{{"name": "default", "attachmentTarget": "projects/writer-prod/global/networks/default"}},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/packetMirrorings":
			requireQuery(t, r, "maxResults", "10", "packet mirrorings")
			requireQuery(t, r, "returnPartialSuccess", "true", "packet mirrorings")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"packetMirrorings": []map[string]any{{
				"id": "pm-1", "name": "prod-mirror", "selfLink": "projects/writer-prod/regions/us-central1/packetMirrorings/prod-mirror", "description": "mirror prod traffic to ids",
				"region": "projects/writer-prod/regions/us-central1", "network": map[string]string{"url": "projects/writer-prod/global/networks/default"}, "priority": 100,
				"collectorIlb":      map[string]string{"url": "projects/writer-prod/regions/us-central1/forwardingRules/ids-ilb"},
				"mirroredResources": map[string]any{"subnetworks": []map[string]string{{"url": "projects/writer-prod/regions/us-central1/subnetworks/default"}}, "instances": []map[string]string{{"url": "projects/writer-prod/zones/us-central1-a/instances/web-1"}}, "tags": []string{"web"}},
				"filter":            map[string]any{"cidrRanges": []string{"10.0.0.0/24"}, "IPProtocols": []string{"tcp"}, "direction": "INGRESS"}, "enable": "TRUE",
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/targetVpnGateways":
			requireQuery(t, r, "maxResults", "10", "target vpn gateways")
			requireQuery(t, r, "returnPartialSuccess", "true", "target vpn gateways")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"targetVpnGateways": []map[string]any{{
				"id": "tvg-1", "name": "classic-vpn", "selfLink": "projects/writer-prod/regions/us-central1/targetVpnGateways/classic-vpn", "description": "classic vpn gateway",
				"region": "projects/writer-prod/regions/us-central1", "network": "projects/writer-prod/global/networks/default", "status": "READY",
				"tunnels": []string{"projects/writer-prod/regions/us-central1/vpnTunnels/classic-tunnel"}, "forwardingRules": []string{"projects/writer-prod/regions/us-central1/forwardingRules/classic-vpn-esp"},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/vpnGateways":
			requireQuery(t, r, "maxResults", "10", "vpn gateways")
			requireQuery(t, r, "returnPartialSuccess", "true", "vpn gateways")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"vpnGateways": []map[string]any{{
				"id": "vgw-1", "name": "ha-vpn", "selfLink": "projects/writer-prod/regions/us-central1/vpnGateways/ha-vpn", "description": "ha vpn gateway",
				"region": "projects/writer-prod/regions/us-central1", "network": "projects/writer-prod/global/networks/default", "gatewayIpVersion": "IPV4", "stackType": "IPV4_ONLY",
				"vpnInterfaces": []map[string]any{{"id": 0, "ipAddress": "203.0.113.31"}},
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/vpnTunnels":
			requireQuery(t, r, "maxResults", "10", "vpn tunnels")
			requireQuery(t, r, "returnPartialSuccess", "true", "vpn tunnels")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"vpnTunnels": []map[string]any{{
				"id": "tunnel-1", "name": "ha-tunnel", "selfLink": "projects/writer-prod/regions/us-central1/vpnTunnels/ha-tunnel", "description": "ha vpn tunnel",
				"region": "projects/writer-prod/regions/us-central1", "status": "ESTABLISHED", "detailedStatus": "Tunnel is up and running.", "ikeVersion": 2,
				"peerIp": "198.51.100.10", "peerExternalGateway": "projects/writer-prod/global/externalVpnGateways/onprem", "peerExternalGatewayInterface": 0,
				"vpnGateway": "projects/writer-prod/regions/us-central1/vpnGateways/ha-vpn", "vpnGatewayInterface": 0, "router": "projects/writer-prod/regions/us-central1/routers/prod-router",
				"localTrafficSelector": []string{"10.0.0.0/24"}, "remoteTrafficSelector": []string{"172.16.0.0/16"}, "sharedSecretHash": "hash",
			}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/backendServices":
			requireQuery(t, r, "maxResults", "10", "backend services")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"backendServices": []map[string]any{{"id": "bs-1", "name": "prod-backend", "selfLink": "projects/writer-prod/global/backendServices/prod-backend", "description": "prod https backend", "protocol": "HTTPS", "portName": "https", "loadBalancingScheme": "EXTERNAL_MANAGED", "sessionAffinity": "NONE", "localityLbPolicy": "ROUND_ROBIN", "timeoutSec": 30, "enableCDN": true, "healthChecks": []string{"projects/writer-prod/global/healthChecks/prod-hc"}, "backends": []map[string]any{{"group": "projects/writer-prod/zones/us-central1-a/instanceGroups/prod-mig", "balancingMode": "UTILIZATION", "capacityScaler": 1.0, "maxUtilization": 0.8}}, "connectionDraining": map[string]int{"drainingTimeoutSec": 300}, "logConfig": map[string]any{"enable": true, "sampleRate": 1.0}, "iap": map[string]bool{"enabled": true}, "securityPolicy": "projects/writer-prod/global/securityPolicies/prod-armor", "network": "projects/writer-prod/global/networks/default", "customRequestHeaders": []string{"X-Forwarded-Proto:{client_protocol}"}, "labels": map[string]string{"env": "prod"}}}}}})
		case "/compute/v1/projects/writer-prod/global/backendBuckets":
			requireQuery(t, r, "maxResults", "10", "backend buckets")
			requireQuery(t, r, "returnPartialSuccess", "true", "backend buckets")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "bb-1", "name": "prod-static-bucket", "selfLink": "projects/writer-prod/global/backendBuckets/prod-static-bucket", "description": "prod static assets backend", "bucketName": "writer-prod-static", "enableCdn": true, "cdnPolicy": map[string]any{"signedUrlKeyNames": []string{"prod-key"}, "signedUrlCacheMaxAgeSec": "3600", "requestCoalescing": true, "cacheMode": "CACHE_ALL_STATIC", "defaultTtl": 3600, "maxTtl": 86400, "clientTtl": 600, "negativeCaching": true, "negativeCachingPolicy": []map[string]any{{"code": 404, "ttl": 120}}, "serveWhileStale": 86400, "bypassCacheOnRequestHeaders": []map[string]string{{"headerName": "Authorization"}}, "cacheKeyPolicy": map[string]any{"queryStringWhitelist": []string{"v"}, "includeHttpHeaders": []string{"Accept-Language"}}}, "customResponseHeaders": []string{"X-Content-Type-Options:nosniff"}, "edgeSecurityPolicy": "projects/writer-prod/global/securityPolicies/prod-edge-armor", "compressionMode": "AUTOMATIC", "loadBalancingScheme": "EXTERNAL_MANAGED", "usedBy": []map[string]string{{"reference": "projects/writer-prod/global/urlMaps/prod-url-map"}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/addresses":
			requireQuery(t, r, "maxResults", "10", "addresses")
			requireQuery(t, r, "returnPartialSuccess", "true", "addresses")
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"addresses": []map[string]any{{"id": "addr-1", "name": "prod-https-ip", "selfLink": "projects/writer-prod/regions/us-central1/addresses/prod-https-ip", "description": "prod https frontend ip", "address": "203.0.113.20", "status": "IN_USE", "region": "projects/writer-prod/regions/us-central1", "users": []string{"projects/writer-prod/regions/us-central1/forwardingRules/prod-https"}, "networkTier": "PREMIUM", "ipVersion": "IPV4", "addressType": "EXTERNAL", "purpose": "GCE_ENDPOINT", "labels": map[string]string{"env": "prod"}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/securityPolicies":
			requireQuery(t, r, "maxResults", "10", "security policies")
			requireQuery(t, r, "returnPartialSuccess", "true", "security policies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"securityPolicies": []map[string]any{{"id": "sp-1", "name": "prod-armor", "selfLink": "projects/writer-prod/global/securityPolicies/prod-armor", "description": "prod cloud armor policy", "type": "CLOUD_ARMOR", "fingerprint": "abc123", "rules": []map[string]any{{"priority": 1000, "action": "deny(403)", "description": "block sqli", "match": map[string]any{"expr": map[string]string{"expression": "evaluatePreconfiguredWaf('sqli-v33-stable')"}}}, {"priority": 2000, "action": "throttle", "preview": true, "description": "rate limit broad traffic", "match": map[string]any{"versionedExpr": "SRC_IPS_V1", "config": map[string]any{"srcIpRanges": []string{"0.0.0.0/0"}}}}, {"priority": 2147483647, "action": "allow", "description": "default allow", "match": map[string]any{"versionedExpr": "SRC_IPS_V1", "config": map[string]any{"srcIpRanges": []string{"0.0.0.0/0"}}}}}, "adaptiveProtectionConfig": map[string]any{"layer7DdosDefenseConfig": map[string]bool{"enable": true}}, "advancedOptionsConfig": map[string]any{"jsonParsing": "STANDARD", "logLevel": "VERBOSE", "userIpRequestHeaders": []string{"X-Forwarded-For"}}, "associations": []map[string]any{{"name": "prod-backend", "attachmentId": "projects/writer-prod/global/backendServices/prod-backend", "securityPolicyId": "sp-1", "shortName": "prod-armor"}}, "labels": map[string]string{"env": "prod"}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/sslCertificates":
			requireQuery(t, r, "maxResults", "10", "ssl certificates")
			requireQuery(t, r, "returnPartialSuccess", "true", "ssl certificates")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"sslCertificates": []map[string]any{{"id": "cert-1", "name": "prod-cert", "selfLink": "projects/writer-prod/global/sslCertificates/prod-cert", "description": "prod managed cert", "type": "MANAGED", "managed": map[string]any{"domains": []string{"app.writer.example"}, "status": "ACTIVE", "domainStatus": map[string]string{"app.writer.example": "ACTIVE"}}, "subjectAlternativeNames": []string{"app.writer.example"}, "expireTime": "2026-12-31T23:59:59Z"}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/sslPolicies":
			requireQuery(t, r, "maxResults", "10", "ssl policies")
			requireQuery(t, r, "returnPartialSuccess", "true", "ssl policies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"sslPolicies": []map[string]any{{"id": "ssl-policy-1", "name": "modern", "selfLink": "projects/writer-prod/global/sslPolicies/modern", "description": "modern external lb tls", "profile": "MODERN", "minTlsVersion": "TLS_1_2", "enabledFeatures": []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}, "customFeatures": []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}, "postQuantumKeyExchange": "ENABLED", "fingerprint": "sslpolicyfp"}}}}})
		case "/compute/v1/projects/writer-prod/global/targetGrpcProxies":
			requireQuery(t, r, "maxResults", "10", "target grpc proxies")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "tgrp-1", "name": "prod-grpc-proxy", "selfLink": "projects/writer-prod/global/targetGrpcProxies/prod-grpc-proxy", "description": "prod grpc proxy", "urlMap": "projects/writer-prod/global/urlMaps/prod-url-map", "validateForProxyless": true, "fingerprint": "grpcfp"}}})
		case "/compute/v1/projects/writer-prod/aggregated/targetHttpProxies":
			requireQuery(t, r, "maxResults", "10", "target http proxies")
			requireQuery(t, r, "returnPartialSuccess", "true", "target http proxies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"targetHttpProxies": []map[string]any{{"id": "thp-1", "name": "prod-http-proxy", "selfLink": "projects/writer-prod/global/targetHttpProxies/prod-http-proxy", "description": "prod http proxy", "urlMap": "projects/writer-prod/global/urlMaps/prod-url-map", "httpKeepAliveTimeoutSec": 610, "fingerprint": "httpfp"}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/targetHttpsProxies":
			requireQuery(t, r, "maxResults", "10", "target https proxies")
			requireQuery(t, r, "returnPartialSuccess", "true", "target https proxies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"targetHttpsProxies": []map[string]any{{"id": "thsp-1", "name": "prod-https-proxy", "selfLink": "projects/writer-prod/global/targetHttpsProxies/prod-https-proxy", "description": "prod https proxy", "urlMap": "projects/writer-prod/global/urlMaps/prod-url-map", "sslCertificates": []string{"projects/writer-prod/global/sslCertificates/prod-cert"}, "certificateMap": "//certificatemanager.googleapis.com/projects/writer-prod/locations/global/certificateMaps/prod-map", "quicOverride": "ENABLE", "sslPolicy": "projects/writer-prod/global/sslPolicies/modern", "serverTlsPolicy": "projects/writer-prod/locations/global/serverTlsPolicies/prod-server-tls", "authorizationPolicy": "projects/writer-prod/locations/global/authorizationPolicies/prod-authz", "httpKeepAliveTimeoutSec": 610, "fingerprint": "httpsfp"}}}}})
		case "/compute/v1/projects/writer-prod/global/targetSslProxies":
			requireQuery(t, r, "maxResults", "10", "target ssl proxies")
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "tsp-1", "name": "prod-ssl-proxy", "selfLink": "projects/writer-prod/global/targetSslProxies/prod-ssl-proxy", "description": "prod ssl proxy", "service": "projects/writer-prod/global/backendServices/prod-ssl-backend", "sslCertificates": []string{"projects/writer-prod/global/sslCertificates/prod-cert"}, "certificateMap": "//certificatemanager.googleapis.com/projects/writer-prod/locations/global/certificateMaps/prod-map", "sslPolicy": "projects/writer-prod/global/sslPolicies/modern", "proxyHeader": "PROXY_V1"}}})
		case "/compute/v1/projects/writer-prod/aggregated/targetTcpProxies":
			requireQuery(t, r, "maxResults", "10", "target tcp proxies")
			requireQuery(t, r, "returnPartialSuccess", "true", "target tcp proxies")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"targetTcpProxies": []map[string]any{{"id": "ttp-1", "name": "prod-tcp-proxy", "selfLink": "projects/writer-prod/global/targetTcpProxies/prod-tcp-proxy", "description": "prod tcp proxy", "service": "projects/writer-prod/global/backendServices/prod-tcp-backend", "proxyHeader": "PROXY_V1", "proxyBind": true, "loadBalancingScheme": "EXTERNAL_MANAGED"}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/healthChecks":
			requireQuery(t, r, "maxResults", "10", "health checks")
			requireQuery(t, r, "returnPartialSuccess", "true", "health checks")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"healthChecks": []map[string]any{{"id": "hc-1", "name": "prod-hc", "selfLink": "projects/writer-prod/global/healthChecks/prod-hc", "description": "prod http health check", "checkIntervalSec": 5, "timeoutSec": 5, "healthyThreshold": 2, "unhealthyThreshold": 3, "type": "HTTP", "httpHealthCheck": map[string]any{"port": 8080, "portSpecification": "USE_FIXED_PORT", "host": "app.writer.example", "requestPath": "/healthz", "proxyHeader": "NONE", "response": "ok"}, "sourceRegions": []string{"us-central1", "us-east1", "us-west1"}, "logConfig": map[string]bool{"enable": true}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/subnetworks":
			writeJSON(t, w, map[string]any{"items": map[string]any{"regions/us-central1": map[string]any{"subnetworks": []map[string]any{{"id": "subnet-1", "name": "default", "selfLink": "projects/writer-prod/regions/us-central1/subnetworks/default", "network": "projects/writer-prod/global/networks/default", "region": "projects/writer-prod/regions/us-central1", "ipCidrRange": "10.0.0.0/24", "privateIpGoogleAccess": true, "purpose": "PRIVATE", "stackType": "IPV4_ONLY", "labels": map[string]string{"env": "prod"}}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/urlMaps":
			requireQuery(t, r, "maxResults", "10", "url maps")
			requireQuery(t, r, "returnPartialSuccess", "true", "url maps")
			writeJSON(t, w, map[string]any{"items": map[string]any{"global": map[string]any{"urlMaps": []map[string]any{{"id": "um-1", "name": "prod-url-map", "selfLink": "projects/writer-prod/global/urlMaps/prod-url-map", "description": "prod application routing", "defaultService": "projects/writer-prod/global/backendServices/prod-backend", "hostRules": []map[string]any{{"hosts": []string{"app.writer.example"}, "pathMatcher": "app"}}, "pathMatchers": []map[string]any{{"name": "app", "defaultService": "projects/writer-prod/global/backendServices/prod-backend", "pathRules": []map[string]any{{"paths": []string{"/api/*"}, "service": "projects/writer-prod/global/backendServices/api-backend"}, {"paths": []string{"/old/*"}, "urlRedirect": map[string]any{"prefixRedirect": "/new", "redirectResponseCode": "MOVED_PERMANENTLY_DEFAULT"}}}, "routeRules": []map[string]any{{"priority": 10, "routeAction": map[string]any{"weightedBackendServices": []map[string]any{{"backendService": "projects/writer-prod/global/backendServices/canary-backend", "weight": 10}}}}}}}, "tests": []map[string]any{{"host": "app.writer.example", "path": "/api/health", "service": "projects/writer-prod/global/backendServices/api-backend"}}, "fingerprint": "urlmap123"}}}}})
		case "/compute/v1/projects/writer-prod/aggregated/disks":
			writeJSON(t, w, map[string]any{"items": map[string]any{"zones/us-central1-a": map[string]any{"disks": []map[string]any{{"id": "disk-1", "name": "web-1", "selfLink": "projects/writer-prod/zones/us-central1-a/disks/web-1", "zone": "projects/writer-prod/zones/us-central1-a", "type": "projects/writer-prod/zones/us-central1-a/diskTypes/pd-balanced", "status": "READY", "sizeGb": "100", "users": []string{"projects/writer-prod/zones/us-central1-a/instances/web-1"}, "labels": map[string]string{"env": "prod"}, "diskEncryptionKey": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/disk"}}}}}})
		case "/dns/v1/projects/writer-prod/managedZones":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("dns maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"managedZones": []map[string]any{{"id": "zone-1", "name": "prod-zone", "dnsName": "writer.example.", "description": "prod public zone", "nameServers": []string{"ns-cloud-a1.googledomains.com."}, "creationTime": "2026-04-23T00:00:00Z", "dnssecConfig": map[string]string{"state": "on", "nonExistence": "nsec3"}, "visibility": "public", "labels": map[string]string{"env": "prod"}, "cloudLoggingConfig": map[string]bool{"enableLogging": true}}}})
		case "/dns/v1/projects/writer-prod/managedZones/prod-zone/rrsets":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("dns rrsets maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"rrsets": []map[string]any{{"name": "api.writer.example.", "type": "A", "ttl": 300, "rrdatas": []string{"203.0.113.10"}}}})
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
		case "/v1/projects/writer-prod/locations/-/jobs":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("cloud scheduler pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"jobs": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/jobs/nightly-reconcile", "description": "nightly reconcile", "schedule": "0 2 * * *", "timeZone": "Etc/UTC", "state": "ENABLED", "httpTarget": map[string]any{"uri": "https://reconcile.writer.com/jobs/nightly", "httpMethod": "POST", "oidcToken": map[string]string{"serviceAccountEmail": "scheduler@writer-prod.iam.gserviceaccount.com", "audience": "reconcile"}}, "retryConfig": map[string]any{"retryCount": 3, "minBackoffDuration": "5s", "maxBackoffDuration": "300s", "maxDoublings": 4}, "attemptDeadline": "180s", "userUpdateTime": "2026-04-23T00:00:00Z", "scheduleTime": "2026-04-24T02:00:00Z", "lastAttemptTime": "2026-04-23T02:00:00Z", "satisfiesPzs": true}}})
		case "/v2/projects/writer-prod/locations/-/services":
			writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/services/api", "uid": "run-1", "uri": "https://api.run.app", "ingress": "INGRESS_TRAFFIC_ALL", "labels": map[string]string{"env": "prod"}, "template": map[string]any{"serviceAccount": "run@writer-prod.iam.gserviceaccount.com", "containers": []map[string]string{{"image": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc"}}, "vpcAccess": map[string]string{"connector": "projects/writer-prod/locations/us-central1/connectors/serverless"}}}}})
		case "/v2/projects/writer-prod/locations/us-central1/services/api/revisions":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("cloud run revisions pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"revisions": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/services/api/revisions/api-00001", "uid": "revision-1", "service": "projects/writer-prod/locations/us-central1/services/api", "serviceAccount": "run@writer-prod.iam.gserviceaccount.com", "containers": []map[string]string{{"image": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc"}}, "vpcAccess": map[string]string{"connector": "projects/writer-prod/locations/us-central1/connectors/serverless", "egress": "PRIVATE_RANGES_ONLY"}, "encryptionKey": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/run", "labels": map[string]string{"env": "prod"}, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z"}}})
		case "/v2/projects/writer-prod/locations/-/functions":
			writeJSON(t, w, map[string]any{"functions": []map[string]any{{"name": "projects/writer-prod/locations/us-central1/functions/ingest", "state": "ACTIVE", "environment": "GEN_2", "labels": map[string]string{"env": "prod"}, "serviceConfig": map[string]string{"serviceAccountEmail": "fn@writer-prod.iam.gserviceaccount.com", "uri": "https://ingest.cloudfunctions.net", "ingressSettings": "ALLOW_ALL", "vpcConnector": "projects/writer-prod/locations/us-central1/connectors/serverless"}}}})
		case "/v1/projects/writer-prod/locations/-/connectors":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("vpc access connectors pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"connectors": []map[string]any{{
				"name":              "projects/writer-prod/locations/us-central1/connectors/serverless",
				"network":           "default",
				"ipCidrRange":       "10.8.0.0/28",
				"state":             "READY",
				"machineType":       "e2-micro",
				"minInstances":      2,
				"maxInstances":      4,
				"connectedProjects": []string{"writer-prod"},
				"subnet":            map[string]string{"name": "serverless", "projectId": "writer-prod"},
			}}})
		case "/sql/v1beta4/projects/writer-prod/instances":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"name": "prod-sql", "selfLink": "https://sqladmin.googleapis.com/sql/v1beta4/projects/writer-prod/instances/prod-sql", "region": "us-central1", "gceZone": "us-central1-a", "databaseVersion": "POSTGRES_15", "state": "RUNNABLE", "serviceAccountEmailAddress": "sql@writer-prod.iam.gserviceaccount.com", "settings": map[string]any{"userLabels": map[string]string{"env": "prod"}, "storageAutoResize": true, "deletionProtectionEnabled": true, "backupConfiguration": map[string]any{"enabled": true, "pointInTimeRecoveryEnabled": true, "startTime": "03:00"}, "ipConfiguration": map[string]any{"ipv4Enabled": true, "privateNetwork": "projects/writer-prod/global/networks/default", "authorizedNetworks": []map[string]string{{"name": "all", "value": "0.0.0.0/0"}}}}, "ipAddresses": []map[string]string{{"type": "PRIMARY", "ipAddress": "35.2.3.4"}, {"type": "PRIVATE", "ipAddress": "10.10.0.3"}}, "diskEncryptionConfiguration": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/sql"}}}})
		case "/sql/v1beta4/projects/writer-prod/instances/prod-sql/databases":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("cloud sql database maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"name": "app", "instance": "prod-sql", "project": "writer-prod", "selfLink": "https://sqladmin.googleapis.com/sql/v1beta4/projects/writer-prod/instances/prod-sql/databases/app", "charset": "UTF8", "collation": "en_US.UTF8", "etag": "db-etag"}}})
		case "/sql/v1beta4/projects/writer-prod/instances/prod-sql/users":
			if got := r.URL.Query().Get("maxResults"); got != "10" {
				t.Fatalf("cloud sql user maxResults = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"name": "app", "host": "%", "instance": "prod-sql", "project": "writer-prod", "type": "BUILT_IN", "etag": "user-etag", "passwordPolicy": map[string]any{"status": map[string]string{"locked": "false"}}}}})
		case "/storage/v1/b/artifacts.writer-prod.appspot.com":
			writeJSON(t, w, map[string]any{"id": "artifacts.writer-prod.appspot.com", "name": "artifacts.writer-prod.appspot.com", "location": "US", "storageClass": "STANDARD", "labels": map[string]string{"env": "prod"}, "encryption": map[string]string{"defaultKmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/gcr"}, "versioning": map[string]bool{"enabled": true}, "iamConfiguration": map[string]any{"uniformBucketLevelAccess": map[string]bool{"enabled": true}, "publicAccessPrevention": "enforced"}})
		case "/storage/v1/b/artifacts.writer-prod.appspot.com/iam":
			if got := r.URL.Query().Get("optionsRequestedPolicyVersion"); got != "3" {
				t.Fatalf("gcr iam optionsRequestedPolicyVersion = %q, want 3", got)
			}
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/storage.admin", "members": []string{"serviceAccount:gcr-admin@writer-prod.iam.gserviceaccount.com"}}}})
		case "/storage/v1/b":
			if got := r.URL.Query().Get("project"); got != "writer-prod" {
				t.Fatalf("storage project = %q, want writer-prod", got)
			}
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data", "name": "data", "location": "US", "storageClass": "STANDARD", "labels": map[string]string{"env": "prod"}, "encryption": map[string]string{"defaultKmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/storage"}, "versioning": map[string]bool{"enabled": true}, "iamConfiguration": map[string]any{"uniformBucketLevelAccess": map[string]bool{"enabled": true}, "publicAccessPrevention": "enforced"}}}})
		case "/storage/v1/b/data/o":
			if got := r.URL.Query().Get("projection"); got != "full" {
				t.Fatalf("storage object projection = %q, want full", got)
			}
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "data/training.csv/1770000000000000", "name": "training.csv", "bucket": "data", "generation": "1770000000000000", "contentType": "text/csv", "storageClass": "STANDARD", "size": "42", "kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/storage", "timeCreated": "2026-04-23T00:00:00Z", "updated": "2026-04-24T00:00:00Z", "metadata": map[string]string{"data_classification": "restricted", "pii": "true"}, "acl": []map[string]string{{"entity": "allUsers", "role": "READER"}, {"entity": "user-ml-admin@writer.com", "role": "OWNER", "email": "ml-admin@writer.com"}}}}})
		case "/storage/v1/b/data/o/training.csv":
			if got := r.URL.Query().Get("alt"); got != "media" {
				t.Fatalf("storage object media alt = %q, want media", got)
			}
			if got := r.URL.Query().Get("generation"); got != "1770000000000000" {
				t.Fatalf("storage object media generation = %q, want 1770000000000000", got)
			}
			if got := r.Header.Get("Range"); got != "bytes=0-65535" {
				t.Fatalf("storage object media Range = %q, want bytes=0-65535", got)
			}
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Range", "bytes 0-64/65")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("email,token\nadmin@example.com,api_key=abcdefghijklmnopqrstuvwxyz\n"))
		case "/v1/projects/writer-prod/secrets":
			writeJSON(t, w, map[string]any{"secrets": []map[string]any{{"name": "projects/writer-prod/secrets/api-key", "labels": map[string]string{"env": "prod"}, "expireTime": "2027-04-23T00:00:00Z", "replication": map[string]any{"userManaged": map[string]any{"replicas": []map[string]any{{"location": "us-central1", "customerManagedEncryption": map[string]string{"kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/secrets"}}}}}, "rotation": map[string]string{"nextRotationTime": "2026-05-23T00:00:00Z", "rotationPeriod": "2592000s"}}}})
		case "/v1/projects/writer-prod/secrets/api-key/versions":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("secret version pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"versions": []map[string]any{{"name": "projects/writer-prod/secrets/api-key/versions/1", "state": "ENABLED", "createTime": "2026-04-23T00:00:00Z", "etag": "version-etag", "clientSpecifiedPayloadChecksum": true, "replicationStatus": map[string]any{"userManaged": map[string]any{"replicas": []map[string]any{{"location": "us-central1"}}}}}}})
		case "/v1/projects/writer-prod/locations/us/keyRings/prod/cryptoKeys":
			writeJSON(t, w, map[string]any{"cryptoKeys": []map[string]any{{"name": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/app", "purpose": "ENCRYPT_DECRYPT", "nextRotationTime": "2026-05-23T00:00:00Z", "rotationPeriod": "2592000s", "labels": map[string]string{"env": "prod"}, "versionTemplate": map[string]string{"protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}, "primary": map[string]string{"name": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/app/cryptoKeyVersions/1", "state": "ENABLED", "protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}}})
		case "/v2/projects/writer-prod/sinks":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("logging sink pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"sinks": []map[string]any{{"name": "ids-threat", "resourceName": "projects/writer-prod/sinks/ids-threat", "description": "cloud ids threat export", "destination": "pubsub.googleapis.com/projects/writer-prod/topics/security-alerts", "filter": `logName="projects/writer-prod/logs/ids.googleapis.com%2Fthreat"`, "disabled": false, "writerIdentity": "serviceAccount:writer-prod@gcp-sa-logging.iam.gserviceaccount.com", "includeChildren": false, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "exclusions": []map[string]any{{"name": "debug", "filter": "severity<ERROR", "disabled": false}}}}})
		case "/v2/projects/writer-prod/metrics":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("logging metric pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"metrics": []map[string]any{{"name": "error_count", "description": "error log count", "filter": `severity>=ERROR`, "disabled": false, "metricDescriptor": map[string]string{"type": "logging.googleapis.com/user/error_count", "metricKind": "DELTA", "valueType": "INT64", "unit": "1", "displayName": "Error count"}, "labelExtractors": map[string]string{"service": `EXTRACT(resource.labels.service_name)`}, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "version": "V2"}}})
		case "/v3/projects/writer-prod/alertPolicies":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("monitoring alert policy pageSize = %q, want 10", got)
			}
			enabled := true
			writeJSON(t, w, map[string]any{"alertPolicies": []map[string]any{{"name": "projects/writer-prod/alertPolicies/policy-1", "displayName": "Critical error rate", "documentation": map[string]string{"content": "Investigate service errors", "mimeType": "text/markdown", "subject": "Critical errors"}, "userLabels": map[string]string{"env": "prod"}, "enabled": enabled, "combiner": "OR", "conditions": []map[string]any{{"name": "projects/writer-prod/alertPolicies/policy-1/conditions/condition-1", "displayName": "error rate", "conditionThreshold": map[string]any{"filter": `metric.type="logging.googleapis.com/user/error_count"`}}}, "notificationChannels": []string{"projects/writer-prod/notificationChannels/channel-1"}, "severity": "CRITICAL", "creationRecord": map[string]string{"mutateTime": "2026-04-23T00:00:00Z", "mutatedBy": "admin@writer.com"}, "mutationRecord": map[string]string{"mutateTime": "2026-04-24T00:00:00Z", "mutatedBy": "admin@writer.com"}}}})
		case "/v3/projects/writer-prod/notificationChannels":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("monitoring notification channel pageSize = %q, want 10", got)
			}
			enabled := true
			writeJSON(t, w, map[string]any{"notificationChannels": []map[string]any{{"name": "projects/writer-prod/notificationChannels/channel-1", "type": "email", "displayName": "Security Oncall", "description": "security paging channel", "labels": map[string]string{"email_address": "security-oncall@writer.com"}, "userLabels": map[string]string{"env": "prod"}, "enabled": enabled, "verificationStatus": "VERIFIED", "creationRecord": map[string]string{"mutateTime": "2026-04-23T00:00:00Z", "mutatedBy": "admin@writer.com"}, "mutationRecords": []map[string]string{{"mutateTime": "2026-04-24T00:00:00Z", "mutatedBy": "admin@writer.com"}, {"mutateTime": "2026-04-25T00:00:00Z", "mutatedBy": "secops@writer.com"}}}}})
		case "/v1/projects/writer-prod/topics":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("pubsub topic pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"topics": []map[string]any{{"name": "projects/writer-prod/topics/security-alerts", "labels": map[string]string{"env": "prod"}, "kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/pubsub", "messageStoragePolicy": map[string]any{"allowedPersistenceRegions": []string{"us-central1", "us-east1"}}, "schemaSettings": map[string]string{"schema": "projects/writer-prod/schemas/alert", "encoding": "JSON", "firstRevisionId": "rev-1", "lastRevisionId": "rev-2"}, "messageRetentionDuration": "604800s", "state": "ACTIVE", "satisfiesPzs": true}}})
		case "/v1/projects/writer-prod/topics/security-alerts:getIamPolicy":
			if r.Method != http.MethodPost {
				t.Fatalf("pubsub topic getIamPolicy method = %s, want POST", r.Method)
			}
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/pubsub.publisher", "members": []string{"serviceAccount:logging@writer-prod.iam.gserviceaccount.com"}}, {"role": "roles/pubsub.viewer", "members": []string{"allUsers"}}}})
		case "/v1/projects/writer-prod/subscriptions":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("pubsub subscription pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"subscriptions": []map[string]any{{"name": "projects/writer-prod/subscriptions/security-alerts-worker", "topic": "projects/writer-prod/topics/security-alerts", "labels": map[string]string{"env": "prod"}, "pushConfig": map[string]any{"pushEndpoint": "https://alerts.writer.com/pubsub", "oidcToken": map[string]string{"serviceAccountEmail": "pubsub-push@writer-prod.iam.gserviceaccount.com", "audience": "alerts"}}, "deadLetterPolicy": map[string]any{"deadLetterTopic": "projects/writer-prod/topics/dead-letter", "maxDeliveryAttempts": 5}, "retryPolicy": map[string]string{"minimumBackoff": "10s", "maximumBackoff": "600s"}, "expirationPolicy": map[string]string{"ttl": "2678400s"}, "messageRetentionDuration": "604800s", "topicMessageRetentionDuration": "604800s", "ackDeadlineSeconds": 30, "retainAckedMessages": true, "enableMessageOrdering": true, "filter": `attributes.severity="critical"`, "state": "ACTIVE"}}})
		case "/v1/projects/writer-prod/subscriptions/security-alerts-worker:getIamPolicy":
			if r.Method != http.MethodPost {
				t.Fatalf("pubsub subscription getIamPolicy method = %s, want POST", r.Method)
			}
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/pubsub.subscriber", "members": []string{"serviceAccount:worker@writer-prod.iam.gserviceaccount.com"}}}})
		case "/v1/projects/writer-prod":
			writeJSON(t, w, map[string]any{"projectNumber": "123456789", "projectId": "writer-prod", "name": "Writer Prod", "lifecycleState": "ACTIVE", "labels": map[string]string{"env": "prod"}, "createTime": "2026-04-23T00:00:00Z", "parent": map[string]string{"type": "organization", "id": "1234"}})
		case "/v1/projects/writer-prod/services", "/v1/projects/123456789/services":
			if got := r.URL.Query().Get("filter"); got != "state:ENABLED" {
				t.Fatalf("service usage filter = %q, want state:ENABLED", got)
			}
			if r.URL.Path == "/v1/projects/writer-prod/services" {
				writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/writer-prod/services/bigquery.googleapis.com", "state": "ENABLED", "config": map[string]string{"name": "bigquery.googleapis.com", "title": "BigQuery API"}}}})
				return
			}
			writeJSON(t, w, map[string]any{"services": []map[string]any{{"name": "projects/123456789/services/bigquery.googleapis.com", "state": "ENABLED", "config": map[string]string{"name": "bigquery.googleapis.com", "title": "BigQuery API"}}, {"name": "projects/123456789/services/aiplatform.googleapis.com", "state": "ENABLED", "config": map[string]string{"name": "aiplatform.googleapis.com", "title": "Vertex AI API"}}}})
		case "/v1/projects/writer-prod/instances":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("spanner instance pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"instances": []map[string]any{{"name": "projects/writer-prod/instances/prod-spanner", "config": "projects/writer-prod/instanceConfigs/regional-us-central1", "displayName": "prod-spanner", "processingUnits": 100, "state": "READY", "labels": map[string]string{"env": "prod"}, "endpointUris": []string{"spanner.googleapis.com"}, "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "instanceType": "PROVISIONED"}}})
		case "/v1/projects/writer-prod/instances/prod-spanner/databases":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("spanner database pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"databases": []map[string]any{{"name": "projects/writer-prod/instances/prod-spanner/databases/app", "state": "READY", "createTime": "2026-04-23T00:00:00Z", "versionRetentionPeriod": "1h", "earliestVersionTime": "2026-04-23T00:00:00Z", "encryptionConfig": map[string]string{"encryptionType": "CUSTOMER_MANAGED_ENCRYPTION", "kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/spanner"}, "encryptionInfo": []map[string]string{{"encryptionType": "CUSTOMER_MANAGED_ENCRYPTION", "kmsKeyVersion": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/spanner/cryptoKeyVersions/1"}}, "databaseDialect": "POSTGRESQL", "enableDropProtection": true}}})
		case "/v2/projects/writer-prod/policies":
			enforce := true
			writeJSON(t, w, map[string]any{"policies": []map[string]any{{"name": "projects/writer-prod/policies/iam.disableServiceAccountKeyCreation", "spec": map[string]any{"rules": []map[string]any{{"enforce": enforce}}}}}})
		case "/v1/projects/writer-prod/locations/-/repositories":
			writeJSON(t, w, map[string]any{"repositories": []map[string]any{{"name": "projects/writer-prod/locations/us/repositories/app", "format": "DOCKER", "mode": "STANDARD_REPOSITORY", "kmsKeyName": "projects/writer-prod/locations/us/keyRings/prod/cryptoKeys/artifacts", "labels": map[string]string{"env": "prod"}, "dockerConfig": map[string]bool{"immutableTags": true}}}})
		case "/v1/projects/writer-prod/locations/us/repositories/app/dockerImages":
			writeJSON(t, w, map[string]any{"dockerImages": []map[string]any{{"name": "projects/writer-prod/locations/us/repositories/app/dockerImages/us-docker.pkg.dev%2Fwriter-prod%2Fapp%2Fapi@sha256:abc", "uri": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc", "tags": []string{"latest", "prod"}, "imageSizeBytes": "12345", "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "uploadTime": "2026-04-23T00:00:00Z"}}})
		case "/v1/projects/writer-prod/occurrences":
			if got := r.URL.Query().Get("filter"); got != `kind="VULNERABILITY"` {
				t.Fatalf("container analysis filter = %q, want vulnerability filter", got)
			}
			writeJSON(t, w, map[string]any{"occurrences": []map[string]any{{"name": "projects/writer-prod/occurrences/vuln-1", "resourceUri": "us-docker.pkg.dev/writer-prod/app/api@sha256:abc", "noteName": "projects/goog-vulnz/notes/CVE-2026-4242", "kind": "VULNERABILITY", "remediation": "Upgrade openssl", "createTime": "2026-04-23T00:00:00Z", "updateTime": "2026-04-24T00:00:00Z", "vulnerability": map[string]any{"effectiveSeverity": "HIGH", "severity": "HIGH", "shortDescription": "openssl issue", "cvssScore": 8.8, "packageIssue": []map[string]any{{"affectedPackage": "openssl", "affectedVersion": map[string]string{"name": "3.0.0"}, "fixedPackage": "openssl", "fixedVersion": map[string]string{"name": "3.0.1"}, "fixAvailable": true, "packageType": "OS"}}}}}})
		case "/v2/projects/writer-prod/sources/-/findings":
			if got := r.URL.Query().Get("pageSize"); got != "10" {
				t.Fatalf("security center findings pageSize = %q, want 10", got)
			}
			writeJSON(t, w, map[string]any{"listFindingsResults": []map[string]any{{
				"finding": map[string]any{
					"name":         "projects/writer-prod/sources/123/findings/public-bucket",
					"parent":       "projects/writer-prod/sources/123",
					"resourceName": "//storage.googleapis.com/projects/_/buckets/data",
					"state":        "ACTIVE",
					"category":     "PUBLIC_BUCKET_ACL",
					"severity":     "HIGH",
					"mute":         "UNMUTED",
					"findingClass": "MISCONFIGURATION",
					"description":  "Bucket grants allUsers read access",
					"nextSteps":    "Remove public ACL grants",
					"eventTime":    "2026-04-23T00:00:00Z",
					"createTime":   "2026-04-23T00:00:00Z",
				},
				"resource": map[string]any{
					"name":               "//storage.googleapis.com/projects/_/buckets/data",
					"displayName":        "data",
					"type":               "google.cloud.storage.Bucket",
					"service":            "storage.googleapis.com",
					"location":           "US",
					"cloudProvider":      "GOOGLE_CLOUD_PLATFORM",
					"projectName":        "//cloudresourcemanager.googleapis.com/projects/writer-prod",
					"projectDisplayName": "writer-prod",
				},
			}}})
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

func requireQuery(t *testing.T, r *http.Request, key, want, label string) {
	t.Helper()
	if got := r.URL.Query().Get(key); got != want {
		t.Fatalf("%s %s = %q, want %s", label, key, got, want)
	}
}
