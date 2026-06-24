package gcp

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/gcpcloud"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultFamily                                                                                                                                                                                        = familyAudit
	defaultPageSize                                                                                                                                                                                      = 10
	gcpComputeInventoryMaxBodyBytes                                                                                                                                                                      = 64 << 20
	gcsObjectContentSampleBytes                                                                                                                                                                          = 64 << 10
	maxPageSize                                                                                                                                                                                          = 200
	familyAssetMetadata                                                                                                                                                                                  = "asset_metadata"
	familyAIDataset                                                                                                                                                                                      = "aiplatform_dataset"
	familyAIEndpoint                                                                                                                                                                                     = "aiplatform_endpoint"
	familyArtifactImage                                                                                                                                                                                  = "artifact_registry_image"
	familyArtifactRepo                                                                                                                                                                                   = "artifact_registry_repository"
	familyAudit                                                                                                                                                                                          = "audit"
	familyBinaryAuthorizationPolicy, familyBinaryAuthorizationAttestor                                                                                                                                   = "binary_authorization_policy", "binary_authorization_attestor"
	familyBigQueryDataset, familyBigQueryTable, familyBigtableInstance, familyBigtableTable                                                                                                              = "bigquery_dataset", "bigquery_table", "bigtable_instance", "bigtable_table"
	familyCertificateManagerCertificate                                                                                                                                                                  = "certificate_manager_certificate"
	familyCertificateManagerCertificateMap                                                                                                                                                               = "certificate_manager_certificate_map"
	familyCertificateManagerCertificateMapEntry                                                                                                                                                          = "certificate_manager_certificate_map_entry"
	familyCertificateManagerDNSAuthorization                                                                                                                                                             = "certificate_manager_dns_authorization"
	familyCloudFunction                                                                                                                                                                                  = "cloud_function"
	familyCloudIDSEndpoint                                                                                                                                                                               = "cloud_ids_endpoint"
	familyCloudSchedulerJob                                                                                                                                                                              = "cloud_scheduler_job"
	familyCloudRunRevision                                                                                                                                                                               = "cloud_run_revision"
	familyCloudRunService                                                                                                                                                                                = "cloud_run_service"
	familyCloudSQLDatabase, familyCloudSQLInstance, familyCloudSQLUser                                                                                                                                   = "cloud_sql_database", "cloud_sql_instance", "cloud_sql_user"
	familyContainerRegistry, familyContainerVuln                                                                                                                                                         = "container_registry", "container_vulnerability"
	familyComputeAddress, familyComputeBackendBucket                                                                                                                                                     = "compute_address", "compute_backend_bucket"
	familyComputeBackendService, familyComputeDisk                                                                                                                                                       = "compute_backend_service", "compute_disk"
	familyComputeFirewall, familyComputeInstance                                                                                                                                                         = "compute_firewall", "compute_instance"
	familyComputeInstanceGroup, familyComputeInstanceGroupMgr, familyComputeInstanceTemplate, familyComputeNetworkEndpointGroup                                                                          = "compute_instance_group", "compute_instance_group_manager", "compute_instance_template", "compute_network_endpoint_group"
	familyComputeInterconnectAttachment, familyComputeExternalVPNGateway, familyComputeInterconnect, familyComputeRouter, familyComputeTargetVPNGateway, familyComputeVPNGateway, familyComputeVPNTunnel = "compute_interconnect_attachment", "compute_external_vpn_gateway", "compute_interconnect", "compute_router", "compute_target_vpn_gateway", "compute_vpn_gateway", "compute_vpn_tunnel"
	familyComputeForwardingRule, familyComputeHealthCheck, familyComputeNetwork, familyComputeRoute                                                                                                      = "compute_forwarding_rule", "compute_health_check", "compute_network", "compute_route"
	familyComputeSecurityPolicy, familyComputeSSLPolicy                                                                                                                                                  = "compute_security_policy", "compute_ssl_policy"
	familyComputeSSLCertificate, familyComputeSubnetwork                                                                                                                                                 = "compute_ssl_certificate", "compute_subnetwork"
	familyComputeTargetGRPCProxy, familyComputeTargetHTTPProxy, familyComputeTargetHTTPSProxy                                                                                                            = "compute_target_grpc_proxy", "compute_target_http_proxy", "compute_target_https_proxy"
	familyComputeTargetSSLProxy, familyComputeTargetTCPProxy                                                                                                                                             = "compute_target_ssl_proxy", "compute_target_tcp_proxy"
	familyComputeNetworkFirewallPolicy, familyComputePacketMirroring, familyComputeURLMap                                                                                                                = "compute_network_firewall_policy", "compute_packet_mirroring", "compute_url_map"
	familyDNSManagedZone                                                                                                                                                                                 = "dns_managed_zone"
	familyDNSRecordSet                                                                                                                                                                                   = "dns_record_set"
	familyEffectivePermission                                                                                                                                                                            = "effective_permission"
	familyGCSBucket, familyGCSObject                                                                                                                                                                     = "gcs_bucket", "gcs_object"
	familyGKECluster                                                                                                                                                                                     = "gke_cluster"
	familyGKENodePool                                                                                                                                                                                    = "gke_node_pool"
	familyGroup, familyGroupMember                                                                                                                                                                       = "group", "group_membership"
	familyKMSKey, familyLoggingMetric, familyLoggingSink                                                                                                                                                 = "kms_key", "logging_metric", "logging_project_sink"
	familyMonitoringAlertPolicy, familyMonitoringNotificationChannel, familyOrgPolicy                                                                                                                    = "monitoring_alert_policy", "monitoring_notification_channel", "org_policy"
	familyPubSubSubscription                                                                                                                                                                             = "pubsub_subscription"
	familyPubSubTopic                                                                                                                                                                                    = "pubsub_topic"
	familyResourceProject                                                                                                                                                                                = "resourcemanager_project"
	familyRoleAssign                                                                                                                                                                                     = "iam_role_assignment"
	familyResourceExposure                                                                                                                                                                               = "resource_exposure"
	familySAImpersonation                                                                                                                                                                                = "service_account_impersonation"
	familySecurityCenterFinding                                                                                                                                                                          = "security_center_finding"
	familyServiceAcct                                                                                                                                                                                    = "service_account"
	familyServiceUsageService, familySpannerDatabase, familySpannerInstance                                                                                                                              = "service_usage_service", "spanner_database", "spanner_instance"
	familySAKey                                                                                                                                                                                          = "service_account_key"
	gcpCloudPlatformScope                                                                                                                                                                                = "https://www.googleapis.com/auth/cloud-platform"
	familySecret, familySecretVersion                                                                                                                                                                    = "secret_manager_secret", "secret_manager_version"
	familyVPCAccessConnector                                                                                                                                                                             = "vpc_access_connector"
	familyWorkloadIdentityPool, familyWorkloadIdentityProvider                                                                                                                                           = "workload_identity_pool", "workload_identity_provider"
)

// Source reads GCP IAM, Cloud Identity, and Cloud Audit surfaces.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	tokenSources         sync.Map
	tokenSourceFactory   func(context.Context, settings) (oauth2.TokenSource, error)
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type settings struct {
	family, projectID, customerID, groupKey                    string
	serviceAccountEmail, location, keyRing, artifactRepository string
	token, wifAudience, wifServiceAccount, wifAWSRegion        string
	tenantID, wifBindings                                      string
	baseURL, filter                                            string
	perPage                                                    int
}

type pageResponse = gcpcloud.GenericPageResponse

type gcpFamilyOptions[T any] struct {
	Name               string
	Label              string
	List               func(context.Context, *Source, settings, string, int) ([]T, string, error)
	ListWithCheckpoint func(context.Context, *Source, settings, string, int, *cerebrov1.SourceCheckpoint) ([]T, string, error)
	Event              func(settings, T) (*primitives.Event, error)
	URN                func(settings, T) (string, error)
	Discover           func(context.Context, *Source, settings) ([]sourcecdk.URN, error)
}

type gcpResourceIdentifier interface{ CerebroResourceID() string }

func gcpResourceURN[T gcpResourceIdentifier](resourceType string) func(settings, T) (string, error) {
	return func(settings settings, record T) (string, error) {
		return fmt.Sprintf("urn:cerebro:%s:%s:%s", tenantID(settings), resourceType, record.CerebroResourceID()), nil
	}
}

// New constructs the live GCP source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, lookupIPAddrs: net.DefaultResolver.LookupIPAddr}
	source.client = source.safeClient()
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns tenant-scoped GCP URNs.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized GCP events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

// ReadWithCheckpoint lets GCP families with provider-supported event ordering stop once they reach the durable runtime watermark.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngineWithSourceID("gcp", parseSettings, func(settings settings) string { return settings.family },
		gcpFamily(s, gcpFamilyOptions[assetMetadataRecord]{
			Name:  familyAssetMetadata,
			Label: "gcp asset metadata",
			List:  listAssetMetadata,
			Event: assetMetadataEvent,
			URN: func(settings settings, asset assetMetadataRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_asset_metadata:%s", tenantID(settings), firstNonEmpty(asset.Name, asset.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.AIDatasetRecord]{
			Name:  familyAIDataset,
			Label: "gcp vertex ai datasets",
			List:  listAIDatasets,
			Event: gcpCloudEvent(gcpcloud.AIDatasetEvent),
			URN: func(settings settings, dataset gcpcloud.AIDatasetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_aiplatform_dataset:%s", tenantID(settings), firstNonEmpty(dataset.Name, dataset.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.AIEndpointRecord]{
			Name:  familyAIEndpoint,
			Label: "gcp vertex ai endpoints",
			List:  listAIEndpoints,
			Event: gcpCloudEvent(gcpcloud.AIEndpointEvent),
			URN: func(settings settings, endpoint gcpcloud.AIEndpointRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_aiplatform_endpoint:%s", tenantID(settings), firstNonEmpty(endpoint.Name, endpoint.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ArtifactImageRecord]{
			Name:  familyArtifactImage,
			Label: "gcp artifact registry images",
			List:  listArtifactImages,
			Event: artifactImageEvent,
			URN: func(settings settings, image gcpcloud.ArtifactImageRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_artifact_registry_image:%s", tenantID(settings), firstNonEmpty(image.URI, image.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ArtifactRepositoryRecord]{
			Name:  familyArtifactRepo,
			Label: "gcp artifact registry repositories",
			List:  listArtifactRepositories,
			Event: gcpCloudEvent(gcpcloud.ArtifactRepositoryEvent),
			URN: func(settings settings, repo gcpcloud.ArtifactRepositoryRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_artifact_registry_repository:%s", tenantID(settings), firstNonEmpty(repo.Name, repo.Description)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[auditRecord]{
			Name:               familyAudit,
			Label:              "gcp audit logs",
			List:               listAuditRecords,
			ListWithCheckpoint: listAuditRecordsWithCheckpoint,
			Event:              auditEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := gcpcloud.CheckList(ctx, source, settings, tenantID(settings), listAuditRecords, "gcp audit logs"); err != nil {
					return nil, err
				}
				return gcpcloud.ParseURNs(fmt.Sprintf("urn:cerebro:%s:gcp_project:%s", settings.projectID, settings.projectID))
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BinaryAuthorizationPolicyRecord]{
			Name:  familyBinaryAuthorizationPolicy,
			Label: "gcp binary authorization policies",
			List:  listBinaryAuthorizationPolicies,
			Event: gcpCloudEvent(gcpcloud.BinaryAuthorizationPolicyEvent),
			URN: func(settings settings, policy gcpcloud.BinaryAuthorizationPolicyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_binary_authorization_policy:%s", tenantID(settings), firstNonEmpty(policy.Name, "projects/"+settings.projectID+"/policy")), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BinaryAuthorizationAttestorRecord]{
			Name:  familyBinaryAuthorizationAttestor,
			Label: "gcp binary authorization attestors",
			List:  listBinaryAuthorizationAttestors,
			Event: gcpCloudEvent(gcpcloud.BinaryAuthorizationAttestorEvent),
			URN: func(settings settings, attestor gcpcloud.BinaryAuthorizationAttestorRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_binary_authorization_attestor:%s", tenantID(settings), firstNonEmpty(attestor.Name, attestor.Description)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BigQueryDatasetRecord]{
			Name:  familyBigQueryDataset,
			Label: "gcp bigquery datasets",
			List:  listBigQueryDatasets,
			Event: gcpCloudEvent(gcpcloud.BigQueryDatasetEvent),
			URN: func(settings settings, dataset gcpcloud.BigQueryDatasetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_bigquery_dataset:%s", tenantID(settings), firstNonEmpty(dataset.ID, dataset.DatasetReference.DatasetID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BigQueryTableRecord]{Name: familyBigQueryTable, Label: "gcp bigquery tables", List: listBigQueryTables, Event: gcpCloudEvent(gcpcloud.BigQueryTableEvent), URN: func(settings settings, table gcpcloud.BigQueryTableRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_bigquery_table:%s", tenantID(settings), gcpcloud.BigQueryTableResourceID(settings.projectID, table)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BigtableInstanceRecord]{Name: familyBigtableInstance, Label: "gcp bigtable instances", List: listBigtableInstances, Event: gcpCloudEvent(gcpcloud.BigtableInstanceEvent), URN: gcpResourceURN[gcpcloud.BigtableInstanceRecord]("gcp_bigtable_instance")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.BigtableTableRecord]{Name: familyBigtableTable, Label: "gcp bigtable tables", List: listBigtableTables, Event: gcpCloudEvent(gcpcloud.BigtableTableEvent), URN: gcpResourceURN[gcpcloud.BigtableTableRecord]("gcp_bigtable_table")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CertificateManagerCertificateRecord]{Name: familyCertificateManagerCertificate, Label: "gcp certificate manager certificates", List: listCertificateManagerCertificates, Event: gcpCloudEvent(gcpcloud.CertificateManagerCertificateEvent), URN: gcpResourceURN[gcpcloud.CertificateManagerCertificateRecord]("gcp_certificate_manager_certificate")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CertificateManagerCertificateMapRecord]{Name: familyCertificateManagerCertificateMap, Label: "gcp certificate manager certificate maps", List: listCertificateManagerCertificateMaps, Event: gcpCloudEvent(gcpcloud.CertificateManagerCertificateMapEvent), URN: gcpResourceURN[gcpcloud.CertificateManagerCertificateMapRecord]("gcp_certificate_manager_certificate_map")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CertificateManagerCertificateMapEntryRecord]{Name: familyCertificateManagerCertificateMapEntry, Label: "gcp certificate manager certificate map entries", List: listCertificateManagerCertificateMapEntries, Event: gcpCloudEvent(gcpcloud.CertificateManagerCertificateMapEntryEvent), URN: gcpResourceURN[gcpcloud.CertificateManagerCertificateMapEntryRecord]("gcp_certificate_manager_certificate_map_entry")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CertificateManagerDNSAuthorizationRecord]{Name: familyCertificateManagerDNSAuthorization, Label: "gcp certificate manager dns authorizations", List: listCertificateManagerDNSAuthorizations, Event: gcpCloudEvent(gcpcloud.CertificateManagerDNSAuthorizationEvent), URN: gcpResourceURN[gcpcloud.CertificateManagerDNSAuthorizationRecord]("gcp_certificate_manager_dns_authorization")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudFunctionRecord]{Name: familyCloudFunction, Label: "gcp cloud functions", List: listCloudFunctions, Event: gcpCloudEvent(gcpcloud.CloudFunctionEvent), URN: func(settings settings, fn gcpcloud.CloudFunctionRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_function:%s", tenantID(settings), firstNonEmpty(fn.Name, fn.ServiceConfig.URI)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudIDSEndpointRecord]{Name: familyCloudIDSEndpoint, Label: "gcp cloud ids endpoints", List: listCloudIDSEndpoints, Event: gcpCloudEvent(gcpcloud.CloudIDSEndpointEvent), URN: func(settings settings, endpoint gcpcloud.CloudIDSEndpointRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_ids_endpoint:%s", tenantID(settings), endpoint.Name), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSchedulerJobRecord]{Name: familyCloudSchedulerJob, Label: "gcp cloud scheduler jobs", List: listCloudSchedulerJobs, Event: gcpCloudEvent(gcpcloud.CloudSchedulerJobEvent), URN: func(settings settings, job gcpcloud.CloudSchedulerJobRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_scheduler_job:%s", tenantID(settings), firstNonEmpty(job.Name, settings.projectID)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudRunRevisionRecord]{Name: familyCloudRunRevision, Label: "gcp cloud run revisions", List: listCloudRunRevisions, Event: gcpCloudEvent(gcpcloud.CloudRunRevisionEvent), URN: func(settings settings, revision gcpcloud.CloudRunRevisionRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_revision:%s", tenantID(settings), firstNonEmpty(revision.Name, revision.UID)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudRunServiceRecord]{Name: familyCloudRunService, Label: "gcp cloud run services", List: listCloudRunServices, Event: gcpCloudEvent(gcpcloud.CloudRunServiceEvent), URN: func(settings settings, service gcpcloud.CloudRunServiceRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_service:%s", tenantID(settings), firstNonEmpty(service.Name, service.UID)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSQLInstanceRecord]{Name: familyCloudSQLInstance, Label: "gcp cloud sql instances", List: listCloudSQLInstances, Event: gcpCloudEvent(gcpcloud.CloudSQLInstanceEvent), URN: func(settings settings, instance gcpcloud.CloudSQLInstanceRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_sql_instance:%s", tenantID(settings), firstNonEmpty(instance.SelfLink, instance.Name)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSQLDatabaseRecord]{Name: familyCloudSQLDatabase, Label: "gcp cloud sql databases", List: listCloudSQLDatabases, Event: gcpCloudEvent(gcpcloud.CloudSQLDatabaseEvent), URN: func(settings settings, database gcpcloud.CloudSQLDatabaseRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_sql_database:%s", tenantID(settings), gcpcloud.CloudSQLDatabaseResourceID(settings.projectID, database)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSQLUserRecord]{Name: familyCloudSQLUser, Label: "gcp cloud sql users", List: listCloudSQLUsers, Event: gcpCloudEvent(gcpcloud.CloudSQLUserEvent), URN: func(settings settings, user gcpcloud.CloudSQLUserRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_sql_user:%s", tenantID(settings), gcpcloud.CloudSQLUserResourceID(settings.projectID, user)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ContainerVulnerabilityRecord]{
			Name:  familyContainerVuln,
			Label: "gcp container vulnerabilities",
			List:  listContainerVulnerabilities,
			Event: gcpCloudEvent(gcpcloud.ContainerVulnerabilityEvent),
			URN: func(settings settings, occurrence gcpcloud.ContainerVulnerabilityRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_container_vulnerability:%s", tenantID(settings), firstNonEmpty(occurrence.Name, occurrence.NoteName, occurrence.ResourceURI)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ContainerRegistryRecord]{
			Name:  familyContainerRegistry,
			Label: "gcp container registries",
			List:  listContainerRegistries,
			Event: gcpCloudEvent(gcpcloud.ContainerRegistryEvent),
			URN: func(settings settings, registry gcpcloud.ContainerRegistryRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_container_registry:%s/%s", tenantID(settings), registry.Host, settings.projectID), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeAddressRecord]{Name: familyComputeAddress, Label: "gcp compute addresses", List: listComputeAddresses, Event: gcpCloudEvent(gcpcloud.ComputeAddressEvent), URN: gcpResourceURN[gcpcloud.ComputeAddressRecord]("gcp_compute_address")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeBackendBucketRecord]{Name: familyComputeBackendBucket, Label: "gcp compute backend buckets", List: listComputeBackendBuckets, Event: gcpCloudEvent(gcpcloud.ComputeBackendBucketEvent), URN: gcpResourceURN[gcpcloud.ComputeBackendBucketRecord]("gcp_compute_backend_bucket")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeBackendServiceRecord]{Name: familyComputeBackendService, Label: "gcp compute backend services", List: listComputeBackendServices, Event: gcpCloudEvent(gcpcloud.ComputeBackendServiceEvent), URN: gcpResourceURN[gcpcloud.ComputeBackendServiceRecord]("gcp_compute_backend_service")}),
		gcpFamily(s, gcpFamilyOptions[computeInstanceRecord]{Name: familyComputeInstance, Label: "gcp compute instances", List: listComputeInstances, Event: gcpCloudEvent(gcpcloud.ComputeInstanceEvent), URN: func(settings settings, instance computeInstanceRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_compute_instance:%s", tenantID(settings), firstNonEmpty(instance.ID, instance.Name)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeInstanceGroupRecord]{Name: familyComputeInstanceGroup, Label: "gcp compute instance groups", List: listComputeInstanceGroups, Event: gcpCloudEvent(gcpcloud.ComputeInstanceGroupEvent), URN: gcpResourceURN[gcpcloud.ComputeInstanceGroupRecord]("gcp_compute_instance_group")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeInstanceGroupManagerRecord]{Name: familyComputeInstanceGroupMgr, Label: "gcp compute instance group managers", List: listComputeInstanceGroupManagers, Event: gcpCloudEvent(gcpcloud.ComputeInstanceGroupManagerEvent), URN: gcpResourceURN[gcpcloud.ComputeInstanceGroupManagerRecord]("gcp_compute_instance_group_manager")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeInstanceTemplateRecord]{Name: familyComputeInstanceTemplate, Label: "gcp compute instance templates", List: listComputeInstanceTemplates, Event: gcpCloudEvent(gcpcloud.ComputeInstanceTemplateEvent), URN: gcpResourceURN[gcpcloud.ComputeInstanceTemplateRecord]("gcp_compute_instance_template")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeInterconnectAttachmentRecord]{Name: familyComputeInterconnectAttachment, Label: "gcp compute interconnect attachments", List: listComputeInterconnectAttachments, Event: gcpCloudEvent(gcpcloud.ComputeInterconnectAttachmentEvent), URN: gcpResourceURN[gcpcloud.ComputeInterconnectAttachmentRecord]("gcp_compute_interconnect_attachment")}), gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeExternalVPNGatewayRecord]{Name: familyComputeExternalVPNGateway, Label: "gcp compute external vpn gateways", List: listComputeExternalVPNGateways, Event: gcpCloudEvent(gcpcloud.ComputeExternalVPNGatewayEvent), URN: gcpResourceURN[gcpcloud.ComputeExternalVPNGatewayRecord]("gcp_compute_external_vpn_gateway")}), gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeInterconnectRecord]{Name: familyComputeInterconnect, Label: "gcp compute interconnects", List: listComputeInterconnects, Event: gcpCloudEvent(gcpcloud.ComputeInterconnectEvent), URN: gcpResourceURN[gcpcloud.ComputeInterconnectRecord]("gcp_compute_interconnect")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeNetworkEndpointGroupRecord]{Name: familyComputeNetworkEndpointGroup, Label: "gcp compute network endpoint groups", List: listComputeNetworkEndpointGroups, Event: gcpCloudEvent(gcpcloud.ComputeNetworkEndpointGroupEvent), URN: gcpResourceURN[gcpcloud.ComputeNetworkEndpointGroupRecord]("gcp_compute_network_endpoint_group")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeHealthCheckRecord]{Name: familyComputeHealthCheck, Label: "gcp compute health checks", List: listComputeHealthChecks, Event: gcpCloudEvent(gcpcloud.ComputeHealthCheckEvent), URN: gcpResourceURN[gcpcloud.ComputeHealthCheckRecord]("gcp_compute_health_check")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeNetworkRecord]{Name: familyComputeNetwork, Label: "gcp compute networks", List: listComputeNetworks, Event: gcpCloudEvent(gcpcloud.ComputeNetworkEvent), URN: gcpResourceURN[gcpcloud.ComputeNetworkRecord]("gcp_compute_network")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeRouteRecord]{Name: familyComputeRoute, Label: "gcp compute routes", List: listComputeRoutes, Event: gcpCloudEvent(gcpcloud.ComputeRouteEvent), URN: gcpResourceURN[gcpcloud.ComputeRouteRecord]("gcp_compute_route")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeRouterRecord]{Name: familyComputeRouter, Label: "gcp compute routers", List: listComputeRouters, Event: gcpCloudEvent(gcpcloud.ComputeRouterEvent), URN: gcpResourceURN[gcpcloud.ComputeRouterRecord]("gcp_compute_router")}), gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputePacketMirroringRecord]{Name: familyComputePacketMirroring, Label: "gcp compute packet mirrorings", List: listComputePacketMirrorings, Event: gcpCloudEvent(gcpcloud.ComputePacketMirroringEvent), URN: gcpResourceURN[gcpcloud.ComputePacketMirroringRecord]("gcp_compute_packet_mirroring")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeSecurityPolicyRecord]{Name: familyComputeSecurityPolicy, Label: "gcp compute security policies", List: listComputeSecurityPolicies, Event: gcpCloudEvent(gcpcloud.ComputeSecurityPolicyEvent), URN: gcpResourceURN[gcpcloud.ComputeSecurityPolicyRecord]("gcp_compute_security_policy")}), gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeNetworkFirewallPolicyRecord]{Name: familyComputeNetworkFirewallPolicy, Label: "gcp compute network firewall policies", List: listComputeNetworkFirewallPolicies, Event: gcpCloudEvent(gcpcloud.ComputeNetworkFirewallPolicyEvent), URN: gcpResourceURN[gcpcloud.ComputeNetworkFirewallPolicyRecord]("gcp_compute_network_firewall_policy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeSSLCertificateRecord]{Name: familyComputeSSLCertificate, Label: "gcp compute ssl certificates", List: listComputeSSLCertificates, Event: gcpCloudEvent(gcpcloud.ComputeSSLCertificateEvent), URN: gcpResourceURN[gcpcloud.ComputeSSLCertificateRecord]("gcp_compute_ssl_certificate")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeSSLPolicyRecord]{Name: familyComputeSSLPolicy, Label: "gcp compute ssl policies", List: listComputeSSLPolicies, Event: gcpCloudEvent(gcpcloud.ComputeSSLPolicyEvent), URN: gcpResourceURN[gcpcloud.ComputeSSLPolicyRecord]("gcp_compute_ssl_policy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeSubnetworkRecord]{Name: familyComputeSubnetwork, Label: "gcp compute subnetworks", List: listComputeSubnetworks, Event: gcpCloudEvent(gcpcloud.ComputeSubnetworkEvent), URN: gcpResourceURN[gcpcloud.ComputeSubnetworkRecord]("gcp_compute_subnetwork")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetGRPCProxyRecord]{Name: familyComputeTargetGRPCProxy, Label: "gcp compute target grpc proxies", List: listComputeTargetGRPCProxies, Event: gcpCloudEvent(gcpcloud.ComputeTargetGRPCProxyEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetGRPCProxyRecord]("gcp_compute_target_grpc_proxy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetHTTPProxyRecord]{Name: familyComputeTargetHTTPProxy, Label: "gcp compute target http proxies", List: listComputeTargetHTTPProxies, Event: gcpCloudEvent(gcpcloud.ComputeTargetHTTPProxyEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetHTTPProxyRecord]("gcp_compute_target_http_proxy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetHTTPSProxyRecord]{Name: familyComputeTargetHTTPSProxy, Label: "gcp compute target https proxies", List: listComputeTargetHTTPSProxies, Event: gcpCloudEvent(gcpcloud.ComputeTargetHTTPSProxyEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetHTTPSProxyRecord]("gcp_compute_target_https_proxy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetVPNGatewayRecord]{Name: familyComputeTargetVPNGateway, Label: "gcp compute target vpn gateways", List: listComputeTargetVPNGateways, Event: gcpCloudEvent(gcpcloud.ComputeTargetVPNGatewayEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetVPNGatewayRecord]("gcp_compute_target_vpn_gateway")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetSSLProxyRecord]{Name: familyComputeTargetSSLProxy, Label: "gcp compute target ssl proxies", List: listComputeTargetSSLProxies, Event: gcpCloudEvent(gcpcloud.ComputeTargetSSLProxyEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetSSLProxyRecord]("gcp_compute_target_ssl_proxy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeTargetTCPProxyRecord]{Name: familyComputeTargetTCPProxy, Label: "gcp compute target tcp proxies", List: listComputeTargetTCPProxies, Event: gcpCloudEvent(gcpcloud.ComputeTargetTCPProxyEvent), URN: gcpResourceURN[gcpcloud.ComputeTargetTCPProxyRecord]("gcp_compute_target_tcp_proxy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeURLMapRecord]{Name: familyComputeURLMap, Label: "gcp compute url maps", List: listComputeURLMaps, Event: gcpCloudEvent(gcpcloud.ComputeURLMapEvent), URN: gcpResourceURN[gcpcloud.ComputeURLMapRecord]("gcp_compute_url_map")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeVPNGatewayRecord]{Name: familyComputeVPNGateway, Label: "gcp compute vpn gateways", List: listComputeVPNGateways, Event: gcpCloudEvent(gcpcloud.ComputeVPNGatewayEvent), URN: gcpResourceURN[gcpcloud.ComputeVPNGatewayRecord]("gcp_compute_vpn_gateway")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeVPNTunnelRecord]{Name: familyComputeVPNTunnel, Label: "gcp compute vpn tunnels", List: listComputeVPNTunnels, Event: gcpCloudEvent(gcpcloud.ComputeVPNTunnelEvent), URN: gcpResourceURN[gcpcloud.ComputeVPNTunnelRecord]("gcp_compute_vpn_tunnel")}),
		gcpFamily(s, gcpFamilyOptions[firewallRecord]{
			Name:  familyComputeFirewall,
			Label: "gcp compute firewall rules",
			List:  listComputeFirewalls,
			Event: gcpCloudEvent(gcpcloud.ComputeFirewallEvent),
			URN: func(settings settings, firewall firewallRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_firewall:%s", tenantID(settings), firstNonEmpty(firewall.ID, firewall.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeForwardingRuleRecord]{Name: familyComputeForwardingRule, Label: "gcp compute forwarding rules", List: listComputeForwardingRules, Event: gcpCloudEvent(gcpcloud.ComputeForwardingRuleEvent), URN: gcpResourceURN[gcpcloud.ComputeForwardingRuleRecord]("gcp_compute_forwarding_rule")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ComputeDiskRecord]{Name: familyComputeDisk, Label: "gcp compute disks", List: listComputeDisks, Event: gcpCloudEvent(gcpcloud.ComputeDiskEvent), URN: gcpResourceURN[gcpcloud.ComputeDiskRecord]("gcp_compute_disk")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.DNSManagedZoneRecord]{
			Name:  familyDNSManagedZone,
			Label: "gcp cloud dns managed zones",
			List:  listDNSManagedZones,
			Event: gcpCloudEvent(gcpcloud.DNSManagedZoneEvent),
			URN: func(settings settings, zone gcpcloud.DNSManagedZoneRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_dns_managed_zone:%s", tenantID(settings), firstNonEmpty(zone.ID, zone.Name, zone.DNSName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.DNSRecordSetRecord]{
			Name:  familyDNSRecordSet,
			Label: "gcp cloud dns record sets",
			List:  listDNSRecordSets,
			Event: gcpCloudEvent(gcpcloud.DNSRecordSetEvent),
			URN: func(settings settings, recordSet gcpcloud.DNSRecordSetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_dns_record_set:%s:%s:%s", tenantID(settings), gcpcloud.SanitizeURNPart(recordSet.ManagedZoneName), gcpcloud.SanitizeURNPart(recordSet.Name), gcpcloud.SanitizeURNPart(recordSet.Type)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "gcp cloud identity groups",
			List:  listGroups,
			Event: gcpCloudEvent(gcpcloud.GroupEvent),
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group:%s", tenantID(settings), firstNonEmpty(group.GroupKey.ID, group.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[membershipRecord]{
			Name:  familyGroupMember,
			Label: "gcp cloud identity group memberships",
			List:  listGroupMemberships,
			Event: gcpCloudEvent(gcpcloud.GroupMembershipEvent),
			URN: func(settings settings, member membershipRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group_membership:%s:%s", tenantID(settings), settings.groupKey, firstNonEmpty(member.PreferredMemberKey.ID, member.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.GCSBucketRecord]{
			Name:  familyGCSBucket,
			Label: "gcp cloud storage buckets",
			List:  listGCSBuckets,
			Event: gcpCloudEvent(gcpcloud.GCSBucketEvent),
			URN: func(settings settings, bucket gcpcloud.GCSBucketRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gcs_bucket:%s", tenantID(settings), firstNonEmpty(bucket.ID, bucket.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.GCSObjectRecord]{
			Name:  familyGCSObject,
			Label: "gcp cloud storage objects",
			List:  listGCSObjects,
			Event: gcpCloudEvent(gcpcloud.GCSObjectEvent),
			URN: func(settings settings, object gcpcloud.GCSObjectRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gcs_object:%s:%s", tenantID(settings), gcpcloud.SanitizeURNPart(object.Bucket), gcpcloud.SanitizeURNPart(firstNonEmpty(object.Name, object.ID))), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.GKEClusterRecord]{
			Name:  familyGKECluster,
			Label: "gcp gke clusters",
			List:  listGKEClusters,
			Event: gcpCloudEvent(gcpcloud.GKEClusterEvent),
			URN: func(settings settings, cluster gcpcloud.GKEClusterRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gke_cluster:%s", tenantID(settings), firstNonEmpty(cluster.SelfLink, cluster.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.GKENodePoolRecord]{
			Name:  familyGKENodePool,
			Label: "gcp gke node pools",
			List:  listGKENodePools,
			Event: gcpCloudEvent(gcpcloud.GKENodePoolEvent),
			URN: func(settings settings, nodePool gcpcloud.GKENodePoolRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gke_node_pool:%s", tenantID(settings), firstNonEmpty(nodePool.SelfLink, nodePool.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.KMSKeyRecord]{
			Name:  familyKMSKey,
			Label: "gcp kms keys",
			List:  listKMSKeys,
			Event: kmsKeyEvent,
			URN: func(settings settings, key gcpcloud.KMSKeyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_kms_key:%s", tenantID(settings), key.Name), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.LoggingSinkRecord]{
			Name:  familyLoggingSink,
			Label: "gcp cloud logging project sinks",
			List:  listLoggingSinks,
			Event: gcpCloudEvent(gcpcloud.LoggingSinkEvent),
			URN: func(settings settings, sink gcpcloud.LoggingSinkRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_logging_project_sink:%s", tenantID(settings), firstNonEmpty(sink.ResourceName, "projects/"+settings.projectID+"/sinks/"+sink.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.LoggingMetricRecord]{Name: familyLoggingMetric, Label: "gcp cloud logging metrics", List: listLoggingMetrics, Event: gcpCloudEvent(gcpcloud.LoggingMetricEvent), URN: func(settings settings, metric gcpcloud.LoggingMetricRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_logging_metric:%s", tenantID(settings), gcpcloud.LoggingMetricResourceName(settings.projectID, metric)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.MonitoringAlertPolicyRecord]{Name: familyMonitoringAlertPolicy, Label: "gcp monitoring alert policies", List: listMonitoringAlertPolicies, Event: gcpCloudEvent(gcpcloud.MonitoringAlertPolicyEvent), URN: gcpResourceURN[gcpcloud.MonitoringAlertPolicyRecord]("gcp_monitoring_alert_policy")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.MonitoringNotificationChannelRecord]{Name: familyMonitoringNotificationChannel, Label: "gcp monitoring notification channels", List: listMonitoringNotificationChannels, Event: gcpCloudEvent(gcpcloud.MonitoringNotificationChannelEvent), URN: gcpResourceURN[gcpcloud.MonitoringNotificationChannelRecord]("gcp_monitoring_notification_channel")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.OrgPolicyRecord]{Name: familyOrgPolicy, Label: "gcp organization policies", List: listOrgPolicies, Event: gcpCloudEvent(gcpcloud.OrgPolicyEvent), URN: func(settings settings, policy gcpcloud.OrgPolicyRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_org_policy:%s", tenantID(settings), firstNonEmpty(policy.Name, settings.projectID)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.PubSubTopicRecord]{
			Name:  familyPubSubTopic,
			Label: "gcp pubsub topics",
			List:  listPubSubTopics,
			Event: gcpCloudEvent(gcpcloud.PubSubTopicEvent),
			URN: func(settings settings, topic gcpcloud.PubSubTopicRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_pubsub_topic:%s", tenantID(settings), firstNonEmpty(topic.Name, settings.projectID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.PubSubSubscriptionRecord]{
			Name:  familyPubSubSubscription,
			Label: "gcp pubsub subscriptions",
			List:  listPubSubSubscriptions,
			Event: gcpCloudEvent(gcpcloud.PubSubSubscriptionEvent),
			URN: func(settings settings, subscription gcpcloud.PubSubSubscriptionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_pubsub_subscription:%s", tenantID(settings), firstNonEmpty(subscription.Name, settings.projectID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ResourceManagerProjectRecord]{
			Name:  familyResourceProject,
			Label: "gcp resource manager projects",
			List:  listResourceManagerProjects,
			Event: gcpCloudEvent(gcpcloud.ResourceManagerProjectEvent),
			URN: func(settings settings, project gcpcloud.ResourceManagerProjectRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_resourcemanager_project:%s", tenantID(settings), firstNonEmpty(project.ProjectID, settings.projectID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[roleAssignmentRecord]{
			Name:  familyRoleAssign,
			Label: "gcp iam role assignments",
			List:  listRoleAssignments,
			Event: gcpCloudEvent(gcpcloud.RoleAssignmentEvent),
			URN: func(settings settings, assignment roleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_iam_role_assignment:%s:%s", tenantID(settings), gcpcloud.SanitizeURNPart(assignment.Member), gcpcloud.SanitizeURNPart(assignment.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[roleAssignmentRecord]{
			Name:  familyEffectivePermission,
			Label: "gcp effective permissions",
			List:  listRoleAssignments,
			Event: gcpCloudEvent(gcpcloud.EffectivePermissionEvent),
			URN: func(settings settings, assignment roleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_effective_permission:%s:%s", tenantID(settings), gcpcloud.SanitizeURNPart(assignment.Member), gcpcloud.SanitizeURNPart(assignment.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[firewallRecord]{
			Name:  familyResourceExposure,
			Label: "gcp resource exposures",
			List:  listResourceExposures,
			Event: resourceExposureEvent,
			URN: func(settings settings, firewall firewallRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_resource_exposure:%s", tenantID(settings), firstNonEmpty(firewall.ID, firewall.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountImpersonationRecord]{
			Name:  familySAImpersonation,
			Label: "gcp service account impersonation bindings",
			List:  listServiceAccountImpersonation,
			Event: serviceAccountImpersonationEvent,
			URN: func(settings settings, binding serviceAccountImpersonationRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account_impersonation:%s:%s", tenantID(settings), gcpcloud.SanitizeURNPart(binding.Member), gcpcloud.SanitizeURNPart(binding.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SecurityCenterFindingRecord]{Name: familySecurityCenterFinding, Label: "gcp security command center findings", List: listSecurityCenterFindings, ListWithCheckpoint: listSecurityCenterFindingsWithCheckpoint, Event: gcpCloudEvent(gcpcloud.SecurityCenterFindingEvent), URN: func(settings settings, finding gcpcloud.SecurityCenterFindingRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_security_center_finding:%s", tenantID(settings), firstNonEmpty(finding.Finding.Name, finding.Finding.ResourceName, finding.Resource.Name)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountRecord]{
			Name:  familyServiceAcct,
			Label: "gcp service accounts",
			List:  listServiceAccounts,
			Event: gcpCloudEvent(gcpcloud.ServiceAccountEvent),
			URN: func(settings settings, account serviceAccountRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account:%s", tenantID(settings), firstNonEmpty(account.Email, account.UniqueID, account.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.ServiceUsageServiceRecord]{Name: familyServiceUsageService, Label: "gcp service usage services", List: listServiceUsageServices, Event: gcpCloudEvent(gcpcloud.ServiceUsageServiceEvent), URN: func(settings settings, service gcpcloud.ServiceUsageServiceRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_service_usage_service:%s", tenantID(settings), firstNonEmpty(service.Name, service.Config.Name)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SpannerInstanceRecord]{Name: familySpannerInstance, Label: "gcp spanner instances", List: listSpannerInstances, Event: gcpCloudEvent(gcpcloud.SpannerInstanceEvent), URN: gcpResourceURN[gcpcloud.SpannerInstanceRecord]("gcp_spanner_instance")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SpannerDatabaseRecord]{Name: familySpannerDatabase, Label: "gcp spanner databases", List: listSpannerDatabases, Event: gcpCloudEvent(gcpcloud.SpannerDatabaseEvent), URN: gcpResourceURN[gcpcloud.SpannerDatabaseRecord]("gcp_spanner_database")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.VPCAccessConnectorRecord]{Name: familyVPCAccessConnector, Label: "gcp serverless vpc access connectors", List: listVPCAccessConnectors, Event: gcpCloudEvent(gcpcloud.VPCAccessConnectorEvent), URN: gcpResourceURN[gcpcloud.VPCAccessConnectorRecord]("gcp_vpc_access_connector")}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountKeyRecord]{
			Name:  familySAKey,
			Label: "gcp service account keys",
			List:  listServiceAccountKeys,
			Event: gcpCloudEvent(gcpcloud.ServiceAccountKeyEvent),
			URN: func(settings settings, key serviceAccountKeyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account_key:%s", tenantID(settings), firstNonEmpty(key.Name, settings.serviceAccountEmail)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SecretRecord]{
			Name:  familySecret,
			Label: "gcp secret manager secrets",
			List:  listSecrets,
			Event: gcpCloudEvent(gcpcloud.SecretEvent),
			URN: func(settings settings, secret gcpcloud.SecretRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_secret_manager_secret:%s", tenantID(settings), secret.Name), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SecretVersionRecord]{Name: familySecretVersion, Label: "gcp secret manager versions", List: listSecretVersions, Event: gcpCloudEvent(gcpcloud.SecretVersionEvent), URN: func(settings settings, version gcpcloud.SecretVersionRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_secret_manager_version:%s", tenantID(settings), version.Name), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.WorkloadIdentityPoolRecord]{Name: familyWorkloadIdentityPool, Label: "gcp workload identity pools", List: listWorkloadIdentityPools, Event: gcpCloudEvent(gcpcloud.WorkloadIdentityPoolEvent), URN: gcpResourceURN[gcpcloud.WorkloadIdentityPoolRecord]("gcp_workload_identity_pool")}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.WorkloadIdentityProviderRecord]{Name: familyWorkloadIdentityProvider, Label: "gcp workload identity providers", List: listWorkloadIdentityProviders, Event: gcpCloudEvent(gcpcloud.WorkloadIdentityProviderEvent), URN: gcpResourceURN[gcpcloud.WorkloadIdentityProviderRecord]("gcp_workload_identity_provider")}),
	)
}

func gcpFamily[T any](source *Source, options gcpFamilyOptions[T]) sourcecdk.Family[settings] {
	family := sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			return gcpcloud.CheckList(ctx, source, settings, tenantID(settings), options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, source, settings)
			}
			records, _, err := options.List(ctx, source, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			return gcpcloud.URNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return gcpcloud.PullFromRecords(records, next, build)
		},
	}
	if options.ListWithCheckpoint != nil {
		family.ReadWithCheckpoint = func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
			readCheckpoint := sourcecdk.IncrementalCheckpointForCursor("gcp", options.Name, cursor, checkpoint)
			token := sourcecdk.IncrementalCursorToken("gcp", options.Name, cursor, checkpoint)
			records, next, err := options.ListWithCheckpoint(ctx, source, settings, token, settings.perPage, readCheckpoint)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return sourcecdk.IncrementalPullFromRecords("gcp", options.Name, records, next, readCheckpoint, build)
		}
	}
	return family
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:              sourcecdk.ConfigValue(cfg, "family"),
		projectID:           sourcecdk.ConfigValue(cfg, "project_id"),
		customerID:          sourcecdk.ConfigValue(cfg, "customer_id"),
		groupKey:            sourcecdk.ConfigValue(cfg, "group_key"),
		serviceAccountEmail: sourcecdk.ConfigValue(cfg, "service_account_email"),
		location:            sourcecdk.ConfigValue(cfg, "location"),
		keyRing:             sourcecdk.ConfigValue(cfg, "key_ring"),
		artifactRepository:  sourcecdk.ConfigValue(cfg, "artifact_repository"),
		token:               sourcecdk.ConfigValue(cfg, "token"),
		wifAudience:         sourcecdk.ConfigValue(cfg, "wif_audience"),
		wifServiceAccount:   sourcecdk.ConfigValue(cfg, "wif_service_account_email"),
		wifAWSRegion:        sourcecdk.ConfigValue(cfg, "wif_aws_region"),
		tenantID:            sourcecdk.ConfigValue(cfg, sourceconfig.RuntimeTenantIDKey),
		wifBindings:         sourcecdk.ConfigValue(cfg, sourceconfig.GCPWIFAllowlistKey),
		baseURL:             strings.TrimRight(sourcecdk.ConfigValue(cfg, "base_url"), "/"),
		filter:              sourcecdk.ConfigValue(cfg, "filter"),
		perPage:             defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse gcp per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("gcp per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	if err := sourceconfig.ValidateGCPTokenOrWIF(settings.token, settings.wifAudience, settings.wifServiceAccount, settings.tenantID, settings.wifBindings); err != nil {
		return settings, err
	}
	switch settings.family {
	case familyAssetMetadata, familyAIDataset, familyAIEndpoint, familyArtifactRepo, familyAudit, familyBinaryAuthorizationPolicy, familyBinaryAuthorizationAttestor, familyBigQueryDataset, familyBigQueryTable, familyBigtableInstance, familyBigtableTable, familyCertificateManagerCertificate, familyCertificateManagerCertificateMap, familyCertificateManagerCertificateMapEntry, familyCertificateManagerDNSAuthorization, familyCloudFunction, familyCloudIDSEndpoint, familyCloudSchedulerJob, familyCloudRunRevision, familyCloudRunService, familyCloudSQLDatabase, familyCloudSQLInstance, familyCloudSQLUser, familyContainerRegistry, familyContainerVuln, familyComputeAddress, familyComputeBackendBucket, familyComputeBackendService, familyComputeDisk, familyComputeExternalVPNGateway, familyComputeFirewall, familyComputeForwardingRule, familyComputeHealthCheck, familyComputeInstance, familyComputeInstanceGroup, familyComputeInstanceGroupMgr, familyComputeInstanceTemplate, familyComputeInterconnect, familyComputeInterconnectAttachment, familyComputeNetworkEndpointGroup, familyComputeNetworkFirewallPolicy, familyComputeNetwork, familyComputePacketMirroring, familyComputeRoute, familyComputeRouter, familyComputeSecurityPolicy, familyComputeSSLCertificate, familyComputeSSLPolicy, familyComputeSubnetwork, familyComputeTargetGRPCProxy, familyComputeTargetHTTPProxy, familyComputeTargetHTTPSProxy, familyComputeTargetSSLProxy, familyComputeTargetTCPProxy, familyComputeTargetVPNGateway, familyComputeURLMap, familyComputeVPNGateway, familyComputeVPNTunnel, familyDNSManagedZone, familyDNSRecordSet, familyEffectivePermission, familyGCSBucket, familyGCSObject, familyGKECluster, familyGKENodePool, familyLoggingMetric, familyLoggingSink, familyMonitoringAlertPolicy, familyMonitoringNotificationChannel, familyOrgPolicy, familyPubSubSubscription, familyPubSubTopic, familyResourceExposure, familyResourceProject, familyRoleAssign, familySecret, familySecretVersion, familySecurityCenterFinding, familyServiceAcct, familyServiceUsageService, familySpannerDatabase, familySpannerInstance, familyVPCAccessConnector, familyWorkloadIdentityPool, familyWorkloadIdentityProvider:
		if settings.projectID == "" {
			return settings, fmt.Errorf("gcp project_id is required when family=%q", settings.family)
		}
	case familyArtifactImage:
		if settings.projectID == "" {
			return settings, fmt.Errorf("gcp project_id is required when family=%q", settings.family)
		}
		if settings.artifactRepository == "" {
			return settings, fmt.Errorf("gcp artifact_repository is required when family=%q", settings.family)
		}
	case familyKMSKey:
		if settings.projectID == "" {
			return settings, fmt.Errorf("gcp project_id is required when family=%q", settings.family)
		}
		if settings.location == "" {
			return settings, fmt.Errorf("gcp location is required when family=%q", settings.family)
		}
		if settings.keyRing == "" {
			return settings, fmt.Errorf("gcp key_ring is required when family=%q", settings.family)
		}
	case familySAImpersonation, familySAKey:
		if settings.projectID == "" {
			return settings, fmt.Errorf("gcp project_id is required when family=%q", settings.family)
		}
		if settings.serviceAccountEmail == "" {
			return settings, fmt.Errorf("gcp service_account_email is required when family=%q", settings.family)
		}
	case familyGroup:
		if settings.customerID == "" {
			return settings, fmt.Errorf("gcp customer_id is required when family=%q", familyGroup)
		}
	case familyGroupMember:
		if settings.groupKey == "" {
			return settings, fmt.Errorf("gcp group_key is required when family=%q", familyGroupMember)
		}
	default:
		return settings, fmt.Errorf("gcp family must be one of asset_metadata, aiplatform_dataset, aiplatform_endpoint, artifact_registry_image, artifact_registry_repository, audit, binary_authorization_policy, binary_authorization_attestor, bigquery_dataset, bigquery_table, bigtable_instance, bigtable_table, certificate_manager_certificate, certificate_manager_certificate_map, certificate_manager_certificate_map_entry, certificate_manager_dns_authorization, cloud_function, cloud_ids_endpoint, cloud_scheduler_job, cloud_run_revision, cloud_run_service, cloud_sql_database, cloud_sql_instance, cloud_sql_user, compute_address, compute_backend_bucket, compute_backend_service, compute_disk, compute_external_vpn_gateway, compute_firewall, compute_forwarding_rule, compute_health_check, compute_instance, compute_instance_group, compute_instance_group_manager, compute_instance_template, compute_interconnect, compute_interconnect_attachment, compute_network_endpoint_group, compute_network_firewall_policy, compute_network, compute_packet_mirroring, compute_route, compute_router, compute_security_policy, compute_ssl_certificate, compute_ssl_policy, compute_subnetwork, compute_target_grpc_proxy, compute_target_http_proxy, compute_target_https_proxy, compute_target_ssl_proxy, compute_target_tcp_proxy, compute_target_vpn_gateway, compute_url_map, compute_vpn_gateway, compute_vpn_tunnel, container_registry, container_vulnerability, dns_managed_zone, dns_record_set, effective_permission, gcs_bucket, gcs_object, gke_cluster, gke_node_pool, group, group_membership, iam_role_assignment, kms_key, logging_metric, logging_project_sink, monitoring_alert_policy, monitoring_notification_channel, org_policy, pubsub_subscription, pubsub_topic, resource_exposure, resourcemanager_project, secret_manager_secret, secret_manager_version, security_center_finding, service_account, service_account_impersonation, service_usage_service, spanner_database, spanner_instance, vpc_access_connector, workload_identity_pool, workload_identity_provider, or service_account_key")
	}
	return settings, nil
}

func assetMetadataEvent(settings settings, record assetMetadataRecord) (*primitives.Event, error) {
	labels := record.Labels
	resourceID := firstNonEmpty(record.Name, record.DisplayName)
	resourceType := firstNonEmpty(record.AssetType, "resource")
	attributes := map[string]string{
		"asset_criticality":   firstNonEmpty(gcpcloud.LabelLookup(labels, "asset_criticality", "business_criticality", "criticality", "tier"), gcpcloud.CriticalityFromLabels(labels)),
		"contains_pci":        gcpcloud.LabelLookup(labels, "contains_pci", "pci"),
		"contains_phi":        gcpcloud.LabelLookup(labels, "contains_phi", "phi"),
		"contains_pii":        gcpcloud.LabelLookup(labels, "contains_pii", "pii"),
		"contains_secrets":    gcpcloud.LabelLookup(labels, "contains_secrets", "secrets"),
		"crown_jewel":         strconv.FormatBool(gcpcloud.CrownJewelFromLabels(labels)),
		"data_classification": gcpcloud.LabelLookup(labels, "data_classification", "data-classification", "classification", "sensitivity", "data_sensitivity"),
		"description":         record.Description,
		"domain":              tenantID(settings),
		"environment":         gcpcloud.LabelLookup(labels, "environment", "env", "stage"),
		"gcp_project_id":      settings.projectID,
		"internet_exposed":    gcpcloud.LabelLookup(labels, "internet_exposed", "internet-exposed", "externally_exposed", "external_exposure"),
		"owner":               gcpcloud.LabelLookup(labels, "owner", "application_owner", "business_owner", "service_owner"),
		"project_id":          settings.projectID,
		"public":              gcpcloud.LabelLookup(labels, "public", "public_access"),
		"region":              record.Location,
		"resource_id":         resourceID,
		"resource_name":       firstNonEmpty(record.DisplayName, resourceID),
		"resource_provider":   "gcp",
		"resource_type":       resourceType,
		"source_provider":     "gcp",
		"team":                gcpcloud.LabelLookup(labels, "team", "squad", "group"),
	}
	payload, err := gcpcloud.PayloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-asset-metadata-"+firstNonEmpty(resourceID, resourceType), "asset.data_sensitivity", "asset/data_sensitivity/v1", payload, attributes, time.Now().UTC())
}

func gcpCloudSettings(settings settings) gcpcloud.Settings {
	return gcpcloud.Settings{ProjectID: settings.projectID, TenantID: tenantID(settings), Location: settings.location, CustomerID: settings.customerID, GroupKey: settings.groupKey, ServiceAccountEmail: settings.serviceAccountEmail}
}

func gcpCloudEvent[T any](build func(gcpcloud.Settings, T) (*primitives.Event, error)) func(settings, T) (*primitives.Event, error) {
	return func(settings settings, record T) (*primitives.Event, error) {
		return build(gcpCloudSettings(settings), record)
	}
}

func kmsKeyEvent(settings settings, record gcpcloud.KMSKeyRecord) (*primitives.Event, error) {
	return gcpcloud.KMSKeyEvent(gcpCloudSettings(settings), record, settings.keyRing)
}

func artifactImageEvent(settings settings, record gcpcloud.ArtifactImageRecord) (*primitives.Event, error) {
	return gcpcloud.ArtifactImageEvent(gcpCloudSettings(settings), record, settings.artifactRepository)
}

func resourceExposureEvent(settings settings, record firewallRecord) (*primitives.Event, error) {
	allowed := firewallPrimaryAllowed(record)
	sourceCIDR := sourcecdk.FirstOpenCIDR(record.SourceRanges)
	resourceID := firstNonEmpty(record.ID, record.Name)
	attributes := map[string]string{
		"action":            "allow",
		"direction":         "ingress",
		"domain":            tenantID(settings),
		"exposed_to":        "public_internet",
		"exposure_id":       firstNonEmpty(record.ID, record.Name),
		"exposure_type":     "public_network_ingress",
		"external_exposure": "true",
		"family":            familyResourceExposure,
		"internet_exposed":  "true",
		"port_range":        strings.Join(allowed.Ports, ","),
		"protocol":          allowed.IPProtocol,
		"public":            "true",
		"resource_id":       resourceID,
		"resource_name":     firstNonEmpty(record.Name, resourceID),
		"resource_provider": "gcp",
		"resource_type":     "firewall_rule",
		"rule_id":           firstNonEmpty(record.ID, record.Name),
		"rule_name":         record.Name,
		"scope":             record.Network,
		"source_cidr":       sourceCIDR,
	}
	payload, err := gcpcloud.PayloadWithRaw(record.Raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-resource-exposure-"+firstNonEmpty(record.ID, record.Name), "gcp.resource_exposure", "gcp/resource_exposure/v1", payload, attributes, time.Now().UTC())
}

func serviceAccountImpersonationEvent(settings settings, record serviceAccountImpersonationRecord) (*primitives.Event, error) {
	return gcpcloud.ServiceAccountImpersonationEvent(gcpCloudSettings(settings), record)
}

func auditEvent(settings settings, record auditRecord) (*primitives.Event, error) {
	return gcpcloud.AuditEvent(gcpCloudSettings(settings), record)
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	gcpcloud.TrimEmptyAttributes(attributes)
	return &primitives.Event{Id: gcpcloud.SanitizeEventID(id), TenantId: tenantID(settings), SourceId: "gcp", Kind: kind, OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: schemaRef, Payload: payload, Attributes: attributes}, nil
}

func getJSON(ctx context.Context, source *Source, settings settings, defaultBaseURL func() string, method string, requestPath string, query url.Values, body any, target any) error {
	return getJSONWithMaxBytes(ctx, source, settings, defaultBaseURL, method, requestPath, query, body, target, 0)
}

func getComputeJSON(ctx context.Context, source *Source, settings settings, requestPath string, query url.Values, target any) error {
	return getJSONWithMaxBytes(ctx, source, settings, computeBaseURL, http.MethodGet, requestPath, query, nil, target, gcpComputeInventoryMaxBodyBytes)
}

func getJSONWithMaxBytes(ctx context.Context, source *Source, settings settings, defaultBaseURL func() string, method string, requestPath string, query url.Values, body any, target any, maxBytes int) error {
	content, _, err := getBytes(ctx, source, settings, defaultBaseURL, method, requestPath, query, body, maxBytes)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func getBytes(ctx context.Context, source *Source, settings settings, defaultBaseURL func() string, method string, requestPath string, query url.Values, body any, maxBytes int) ([]byte, bool, error) {
	baseURL := settings.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL()
	}
	req, err := sourcehttp.NewJSONRequest(ctx, "gcp", baseURL, source != nil && source.allowLoopbackBaseURL, method, requestPath, query, body)
	if err != nil {
		return nil, false, err
	}
	if maxBytes > 0 {
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))
	}
	token, err := gcpBearerToken(ctx, source, settings)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: "gcp"})
	if source != nil && source.client != nil {
		client = source.client
	}
	resp, err := sourcehttp.DoWithRetry(ctx, client, req, sourcehttp.RetryOptions{MaxAttempts: 1, MaxBodyBytes: maxBytes})
	if err != nil {
		return nil, false, fmt.Errorf("request %s: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, false, fmt.Errorf("gcp API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(resp.Body)))
	}
	return resp.Body, sourcehttp.ResponseBodyTruncated(resp.StatusCode, resp.Header.Get("Content-Range"), len(resp.Body), maxBytes), nil
}

func gcpBearerToken(ctx context.Context, source *Source, settings settings) (string, error) {
	if settings.token != "" {
		return settings.token, nil
	}
	if source == nil {
		return "", fmt.Errorf("gcp wif auth requires source")
	}
	cacheKey := settings.wifAudience + "\x00" + settings.wifServiceAccount + "\x00" + settings.wifAWSRegion
	if cached, ok := source.tokenSources.Load(cacheKey); ok {
		return tokenFromSource(cached.(oauth2.TokenSource))
	}
	factory := defaultGCPTokenSource
	if source.tokenSourceFactory != nil {
		factory = source.tokenSourceFactory
	}
	tokenSource, err := factory(ctx, settings)
	if err != nil {
		return "", err
	}
	actual, _ := source.tokenSources.LoadOrStore(cacheKey, oauth2.ReuseTokenSource(nil, tokenSource))
	return tokenFromSource(actual.(oauth2.TokenSource))
}

func tokenFromSource(tokenSource oauth2.TokenSource) (string, error) {
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("fetch gcp access token: %w", err)
	}
	if !token.Valid() || strings.TrimSpace(token.AccessToken) == "" {
		return "", fmt.Errorf("fetch gcp access token: token is invalid")
	}
	return token.AccessToken, nil
}

func defaultGCPTokenSource(ctx context.Context, settings settings) (oauth2.TokenSource, error) {
	region := firstNonEmpty(settings.wifAWSRegion, "us-east-1")
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load aws config for gcp wif: %w", err)
	}
	serviceAccountPath := url.PathEscape(settings.wifServiceAccount)
	return externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience:                       settings.wifAudience,
		SubjectTokenType:               strings.Join([]string{"urn", "ietf", "params", "aws", "token-type", "aws4_request"}, ":"),
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + serviceAccountPath + ":generateAccessToken",
		Scopes:                         []string{gcpCloudPlatformScope},
		AwsSecurityCredentialsSupplier: awsCredentialsSupplier{region: region, config: awsConfig},
	})
}

type awsCredentialsSupplier struct {
	region string
	config awssdk.Config
}

func (s awsCredentialsSupplier) AwsRegion(context.Context, externalaccount.SupplierOptions) (string, error) {
	return s.region, nil
}

func (s awsCredentialsSupplier) AwsSecurityCredentials(ctx context.Context, _ externalaccount.SupplierOptions) (*externalaccount.AwsSecurityCredentials, error) {
	credentials, err := s.config.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve aws credentials for gcp wif: %w", err)
	}
	return &externalaccount.AwsSecurityCredentials{
		AccessKeyID:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
	}, nil
}

func (s *Source) safeClient() *http.Client {
	return sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      "gcp",
		Timeout:       30 * time.Second,
		AllowLoopback: s != nil && s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
}

func firewallPublicIngress(record firewallRecord) bool {
	return strings.EqualFold(record.Direction, "INGRESS") && !record.Disabled && sourcecdk.FirstOpenCIDR(record.SourceRanges) != "" && len(record.Allowed) != 0
}

func firewallPrimaryAllowed(record firewallRecord) gcpcloud.ComputeFirewallAllowed {
	if len(record.Allowed) == 0 {
		return gcpcloud.ComputeFirewallAllowed{IPProtocol: "all"}
	}
	allowed := record.Allowed[0]
	if len(allowed.Ports) == 0 {
		allowed.Ports = []string{"all"}
	}
	return allowed
}

func impersonationRole(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "roles/iam.serviceaccounttokencreator" ||
		normalized == "roles/iam.serviceaccountuser" ||
		normalized == "roles/iam.workloadidentityuser"
}

func tenantID(settings settings) string {
	return firstNonEmpty(settings.projectID, settings.customerID, settings.groupKey)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func aiPlatformBaseURL() string          { return "https://aiplatform.googleapis.com" }
func artifactRegistryBaseURL() string    { return "https://artifactregistry.googleapis.com" }
func binaryAuthorizationBaseURL() string { return "https://binaryauthorization.googleapis.com" }
func bigQueryBaseURL() string            { return "https://bigquery.googleapis.com" }
func bigtableAdminBaseURL() string       { return "https://bigtableadmin.googleapis.com" }
func certificateManagerBaseURL() string  { return "https://certificatemanager.googleapis.com" }
func cloudAssetBaseURL() string          { return "https://cloudasset.googleapis.com" }
func cloudSchedulerBaseURL() string      { return "https://cloudscheduler.googleapis.com" }
func computeBaseURL() string             { return "https://www.googleapis.com" }
func containerAnalysisBaseURL() string   { return "https://containeranalysis.googleapis.com" }
func containerBaseURL() string           { return "https://container.googleapis.com" }
func dnsBaseURL() string                 { return "https://dns.googleapis.com" }
func functionsBaseURL() string           { return "https://cloudfunctions.googleapis.com" }
func identityBaseURL() string            { return "https://cloudidentity.googleapis.com" }
func idsBaseURL() string                 { return "https://ids.googleapis.com" }
func kmsBaseURL() string                 { return "https://cloudkms.googleapis.com" }
func loggingBaseURL() string             { return "https://logging.googleapis.com" }
func monitoringBaseURL() string          { return "https://monitoring.googleapis.com" }
func orgPolicyBaseURL() string           { return "https://orgpolicy.googleapis.com" }
func pubSubBaseURL() string              { return "https://pubsub.googleapis.com" }
func resourceManagerBaseURL() string     { return "https://cloudresourcemanager.googleapis.com" }
func runBaseURL() string                 { return "https://run.googleapis.com" }
func secretManagerBaseURL() string       { return "https://secretmanager.googleapis.com" }
func securityCenterBaseURL() string      { return "https://securitycenter.googleapis.com" }
func serviceBaseURL() string             { return "https://iam.googleapis.com" }
func serviceUsageBaseURL() string        { return "https://serviceusage.googleapis.com" }
func sqlBaseURL() string                 { return "https://sqladmin.googleapis.com" }
func spannerBaseURL() string             { return "https://spanner.googleapis.com" }
func storageBaseURL() string             { return "https://storage.googleapis.com" }
func vpcAccessBaseURL() string           { return "https://vpcaccess.googleapis.com" }
