package gcp

import (
	"bytes"
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
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/gcpcloud"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultFamily                                                                                                                                                                                        = familyAudit
	defaultPageSize                                                                                                                                                                                      = 10
	gcsObjectContentSampleBytes                                                                                                                                                                          = 64 << 10
	maxPageSize                                                                                                                                                                                          = 200
	familyAssetMetadata                                                                                                                                                                                  = "asset_metadata"
	familyAIDataset                                                                                                                                                                                      = "aiplatform_dataset"
	familyAIEndpoint                                                                                                                                                                                     = "aiplatform_endpoint"
	familyArtifactImage                                                                                                                                                                                  = "artifact_registry_image"
	familyArtifactRepo                                                                                                                                                                                   = "artifact_registry_repository"
	familyAudit                                                                                                                                                                                          = "audit"
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
	family                                              string
	projectID                                           string
	customerID                                          string
	groupKey                                            string
	serviceAccountEmail                                 string
	location                                            string
	keyRing                                             string
	artifactRepository                                  string
	token, wifAudience, wifServiceAccount, wifAWSRegion string
	baseURL                                             string
	filter                                              string
	perPage                                             int
}

type pageResponse = gcpcloud.GenericPageResponse
type certificateManagerPageResponse = gcpcloud.CertificateManagerPageResponse
type vpcAccessPageResponse = gcpcloud.VPCAccessPageResponse
type securityCenterFindingsPageResponse = gcpcloud.SecurityCenterFindingsPageResponse
type workloadIdentityPoolsPageResponse = gcpcloud.WorkloadIdentityPoolsPageResponse
type workloadIdentityProvidersPageResponse = gcpcloud.WorkloadIdentityProvidersPageResponse
type pubSubPageResponse = gcpcloud.PubSubPageResponse

type computeAggregatedListResponse struct {
	Items         map[string]computeScopedResources `json:"items"`
	NextPageToken string                            `json:"nextPageToken"`
}

type computeScopedResources struct {
	Addresses               []json.RawMessage `json:"addresses"`
	BackendServices         []json.RawMessage `json:"backendServices"`
	Disks                   []json.RawMessage `json:"disks"`
	ForwardingRules         []json.RawMessage `json:"forwardingRules"`
	HealthChecks            []json.RawMessage `json:"healthChecks"`
	Instances               []json.RawMessage `json:"instances"`
	InstanceGroups          []json.RawMessage `json:"instanceGroups"`
	InstanceGroupMgrs       []json.RawMessage `json:"instanceGroupManagers"`
	InstanceTemplates       []json.RawMessage `json:"instanceTemplates"`
	InterconnectAttachments []json.RawMessage `json:"interconnectAttachments"`
	NetworkEndpointGroups   []json.RawMessage `json:"networkEndpointGroups"`
	Routers                 []json.RawMessage `json:"routers"`
	SecurityPolicies        []json.RawMessage `json:"securityPolicies"`
	SSLCertificates         []json.RawMessage `json:"sslCertificates"`
	SSLPolicies             []json.RawMessage `json:"sslPolicies"`
	Subnetworks             []json.RawMessage `json:"subnetworks"`
	TargetTCPProxies        []json.RawMessage `json:"targetTcpProxies"`
	TargetHTTPProxies       []json.RawMessage `json:"targetHttpProxies"`
	TargetHTTPSProxies      []json.RawMessage `json:"targetHttpsProxies"`
	TargetVPNGateways       []json.RawMessage `json:"targetVpnGateways"`
	URLMaps                 []json.RawMessage `json:"urlMaps"`
	VPNGateways             []json.RawMessage `json:"vpnGateways"`
	VPNTunnels              []json.RawMessage `json:"vpnTunnels"`
	computeScopedSecurityResources
}

type computeScopedSecurityResources struct {
	FirewallPolicies []json.RawMessage `json:"firewallPolicies"`
	PacketMirrorings []json.RawMessage `json:"packetMirrorings"`
}

type serviceAccountRecord = gcpcloud.ServiceAccountRecord
type serviceAccountKeyRecord = gcpcloud.ServiceAccountKeyRecord
type groupRecord = gcpcloud.GroupRecord

type lookupGroupResponse struct {
	Name     string             `json:"name"`
	GroupKey gcpcloud.EntityKey `json:"groupKey"`
}

type membershipRecord = gcpcloud.MembershipRecord

type policyResponse struct {
	Bindings []gcpcloud.IAMBinding `json:"bindings"`
}

type roleAssignmentRecord = gcpcloud.RoleAssignmentRecord

type assetMetadataRecord struct {
	Name        string            `json:"name"`
	AssetType   string            `json:"assetType"`
	Project     string            `json:"project"`
	DisplayName string            `json:"displayName"`
	Description string            `json:"description"`
	Location    string            `json:"location"`
	Labels      map[string]string `json:"labels"`
	raw         json.RawMessage
}

type computeInstanceRecord = gcpcloud.ComputeInstanceRecord
type firewallRecord = gcpcloud.ComputeFirewallRecord
type serviceAccountImpersonationRecord = gcpcloud.ServiceAccountImpersonationRecord
type auditRecord = gcpcloud.AuditRecord

type gcpFamilyOptions[T any] struct {
	Name     string
	Label    string
	List     func(context.Context, *Source, settings, string, int) ([]T, string, error)
	Event    func(settings, T) (*primitives.Event, error)
	URN      func(settings, T) (string, error)
	Discover func(context.Context, *Source, settings) ([]sourcecdk.URN, error)
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
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
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
			Name:  familyAudit,
			Label: "gcp audit logs",
			List:  listAuditRecords,
			Event: auditEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := gcpcloud.CheckList(ctx, source, settings, tenantID(settings), listAuditRecords, "gcp audit logs"); err != nil {
					return nil, err
				}
				return gcpcloud.ParseURNs(fmt.Sprintf("urn:cerebro:%s:gcp_project:%s", settings.projectID, settings.projectID))
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
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudFunctionRecord]{
			Name:  familyCloudFunction,
			Label: "gcp cloud functions",
			List:  listCloudFunctions,
			Event: gcpCloudEvent(gcpcloud.CloudFunctionEvent),
			URN: func(settings settings, fn gcpcloud.CloudFunctionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_function:%s", tenantID(settings), firstNonEmpty(fn.Name, fn.ServiceConfig.URI)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudIDSEndpointRecord]{
			Name:  familyCloudIDSEndpoint,
			Label: "gcp cloud ids endpoints",
			List:  listCloudIDSEndpoints,
			Event: gcpCloudEvent(gcpcloud.CloudIDSEndpointEvent),
			URN: func(settings settings, endpoint gcpcloud.CloudIDSEndpointRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_ids_endpoint:%s", tenantID(settings), endpoint.Name), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSchedulerJobRecord]{Name: familyCloudSchedulerJob, Label: "gcp cloud scheduler jobs", List: listCloudSchedulerJobs, Event: gcpCloudEvent(gcpcloud.CloudSchedulerJobEvent), URN: func(settings settings, job gcpcloud.CloudSchedulerJobRecord) (string, error) {
			return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_scheduler_job:%s", tenantID(settings), firstNonEmpty(job.Name, settings.projectID)), nil
		}}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudRunRevisionRecord]{
			Name:  familyCloudRunRevision,
			Label: "gcp cloud run revisions",
			List:  listCloudRunRevisions,
			Event: gcpCloudEvent(gcpcloud.CloudRunRevisionEvent),
			URN: func(settings settings, revision gcpcloud.CloudRunRevisionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_revision:%s", tenantID(settings), firstNonEmpty(revision.Name, revision.UID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudRunServiceRecord]{
			Name:  familyCloudRunService,
			Label: "gcp cloud run services",
			List:  listCloudRunServices,
			Event: gcpCloudEvent(gcpcloud.CloudRunServiceEvent),
			URN: func(settings settings, service gcpcloud.CloudRunServiceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_service:%s", tenantID(settings), firstNonEmpty(service.Name, service.UID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcpcloud.CloudSQLInstanceRecord]{
			Name:  familyCloudSQLInstance,
			Label: "gcp cloud sql instances",
			List:  listCloudSQLInstances,
			Event: gcpCloudEvent(gcpcloud.CloudSQLInstanceEvent),
			URN: func(settings settings, instance gcpcloud.CloudSQLInstanceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_sql_instance:%s", tenantID(settings), firstNonEmpty(instance.SelfLink, instance.Name)), nil
			},
		}),
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
		gcpFamily(s, gcpFamilyOptions[gcpcloud.SecurityCenterFindingRecord]{Name: familySecurityCenterFinding, Label: "gcp security command center findings", List: listSecurityCenterFindings, Event: gcpCloudEvent(gcpcloud.SecurityCenterFindingEvent), URN: func(settings settings, finding gcpcloud.SecurityCenterFindingRecord) (string, error) {
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
	return sourcecdk.Family[settings]{
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
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:              configValue(cfg, "family"),
		projectID:           configValue(cfg, "project_id"),
		customerID:          configValue(cfg, "customer_id"),
		groupKey:            configValue(cfg, "group_key"),
		serviceAccountEmail: configValue(cfg, "service_account_email"),
		location:            configValue(cfg, "location"),
		keyRing:             configValue(cfg, "key_ring"),
		artifactRepository:  configValue(cfg, "artifact_repository"),
		token:               configValue(cfg, "token"),
		wifAudience:         configValue(cfg, "wif_audience"),
		wifServiceAccount:   configValue(cfg, "wif_service_account_email"),
		wifAWSRegion:        configValue(cfg, "wif_aws_region"),
		baseURL:             strings.TrimRight(configValue(cfg, "base_url"), "/"),
		filter:              configValue(cfg, "filter"),
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
	if settings.token == "" {
		if settings.wifAudience == "" && settings.wifServiceAccount == "" {
			return settings, fmt.Errorf("gcp token or wif_audience and wif_service_account_email are required")
		}
		if settings.wifAudience == "" {
			return settings, fmt.Errorf("gcp wif_audience is required when token is not provided")
		}
		if settings.wifServiceAccount == "" {
			return settings, fmt.Errorf("gcp wif_service_account_email is required when token is not provided")
		}
	}
	switch settings.family {
	case familyAssetMetadata, familyAIDataset, familyAIEndpoint, familyArtifactRepo, familyAudit, familyBigQueryDataset, familyBigQueryTable, familyBigtableInstance, familyBigtableTable, familyCertificateManagerCertificate, familyCertificateManagerCertificateMap, familyCertificateManagerCertificateMapEntry, familyCertificateManagerDNSAuthorization, familyCloudFunction, familyCloudIDSEndpoint, familyCloudSchedulerJob, familyCloudRunRevision, familyCloudRunService, familyCloudSQLDatabase, familyCloudSQLInstance, familyCloudSQLUser, familyContainerRegistry, familyContainerVuln, familyComputeAddress, familyComputeBackendBucket, familyComputeBackendService, familyComputeDisk, familyComputeExternalVPNGateway, familyComputeFirewall, familyComputeForwardingRule, familyComputeHealthCheck, familyComputeInstance, familyComputeInstanceGroup, familyComputeInstanceGroupMgr, familyComputeInstanceTemplate, familyComputeInterconnect, familyComputeInterconnectAttachment, familyComputeNetworkEndpointGroup, familyComputeNetworkFirewallPolicy, familyComputeNetwork, familyComputePacketMirroring, familyComputeRoute, familyComputeRouter, familyComputeSecurityPolicy, familyComputeSSLCertificate, familyComputeSSLPolicy, familyComputeSubnetwork, familyComputeTargetGRPCProxy, familyComputeTargetHTTPProxy, familyComputeTargetHTTPSProxy, familyComputeTargetSSLProxy, familyComputeTargetTCPProxy, familyComputeTargetVPNGateway, familyComputeURLMap, familyComputeVPNGateway, familyComputeVPNTunnel, familyDNSManagedZone, familyDNSRecordSet, familyEffectivePermission, familyGCSBucket, familyGCSObject, familyGKECluster, familyGKENodePool, familyLoggingMetric, familyLoggingSink, familyMonitoringAlertPolicy, familyMonitoringNotificationChannel, familyOrgPolicy, familyPubSubSubscription, familyPubSubTopic, familyResourceExposure, familyResourceProject, familyRoleAssign, familySecret, familySecretVersion, familySecurityCenterFinding, familyServiceAcct, familyServiceUsageService, familySpannerDatabase, familySpannerInstance, familyVPCAccessConnector, familyWorkloadIdentityPool, familyWorkloadIdentityProvider:
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
		return settings, fmt.Errorf("gcp family must be one of asset_metadata, aiplatform_dataset, aiplatform_endpoint, artifact_registry_image, artifact_registry_repository, audit, bigquery_dataset, bigquery_table, bigtable_instance, bigtable_table, certificate_manager_certificate, certificate_manager_certificate_map, certificate_manager_certificate_map_entry, certificate_manager_dns_authorization, cloud_function, cloud_ids_endpoint, cloud_scheduler_job, cloud_run_revision, cloud_run_service, cloud_sql_database, cloud_sql_instance, cloud_sql_user, compute_address, compute_backend_bucket, compute_backend_service, compute_disk, compute_external_vpn_gateway, compute_firewall, compute_forwarding_rule, compute_health_check, compute_instance, compute_instance_group, compute_instance_group_manager, compute_instance_template, compute_interconnect, compute_interconnect_attachment, compute_network_endpoint_group, compute_network_firewall_policy, compute_network, compute_packet_mirroring, compute_route, compute_router, compute_security_policy, compute_ssl_certificate, compute_ssl_policy, compute_subnetwork, compute_target_grpc_proxy, compute_target_http_proxy, compute_target_https_proxy, compute_target_ssl_proxy, compute_target_tcp_proxy, compute_target_vpn_gateway, compute_url_map, compute_vpn_gateway, compute_vpn_tunnel, container_registry, container_vulnerability, dns_managed_zone, dns_record_set, effective_permission, gcs_bucket, gcs_object, gke_cluster, gke_node_pool, group, group_membership, iam_role_assignment, kms_key, logging_metric, logging_project_sink, monitoring_alert_policy, monitoring_notification_channel, org_policy, pubsub_subscription, pubsub_topic, resource_exposure, resourcemanager_project, secret_manager_secret, secret_manager_version, security_center_finding, service_account, service_account_impersonation, service_usage_service, spanner_database, spanner_instance, vpc_access_connector, workload_identity_pool, workload_identity_provider, or service_account_key")
	}
	return settings, nil
}

func listServiceAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, "/v1/projects/"+url.PathEscape(settings.projectID)+"/serviceAccounts", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Accounts, "gcp service account", func(record *serviceAccountRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listServiceAccountKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/serviceAccounts/" + url.PathEscape(settings.serviceAccountEmail) + "/keys"
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Keys, "gcp service account key", func(record *serviceAccountKeyRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listWorkloadIdentityPools(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.WorkloadIdentityPoolRecord, string, error) {
	location := firstNonEmpty(settings.location, "global")
	projectID := url.PathEscape(settings.projectID)
	path := "/v1/projects/" + projectID + "/locations/" + url.PathEscape(location) + "/workloadIdentityPools"
	return listPagedRecords[gcpcloud.WorkloadIdentityPoolRecord, workloadIdentityPoolsPageResponse](ctx, source, settings, pageToken, limit, serviceBaseURL, path, "pageSize", "gcp workload identity pool", func(response workloadIdentityPoolsPageResponse) []json.RawMessage {
		return response.WorkloadIdentityPools
	}, true, false, nil)
}

func listWorkloadIdentityProviders(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.WorkloadIdentityProviderRecord, string, error) {
	pools, next, err := listWorkloadIdentityPools(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectWorkloadIdentityProviders(pools, func(poolName string, providerPageToken string) ([]gcpcloud.WorkloadIdentityProviderRecord, string, error) {
		path := "/v1/" + gcpcloud.EscapePathSegments(poolName) + "/providers"
		return listPagedRecords[gcpcloud.WorkloadIdentityProviderRecord, workloadIdentityProvidersPageResponse](ctx, source, settings, providerPageToken, limit, serviceBaseURL, path, "pageSize", "gcp workload identity provider", func(response workloadIdentityProvidersPageResponse) []json.RawMessage {
			return response.WorkloadIdentityPoolProviders
		}, true, false, nil)
	})
	return records, next, nil
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "parent": {"customers/" + settings.customerID}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Groups, "gcp group", func(record *groupRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]membershipRecord, string, error) {
	groupName, err := resolveGroupName(ctx, source, settings)
	if err != nil {
		return nil, "", err
	}
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/"+groupName+"/memberships", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Memberships, "gcp group membership", func(record *membershipRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func resolveGroupName(ctx context.Context, source *Source, settings settings) (string, error) {
	if strings.HasPrefix(settings.groupKey, "groups/") {
		return settings.groupKey, nil
	}
	query := url.Values{"groupKey.id": {settings.groupKey}}
	var response lookupGroupResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups:lookup", query, nil, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Name) == "" {
		return "", fmt.Errorf("gcp group lookup returned empty name for %q", settings.groupKey)
	}
	return response.Name, nil
}

func listRoleAssignments(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]roleAssignmentRecord, string, error) {
	var response policyResponse
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodPost, "/v1/projects/"+url.PathEscape(settings.projectID)+":getIamPolicy", nil, map[string]any{}, &response); err != nil {
		return nil, "", err
	}
	records := make([]roleAssignmentRecord, 0)
	for _, binding := range response.Bindings {
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		for _, member := range binding.Members {
			records = append(records, roleAssignmentRecord{Role: binding.Role, Member: member, Raw: raw})
		}
	}
	return records, "", nil
}

func listAssetMetadata(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]assetMetadataRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + ":searchAllResources"
	if err := getJSON(ctx, source, settings, cloudAssetBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Results, "gcp asset metadata", func(record *assetMetadataRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listAIDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.AIDatasetRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/datasets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Datasets, "gcp vertex ai dataset", func(record *gcpcloud.AIDatasetRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		if strings.TrimSpace(records[index].Name) == "" {
			continue
		}
		policy, err := lookupAIResourcePolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			return nil, "", err
		}
		records[index].IAMPolicy = policy
	}
	return records, response.NextPageToken, nil
}

func listAIEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.AIEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Endpoints, "gcp vertex ai endpoint", func(record *gcpcloud.AIEndpointRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		if strings.TrimSpace(records[index].Name) == "" {
			continue
		}
		policy, err := lookupAIResourcePolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			return nil, "", err
		}
		records[index].IAMPolicy = policy
	}
	return records, response.NextPageToken, nil
}

func lookupAIResourcePolicy(ctx context.Context, source *Source, settings settings, resourceName string) (gcpcloud.IAMPolicy, error) {
	var policy gcpcloud.IAMPolicy
	path := "/v1/" + gcpcloud.EscapePathSegments(resourceName) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodPost, path, nil, map[string]any{}, &policy); err != nil {
		if gcpcloud.OptionalEnrichmentErr(err) == nil {
			return gcpcloud.IAMPolicy{}, nil
		}
		return gcpcloud.IAMPolicy{}, err
	}
	return policy, nil
}

func listBigQueryDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigQueryDatasetRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/bigquery/v2/projects/" + url.PathEscape(settings.projectID) + "/datasets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Datasets, "gcp bigquery dataset", func(record *gcpcloud.BigQueryDatasetRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		datasetID := records[index].DatasetReference.DatasetID
		if strings.TrimSpace(datasetID) == "" {
			continue
		}
		detailPath := "/bigquery/v2/projects/" + url.PathEscape(settings.projectID) + "/datasets/" + url.PathEscape(datasetID)
		var raw json.RawMessage
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, detailPath, nil, nil, &raw)); err != nil {
			return nil, "", err
		}
		if len(raw) == 0 {
			continue
		}
		var detailed gcpcloud.BigQueryDatasetRecord
		if err := json.Unmarshal(raw, &detailed); err != nil {
			return nil, "", fmt.Errorf("decode gcp bigquery dataset detail: %w", err)
		}
		detailed.Raw = append(json.RawMessage(nil), raw...)
		records[index] = detailed
	}
	return records, response.NextPageToken, nil
}

func listBigQueryTables(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigQueryTableRecord, string, error) {
	datasets, next, err := listBigQueryDatasets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectBigQueryTables(settings.projectID, datasets, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listBigtableInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigtableInstanceRecord, string, error) {
	return listPagedRecords[gcpcloud.BigtableInstanceRecord, gcpcloud.BigtablePageResponse](ctx, source, settings, pageToken, limit, bigtableAdminBaseURL, "/v2/projects/"+url.PathEscape(settings.projectID)+"/instances", "", "gcp bigtable instance", func(response gcpcloud.BigtablePageResponse) []json.RawMessage { return response.Instances }, true, false, nil)
}

func listBigtableTables(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigtableTableRecord, string, error) {
	instances, next, err := listBigtableInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectBigtableTables(instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigtableAdminBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listCertificateManagerCertificates(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/certificates"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Certificates, "gcp certificate manager certificate", gcpcloud.SaveRawField[gcpcloud.CertificateManagerCertificateRecord])
	return records, response.NextPageToken, err
}

func listCertificateManagerCertificateMaps(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateMapRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/certificateMaps"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.CertificateMaps, "gcp certificate manager certificate map", gcpcloud.SaveRawField[gcpcloud.CertificateManagerCertificateMapRecord])
	return records, response.NextPageToken, err
}

func listCertificateManagerCertificateMapEntries(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerCertificateMapEntryRecord, string, error) {
	maps, next, err := listCertificateManagerCertificateMaps(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.CertificateManagerCertificateMapEntryRecord, 0)
	for _, certificateMap := range maps {
		if strings.TrimSpace(certificateMap.Name) == "" {
			continue
		}
		entries, err := gcpcloud.CollectPages(func(entryPageToken string) ([]gcpcloud.CertificateManagerCertificateMapEntryRecord, string, error) {
			query := url.Values{"pageSize": {strconv.Itoa(limit)}}
			gcpcloud.AddPageToken(query, entryPageToken)
			if strings.TrimSpace(settings.filter) != "" {
				query.Set("filter", settings.filter)
			}
			var response certificateManagerPageResponse
			path := "/v1/" + gcpcloud.EscapePathSegments(certificateMap.Name) + "/certificateMapEntries"
			if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
				return nil, "", err
			}
			entries, err := gcpcloud.DecodeRecords(response.CertificateMapEntries, "gcp certificate manager certificate map entry", func(record *gcpcloud.CertificateManagerCertificateMapEntryRecord, raw json.RawMessage) {
				record.CertificateMap = certificateMap.Name
				record.Raw = append(json.RawMessage(nil), raw...)
			})
			return entries, response.NextPageToken, err
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, entries...)
	}
	return records, next, nil
}

func listCertificateManagerDNSAuthorizations(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CertificateManagerDNSAuthorizationRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response certificateManagerPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/dnsAuthorizations"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, certificateManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.DNSAuthorizations, "gcp certificate manager dns authorization", gcpcloud.SaveRawField[gcpcloud.CertificateManagerDNSAuthorizationRecord])
	return records, response.NextPageToken, err
}

func listComputeInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/instances"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	rawRecords := make([]json.RawMessage, 0)
	for scope, scoped := range response.Items {
		for _, raw := range scoped.Instances {
			if len(raw) == 0 {
				continue
			}
			rawRecords = append(rawRecords, raw)
			if scope != "" && !bytes.Contains(raw, []byte(`"zone"`)) {
				var withZone map[string]any
				if err := json.Unmarshal(raw, &withZone); err == nil {
					withZone["zone"] = scope
					if patched, err := json.Marshal(withZone); err == nil {
						rawRecords[len(rawRecords)-1] = patched
					}
				}
			}
		}
	}
	records, err := gcpcloud.DecodeRecords(rawRecords, "gcp compute instance", gcpcloud.SaveRawField[computeInstanceRecord])
	return records, response.NextPageToken, err
}

func computeAggregatedLister[T any](collection, label string, selectRecords func(computeScopedResources) []json.RawMessage, scopeField string, extraQuery url.Values) func(context.Context, *Source, settings, string, int) ([]T, string, error) {
	return func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]T, string, error) {
		return listComputeAggregatedRecords[T](ctx, source, settings, pageToken, limit, collection, label, selectRecords, scopeField, extraQuery)
	}
}

func computeGlobalLister[T any](collection, label string, extraQuery url.Values) func(context.Context, *Source, settings, string, int) ([]T, string, error) {
	return func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]T, string, error) {
		query := url.Values{"maxResults": {strconv.Itoa(limit)}}
		for key, values := range extraQuery {
			query[key] = values
		}
		gcpcloud.AddPageToken(query, pageToken)
		var response pageResponse
		path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/" + collection
		if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
			return nil, "", err
		}
		records, err := gcpcloud.DecodeRecords(response.Items, label, gcpcloud.SaveRawField[T])
		return records, response.NextPageToken, err
	}
}

var (
	listComputeBackendServices, listComputeBackendBuckets                                                              = computeAggregatedLister[gcpcloud.ComputeBackendServiceRecord]("backendServices", "gcp compute backend service", func(scoped computeScopedResources) []json.RawMessage { return scoped.BackendServices }, "", nil), computeGlobalLister[gcpcloud.ComputeBackendBucketRecord]("backendBuckets", "gcp compute backend bucket", url.Values{"returnPartialSuccess": {"true"}})
	listComputeAddresses, listComputeSecurityPolicies, listComputeNetworkFirewallPolicies, listComputePacketMirrorings = computeAggregatedLister[gcpcloud.ComputeAddressRecord]("addresses", "gcp compute address", func(scoped computeScopedResources) []json.RawMessage { return scoped.Addresses }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSecurityPolicyRecord]("securityPolicies", "gcp compute security policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.SecurityPolicies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeNetworkFirewallPolicyRecord]("firewallPolicies", "gcp compute network firewall policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.FirewallPolicies }, "region", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputePacketMirroringRecord]("packetMirrorings", "gcp compute packet mirroring", func(scoped computeScopedResources) []json.RawMessage { return scoped.PacketMirrorings }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeSSLCertificates, listComputeSSLPolicies                                                                 = computeAggregatedLister[gcpcloud.ComputeSSLCertificateRecord]("sslCertificates", "gcp compute ssl certificate", func(scoped computeScopedResources) []json.RawMessage { return scoped.SSLCertificates }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSSLPolicyRecord]("sslPolicies", "gcp compute ssl policy", func(scoped computeScopedResources) []json.RawMessage { return scoped.SSLPolicies }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetGRPCProxies, listComputeTargetHTTPProxies                                                         = computeGlobalLister[gcpcloud.ComputeTargetGRPCProxyRecord]("targetGrpcProxies", "gcp compute target grpc proxy", nil), computeAggregatedLister[gcpcloud.ComputeTargetHTTPProxyRecord]("targetHttpProxies", "gcp compute target http proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetHTTPProxies }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetHTTPSProxies, listComputeTargetSSLProxies                                                         = computeAggregatedLister[gcpcloud.ComputeTargetHTTPSProxyRecord]("targetHttpsProxies", "gcp compute target https proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetHTTPSProxies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeTargetSSLProxyRecord]("targetSslProxies", "gcp compute target ssl proxy", nil)
	listComputeTargetTCPProxies, listComputeHealthChecks                                                               = computeAggregatedLister[gcpcloud.ComputeTargetTCPProxyRecord]("targetTcpProxies", "gcp compute target tcp proxy", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetTCPProxies }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeHealthCheckRecord]("healthChecks", "gcp compute health check", func(scoped computeScopedResources) []json.RawMessage { return scoped.HealthChecks }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInstanceGroups, listComputeInstanceGroupManagers                                                        = computeAggregatedLister[gcpcloud.ComputeInstanceGroupRecord]("instanceGroups", "gcp compute instance group", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceGroups }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeInstanceGroupManagerRecord]("instanceGroupManagers", "gcp compute instance group manager", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceGroupMgrs }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInstanceTemplates, listComputeNetworkEndpointGroups                                                     = computeAggregatedLister[gcpcloud.ComputeInstanceTemplateRecord]("instanceTemplates", "gcp compute instance template", func(scoped computeScopedResources) []json.RawMessage { return scoped.InstanceTemplates }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeNetworkEndpointGroupRecord]("networkEndpointGroups", "gcp compute network endpoint group", func(scoped computeScopedResources) []json.RawMessage { return scoped.NetworkEndpointGroups }, "", url.Values{"returnPartialSuccess": {"true"}})
	listComputeInterconnectAttachments, listComputeExternalVPNGateways, listComputeInterconnects, listComputeRouters   = computeAggregatedLister[gcpcloud.ComputeInterconnectAttachmentRecord]("interconnectAttachments", "gcp compute interconnect attachment", func(scoped computeScopedResources) []json.RawMessage { return scoped.InterconnectAttachments }, "", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeExternalVPNGatewayRecord]("externalVpnGateways", "gcp compute external vpn gateway", url.Values{"returnPartialSuccess": {"true"}}), computeGlobalLister[gcpcloud.ComputeInterconnectRecord]("interconnects", "gcp compute interconnect", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeRouterRecord]("routers", "gcp compute router", func(scoped computeScopedResources) []json.RawMessage { return scoped.Routers }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeTargetVPNGateways, listComputeVPNGateways                                                               = computeAggregatedLister[gcpcloud.ComputeTargetVPNGatewayRecord]("targetVpnGateways", "gcp compute target vpn gateway", func(scoped computeScopedResources) []json.RawMessage { return scoped.TargetVPNGateways }, "region", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeVPNGatewayRecord]("vpnGateways", "gcp compute vpn gateway", func(scoped computeScopedResources) []json.RawMessage { return scoped.VPNGateways }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeURLMaps, listComputeSubnetworks, listComputeForwardingRules                                             = computeAggregatedLister[gcpcloud.ComputeURLMapRecord]("urlMaps", "gcp compute url map", func(scoped computeScopedResources) []json.RawMessage { return scoped.URLMaps }, "", url.Values{"returnPartialSuccess": {"true"}}), computeAggregatedLister[gcpcloud.ComputeSubnetworkRecord]("subnetworks", "gcp compute subnetwork", func(scoped computeScopedResources) []json.RawMessage { return scoped.Subnetworks }, "region", nil), computeAggregatedLister[gcpcloud.ComputeForwardingRuleRecord]("forwardingRules", "gcp compute forwarding rule", func(scoped computeScopedResources) []json.RawMessage { return scoped.ForwardingRules }, "", nil)
	listComputeDisks, listComputeNetworks, listComputeRoutes, listComputeVPNTunnels                                    = computeAggregatedLister[gcpcloud.ComputeDiskRecord]("disks", "gcp compute disk", func(scoped computeScopedResources) []json.RawMessage { return scoped.Disks }, "", nil), computeGlobalLister[gcpcloud.ComputeNetworkRecord]("networks", "gcp compute network", nil), computeGlobalLister[gcpcloud.ComputeRouteRecord]("routes", "gcp compute route", nil), computeAggregatedLister[gcpcloud.ComputeVPNTunnelRecord]("vpnTunnels", "gcp compute vpn tunnel", func(scoped computeScopedResources) []json.RawMessage { return scoped.VPNTunnels }, "region", url.Values{"returnPartialSuccess": {"true"}})
	listComputeFirewalls                                                                                               = computeGlobalLister[firewallRecord]("firewalls", "gcp compute firewall", nil)
)

func listComputeAggregatedRecords[T any](ctx context.Context, source *Source, settings settings, pageToken string, limit int, collection string, label string, selectRecords func(computeScopedResources) []json.RawMessage, scopeField string, extraQuery url.Values) ([]T, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	for key, values := range extraQuery {
		query[key] = append(query[key], values...)
	}
	gcpcloud.AddPageToken(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/" + collection
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(gcpcloud.ComputeAggregatedRawRecords(response.Items, selectRecords, scopeField), label, gcpcloud.SaveRawField[T])
	return records, response.NextPageToken, err
}

func listDNSManagedZones(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.DNSManagedZoneRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.ManagedZones, "gcp dns managed zone", func(record *gcpcloud.DNSManagedZoneRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listDNSRecordSets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.DNSRecordSetRecord, string, error) {
	zones, next, err := listDNSManagedZones(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.DNSRecordSetRecord, 0)
	for _, zone := range zones {
		if strings.TrimSpace(zone.Name) == "" {
			continue
		}
		query := url.Values{"maxResults": {strconv.Itoa(limit)}}
		var response pageResponse
		path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones/" + url.PathEscape(zone.Name) + "/rrsets"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		recordSets, err := gcpcloud.DecodeRecords(response.RRSets, "gcp dns record set", func(record *gcpcloud.DNSRecordSetRecord, raw json.RawMessage) {
			record.ManagedZoneName = zone.Name
			record.ManagedZoneDNSName = zone.DNSName
			record.ManagedZoneVisibility = zone.Visibility
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, recordSets...)
	}
	return records, next, nil
}

func listGKEClusters(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]gcpcloud.GKEClusterRecord, string, error) {
	query := url.Values{}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/clusters"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Clusters, "gcp gke cluster", func(record *gcpcloud.GKEClusterRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listGKENodePools(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GKENodePoolRecord, string, error) {
	clusters, next, err := listGKEClusters(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.GKENodePoolRecord, 0)
	for _, cluster := range clusters {
		clusterName := gcpcloud.LastPathSegment(cluster.Name)
		if clusterName == "" {
			continue
		}
		location := firstNonEmpty(cluster.Location, gcpcloud.LocationFromResourceName(cluster.SelfLink), settings.location)
		var response pageResponse
		path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/clusters/" + url.PathEscape(clusterName) + "/nodePools"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, nil, nil, &response)); err != nil {
			return nil, "", err
		}
		nodePools, err := gcpcloud.DecodeRecords(response.NodePools, "gcp gke node pool", func(record *gcpcloud.GKENodePoolRecord, raw json.RawMessage) {
			record.ClusterName = clusterName
			record.ClusterLocation = location
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, nodePools...)
	}
	return records, next, nil
}

func listCloudIDSEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudIDSEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, idsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Endpoints, "gcp cloud ids endpoint", func(record *gcpcloud.CloudIDSEndpointRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil || len(records) == 0 {
		return records, response.NextPageToken, err
	}
	sinks, sinkErr := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.LoggingSinkRecord, string, error) {
		return listLoggingSinks(ctx, source, settings, pageToken, settings.perPage)
	})
	if sinkErr != nil && gcpcloud.OptionalEnrichmentErr(sinkErr) != nil {
		return nil, "", sinkErr
	}
	gcpcloud.AttachCloudIDSLoggingSinks(records, sinks)
	return records, response.NextPageToken, nil
}

func listCloudRunServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudRunServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/services"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Services, "gcp cloud run service", func(record *gcpcloud.CloudRunServiceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCloudRunRevisions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudRunRevisionRecord, string, error) {
	services, next, err := listCloudRunServices(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.CloudRunRevisionRecord, 0)
	for _, service := range services {
		if strings.TrimSpace(service.Name) == "" {
			continue
		}
		query := url.Values{"pageSize": {strconv.Itoa(limit)}}
		var response pageResponse
		path := "/v2/" + gcpcloud.EscapePathSegments(service.Name) + "/revisions"
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		revisions, err := gcpcloud.DecodeRecords(response.Revisions, "gcp cloud run revision", func(record *gcpcloud.CloudRunRevisionRecord, raw json.RawMessage) {
			record.ServiceName = service.Name
			record.ServiceLocation = gcpcloud.LocationFromResourceName(service.Name)
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, revisions...)
	}
	return records, next, nil
}

func listCloudFunctions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudFunctionRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/functions"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, functionsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Functions, "gcp cloud function", func(record *gcpcloud.CloudFunctionRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listVPCAccessConnectors(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.VPCAccessConnectorRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response vpcAccessPageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/connectors"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, vpcAccessBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Connectors, "gcp serverless vpc access connector", gcpcloud.SaveRawField[gcpcloud.VPCAccessConnectorRecord])
	return records, response.NextPageToken, err
}

func listCloudSchedulerJobs(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSchedulerJobRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response gcpcloud.CloudSchedulerJobsResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/jobs"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, cloudSchedulerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Jobs, "gcp cloud scheduler job", func(record *gcpcloud.CloudSchedulerJobRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listContainerVulnerabilities(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ContainerVulnerabilityRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	} else {
		query.Set("filter", `kind="VULNERABILITY"`)
	}
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/occurrences"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, containerAnalysisBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Occurrences, "gcp container vulnerability", func(record *gcpcloud.ContainerVulnerabilityRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listContainerRegistries(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]gcpcloud.ContainerRegistryRecord, string, error) {
	if strings.TrimSpace(pageToken) != "" {
		return nil, "", nil
	}
	records, err := gcpcloud.ListContainerRegistries(settings.projectID, func(path string, query url.Values, target any) error {
		return getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, target)
	})
	return records, "", err
}

func listCloudSQLInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/sql/v1beta4/projects/" + url.PathEscape(settings.projectID) + "/instances"
	if err := getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Items, "gcp cloud sql instance", func(record *gcpcloud.CloudSQLInstanceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCloudSQLDatabases(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLDatabaseRecord, string, error) {
	instances, next, err := listCloudSQLInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectCloudSQLChildRecords(settings.projectID, "databases", "gcp cloud sql database", instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, target))
	}, func(record *gcpcloud.CloudSQLDatabaseRecord, instance gcpcloud.CloudSQLInstanceRecord) {
		record.InstanceName = instance.Name
		record.InstanceRegion = instance.Region
	})
	return records, next, err
}

func listCloudSQLUsers(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.CloudSQLUserRecord, string, error) {
	instances, next, err := listCloudSQLInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectCloudSQLChildRecords(settings.projectID, "users", "gcp cloud sql user", instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, target))
	}, func(record *gcpcloud.CloudSQLUserRecord, instance gcpcloud.CloudSQLInstanceRecord) {
		record.InstanceName = instance.Name
		record.InstanceRegion = instance.Region
	})
	return records, next, err
}

func listGCSBuckets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GCSBucketRecord, string, error) {
	query := url.Values{"project": {settings.projectID}, "maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, "/storage/v1/b", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Items, "gcp storage bucket", func(record *gcpcloud.GCSBucketRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listGCSObjects(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.GCSObjectRecord, string, error) {
	buckets, next, err := listGCSBuckets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcpcloud.GCSObjectRecord, 0)
	for _, bucket := range buckets {
		bucketName := firstNonEmpty(bucket.Name, bucket.ID)
		if strings.TrimSpace(bucketName) == "" {
			continue
		}
		path := "/storage/v1/b/" + url.PathEscape(bucketName) + "/o"
		objects, err := gcpcloud.CollectPages(func(objectPageToken string) ([]gcpcloud.GCSObjectRecord, string, error) {
			query := url.Values{"maxResults": {strconv.Itoa(limit)}, "projection": {"full"}}
			gcpcloud.AddPageToken(query, objectPageToken)
			if strings.TrimSpace(settings.filter) != "" {
				query.Set("prefix", settings.filter)
			}
			var response pageResponse
			if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
				return nil, "", err
			}
			objects, err := gcpcloud.DecodeRecords(response.Items, "gcp storage object", func(record *gcpcloud.GCSObjectRecord, raw json.RawMessage) {
				if strings.TrimSpace(record.Bucket) == "" {
					record.Bucket = bucketName
				}
				record.BucketLocation = bucket.Location
				record.Raw = append(json.RawMessage(nil), raw...)
			})
			gcpcloud.EnrichGCSObjectContentInspections(objects, func(object gcpcloud.GCSObjectRecord) ([]byte, bool, error) {
				path, query := gcpcloud.GCSObjectContentMediaRequest(object)
				return getBytes(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, gcsObjectContentSampleBytes)
			})
			return objects, response.NextPageToken, err
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, objects...)
	}
	return records, next, nil
}

func listSecrets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecretRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/secrets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, secretManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Secrets, "gcp secret", func(record *gcpcloud.SecretRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listSecretVersions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecretVersionRecord, string, error) {
	secrets, next, err := listSecrets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectSecretVersions(secrets, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, secretManagerBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listKMSKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.KMSKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(settings.location) + "/keyRings/" + url.PathEscape(settings.keyRing) + "/cryptoKeys"
	if err := getJSON(ctx, source, settings, kmsBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.CryptoKeys, "gcp kms key", func(record *gcpcloud.KMSKeyRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listLoggingSinks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.LoggingSinkRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/sinks"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, loggingBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Sinks, "gcp logging project sink", func(record *gcpcloud.LoggingSinkRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listMonitoringAlertPolicies(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.MonitoringAlertPolicyRecord, string, error) {
	return listPagedRecords[gcpcloud.MonitoringAlertPolicyRecord, gcpcloud.MonitoringPageResponse](ctx, source, settings, pageToken, limit, monitoringBaseURL, "/v3/projects/"+url.PathEscape(settings.projectID)+"/alertPolicies", "pageSize", "gcp monitoring alert policy", func(response gcpcloud.MonitoringPageResponse) []json.RawMessage { return response.AlertPolicies }, true, true, nil)
}

func listMonitoringNotificationChannels(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.MonitoringNotificationChannelRecord, string, error) {
	return listPagedRecords[gcpcloud.MonitoringNotificationChannelRecord, gcpcloud.MonitoringPageResponse](ctx, source, settings, pageToken, limit, monitoringBaseURL, "/v3/projects/"+url.PathEscape(settings.projectID)+"/notificationChannels", "pageSize", "gcp monitoring notification channel", func(response gcpcloud.MonitoringPageResponse) []json.RawMessage { return response.NotificationChannels }, true, true, nil)
}

func listLoggingMetrics(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.LoggingMetricRecord, string, error) {
	return listPagedRecords[gcpcloud.LoggingMetricRecord, gcpcloud.LoggingMetricsPageResponse](ctx, source, settings, pageToken, limit, loggingBaseURL, "/v2/projects/"+url.PathEscape(settings.projectID)+"/metrics", "pageSize", "gcp logging metric", func(response gcpcloud.LoggingMetricsPageResponse) []json.RawMessage { return response.Metrics }, true, false, nil)
}

func listPagedRecords[T any, R gcpcloud.PageTokenResponse](ctx context.Context, source *Source, settings settings, pageToken string, limit int, defaultBaseURL func() string, path string, pageSizeParam string, label string, selectRecords func(R) []json.RawMessage, optional bool, useFilter bool, extraQuery url.Values) ([]T, string, error) {
	options := gcpcloud.PagedRecordsOptions{PageToken: pageToken, Limit: limit, PageSizeParam: pageSizeParam, Label: label, Optional: optional, UseFilter: useFilter, Filter: settings.filter, ExtraQuery: extraQuery}
	return gcpcloud.ListPagedRecords[T, R](options, func(query url.Values, response *R) error {
		return getJSON(ctx, source, settings, defaultBaseURL, http.MethodGet, path, query, nil, response)
	}, selectRecords)
}

func listPubSubTopics(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.PubSubTopicRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pubSubPageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/topics"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, pubSubBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Topics, "gcp pubsub topic", func(record *gcpcloud.PubSubTopicRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	if err := attachPubSubIAMPolicies(ctx, source, settings, records); err != nil {
		return nil, "", err
	}
	return records, response.NextPageToken, nil
}

func listPubSubSubscriptions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.PubSubSubscriptionRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pubSubPageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/subscriptions"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, pubSubBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Subscriptions, "gcp pubsub subscription", func(record *gcpcloud.PubSubSubscriptionRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	if err := attachPubSubSubscriptionIAMPolicies(ctx, source, settings, records); err != nil {
		return nil, "", err
	}
	return records, response.NextPageToken, nil
}

func attachPubSubIAMPolicies(ctx context.Context, source *Source, settings settings, records []gcpcloud.PubSubTopicRecord) error {
	for index := range records {
		policy, err := getPubSubIAMPolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			if gcpcloud.OptionalEnrichmentErr(err) != nil {
				return err
			}
			continue
		}
		records[index].IAMPolicy = policy
	}
	return nil
}

func attachPubSubSubscriptionIAMPolicies(ctx context.Context, source *Source, settings settings, records []gcpcloud.PubSubSubscriptionRecord) error {
	for index := range records {
		policy, err := getPubSubIAMPolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			if gcpcloud.OptionalEnrichmentErr(err) != nil {
				return err
			}
			continue
		}
		records[index].IAMPolicy = policy
	}
	return nil
}

func getPubSubIAMPolicy(ctx context.Context, source *Source, settings settings, resourceName string) (gcpcloud.IAMPolicy, error) {
	var policy gcpcloud.IAMPolicy
	path := "/v1/" + gcpcloud.EscapePathSegments(resourceName) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, pubSubBaseURL, http.MethodPost, path, nil, map[string]any{"options": map[string]int{"requestedPolicyVersion": 3}}, &policy); err != nil {
		return gcpcloud.IAMPolicy{}, err
	}
	return policy, nil
}

func listResourceManagerProjects(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]gcpcloud.ResourceManagerProjectRecord, string, error) {
	var raw json.RawMessage
	path := "/v1/projects/" + url.PathEscape(settings.projectID)
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodGet, path, nil, nil, &raw); err != nil {
		return nil, "", err
	}
	var record gcpcloud.ResourceManagerProjectRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, "", fmt.Errorf("decode gcp resource manager project: %w", err)
	}
	record.Raw = append(json.RawMessage(nil), raw...)
	serviceSettings := settings
	serviceSettings.projectID = firstNonEmpty(record.ProjectNumber, record.ProjectID, settings.projectID)
	services, err := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.ServiceUsageServiceRecord, string, error) {
		return listServiceUsageServices(ctx, source, serviceSettings, pageToken, settings.perPage)
	})
	if err != nil && gcpcloud.OptionalEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.EnabledServices = services
	policies, err := gcpcloud.CollectPages(func(pageToken string) ([]gcpcloud.OrgPolicyRecord, string, error) {
		return listOrgPolicies(ctx, source, settings, pageToken, settings.perPage)
	})
	if err != nil && gcpcloud.OptionalEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.OrgPolicies = policies
	return []gcpcloud.ResourceManagerProjectRecord{record}, "", nil
}

func listServiceUsageServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ServiceUsageServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "filter": {"state:ENABLED"}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/services"
	if err := getJSON(ctx, source, settings, serviceUsageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Services, "gcp service usage service", func(record *gcpcloud.ServiceUsageServiceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listSpannerInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SpannerInstanceRecord, string, error) {
	return listPagedRecords[gcpcloud.SpannerInstanceRecord, gcpcloud.SpannerPageResponse](ctx, source, settings, pageToken, limit, spannerBaseURL, "/v1/projects/"+url.PathEscape(settings.projectID)+"/instances", "pageSize", "gcp spanner instance", func(response gcpcloud.SpannerPageResponse) []json.RawMessage { return response.Instances }, true, true, nil)
}

func listSpannerDatabases(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SpannerDatabaseRecord, string, error) {
	instances, next, err := listSpannerInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectSpannerDatabases(instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, spannerBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listOrgPolicies(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.OrgPolicyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/policies"
	if err := getJSON(ctx, source, settings, orgPolicyBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Policies, "gcp organization policy", func(record *gcpcloud.OrgPolicyRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listArtifactRepositories(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ArtifactRepositoryRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/repositories"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Repositories, "gcp artifact registry repository", func(record *gcpcloud.ArtifactRepositoryRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listArtifactImages(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.ArtifactImageRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/" + gcpcloud.EscapePathSegments(settings.artifactRepository) + "/dockerImages"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.DockerImages, "gcp artifact registry image", func(record *gcpcloud.ArtifactImageRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listResourceExposures(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]firewallRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/firewalls"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	firewalls, err := gcpcloud.DecodeRecords(response.Items, "gcp firewall", func(record *firewallRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	if err != nil {
		return nil, "", err
	}
	exposed := make([]firewallRecord, 0, len(firewalls))
	for _, firewall := range firewalls {
		if firewallPublicIngress(firewall) {
			exposed = append(exposed, firewall)
		}
	}
	return exposed, response.NextPageToken, nil
}

func listServiceAccountImpersonation(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]serviceAccountImpersonationRecord, string, error) {
	var response policyResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/serviceAccounts/" + url.PathEscape(settings.serviceAccountEmail) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodPost, path, nil, map[string]any{}, &response); err != nil {
		return nil, "", err
	}
	records := make([]serviceAccountImpersonationRecord, 0)
	for _, binding := range response.Bindings {
		if !impersonationRole(binding.Role) {
			continue
		}
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		for _, member := range binding.Members {
			records = append(records, serviceAccountImpersonationRecord{Role: binding.Role, Member: member, Raw: raw})
		}
	}
	return records, "", nil
}

func listSecurityCenterFindings(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecurityCenterFindingRecord, string, error) {
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/sources/-/findings"
	return listPagedRecords[gcpcloud.SecurityCenterFindingRecord, securityCenterFindingsPageResponse](ctx, source, settings, pageToken, limit, securityCenterBaseURL, path, "pageSize", "gcp security command center finding", func(response securityCenterFindingsPageResponse) []json.RawMessage {
		return response.ListFindingsResults
	}, true, true, nil)
}

func listAuditRecords(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]auditRecord, string, error) {
	body := map[string]any{"resourceNames": []string{"projects/" + settings.projectID}, "pageSize": limit}
	if settings.filter != "" {
		body["filter"] = settings.filter
	}
	if pageToken != "" {
		body["pageToken"] = pageToken
	}
	var response pageResponse
	if err := getJSON(ctx, source, settings, loggingBaseURL, http.MethodPost, "/v2/entries:list", nil, body, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Entries, "gcp audit log", func(record *auditRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
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
	sourceCIDR := firstPublicCIDR(record.SourceRanges)
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
	content, _, err := getBytes(ctx, source, settings, defaultBaseURL, method, requestPath, query, body, 0)
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
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, false, fmt.Errorf("marshal %s request: %w", requestPath, err)
		}
	}
	req, err := sourcehttp.NewRequest(ctx, "gcp", baseURL, source != nil && source.allowLoopbackBaseURL, method, requestPath, query, payload)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	if maxBytes > 0 {
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", maxBytes-1))
	}
	token, err := gcpBearerToken(ctx, source, settings)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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
	return strings.EqualFold(record.Direction, "INGRESS") && !record.Disabled && firstPublicCIDR(record.SourceRanges) != "" && len(record.Allowed) != 0
}

func firstPublicCIDR(values []string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "0.0.0.0/0" || trimmed == "::/0" {
			return trimmed
		}
	}
	return ""
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

func aiPlatformBaseURL() string         { return "https://aiplatform.googleapis.com" }
func artifactRegistryBaseURL() string   { return "https://artifactregistry.googleapis.com" }
func bigQueryBaseURL() string           { return "https://bigquery.googleapis.com" }
func bigtableAdminBaseURL() string      { return "https://bigtableadmin.googleapis.com" }
func certificateManagerBaseURL() string { return "https://certificatemanager.googleapis.com" }
func cloudAssetBaseURL() string         { return "https://cloudasset.googleapis.com" }
func cloudSchedulerBaseURL() string     { return "https://cloudscheduler.googleapis.com" }
func computeBaseURL() string            { return "https://www.googleapis.com" }
func containerAnalysisBaseURL() string  { return "https://containeranalysis.googleapis.com" }
func containerBaseURL() string          { return "https://container.googleapis.com" }
func dnsBaseURL() string                { return "https://dns.googleapis.com" }
func functionsBaseURL() string          { return "https://cloudfunctions.googleapis.com" }
func identityBaseURL() string           { return "https://cloudidentity.googleapis.com" }
func idsBaseURL() string                { return "https://ids.googleapis.com" }
func kmsBaseURL() string                { return "https://cloudkms.googleapis.com" }
func loggingBaseURL() string            { return "https://logging.googleapis.com" }
func monitoringBaseURL() string         { return "https://monitoring.googleapis.com" }
func orgPolicyBaseURL() string          { return "https://orgpolicy.googleapis.com" }
func pubSubBaseURL() string             { return "https://pubsub.googleapis.com" }
func resourceManagerBaseURL() string    { return "https://cloudresourcemanager.googleapis.com" }
func runBaseURL() string                { return "https://run.googleapis.com" }
func secretManagerBaseURL() string      { return "https://secretmanager.googleapis.com" }
func securityCenterBaseURL() string     { return "https://securitycenter.googleapis.com" }
func serviceBaseURL() string            { return "https://iam.googleapis.com" }
func serviceUsageBaseURL() string       { return "https://serviceusage.googleapis.com" }
func sqlBaseURL() string                { return "https://sqladmin.googleapis.com" }
func spannerBaseURL() string            { return "https://spanner.googleapis.com" }
func storageBaseURL() string            { return "https://storage.googleapis.com" }
func vpcAccessBaseURL() string          { return "https://vpcaccess.googleapis.com" }

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}
