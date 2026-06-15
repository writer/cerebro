package gcp

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
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
	defaultFamily                    = familyAudit
	defaultPageSize                  = 10
	maxPageSize                      = 200
	familyAssetMetadata              = "asset_metadata"
	familyAIDataset                  = "aiplatform_dataset"
	familyAIEndpoint                 = "aiplatform_endpoint"
	familyArtifactImage              = "artifact_registry_image"
	familyArtifactRepo               = "artifact_registry_repository"
	familyAudit                      = "audit"
	familyBigQueryDataset            = "bigquery_dataset"
	familyCloudFunction              = "cloud_function"
	familyCloudIDSEndpoint           = "cloud_ids_endpoint"
	familyCloudRunRevision           = "cloud_run_revision"
	familyCloudRunService            = "cloud_run_service"
	familyCloudSQLInstance           = "cloud_sql_instance"
	familyContainerVuln              = "container_vulnerability"
	familyComputeDisk                = "compute_disk"
	familyComputeFirewall            = "compute_firewall"
	familyComputeInstance            = "compute_instance"
	familyComputeNetwork             = "compute_network"
	familyComputeSubnetwork          = "compute_subnetwork"
	familyDNSManagedZone             = "dns_managed_zone"
	familyDNSRecordSet               = "dns_record_set"
	familyEffectivePermission        = "effective_permission"
	familyGCSBucket, familyGCSObject = "gcs_bucket", "gcs_object"
	familyGKECluster                 = "gke_cluster"
	familyGKENodePool                = "gke_node_pool"
	familyGroup, familyGroupMember   = "group", "group_membership"
	familyKMSKey                     = "kms_key"
	familyLoggingSink                = "logging_project_sink"
	familyResourceProject            = "resourcemanager_project"
	familyRoleAssign                 = "iam_role_assignment"
	familyResourceExposure           = "resource_exposure"
	familySAImpersonation            = "service_account_impersonation"
	familyServiceAcct                = "service_account"
	familySAKey                      = "service_account_key"
	gcpCloudPlatformScope            = "https://www.googleapis.com/auth/cloud-platform"
	familySecret                     = "secret_manager_secret"
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
	family              string
	projectID           string
	customerID          string
	groupKey            string
	serviceAccountEmail string
	location            string
	keyRing             string
	artifactRepository  string
	token               string
	wifAudience         string
	wifServiceAccount   string
	wifAWSRegion        string
	baseURL             string
	filter              string
	perPage             int
}

type pageResponse struct {
	Accounts      []json.RawMessage `json:"accounts"`
	Policies      []json.RawMessage `json:"policies"`
	Groups        []json.RawMessage `json:"groups"`
	Items         []json.RawMessage `json:"items"`
	Memberships   []json.RawMessage `json:"memberships"`
	Entries       []json.RawMessage `json:"entries"`
	Keys          []json.RawMessage `json:"keys"`
	Results       []json.RawMessage `json:"results"`
	Clusters      []json.RawMessage `json:"clusters"`
	Datasets      []json.RawMessage `json:"datasets"`
	Services      []json.RawMessage `json:"services"`
	Revisions     []json.RawMessage `json:"revisions"`
	Functions     []json.RawMessage `json:"functions"`
	Secrets       []json.RawMessage `json:"secrets"`
	CryptoKeys    []json.RawMessage `json:"cryptoKeys"`
	Endpoints     []json.RawMessage `json:"endpoints"`
	ManagedZones  []json.RawMessage `json:"managedZones"`
	RRSets        []json.RawMessage `json:"rrsets"`
	NodePools     []json.RawMessage `json:"nodePools"`
	Repositories  []json.RawMessage `json:"repositories"`
	Occurrences   []json.RawMessage `json:"occurrences"`
	Sinks         []json.RawMessage `json:"sinks"`
	DockerImages  []json.RawMessage `json:"dockerImages"`
	NextPageToken string            `json:"nextPageToken"`
}

type computeAggregatedListResponse struct {
	Items         map[string]computeScopedResources `json:"items"`
	NextPageToken string                            `json:"nextPageToken"`
}

type computeScopedResources struct {
	Disks       []json.RawMessage `json:"disks"`
	Instances   []json.RawMessage `json:"instances"`
	Subnetworks []json.RawMessage `json:"subnetworks"`
}

type serviceAccountRecord = gcpcloud.ServiceAccountRecord
type serviceAccountKeyRecord = gcpcloud.ServiceAccountKeyRecord
type groupRecord = gcpcloud.GroupRecord

type lookupGroupResponse struct {
	Name     string    `json:"name"`
	GroupKey entityKey `json:"groupKey"`
}

type membershipRecord = gcpcloud.MembershipRecord
type entityKey = gcpcloud.EntityKey

type policyResponse struct {
	Bindings []policyBinding `json:"bindings"`
}

type policyBinding = gcpcloud.IAMBinding
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

type computeInstanceRecord struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Zone              string                    `json:"zone"`
	MachineType       string                    `json:"machineType"`
	Status            string                    `json:"status"`
	Labels            map[string]string         `json:"labels"`
	Tags              computeTags               `json:"tags"`
	NetworkInterfaces []computeNetworkInterface `json:"networkInterfaces"`
	ServiceAccounts   []computeServiceAccount   `json:"serviceAccounts"`
	Disks             []computeDisk             `json:"disks"`
	raw               json.RawMessage
}

type computeTags struct {
	Items []string `json:"items"`
}

type computeNetworkInterface struct {
	Network       string                `json:"network"`
	Subnetwork    string                `json:"subnetwork"`
	NetworkIP     string                `json:"networkIP"`
	AccessConfigs []computeAccessConfig `json:"accessConfigs"`
}

type computeAccessConfig struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	NatIP string `json:"natIP"`
}

type computeServiceAccount struct {
	Email  string   `json:"email"`
	Scopes []string `json:"scopes"`
}

type computeDisk struct {
	Boot              bool              `json:"boot"`
	AutoDelete        bool              `json:"autoDelete"`
	Source            string            `json:"source"`
	DiskEncryptionKey diskEncryptionKey `json:"diskEncryptionKey"`
}

type diskEncryptionKey struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type computeNetworkRecord struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name"`
	SelfLink              string               `json:"selfLink"`
	Description           string               `json:"description"`
	AutoCreateSubnetworks bool                 `json:"autoCreateSubnetworks"`
	RoutingConfig         computeRoutingConfig `json:"routingConfig"`
	Labels                map[string]string    `json:"labels"`
	raw                   json.RawMessage
}

type computeRoutingConfig struct {
	RoutingMode string `json:"routingMode"`
}

type computeSubnetworkRecord struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	SelfLink              string            `json:"selfLink"`
	Network               string            `json:"network"`
	Region                string            `json:"region"`
	IPCIDRRange           string            `json:"ipCidrRange"`
	PrivateIPGoogleAccess bool              `json:"privateIpGoogleAccess"`
	Purpose               string            `json:"purpose"`
	Role                  string            `json:"role"`
	StackType             string            `json:"stackType"`
	Labels                map[string]string `json:"labels"`
	raw                   json.RawMessage
}

type computeDiskRecord struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	SelfLink          string            `json:"selfLink"`
	Zone              string            `json:"zone"`
	Region            string            `json:"region"`
	Type              string            `json:"type"`
	Status            string            `json:"status"`
	SizeGB            string            `json:"sizeGb"`
	Users             []string          `json:"users"`
	Labels            map[string]string `json:"labels"`
	DiskEncryptionKey diskEncryptionKey `json:"diskEncryptionKey"`
	raw               json.RawMessage
}

type cloudIDSEndpointRecord = gcpcloud.CloudIDSEndpointRecord
type dnsManagedZoneRecord = gcpcloud.DNSManagedZoneRecord
type aiDatasetRecord = gcpcloud.AIDatasetRecord
type aiEndpointRecord = gcpcloud.AIEndpointRecord

type gkeClusterRecord struct {
	Name                           string                            `json:"name"`
	SelfLink                       string                            `json:"selfLink"`
	Location                       string                            `json:"location"`
	Endpoint                       string                            `json:"endpoint"`
	Status                         string                            `json:"status"`
	Network                        string                            `json:"network"`
	Subnetwork                     string                            `json:"subnetwork"`
	CurrentMasterVersion           string                            `json:"currentMasterVersion"`
	ResourceLabels                 map[string]string                 `json:"resourceLabels"`
	NodeConfig                     gkeNodeConfig                     `json:"nodeConfig"`
	PrivateClusterConfig           gkePrivateClusterConfig           `json:"privateClusterConfig"`
	MasterAuthorizedNetworksConfig gkeMasterAuthorizedNetworksConfig `json:"masterAuthorizedNetworksConfig"`
	DatabaseEncryption             gkeDatabaseEncryption             `json:"databaseEncryption"`
	raw                            json.RawMessage
}

type gkeNodeConfig struct {
	ServiceAccount string            `json:"serviceAccount"`
	Tags           []string          `json:"tags"`
	Labels         map[string]string `json:"labels"`
}

type gkePrivateClusterConfig struct {
	EnablePrivateNodes    bool   `json:"enablePrivateNodes"`
	EnablePrivateEndpoint bool   `json:"enablePrivateEndpoint"`
	MasterIpv4CidrBlock   string `json:"masterIpv4CidrBlock"`
}

type gkeMasterAuthorizedNetworksConfig struct {
	Enabled    bool           `json:"enabled"`
	CidrBlocks []gkeCidrBlock `json:"cidrBlocks"`
}

type gkeCidrBlock struct {
	CidrBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName"`
}

type gkeDatabaseEncryption struct {
	State   string `json:"state"`
	KeyName string `json:"keyName"`
}

type gkeNodePoolRecord = gcpcloud.GKENodePoolRecord

type cloudRunServiceRecord = gcpcloud.CloudRunServiceRecord
type cloudFunctionRecord = gcpcloud.CloudFunctionRecord

type cloudSQLInstanceRecord = gcpcloud.CloudSQLInstanceRecord
type gcsBucketRecord = gcpcloud.GCSBucketRecord
type gcsObjectRecord = gcpcloud.GCSObjectRecord

type secretRecord = gcpcloud.SecretRecord
type kmsKeyRecord = gcpcloud.KMSKeyRecord

type artifactRepositoryRecord = gcpcloud.ArtifactRepositoryRecord
type artifactImageRecord = gcpcloud.ArtifactImageRecord

type bigQueryDatasetRecord = gcpcloud.BigQueryDatasetRecord
type cloudRunRevisionRecord = gcpcloud.CloudRunRevisionRecord
type containerVulnerabilityRecord = gcpcloud.ContainerVulnerabilityRecord
type dnsRecordSetRecord = gcpcloud.DNSRecordSetRecord
type loggingSinkRecord = gcpcloud.LoggingSinkRecord
type resourceManagerProjectRecord = gcpcloud.ResourceManagerProjectRecord
type serviceUsageServiceRecord = gcpcloud.ServiceUsageServiceRecord
type orgPolicyRecord = gcpcloud.OrgPolicyRecord

type firewallRecord struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name"`
	Network               string            `json:"network"`
	Direction             string            `json:"direction"`
	Disabled              bool              `json:"disabled"`
	SourceRanges          []string          `json:"sourceRanges"`
	Allowed               []firewallAllowed `json:"allowed"`
	TargetTags            []string          `json:"targetTags"`
	TargetServiceAccounts []string          `json:"targetServiceAccounts"`
	raw                   json.RawMessage
}

type firewallAllowed struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}

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
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family },
		gcpFamily(s, gcpFamilyOptions[assetMetadataRecord]{
			Name:  familyAssetMetadata,
			Label: "gcp asset metadata",
			List:  listAssetMetadata,
			Event: assetMetadataEvent,
			URN: func(settings settings, asset assetMetadataRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_asset_metadata:%s", tenantID(settings), firstNonEmpty(asset.Name, asset.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[aiDatasetRecord]{
			Name:  familyAIDataset,
			Label: "gcp vertex ai datasets",
			List:  listAIDatasets,
			Event: aiDatasetEvent,
			URN: func(settings settings, dataset aiDatasetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_aiplatform_dataset:%s", tenantID(settings), firstNonEmpty(dataset.Name, dataset.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[aiEndpointRecord]{
			Name:  familyAIEndpoint,
			Label: "gcp vertex ai endpoints",
			List:  listAIEndpoints,
			Event: aiEndpointEvent,
			URN: func(settings settings, endpoint aiEndpointRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_aiplatform_endpoint:%s", tenantID(settings), firstNonEmpty(endpoint.Name, endpoint.DisplayName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[artifactImageRecord]{
			Name:  familyArtifactImage,
			Label: "gcp artifact registry images",
			List:  listArtifactImages,
			Event: artifactImageEvent,
			URN: func(settings settings, image artifactImageRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_artifact_registry_image:%s", tenantID(settings), firstNonEmpty(image.URI, image.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[artifactRepositoryRecord]{
			Name:  familyArtifactRepo,
			Label: "gcp artifact registry repositories",
			List:  listArtifactRepositories,
			Event: artifactRepositoryEvent,
			URN: func(settings settings, repo artifactRepositoryRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_artifact_registry_repository:%s", tenantID(settings), firstNonEmpty(repo.Name, repo.Description)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[auditRecord]{
			Name:  familyAudit,
			Label: "gcp audit logs",
			List:  listAuditRecords,
			Event: auditEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := gcpCheck(ctx, source, settings, listAuditRecords, "gcp audit logs"); err != nil {
					return nil, err
				}
				return parseGCPURNs(fmt.Sprintf("urn:cerebro:%s:gcp_project:%s", settings.projectID, settings.projectID))
			},
		}),
		gcpFamily(s, gcpFamilyOptions[bigQueryDatasetRecord]{
			Name:  familyBigQueryDataset,
			Label: "gcp bigquery datasets",
			List:  listBigQueryDatasets,
			Event: bigQueryDatasetEvent,
			URN: func(settings settings, dataset bigQueryDatasetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_bigquery_dataset:%s", tenantID(settings), firstNonEmpty(dataset.ID, dataset.DatasetReference.DatasetID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[cloudFunctionRecord]{
			Name:  familyCloudFunction,
			Label: "gcp cloud functions",
			List:  listCloudFunctions,
			Event: cloudFunctionEvent,
			URN: func(settings settings, fn cloudFunctionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_function:%s", tenantID(settings), firstNonEmpty(fn.Name, fn.ServiceConfig.URI)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[cloudIDSEndpointRecord]{
			Name:  familyCloudIDSEndpoint,
			Label: "gcp cloud ids endpoints",
			List:  listCloudIDSEndpoints,
			Event: cloudIDSEndpointEvent,
			URN: func(settings settings, endpoint cloudIDSEndpointRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_ids_endpoint:%s", tenantID(settings), endpoint.Name), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[cloudRunRevisionRecord]{
			Name:  familyCloudRunRevision,
			Label: "gcp cloud run revisions",
			List:  listCloudRunRevisions,
			Event: cloudRunRevisionEvent,
			URN: func(settings settings, revision cloudRunRevisionRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_revision:%s", tenantID(settings), firstNonEmpty(revision.Name, revision.UID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[cloudRunServiceRecord]{
			Name:  familyCloudRunService,
			Label: "gcp cloud run services",
			List:  listCloudRunServices,
			Event: cloudRunServiceEvent,
			URN: func(settings settings, service cloudRunServiceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_run_service:%s", tenantID(settings), firstNonEmpty(service.Name, service.UID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[cloudSQLInstanceRecord]{
			Name:  familyCloudSQLInstance,
			Label: "gcp cloud sql instances",
			List:  listCloudSQLInstances,
			Event: cloudSQLInstanceEvent,
			URN: func(settings settings, instance cloudSQLInstanceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_cloud_sql_instance:%s", tenantID(settings), firstNonEmpty(instance.SelfLink, instance.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[containerVulnerabilityRecord]{
			Name:  familyContainerVuln,
			Label: "gcp container vulnerabilities",
			List:  listContainerVulnerabilities,
			Event: containerVulnerabilityEvent,
			URN: func(settings settings, occurrence containerVulnerabilityRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_container_vulnerability:%s", tenantID(settings), firstNonEmpty(occurrence.Name, occurrence.NoteName, occurrence.ResourceURI)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[computeInstanceRecord]{
			Name:  familyComputeInstance,
			Label: "gcp compute instances",
			List:  listComputeInstances,
			Event: computeInstanceEvent,
			URN: func(settings settings, instance computeInstanceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_instance:%s", tenantID(settings), firstNonEmpty(instance.ID, instance.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[computeNetworkRecord]{
			Name:  familyComputeNetwork,
			Label: "gcp compute networks",
			List:  listComputeNetworks,
			Event: computeNetworkEvent,
			URN: func(settings settings, network computeNetworkRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_network:%s", tenantID(settings), firstNonEmpty(network.SelfLink, network.ID, network.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[computeSubnetworkRecord]{
			Name:  familyComputeSubnetwork,
			Label: "gcp compute subnetworks",
			List:  listComputeSubnetworks,
			Event: computeSubnetworkEvent,
			URN: func(settings settings, subnetwork computeSubnetworkRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_subnetwork:%s", tenantID(settings), firstNonEmpty(subnetwork.SelfLink, subnetwork.ID, subnetwork.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[firewallRecord]{
			Name:  familyComputeFirewall,
			Label: "gcp compute firewall rules",
			List:  listComputeFirewalls,
			Event: computeFirewallEvent,
			URN: func(settings settings, firewall firewallRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_firewall:%s", tenantID(settings), firstNonEmpty(firewall.ID, firewall.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[computeDiskRecord]{
			Name:  familyComputeDisk,
			Label: "gcp compute disks",
			List:  listComputeDisks,
			Event: computeDiskEvent,
			URN: func(settings settings, disk computeDiskRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_compute_disk:%s", tenantID(settings), firstNonEmpty(disk.SelfLink, disk.ID, disk.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[dnsManagedZoneRecord]{
			Name:  familyDNSManagedZone,
			Label: "gcp cloud dns managed zones",
			List:  listDNSManagedZones,
			Event: dnsManagedZoneEvent,
			URN: func(settings settings, zone dnsManagedZoneRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_dns_managed_zone:%s", tenantID(settings), firstNonEmpty(zone.ID, zone.Name, zone.DNSName)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[dnsRecordSetRecord]{
			Name:  familyDNSRecordSet,
			Label: "gcp cloud dns record sets",
			List:  listDNSRecordSets,
			Event: dnsRecordSetEvent,
			URN: func(settings settings, recordSet dnsRecordSetRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_dns_record_set:%s:%s:%s", tenantID(settings), sanitizeURNPart(recordSet.ManagedZoneName), sanitizeURNPart(recordSet.Name), sanitizeURNPart(recordSet.Type)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "gcp cloud identity groups",
			List:  listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group:%s", tenantID(settings), firstNonEmpty(group.GroupKey.ID, group.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[membershipRecord]{
			Name:  familyGroupMember,
			Label: "gcp cloud identity group memberships",
			List:  listGroupMemberships,
			Event: groupMembershipEvent,
			URN: func(settings settings, member membershipRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_group_membership:%s:%s", tenantID(settings), settings.groupKey, firstNonEmpty(member.PreferredMemberKey.ID, member.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcsBucketRecord]{
			Name:  familyGCSBucket,
			Label: "gcp cloud storage buckets",
			List:  listGCSBuckets,
			Event: gcsBucketEvent,
			URN: func(settings settings, bucket gcsBucketRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gcs_bucket:%s", tenantID(settings), firstNonEmpty(bucket.ID, bucket.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gcsObjectRecord]{
			Name:  familyGCSObject,
			Label: "gcp cloud storage objects",
			List:  listGCSObjects,
			Event: gcsObjectEvent,
			URN: func(settings settings, object gcsObjectRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gcs_object:%s:%s", tenantID(settings), sanitizeURNPart(object.Bucket), sanitizeURNPart(firstNonEmpty(object.Name, object.ID))), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gkeClusterRecord]{
			Name:  familyGKECluster,
			Label: "gcp gke clusters",
			List:  listGKEClusters,
			Event: gkeClusterEvent,
			URN: func(settings settings, cluster gkeClusterRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gke_cluster:%s", tenantID(settings), firstNonEmpty(cluster.SelfLink, cluster.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[gkeNodePoolRecord]{
			Name:  familyGKENodePool,
			Label: "gcp gke node pools",
			List:  listGKENodePools,
			Event: gkeNodePoolEvent,
			URN: func(settings settings, nodePool gkeNodePoolRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_gke_node_pool:%s", tenantID(settings), firstNonEmpty(nodePool.SelfLink, nodePool.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[kmsKeyRecord]{
			Name:  familyKMSKey,
			Label: "gcp kms keys",
			List:  listKMSKeys,
			Event: kmsKeyEvent,
			URN: func(settings settings, key kmsKeyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_kms_key:%s", tenantID(settings), key.Name), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[loggingSinkRecord]{
			Name:  familyLoggingSink,
			Label: "gcp cloud logging project sinks",
			List:  listLoggingSinks,
			Event: loggingSinkEvent,
			URN: func(settings settings, sink loggingSinkRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_logging_project_sink:%s", tenantID(settings), firstNonEmpty(sink.ResourceName, "projects/"+settings.projectID+"/sinks/"+sink.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[resourceManagerProjectRecord]{
			Name:  familyResourceProject,
			Label: "gcp resource manager projects",
			List:  listResourceManagerProjects,
			Event: resourceManagerProjectEvent,
			URN: func(settings settings, project resourceManagerProjectRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_resourcemanager_project:%s", tenantID(settings), firstNonEmpty(project.ProjectID, settings.projectID)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[roleAssignmentRecord]{
			Name:  familyRoleAssign,
			Label: "gcp iam role assignments",
			List:  listRoleAssignments,
			Event: roleAssignmentEvent,
			URN: func(settings settings, assignment roleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_iam_role_assignment:%s:%s", tenantID(settings), sanitizeURNPart(assignment.Member), sanitizeURNPart(assignment.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[roleAssignmentRecord]{
			Name:  familyEffectivePermission,
			Label: "gcp effective permissions",
			List:  listRoleAssignments,
			Event: effectivePermissionEvent,
			URN: func(settings settings, assignment roleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_effective_permission:%s:%s", tenantID(settings), sanitizeURNPart(assignment.Member), sanitizeURNPart(assignment.Role)), nil
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
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account_impersonation:%s:%s", tenantID(settings), sanitizeURNPart(binding.Member), sanitizeURNPart(binding.Role)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountRecord]{
			Name:  familyServiceAcct,
			Label: "gcp service accounts",
			List:  listServiceAccounts,
			Event: serviceAccountEvent,
			URN: func(settings settings, account serviceAccountRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account:%s", tenantID(settings), firstNonEmpty(account.Email, account.UniqueID, account.Name)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[serviceAccountKeyRecord]{
			Name:  familySAKey,
			Label: "gcp service account keys",
			List:  listServiceAccountKeys,
			Event: serviceAccountKeyEvent,
			URN: func(settings settings, key serviceAccountKeyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_service_account_key:%s", tenantID(settings), firstNonEmpty(key.Name, settings.serviceAccountEmail)), nil
			},
		}),
		gcpFamily(s, gcpFamilyOptions[secretRecord]{
			Name:  familySecret,
			Label: "gcp secret manager secrets",
			List:  listSecrets,
			Event: secretEvent,
			URN: func(settings settings, secret secretRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:gcp_secret_manager_secret:%s", tenantID(settings), secret.Name), nil
			},
		}),
	)
}

func gcpFamily[T any](source *Source, options gcpFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			return gcpCheck(ctx, source, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, source, settings)
			}
			records, _, err := options.List(ctx, source, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			return gcpURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return gcpPullFromRecords(records, next, build)
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
	case familyAssetMetadata, familyAIDataset, familyAIEndpoint, familyArtifactRepo, familyAudit, familyBigQueryDataset, familyCloudFunction, familyCloudIDSEndpoint, familyCloudRunRevision, familyCloudRunService, familyCloudSQLInstance, familyContainerVuln, familyComputeDisk, familyComputeFirewall, familyComputeInstance, familyComputeNetwork, familyComputeSubnetwork, familyDNSManagedZone, familyDNSRecordSet, familyEffectivePermission, familyGCSBucket, familyGCSObject, familyGKECluster, familyGKENodePool, familyLoggingSink, familyResourceExposure, familyResourceProject, familyRoleAssign, familySecret, familyServiceAcct:
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
		return settings, fmt.Errorf("gcp family must be one of asset_metadata, aiplatform_dataset, aiplatform_endpoint, artifact_registry_image, artifact_registry_repository, audit, bigquery_dataset, cloud_function, cloud_ids_endpoint, cloud_run_revision, cloud_run_service, cloud_sql_instance, compute_disk, compute_firewall, compute_instance, compute_network, compute_subnetwork, container_vulnerability, dns_managed_zone, dns_record_set, effective_permission, gcs_bucket, gcs_object, gke_cluster, gke_node_pool, group, group_membership, iam_role_assignment, kms_key, logging_project_sink, resource_exposure, resourcemanager_project, secret_manager_secret, service_account, service_account_impersonation, or service_account_key")
	}
	return settings, nil
}

func listServiceAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, "/v1/projects/"+url.PathEscape(settings.projectID)+"/serviceAccounts", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Accounts, "gcp service account", func(record *serviceAccountRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listServiceAccountKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/serviceAccounts/" + url.PathEscape(settings.serviceAccountEmail) + "/keys"
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Keys, "gcp service account key", func(record *serviceAccountKeyRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "parent": {"customers/" + settings.customerID}}
	addQuery(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Groups, "gcp group", func(record *groupRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]membershipRecord, string, error) {
	groupName, err := resolveGroupName(ctx, source, settings)
	if err != nil {
		return nil, "", err
	}
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/"+groupName+"/memberships", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Memberships, "gcp group membership", func(record *membershipRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
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
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + ":searchAllResources"
	if err := getJSON(ctx, source, settings, cloudAssetBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Results, "gcp asset metadata", func(record *assetMetadataRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listAIDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]aiDatasetRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/datasets"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Datasets, "gcp vertex ai dataset", func(record *aiDatasetRecord, raw json.RawMessage) {
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

func listAIEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]aiEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Endpoints, "gcp vertex ai endpoint", func(record *aiEndpointRecord, raw json.RawMessage) {
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
	path := "/v1/" + escapePathSegments(resourceName) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodPost, path, nil, map[string]any{}, &policy); err != nil {
		if optionalGCPEnrichmentErr(err) == nil {
			return gcpcloud.IAMPolicy{}, nil
		}
		return gcpcloud.IAMPolicy{}, err
	}
	return policy, nil
}

func listBigQueryDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]bigQueryDatasetRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/bigquery/v2/projects/" + url.PathEscape(settings.projectID) + "/datasets"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Datasets, "gcp bigquery dataset", func(record *bigQueryDatasetRecord, raw json.RawMessage) {
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
		if err := optionalGCPServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, detailPath, nil, nil, &raw)); err != nil {
			return nil, "", err
		}
		if len(raw) == 0 {
			continue
		}
		var detailed bigQueryDatasetRecord
		if err := json.Unmarshal(raw, &detailed); err != nil {
			return nil, "", fmt.Errorf("decode gcp bigquery dataset detail: %w", err)
		}
		detailed.Raw = append(json.RawMessage(nil), raw...)
		records[index] = detailed
	}
	return records, response.NextPageToken, nil
}

func listComputeInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
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
	records, err := decodeRecords(rawRecords, "gcp compute instance", func(record *computeInstanceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listComputeNetworks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeNetworkRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/networks"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Items, "gcp compute network", func(record *computeNetworkRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listComputeSubnetworks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeSubnetworkRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/subnetworks"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	rawRecords := computeAggregatedRawRecords(response.Items, func(scoped computeScopedResources) []json.RawMessage { return scoped.Subnetworks }, "region")
	records, err := decodeRecords(rawRecords, "gcp compute subnetwork", func(record *computeSubnetworkRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listComputeFirewalls(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]firewallRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/firewalls"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Items, "gcp compute firewall", func(record *firewallRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listComputeDisks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]computeDiskRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response computeAggregatedListResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/aggregated/disks"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	rawRecords := computeAggregatedRawRecords(response.Items, func(scoped computeScopedResources) []json.RawMessage { return scoped.Disks }, "")
	records, err := decodeRecords(rawRecords, "gcp compute disk", func(record *computeDiskRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listDNSManagedZones(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]dnsManagedZoneRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.ManagedZones, "gcp dns managed zone", func(record *dnsManagedZoneRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listDNSRecordSets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]dnsRecordSetRecord, string, error) {
	zones, next, err := listDNSManagedZones(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]dnsRecordSetRecord, 0)
	for _, zone := range zones {
		if strings.TrimSpace(zone.Name) == "" {
			continue
		}
		query := url.Values{"maxResults": {strconv.Itoa(limit)}}
		var response pageResponse
		path := "/dns/v1/projects/" + url.PathEscape(settings.projectID) + "/managedZones/" + url.PathEscape(zone.Name) + "/rrsets"
		if err := optionalGCPServiceErr(getJSON(ctx, source, settings, dnsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		recordSets, err := decodeRecords(response.RRSets, "gcp dns record set", func(record *dnsRecordSetRecord, raw json.RawMessage) {
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

func computeAggregatedRawRecords(items map[string]computeScopedResources, get func(computeScopedResources) []json.RawMessage, scopeField string) []json.RawMessage {
	rawRecords := make([]json.RawMessage, 0)
	for scope, scoped := range items {
		field := computeAggregatedScopeField(scope, scopeField)
		fieldNeedle := []byte(`"` + field + `"`)
		for _, raw := range get(scoped) {
			if len(raw) == 0 {
				continue
			}
			rawRecords = append(rawRecords, raw)
			if field != "" && scope != "" && !bytes.Contains(raw, fieldNeedle) {
				var withScope map[string]any
				if err := json.Unmarshal(raw, &withScope); err == nil {
					withScope[field] = scope
					if patched, err := json.Marshal(withScope); err == nil {
						rawRecords[len(rawRecords)-1] = patched
					}
				}
			}
		}
	}
	return rawRecords
}

func computeAggregatedScopeField(scope string, fallback string) string {
	switch {
	case strings.HasPrefix(scope, "regions/"):
		return "region"
	case strings.HasPrefix(scope, "zones/"):
		return "zone"
	default:
		return fallback
	}
}

func listGKEClusters(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]gkeClusterRecord, string, error) {
	query := url.Values{}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/clusters"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Clusters, "gcp gke cluster", func(record *gkeClusterRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGKENodePools(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gkeNodePoolRecord, string, error) {
	clusters, next, err := listGKEClusters(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gkeNodePoolRecord, 0)
	for _, cluster := range clusters {
		clusterName := lastPathSegment(cluster.Name)
		if clusterName == "" {
			continue
		}
		location := firstNonEmpty(cluster.Location, locationFromResourceName(cluster.SelfLink), settings.location)
		var response pageResponse
		path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/clusters/" + url.PathEscape(clusterName) + "/nodePools"
		if err := optionalGCPServiceErr(getJSON(ctx, source, settings, containerBaseURL, http.MethodGet, path, nil, nil, &response)); err != nil {
			return nil, "", err
		}
		nodePools, err := decodeRecords(response.NodePools, "gcp gke node pool", func(record *gkeNodePoolRecord, raw json.RawMessage) {
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

func listCloudIDSEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]cloudIDSEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, idsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Endpoints, "gcp cloud ids endpoint", func(record *cloudIDSEndpointRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCloudRunServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]cloudRunServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/services"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Services, "gcp cloud run service", func(record *cloudRunServiceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCloudRunRevisions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]cloudRunRevisionRecord, string, error) {
	services, next, err := listCloudRunServices(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]cloudRunRevisionRecord, 0)
	for _, service := range services {
		if strings.TrimSpace(service.Name) == "" {
			continue
		}
		query := url.Values{"pageSize": {strconv.Itoa(limit)}}
		var response pageResponse
		path := "/v2/" + escapePathSegments(service.Name) + "/revisions"
		if err := optionalGCPServiceErr(getJSON(ctx, source, settings, runBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
			return nil, "", err
		}
		revisions, err := decodeRecords(response.Revisions, "gcp cloud run revision", func(record *cloudRunRevisionRecord, raw json.RawMessage) {
			record.ServiceName = service.Name
			record.ServiceLocation = locationFromResourceName(service.Name)
			record.Raw = append(json.RawMessage(nil), raw...)
		})
		if err != nil {
			return nil, "", err
		}
		records = append(records, revisions...)
	}
	return records, next, nil
}

func listCloudFunctions(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]cloudFunctionRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/locations/-/functions"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, functionsBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Functions, "gcp cloud function", func(record *cloudFunctionRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listContainerVulnerabilities(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]containerVulnerabilityRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	} else {
		query.Set("filter", `kind="VULNERABILITY"`)
	}
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/occurrences"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, containerAnalysisBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Occurrences, "gcp container vulnerability", func(record *containerVulnerabilityRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listCloudSQLInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]cloudSQLInstanceRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/sql/v1beta4/projects/" + url.PathEscape(settings.projectID) + "/instances"
	if err := getJSON(ctx, source, settings, sqlBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Items, "gcp cloud sql instance", func(record *cloudSQLInstanceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listGCSBuckets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcsBucketRecord, string, error) {
	query := url.Values{"project": {settings.projectID}, "maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, "/storage/v1/b", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Items, "gcp storage bucket", func(record *gcsBucketRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGCSObjects(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcsObjectRecord, string, error) {
	buckets, next, err := listGCSBuckets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := make([]gcsObjectRecord, 0)
	for _, bucket := range buckets {
		bucketName := firstNonEmpty(bucket.Name, bucket.ID)
		if strings.TrimSpace(bucketName) == "" {
			continue
		}
		path := "/storage/v1/b/" + url.PathEscape(bucketName) + "/o"
		objects, err := gcpcloud.CollectPages(func(objectPageToken string) ([]gcsObjectRecord, string, error) {
			query := url.Values{"maxResults": {strconv.Itoa(limit)}, "projection": {"full"}}
			addQuery(query, objectPageToken)
			if strings.TrimSpace(settings.filter) != "" {
				query.Set("prefix", settings.filter)
			}
			var response pageResponse
			if err := getJSON(ctx, source, settings, storageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
				return nil, "", err
			}
			objects, err := decodeRecords(response.Items, "gcp storage object", func(record *gcsObjectRecord, raw json.RawMessage) {
				if strings.TrimSpace(record.Bucket) == "" {
					record.Bucket = bucketName
				}
				record.BucketLocation = bucket.Location
				record.Raw = append(json.RawMessage(nil), raw...)
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

func listSecrets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]secretRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/secrets"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, secretManagerBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Secrets, "gcp secret", func(record *secretRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listKMSKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]kmsKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(settings.location) + "/keyRings/" + url.PathEscape(settings.keyRing) + "/cryptoKeys"
	if err := getJSON(ctx, source, settings, kmsBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.CryptoKeys, "gcp kms key", func(record *kmsKeyRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listLoggingSinks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]loggingSinkRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/sinks"
	if err := optionalGCPServiceErr(getJSON(ctx, source, settings, loggingBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Sinks, "gcp logging project sink", func(record *loggingSinkRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listResourceManagerProjects(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]resourceManagerProjectRecord, string, error) {
	var raw json.RawMessage
	path := "/v1/projects/" + url.PathEscape(settings.projectID)
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodGet, path, nil, nil, &raw); err != nil {
		return nil, "", err
	}
	var record resourceManagerProjectRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, "", fmt.Errorf("decode gcp resource manager project: %w", err)
	}
	record.Raw = append(json.RawMessage(nil), raw...)
	serviceParent := firstNonEmpty(record.ProjectNumber, record.ProjectID, settings.projectID)
	services, err := gcpcloud.CollectPages(func(pageToken string) ([]serviceUsageServiceRecord, string, error) {
		return listServiceUsageServices(ctx, source, settings, serviceParent, pageToken, settings.perPage)
	})
	if err != nil && optionalGCPEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.EnabledServices = services
	policies, err := gcpcloud.CollectPages(func(pageToken string) ([]orgPolicyRecord, string, error) {
		return listOrgPolicies(ctx, source, settings, pageToken, settings.perPage)
	})
	if err != nil && optionalGCPEnrichmentErr(err) != nil {
		return nil, "", err
	}
	record.OrgPolicies = policies
	return []resourceManagerProjectRecord{record}, "", nil
}

func listServiceUsageServices(ctx context.Context, source *Source, settings settings, parent string, pageToken string, limit int) ([]serviceUsageServiceRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "filter": {"state:ENABLED"}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(parent) + "/services"
	if err := getJSON(ctx, source, settings, serviceUsageBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Services, "gcp service usage service", func(record *serviceUsageServiceRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listOrgPolicies(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]orgPolicyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/policies"
	if err := getJSON(ctx, source, settings, orgPolicyBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Policies, "gcp organization policy", func(record *orgPolicyRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listArtifactRepositories(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]artifactRepositoryRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/-/repositories"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.Repositories, "gcp artifact registry repository", func(record *artifactRepositoryRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listArtifactImages(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]artifactImageRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/v1/" + escapePathSegments(settings.artifactRepository) + "/dockerImages"
	if err := getJSON(ctx, source, settings, artifactRegistryBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeRecords(response.DockerImages, "gcp artifact registry image", func(record *artifactImageRecord, raw json.RawMessage) {
		record.Raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.NextPageToken, err
}

func listResourceExposures(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]firewallRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	addQuery(query, pageToken)
	var response pageResponse
	path := "/compute/v1/projects/" + url.PathEscape(settings.projectID) + "/global/firewalls"
	if err := getJSON(ctx, source, settings, computeBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	firewalls, err := decodeRecords(response.Items, "gcp firewall", func(record *firewallRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
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
	records, err := decodeRecords(response.Entries, "gcp audit log", func(record *auditRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func serviceAccountEvent(settings settings, record serviceAccountRecord) (*primitives.Event, error) {
	return gcpcloud.ServiceAccountEvent(gcpCloudSettings(settings), record)
}

func serviceAccountKeyEvent(settings settings, record serviceAccountKeyRecord) (*primitives.Event, error) {
	return gcpcloud.ServiceAccountKeyEvent(gcpCloudSettings(settings), record)
}

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	return gcpcloud.GroupEvent(gcpCloudSettings(settings), record)
}

func groupMembershipEvent(settings settings, record membershipRecord) (*primitives.Event, error) {
	return gcpcloud.GroupMembershipEvent(gcpCloudSettings(settings), record)
}

func roleAssignmentEvent(settings settings, record roleAssignmentRecord) (*primitives.Event, error) {
	return gcpcloud.RoleAssignmentEvent(gcpCloudSettings(settings), record)
}

func effectivePermissionEvent(settings settings, record roleAssignmentRecord) (*primitives.Event, error) {
	return gcpcloud.EffectivePermissionEvent(gcpCloudSettings(settings), record)
}

func assetMetadataEvent(settings settings, record assetMetadataRecord) (*primitives.Event, error) {
	labels := record.Labels
	resourceID := firstNonEmpty(record.Name, record.DisplayName)
	resourceType := firstNonEmpty(record.AssetType, "resource")
	attributes := map[string]string{
		"asset_criticality":   firstNonEmpty(labelLookup(labels, "asset_criticality", "business_criticality", "criticality", "tier"), criticalityFromLabels(labels)),
		"contains_pci":        labelLookup(labels, "contains_pci", "pci"),
		"contains_phi":        labelLookup(labels, "contains_phi", "phi"),
		"contains_pii":        labelLookup(labels, "contains_pii", "pii"),
		"contains_secrets":    labelLookup(labels, "contains_secrets", "secrets"),
		"crown_jewel":         boolString(crownJewelFromLabels(labels)),
		"data_classification": labelLookup(labels, "data_classification", "data-classification", "classification", "sensitivity", "data_sensitivity"),
		"description":         record.Description,
		"domain":              tenantID(settings),
		"environment":         labelLookup(labels, "environment", "env", "stage"),
		"gcp_project_id":      settings.projectID,
		"internet_exposed":    labelLookup(labels, "internet_exposed", "internet-exposed", "externally_exposed", "external_exposure"),
		"owner":               labelLookup(labels, "owner", "application_owner", "business_owner", "service_owner"),
		"project_id":          settings.projectID,
		"public":              labelLookup(labels, "public", "public_access"),
		"region":              record.Location,
		"resource_id":         resourceID,
		"resource_name":       firstNonEmpty(record.DisplayName, resourceID),
		"resource_provider":   "gcp",
		"resource_type":       resourceType,
		"source_provider":     "gcp",
		"team":                labelLookup(labels, "team", "squad", "group"),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-asset-metadata-"+firstNonEmpty(resourceID, resourceType), "asset.data_sensitivity", "asset/data_sensitivity/v1", payload, attributes, time.Now().UTC())
}

func computeInstanceEvent(settings settings, record computeInstanceRecord) (*primitives.Event, error) {
	location := shortLocation(record.Zone)
	network := firstComputeNetworkInterface(record)
	publicIP := computePublicIP(record)
	serviceAccountEmail := firstComputeServiceAccountEmail(record)
	attributes := cloudResourceAttributes(settings, familyComputeInstance, firstNonEmpty(record.ID, record.Name), record.Name, "compute_instance", location, record.Labels)
	attributes["zone"] = location
	attributes["machine_type"] = lastPathSegment(record.MachineType)
	attributes["status"] = record.Status
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network"] = lastPathSegment(network.Network)
	attributes["network_url"] = network.Network
	attributes["subnet"] = lastPathSegment(network.Subnetwork)
	attributes["subnet_url"] = network.Subnetwork
	attributes["private_ip"] = network.NetworkIP
	attributes["public_ip"] = publicIP
	attributes["public"] = boolString(publicIP != "")
	attributes["internet_exposed"] = boolString(publicIP != "")
	attributes["external_exposure"] = boolString(publicIP != "")
	attributes["network_tags"] = strings.Join(record.Tags.Items, ",")
	attributes["security_tags"] = strings.Join(record.Tags.Items, ",")
	attributes["kms_key_name"] = computeInstanceKMSKey(record)
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-instance-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_instance", "gcp/compute_instance/v1", payload, attributes, time.Now().UTC())
}

func computeNetworkEvent(settings settings, record computeNetworkRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, familyComputeNetwork, resourceID, record.Name, "compute_network", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["auto_create_subnetworks"] = boolString(record.AutoCreateSubnetworks)
	attributes["routing_mode"] = record.RoutingConfig.RoutingMode
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-"+resourceID, "gcp.compute_network", "gcp/compute_network/v1", payload, attributes, time.Now().UTC())
}

func computeSubnetworkEvent(settings settings, record computeSubnetworkRecord) (*primitives.Event, error) {
	location := shortLocation(record.Region)
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, familyComputeSubnetwork, resourceID, record.Name, "compute_subnetwork", location, record.Labels)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["ip_cidr_range"] = record.IPCIDRRange
	attributes["private_ip_google_access"] = boolString(record.PrivateIPGoogleAccess)
	attributes["purpose"] = record.Purpose
	attributes["role"] = record.Role
	attributes["stack_type"] = record.StackType
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-subnetwork-"+resourceID, "gcp.compute_subnetwork", "gcp/compute_subnetwork/v1", payload, attributes, time.Now().UTC())
}

func computeFirewallEvent(settings settings, record firewallRecord) (*primitives.Event, error) {
	allowed := firewallPrimaryAllowed(record)
	attributes := cloudResourceAttributes(settings, familyComputeFirewall, firstNonEmpty(record.ID, record.Name), record.Name, "compute_firewall", "global", nil)
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["direction"] = record.Direction
	attributes["disabled"] = boolString(record.Disabled)
	attributes["source_ranges"] = strings.Join(record.SourceRanges, ",")
	attributes["target_tags"] = strings.Join(record.TargetTags, ",")
	attributes["target_service_accounts"] = strings.Join(record.TargetServiceAccounts, ",")
	attributes["protocol"] = allowed.IPProtocol
	attributes["ports"] = strings.Join(allowed.Ports, ",")
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-firewall-"+firstNonEmpty(record.ID, record.Name), "gcp.compute_firewall", "gcp/compute_firewall/v1", payload, attributes, time.Now().UTC())
}

func computeDiskEvent(settings settings, record computeDiskRecord) (*primitives.Event, error) {
	location := shortLocation(firstNonEmpty(record.Zone, record.Region))
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, familyComputeDisk, resourceID, record.Name, "compute_disk", location, record.Labels)
	attributes["zone"] = shortLocation(record.Zone)
	attributes["region"] = firstNonEmpty(shortLocation(record.Region), attributes["region"])
	attributes["disk_type"] = lastPathSegment(record.Type)
	attributes["status"] = record.Status
	attributes["size_gb"] = record.SizeGB
	attributes["attached_to"] = strings.Join(record.Users, ",")
	attributes["kms_key_name"] = record.DiskEncryptionKey.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.DiskEncryptionKey.KMSKeyName != "")
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-disk-"+resourceID, "gcp.compute_disk", "gcp/compute_disk/v1", payload, attributes, time.Now().UTC())
}

func gcpCloudSettings(settings settings) gcpcloud.Settings {
	return gcpcloud.Settings{ProjectID: settings.projectID, TenantID: tenantID(settings), Location: settings.location, CustomerID: settings.customerID, GroupKey: settings.groupKey, ServiceAccountEmail: settings.serviceAccountEmail}
}

func dnsManagedZoneEvent(settings settings, record dnsManagedZoneRecord) (*primitives.Event, error) {
	return gcpcloud.DNSManagedZoneEvent(gcpCloudSettings(settings), record)
}

func dnsRecordSetEvent(settings settings, record dnsRecordSetRecord) (*primitives.Event, error) {
	return gcpcloud.DNSRecordSetEvent(gcpCloudSettings(settings), record)
}

func aiDatasetEvent(settings settings, record aiDatasetRecord) (*primitives.Event, error) {
	return gcpcloud.AIDatasetEvent(gcpCloudSettings(settings), record)
}

func aiEndpointEvent(settings settings, record aiEndpointRecord) (*primitives.Event, error) {
	return gcpcloud.AIEndpointEvent(gcpCloudSettings(settings), record)
}

func cloudIDSEndpointEvent(settings settings, record cloudIDSEndpointRecord) (*primitives.Event, error) {
	return gcpcloud.CloudIDSEndpointEvent(gcpCloudSettings(settings), record)
}

func gkeClusterEvent(settings settings, record gkeClusterRecord) (*primitives.Event, error) {
	location := firstNonEmpty(record.Location, locationFromResourceName(record.Name))
	serviceAccountEmail := record.NodeConfig.ServiceAccount
	publicEndpoint := record.Endpoint != "" && !record.PrivateClusterConfig.EnablePrivateEndpoint
	attributes := cloudResourceAttributes(settings, familyGKECluster, firstNonEmpty(record.SelfLink, record.Name), record.Name, "gke_cluster", location, record.ResourceLabels)
	attributes["status"] = record.Status
	attributes["version"] = record.CurrentMasterVersion
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["subnet"] = lastPathSegment(record.Subnetwork)
	attributes["subnet_url"] = record.Subnetwork
	attributes["network_tags"] = strings.Join(record.NodeConfig.Tags, ",")
	attributes["security_tags"] = strings.Join(record.NodeConfig.Tags, ",")
	attributes["endpoint"] = record.Endpoint
	attributes["public_endpoint"] = record.Endpoint
	attributes["private_nodes"] = boolString(record.PrivateClusterConfig.EnablePrivateNodes)
	attributes["private_endpoint"] = boolString(record.PrivateClusterConfig.EnablePrivateEndpoint)
	attributes["master_authorized_networks"] = boolString(record.MasterAuthorizedNetworksConfig.Enabled)
	attributes["authorized_cidrs"] = strings.Join(gkeAuthorizedCIDRs(record), ",")
	attributes["public"] = boolString(publicEndpoint)
	attributes["internet_exposed"] = boolString(publicEndpoint)
	attributes["external_exposure"] = boolString(publicEndpoint)
	attributes["kms_key_name"] = record.DatabaseEncryption.KeyName
	attributes["encryption_state"] = record.DatabaseEncryption.State
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gke-cluster-"+firstNonEmpty(record.SelfLink, record.Name), "gcp.gke_cluster", "gcp/gke_cluster/v1", payload, attributes, time.Now().UTC())
}

func gkeNodePoolEvent(settings settings, record gkeNodePoolRecord) (*primitives.Event, error) {
	return gcpcloud.GKENodePoolEvent(gcpCloudSettings(settings), record)
}

func cloudRunServiceEvent(settings settings, record cloudRunServiceRecord) (*primitives.Event, error) {
	return gcpcloud.CloudRunServiceEvent(gcpCloudSettings(settings), record)
}

func cloudRunRevisionEvent(settings settings, record cloudRunRevisionRecord) (*primitives.Event, error) {
	return gcpcloud.CloudRunRevisionEvent(gcpCloudSettings(settings), record)
}

func cloudFunctionEvent(settings settings, record cloudFunctionRecord) (*primitives.Event, error) {
	return gcpcloud.CloudFunctionEvent(gcpCloudSettings(settings), record)
}

func cloudSQLInstanceEvent(settings settings, record cloudSQLInstanceRecord) (*primitives.Event, error) {
	return gcpcloud.CloudSQLInstanceEvent(gcpCloudSettings(settings), record)
}

func gcsBucketEvent(settings settings, record gcsBucketRecord) (*primitives.Event, error) {
	return gcpcloud.GCSBucketEvent(gcpCloudSettings(settings), record)
}

func gcsObjectEvent(settings settings, record gcsObjectRecord) (*primitives.Event, error) {
	return gcpcloud.GCSObjectEvent(gcpCloudSettings(settings), record)
}

func secretEvent(settings settings, record secretRecord) (*primitives.Event, error) {
	return gcpcloud.SecretEvent(gcpCloudSettings(settings), record)
}

func kmsKeyEvent(settings settings, record kmsKeyRecord) (*primitives.Event, error) {
	return gcpcloud.KMSKeyEvent(gcpCloudSettings(settings), record, settings.keyRing)
}

func loggingSinkEvent(settings settings, record loggingSinkRecord) (*primitives.Event, error) {
	return gcpcloud.LoggingSinkEvent(gcpCloudSettings(settings), record)
}

func artifactRepositoryEvent(settings settings, record artifactRepositoryRecord) (*primitives.Event, error) {
	return gcpcloud.ArtifactRepositoryEvent(gcpCloudSettings(settings), record)
}

func artifactImageEvent(settings settings, record artifactImageRecord) (*primitives.Event, error) {
	return gcpcloud.ArtifactImageEvent(gcpCloudSettings(settings), record, settings.artifactRepository)
}

func bigQueryDatasetEvent(settings settings, record bigQueryDatasetRecord) (*primitives.Event, error) {
	return gcpcloud.BigQueryDatasetEvent(gcpCloudSettings(settings), record)
}

func containerVulnerabilityEvent(settings settings, record containerVulnerabilityRecord) (*primitives.Event, error) {
	return gcpcloud.ContainerVulnerabilityEvent(gcpCloudSettings(settings), record)
}

func resourceManagerProjectEvent(settings settings, record resourceManagerProjectRecord) (*primitives.Event, error) {
	return gcpcloud.ResourceManagerProjectEvent(gcpCloudSettings(settings), record)
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
	payload, err := payloadWithRaw(record.raw, map[string]any{"project_id": settings.projectID})
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

func cloudResourceAttributes(settings settings, family string, resourceID string, resourceName string, resourceType string, location string, labels map[string]string) map[string]string {
	attributes := map[string]string{
		"domain":            tenantID(settings),
		"family":            family,
		"gcp_project_id":    settings.projectID,
		"location":          location,
		"project_id":        settings.projectID,
		"region":            location,
		"resource_id":       resourceID,
		"resource_name":     firstNonEmpty(resourceName, resourceID),
		"resource_provider": "gcp",
		"resource_type":     resourceType,
		"source_provider":   "gcp",
	}
	addLabelAttributes(attributes, labels)
	return attributes
}

func addLabelAttributes(attributes map[string]string, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	if encoded, err := json.Marshal(labels); err == nil {
		attributes["labels"] = string(encoded)
	}
	attributes["owner"] = labelLookup(labels, "owner", "application_owner", "business_owner", "service_owner")
	attributes["team"] = labelLookup(labels, "team", "squad", "group")
	attributes["environment"] = labelLookup(labels, "environment", "env", "stage")
	for key, value := range labels {
		normalized := normalizeLabelKey(key)
		if normalized == "" || strings.TrimSpace(value) == "" {
			continue
		}
		attributes["label_"+normalized] = value
	}
}

func firstComputeNetworkInterface(record computeInstanceRecord) computeNetworkInterface {
	if len(record.NetworkInterfaces) == 0 {
		return computeNetworkInterface{}
	}
	return record.NetworkInterfaces[0]
}

func firstComputeServiceAccountEmail(record computeInstanceRecord) string {
	for _, account := range record.ServiceAccounts {
		if email := strings.TrimSpace(account.Email); email != "" {
			return email
		}
	}
	return ""
}

func computePublicIP(record computeInstanceRecord) string {
	for _, networkInterface := range record.NetworkInterfaces {
		for _, accessConfig := range networkInterface.AccessConfigs {
			if ip := strings.TrimSpace(accessConfig.NatIP); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func computeInstanceKMSKey(record computeInstanceRecord) string {
	for _, disk := range record.Disks {
		if key := strings.TrimSpace(disk.DiskEncryptionKey.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func gkeAuthorizedCIDRs(record gkeClusterRecord) []string {
	cidrs := make([]string, 0, len(record.MasterAuthorizedNetworksConfig.CidrBlocks))
	for _, block := range record.MasterAuthorizedNetworksConfig.CidrBlocks {
		if cidr := strings.TrimSpace(block.CidrBlock); cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

func shortLocation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return lastPathSegment(value)
}

func locationFromResourceName(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		if part == "locations" && index+1 < len(parts) {
			return parts[index+1]
		}
		if part == "zones" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return ""
}

func lastPathSegment(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "/")
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func escapePathSegments(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		parts[index] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: tenantID(settings), SourceId: "gcp", Kind: kind, OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: schemaRef, Payload: payload, Attributes: attributes}, nil
}

func getJSON(ctx context.Context, source *Source, settings settings, defaultBaseURL func() string, method string, requestPath string, query url.Values, body any, target any) error {
	baseURL := settings.baseURL
	if baseURL == "" {
		baseURL = defaultBaseURL()
	}
	baseURL, _, err := sourcehttp.NormalizeBaseURL("gcp", baseURL, source != nil && source.allowLoopbackBaseURL)
	if err != nil {
		return err
	}
	path, err := sourcehttp.NormalizeRequestPath("gcp", requestPath)
	if err != nil {
		return err
	}
	endpoint := baseURL + path
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	var requestBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s request: %w", requestPath, err)
		}
		requestBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	token, err := gcpBearerToken(ctx, source, settings)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: "gcp"})
	if source != nil && source.client != nil {
		client = source.client
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	content, err := sourcehttp.ReadLimitedBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("gcp API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(content)))
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func optionalGCPServiceErr(err error) error {
	if err != nil && (strings.Contains(fmt.Sprint(err), "SERVICE_DISABLED") || strings.Contains(fmt.Sprint(err), "has not been used")) {
		return nil
	}
	return err
}

func optionalGCPEnrichmentErr(err error) error {
	if err == nil {
		return nil
	}
	message := fmt.Sprint(err)
	if strings.Contains(message, "SERVICE_DISABLED") ||
		strings.Contains(message, "has not been used") ||
		strings.Contains(message, "PERMISSION_DENIED") ||
		strings.Contains(message, "IAM_PERMISSION_DENIED") ||
		strings.Contains(message, "gcp API returned 403") {
		return nil
	}
	return err
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

func decodeRecords[T any](rawRecords []json.RawMessage, label string, setRaw func(*T, json.RawMessage)) ([]T, error) {
	records := make([]T, 0, len(rawRecords))
	for _, raw := range rawRecords {
		var record T
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, raw)
		}
		records = append(records, record)
	}
	return records, nil
}

func gcpPullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error)) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		if next != "" {
			return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
		}
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: events[len(events)-1].OccurredAt, CursorOpaque: firstNonEmpty(next, events[len(events)-1].GetId())}}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func gcpCheck[T any](ctx context.Context, source *Source, settings settings, list func(context.Context, *Source, settings, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, source, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, tenantID(settings), err)
	}
	return nil
}

func gcpURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return parseGCPURNs(values...)
}

func parseGCPURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func payloadWithRaw(raw json.RawMessage, values map[string]any) ([]byte, error) {
	payload := map[string]any{}
	for key, value := range values {
		payload[key] = value
	}
	if len(raw) != 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, err
		}
		payload["raw"] = decoded
	}
	return json.Marshal(payload)
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

func firewallPrimaryAllowed(record firewallRecord) firewallAllowed {
	if len(record.Allowed) == 0 {
		return firewallAllowed{IPProtocol: "all"}
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

func boolString(value bool) string {
	return strconv.FormatBool(value)
}

func tenantID(settings settings) string {
	return firstNonEmpty(settings.projectID, settings.customerID, settings.groupKey)
}

func aiPlatformBaseURL() string        { return "https://aiplatform.googleapis.com" }
func artifactRegistryBaseURL() string  { return "https://artifactregistry.googleapis.com" }
func bigQueryBaseURL() string          { return "https://bigquery.googleapis.com" }
func cloudAssetBaseURL() string        { return "https://cloudasset.googleapis.com" }
func computeBaseURL() string           { return "https://www.googleapis.com" }
func containerAnalysisBaseURL() string { return "https://containeranalysis.googleapis.com" }
func containerBaseURL() string         { return "https://container.googleapis.com" }
func dnsBaseURL() string               { return "https://dns.googleapis.com" }
func functionsBaseURL() string         { return "https://cloudfunctions.googleapis.com" }
func identityBaseURL() string          { return "https://cloudidentity.googleapis.com" }
func idsBaseURL() string               { return "https://ids.googleapis.com" }
func kmsBaseURL() string               { return "https://cloudkms.googleapis.com" }
func loggingBaseURL() string           { return "https://logging.googleapis.com" }
func orgPolicyBaseURL() string         { return "https://orgpolicy.googleapis.com" }
func resourceManagerBaseURL() string   { return "https://cloudresourcemanager.googleapis.com" }
func runBaseURL() string               { return "https://run.googleapis.com" }
func secretManagerBaseURL() string     { return "https://secretmanager.googleapis.com" }
func serviceBaseURL() string           { return "https://iam.googleapis.com" }
func serviceUsageBaseURL() string      { return "https://serviceusage.googleapis.com" }
func sqlBaseURL() string               { return "https://sqladmin.googleapis.com" }
func storageBaseURL() string           { return "https://storage.googleapis.com" }

func addQuery(query url.Values, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set("pageToken", strings.TrimSpace(value))
	}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func labelLookup(labels map[string]string, keys ...string) string {
	if len(labels) == 0 {
		return ""
	}
	normalized := map[string]string{}
	for key, value := range labels {
		normalized[normalizeLabelKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeLabelKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeLabelKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func criticalityFromLabels(labels map[string]string) string {
	for _, value := range labels {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "critical", "high", "tier0", "tier_0", "tier-0", "crown_jewel", "crown-jewel":
			return "critical"
		}
	}
	return ""
}

func crownJewelFromLabels(labels map[string]string) bool {
	for _, key := range []string{"crown_jewel", "crown-jewel", "tier0", "tier_0", "business_critical"} {
		if value := strings.ToLower(labelLookup(labels, key)); value == "true" || value == "yes" || value == "1" || value == "critical" {
			return true
		}
	}
	return strings.EqualFold(criticalityFromLabels(labels), "critical")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}

func sanitizeURNPart(value string) string {
	value = strings.ReplaceAll(value, ":", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return strings.Trim(value, "_")
}
