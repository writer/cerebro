package gcpcloud

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

type Settings struct {
	ProjectID string
	TenantID  string
	Location  string
}

type CloudIDSEndpointRecord struct {
	Name                   string            `json:"name"`
	CreateTime             string            `json:"createTime"`
	UpdateTime             string            `json:"updateTime"`
	Labels                 map[string]string `json:"labels"`
	Network                string            `json:"network"`
	EndpointForwardingRule string            `json:"endpointForwardingRule"`
	EndpointIP             string            `json:"endpointIp"`
	Description            string            `json:"description"`
	Severity               string            `json:"severity"`
	ThreatExceptions       []string          `json:"threatExceptions"`
	State                  string            `json:"state"`
	TrafficLogs            bool              `json:"trafficLogs"`
	Raw                    json.RawMessage   `json:"-"`
}

type DNSManagedZoneRecord struct {
	Name                    string                                `json:"name"`
	DNSName                 string                                `json:"dnsName"`
	Description             string                                `json:"description"`
	ID                      string                                `json:"id"`
	NameServers             []string                              `json:"nameServers"`
	CreationTime            string                                `json:"creationTime"`
	DNSSECConfig            DNSManagedZoneDNSSECConfig            `json:"dnssecConfig"`
	Visibility              string                                `json:"visibility"`
	PrivateVisibilityConfig DNSManagedZonePrivateVisibilityConfig `json:"privateVisibilityConfig"`
	CloudLoggingConfig      DNSManagedZoneCloudLoggingConfig      `json:"cloudLoggingConfig"`
	Labels                  map[string]string                     `json:"labels"`
	Raw                     json.RawMessage                       `json:"-"`
}

type DNSManagedZoneDNSSECConfig struct {
	State        string `json:"state"`
	NonExistence string `json:"nonExistence"`
}

type DNSManagedZonePrivateVisibilityConfig struct {
	Networks []DNSManagedZoneNetwork `json:"networks"`
}

type DNSManagedZoneNetwork struct {
	NetworkURL string `json:"networkUrl"`
}

type DNSManagedZoneCloudLoggingConfig struct {
	EnableLogging bool `json:"enableLogging"`
}

type CloudRunServiceRecord struct {
	Name     string                   `json:"name"`
	UID      string                   `json:"uid"`
	URI      string                   `json:"uri"`
	Ingress  string                   `json:"ingress"`
	Labels   map[string]string        `json:"labels"`
	Template CloudRunRevisionTemplate `json:"template"`
	Raw      json.RawMessage          `json:"-"`
}

type CloudRunRevisionTemplate struct {
	ServiceAccount string              `json:"serviceAccount"`
	Containers     []CloudRunContainer `json:"containers"`
	VpcAccess      CloudRunVpcAccess   `json:"vpcAccess"`
}

type CloudRunContainer struct {
	Image string `json:"image"`
}

type CloudRunVpcAccess struct {
	Connector string `json:"connector"`
	Egress    string `json:"egress"`
}

type CloudFunctionRecord struct {
	Name          string                     `json:"name"`
	Description   string                     `json:"description"`
	State         string                     `json:"state"`
	Environment   string                     `json:"environment"`
	Labels        map[string]string          `json:"labels"`
	ServiceConfig CloudFunctionServiceConfig `json:"serviceConfig"`
	Raw           json.RawMessage            `json:"-"`
}

type CloudFunctionServiceConfig struct {
	ServiceAccountEmail        string `json:"serviceAccountEmail"`
	URI                        string `json:"uri"`
	IngressSettings            string `json:"ingressSettings"`
	VpcConnector               string `json:"vpcConnector"`
	VpcConnectorEgressSettings string `json:"vpcConnectorEgressSettings"`
	KMSKeyName                 string `json:"kmsKeyName"`
}

type CloudSQLInstanceRecord struct {
	Name                       string                   `json:"name"`
	SelfLink                   string                   `json:"selfLink"`
	Region                     string                   `json:"region"`
	GCEZone                    string                   `json:"gceZone"`
	DatabaseVersion            string                   `json:"databaseVersion"`
	State                      string                   `json:"state"`
	InstanceType               string                   `json:"instanceType"`
	BackendType                string                   `json:"backendType"`
	ServiceAccountEmailAddress string                   `json:"serviceAccountEmailAddress"`
	Settings                   CloudSQLSettings         `json:"settings"`
	IPAddresses                []CloudSQLIPAddress      `json:"ipAddresses"`
	DiskEncryptionConfig       CloudSQLEncryptionConfig `json:"diskEncryptionConfiguration"`
	Raw                        json.RawMessage          `json:"-"`
}

type CloudSQLSettings struct {
	ActivationPolicy    string                  `json:"activationPolicy"`
	AvailabilityType    string                  `json:"availabilityType"`
	DataDiskType        string                  `json:"dataDiskType"`
	StorageAutoResize   bool                    `json:"storageAutoResize"`
	DeletionProtection  bool                    `json:"deletionProtectionEnabled"`
	UserLabels          map[string]string       `json:"userLabels"`
	BackupConfiguration CloudSQLBackupConfig    `json:"backupConfiguration"`
	IPConfiguration     CloudSQLIPConfiguration `json:"ipConfiguration"`
}

type CloudSQLBackupConfig struct {
	Enabled                    bool   `json:"enabled"`
	PointInTimeRecoveryEnabled bool   `json:"pointInTimeRecoveryEnabled"`
	StartTime                  string `json:"startTime"`
}

type CloudSQLIPConfiguration struct {
	IPv4Enabled        bool                    `json:"ipv4Enabled"`
	PrivateNetwork     string                  `json:"privateNetwork"`
	RequireSSL         bool                    `json:"requireSsl"`
	AuthorizedNetworks []CloudSQLAuthorizedNet `json:"authorizedNetworks"`
}

type CloudSQLAuthorizedNet struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CloudSQLIPAddress struct {
	IPAddress string `json:"ipAddress"`
	Type      string `json:"type"`
}

type CloudSQLEncryptionConfig struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type GKENodePoolRecord struct {
	Name             string                 `json:"name"`
	SelfLink         string                 `json:"selfLink"`
	Version          string                 `json:"version"`
	Status           string                 `json:"status"`
	Locations        []string               `json:"locations"`
	InitialNodeCount int                    `json:"initialNodeCount"`
	Config           GKENodePoolConfig      `json:"config"`
	Management       GKENodePoolManagement  `json:"management"`
	Autoscaling      GKENodePoolAutoscaling `json:"autoscaling"`
	ClusterName      string
	ClusterLocation  string
	Raw              json.RawMessage `json:"-"`
}

type GKENodePoolConfig struct {
	MachineType              string                    `json:"machineType"`
	DiskType                 string                    `json:"diskType"`
	DiskSizeGB               int                       `json:"diskSizeGb"`
	ImageType                string                    `json:"imageType"`
	ServiceAccount           string                    `json:"serviceAccount"`
	Tags                     []string                  `json:"tags"`
	Labels                   map[string]string         `json:"labels"`
	WorkloadMetadataConfig   GKEWorkloadMetadataConfig `json:"workloadMetadataConfig"`
	ShieldedInstanceConfig   GKEShieldedInstanceConfig `json:"shieldedInstanceConfig"`
	BootDiskKMSCryptoKeyName string                    `json:"bootDiskKmsKey"`
}

type GKEWorkloadMetadataConfig struct {
	Mode string `json:"mode"`
}

type GKEShieldedInstanceConfig struct {
	EnableSecureBoot          bool `json:"enableSecureBoot"`
	EnableIntegrityMonitoring bool `json:"enableIntegrityMonitoring"`
}

type GKENodePoolManagement struct {
	AutoRepair  bool `json:"autoRepair"`
	AutoUpgrade bool `json:"autoUpgrade"`
}

type GKENodePoolAutoscaling struct {
	Enabled      bool `json:"enabled"`
	MinNodeCount int  `json:"minNodeCount"`
	MaxNodeCount int  `json:"maxNodeCount"`
}

type GCSBucketRecord struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	Location         string              `json:"location"`
	StorageClass     string              `json:"storageClass"`
	Labels           map[string]string   `json:"labels"`
	Encryption       GCSEncryption       `json:"encryption"`
	Versioning       GCSVersioning       `json:"versioning"`
	IAMConfiguration GCSIAMConfiguration `json:"iamConfiguration"`
	Raw              json.RawMessage     `json:"-"`
}

type GCSEncryption struct {
	DefaultKMSKeyName string `json:"defaultKmsKeyName"`
}

type GCSVersioning struct {
	Enabled bool `json:"enabled"`
}

type GCSIAMConfiguration struct {
	UniformBucketLevelAccess GCSUniformBucketLevelAccess `json:"uniformBucketLevelAccess"`
	PublicAccessPrevention   string                      `json:"publicAccessPrevention"`
}

type GCSUniformBucketLevelAccess struct {
	Enabled bool `json:"enabled"`
}

type SecretRecord struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	CreateTime  string            `json:"createTime"`
	ExpireTime  string            `json:"expireTime"`
	Replication SecretReplication `json:"replication"`
	Rotation    SecretRotation    `json:"rotation"`
	Raw         json.RawMessage   `json:"-"`
}

type SecretReplication struct {
	Automatic   SecretAutomaticReplication   `json:"automatic"`
	UserManaged SecretUserManagedReplication `json:"userManaged"`
}

type SecretAutomaticReplication struct {
	CustomerManagedEncryption CustomerManagedEncryption `json:"customerManagedEncryption"`
}

type SecretUserManagedReplication struct {
	Replicas []SecretReplica `json:"replicas"`
}

type SecretReplica struct {
	Location                  string                    `json:"location"`
	CustomerManagedEncryption CustomerManagedEncryption `json:"customerManagedEncryption"`
}

type CustomerManagedEncryption struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type SecretRotation struct {
	NextRotationTime string `json:"nextRotationTime"`
	RotationPeriod   string `json:"rotationPeriod"`
}

type KMSKeyRecord struct {
	Name             string              `json:"name"`
	Purpose          string              `json:"purpose"`
	CreateTime       string              `json:"createTime"`
	NextRotationTime string              `json:"nextRotationTime"`
	RotationPeriod   string              `json:"rotationPeriod"`
	Labels           map[string]string   `json:"labels"`
	VersionTemplate  KMSVersionTemplate  `json:"versionTemplate"`
	Primary          KMSCryptoKeyVersion `json:"primary"`
	Raw              json.RawMessage     `json:"-"`
}

type KMSVersionTemplate struct {
	ProtectionLevel string `json:"protectionLevel"`
	Algorithm       string `json:"algorithm"`
}

type KMSCryptoKeyVersion struct {
	Name            string `json:"name"`
	State           string `json:"state"`
	ProtectionLevel string `json:"protectionLevel"`
	Algorithm       string `json:"algorithm"`
}

type ArtifactRepositoryRecord struct {
	Name         string               `json:"name"`
	Format       string               `json:"format"`
	Description  string               `json:"description"`
	KMSKeyName   string               `json:"kmsKeyName"`
	Mode         string               `json:"mode"`
	Labels       map[string]string    `json:"labels"`
	DockerConfig ArtifactDockerConfig `json:"dockerConfig"`
	Raw          json.RawMessage      `json:"-"`
}

type ArtifactDockerConfig struct {
	ImmutableTags bool `json:"immutableTags"`
}

type ArtifactImageRecord struct {
	Name           string          `json:"name"`
	URI            string          `json:"uri"`
	Tags           []string        `json:"tags"`
	ImageSizeBytes string          `json:"imageSizeBytes"`
	MediaType      string          `json:"mediaType"`
	UploadTime     string          `json:"uploadTime"`
	BuildTime      string          `json:"buildTime"`
	UpdateTime     string          `json:"updateTime"`
	Raw            json.RawMessage `json:"-"`
}

type LoggingSinkRecord struct {
	Name              string                 `json:"name"`
	ResourceName      string                 `json:"resourceName"`
	Description       string                 `json:"description"`
	Destination       string                 `json:"destination"`
	Filter            string                 `json:"filter"`
	Disabled          bool                   `json:"disabled"`
	WriterIdentity    string                 `json:"writerIdentity"`
	IncludeChildren   bool                   `json:"includeChildren"`
	InterceptChildren bool                   `json:"interceptChildren"`
	CreateTime        string                 `json:"createTime"`
	UpdateTime        string                 `json:"updateTime"`
	Exclusions        []LoggingSinkExclusion `json:"exclusions"`
	BigQueryOptions   LoggingSinkBQOptions   `json:"bigqueryOptions"`
	Raw               json.RawMessage        `json:"-"`
}

type LoggingSinkExclusion struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Filter      string `json:"filter"`
	Disabled    bool   `json:"disabled"`
}

type LoggingSinkBQOptions struct {
	UsePartitionedTables            bool `json:"usePartitionedTables"`
	UsesTimestampColumnPartitioning bool `json:"usesTimestampColumnPartitioning"`
}

type BigQueryDatasetRecord struct {
	ID                             string                   `json:"id"`
	SelfLink                       string                   `json:"selfLink"`
	DatasetReference               BigQueryDatasetReference `json:"datasetReference"`
	FriendlyName                   string                   `json:"friendlyName"`
	Description                    string                   `json:"description"`
	Location                       string                   `json:"location"`
	Labels                         map[string]string        `json:"labels"`
	Access                         []BigQueryDatasetAccess  `json:"access"`
	DefaultEncryptionConfiguration BigQueryEncryptionConfig `json:"defaultEncryptionConfiguration"`
	CreationTime                   string                   `json:"creationTime"`
	LastModifiedTime               string                   `json:"lastModifiedTime"`
	Raw                            json.RawMessage          `json:"-"`
}

type BigQueryDatasetReference struct {
	ProjectID string `json:"projectId"`
	DatasetID string `json:"datasetId"`
}

type BigQueryDatasetAccess struct {
	Role         string          `json:"role"`
	UserByEmail  string          `json:"userByEmail"`
	GroupByEmail string          `json:"groupByEmail"`
	Domain       string          `json:"domain"`
	SpecialGroup string          `json:"specialGroup"`
	IAMMember    string          `json:"iamMember"`
	View         json.RawMessage `json:"view"`
	Routine      json.RawMessage `json:"routine"`
	Dataset      json.RawMessage `json:"dataset"`
}

type BigQueryEncryptionConfig struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type CloudRunRevisionRecord struct {
	Name                          string              `json:"name"`
	UID                           string              `json:"uid"`
	Service                       string              `json:"service"`
	ServiceAccount                string              `json:"serviceAccount"`
	Containers                    []CloudRunContainer `json:"containers"`
	VpcAccess                     CloudRunVpcAccess   `json:"vpcAccess"`
	EncryptionKey                 string              `json:"encryptionKey"`
	Labels                        map[string]string   `json:"labels"`
	Annotations                   map[string]string   `json:"annotations"`
	CreateTime                    string              `json:"createTime"`
	UpdateTime                    string              `json:"updateTime"`
	DeleteTime                    string              `json:"deleteTime"`
	Reconciling                   bool                `json:"reconciling"`
	ObservedGeneration            string              `json:"observedGeneration"`
	Generation                    string              `json:"generation"`
	MaxInstanceRequestConcurrency int                 `json:"maxInstanceRequestConcurrency"`
	Timeout                       string              `json:"timeout"`
	ServiceName                   string
	ServiceLocation               string
	Raw                           json.RawMessage `json:"-"`
}

type DNSRecordSetRecord struct {
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	TTL                   int             `json:"ttl"`
	RRDatas               []string        `json:"rrdatas"`
	SignatureRrdatas      []string        `json:"signatureRrdatas"`
	RoutingPolicy         json.RawMessage `json:"routingPolicy"`
	ManagedZoneName       string
	ManagedZoneDNSName    string
	ManagedZoneVisibility string
	Raw                   json.RawMessage `json:"-"`
}

type ContainerVulnerabilityRecord struct {
	Name          string                           `json:"name"`
	ResourceURI   string                           `json:"resourceUri"`
	NoteName      string                           `json:"noteName"`
	Kind          string                           `json:"kind"`
	Remediation   string                           `json:"remediation"`
	CreateTime    string                           `json:"createTime"`
	UpdateTime    string                           `json:"updateTime"`
	Vulnerability ContainerVulnerabilityOccurrence `json:"vulnerability"`
	Raw           json.RawMessage                  `json:"-"`
}

type ContainerVulnerabilityOccurrence struct {
	Type              string                               `json:"type"`
	Severity          string                               `json:"severity"`
	EffectiveSeverity string                               `json:"effectiveSeverity"`
	CVSSScore         float64                              `json:"cvssScore"`
	CVSSVersion       string                               `json:"cvssVersion"`
	ShortDescription  string                               `json:"shortDescription"`
	LongDescription   string                               `json:"longDescription"`
	PackageIssue      []ContainerVulnerabilityPackageIssue `json:"packageIssue"`
	RelatedURLs       []ContainerVulnerabilityRelatedURL   `json:"relatedUrls"`
}

type ContainerVulnerabilityPackageIssue struct {
	AffectedCPEURI    string                               `json:"affectedCpeUri"`
	AffectedPackage   string                               `json:"affectedPackage"`
	AffectedVersion   ContainerVulnerabilityVersion        `json:"affectedVersion"`
	FixedCPEURI       string                               `json:"fixedCpeUri"`
	FixedPackage      string                               `json:"fixedPackage"`
	FixedVersion      ContainerVulnerabilityVersion        `json:"fixedVersion"`
	FixAvailable      bool                                 `json:"fixAvailable"`
	PackageType       string                               `json:"packageType"`
	EffectiveSeverity string                               `json:"effectiveSeverity"`
	FileLocation      []ContainerVulnerabilityFileLocation `json:"fileLocation"`
}

type ContainerVulnerabilityVersion struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
	Kind     string `json:"kind"`
	FullName string `json:"fullName"`
}

type ContainerVulnerabilityFileLocation struct {
	FilePath string `json:"filePath"`
}

type ContainerVulnerabilityRelatedURL struct {
	URL   string `json:"url"`
	Label string `json:"label"`
}

type ResourceManagerProjectRecord struct {
	ProjectNumber  string                       `json:"projectNumber"`
	ProjectID      string                       `json:"projectId"`
	LifecycleState string                       `json:"lifecycleState"`
	Name           string                       `json:"name"`
	Labels         map[string]string            `json:"labels"`
	CreateTime     string                       `json:"createTime"`
	Parent         ResourceManagerProjectParent `json:"parent"`
	Raw            json.RawMessage              `json:"-"`
}

type ResourceManagerProjectParent struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func CloudIDSEndpointEvent(settings Settings, record CloudIDSEndpointRecord) (*primitives.Event, error) {
	location := firstNonEmpty(locationFromResourceName(record.Name), settings.Location)
	resourceID := firstNonEmpty(record.Name, record.EndpointForwardingRule)
	resourceName := lastPathSegment(resourceID)
	endpointIP := record.EndpointIP
	attributes := cloudResourceAttributes(settings, "cloud_ids_endpoint", resourceID, resourceName, "cloud_ids_endpoint", location, record.Labels)
	attributes["description"] = record.Description
	attributes["zone"] = location
	attributes["network"] = lastPathSegment(record.Network)
	attributes["network_url"] = record.Network
	attributes["endpoint_forwarding_rule"] = lastPathSegment(record.EndpointForwardingRule)
	attributes["endpoint_forwarding_rule_url"] = record.EndpointForwardingRule
	attributes["endpoint_forwarding_rule_address"] = endpointIP
	attributes["endpoint_ip"] = endpointIP
	attributes["private_ip"] = endpointIP
	attributes["severity"] = record.Severity
	attributes["minimum_alert_severity"] = record.Severity
	attributes["state"] = record.State
	attributes["traffic_logs"] = boolString(record.TrafficLogs)
	attributes["threat_exceptions"] = strings.Join(record.ThreatExceptions, ",")
	attributes["threat_exceptions_count"] = strconv.Itoa(len(record.ThreatExceptions))
	attributes["private_endpoint"] = boolString(endpointIP != "")
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-ids-endpoint-"+resourceID, "gcp.cloud_ids_endpoint", "gcp/cloud_ids_endpoint/v1", payload, attributes)
}

func DNSManagedZoneEvent(settings Settings, record DNSManagedZoneRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ID, record.Name, record.DNSName)
	networks := dnsManagedZoneNetworks(record)
	publicZone := strings.EqualFold(record.Visibility, "public")
	privateZone := strings.EqualFold(record.Visibility, "private")
	dnssecEnabled := strings.EqualFold(record.DNSSECConfig.State, "on") || strings.EqualFold(record.DNSSECConfig.State, "transfer")
	attributes := cloudResourceAttributes(settings, "dns_managed_zone", resourceID, record.Name, "dns_managed_zone", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["dns_name"] = record.DNSName
	attributes["visibility"] = record.Visibility
	attributes["public"] = boolString(publicZone)
	attributes["internet_exposed"] = boolString(publicZone)
	attributes["external_exposure"] = boolString(publicZone)
	attributes["private_zone"] = boolString(privateZone)
	attributes["dnssec_state"] = record.DNSSECConfig.State
	attributes["dnssec_enabled"] = boolString(dnssecEnabled)
	attributes["dnssec_non_existence"] = record.DNSSECConfig.NonExistence
	attributes["query_logging_enabled"] = boolString(record.CloudLoggingConfig.EnableLogging)
	attributes["name_servers"] = strings.Join(record.NameServers, ",")
	attributes["private_networks"] = strings.Join(networks, ",")
	attributes["private_network_count"] = strconv.Itoa(len(networks))
	attributes["creation_time"] = record.CreationTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-dns-managed-zone-"+resourceID, "gcp.dns_managed_zone", "gcp/dns_managed_zone/v1", payload, attributes)
}

func DNSRecordSetEvent(settings Settings, record DNSRecordSetRecord) (*primitives.Event, error) {
	resourceID := strings.Join([]string{record.ManagedZoneName, record.Name, record.Type}, "/")
	publicRecord := strings.EqualFold(record.ManagedZoneVisibility, "public") && dnsRecordMayExpose(record.Type)
	attributes := cloudResourceAttributes(settings, "dns_record_set", resourceID, record.Name, "dns_record_set", "global", nil)
	attributes["managed_zone"] = record.ManagedZoneName
	attributes["managed_zone_dns_name"] = record.ManagedZoneDNSName
	attributes["managed_zone_visibility"] = record.ManagedZoneVisibility
	attributes["record_name"] = record.Name
	attributes["record_type"] = record.Type
	attributes["ttl"] = strconv.Itoa(record.TTL)
	attributes["rrdatas"] = strings.Join(record.RRDatas, ",")
	attributes["records_count"] = strconv.Itoa(len(record.RRDatas))
	attributes["signature_rrdatas_count"] = strconv.Itoa(len(record.SignatureRrdatas))
	attributes["public"] = boolString(publicRecord)
	attributes["internet_exposed"] = boolString(publicRecord)
	attributes["external_exposure"] = boolString(publicRecord)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"managed_zone": record.ManagedZoneName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-dns-record-set-"+resourceID, "gcp.dns_record_set", "gcp/dns_record_set/v1", payload, attributes)
}

func CloudRunServiceEvent(settings Settings, record CloudRunServiceRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	publicEndpoint := cloudRunAllowsAllIngress(record.Ingress) && record.URI != ""
	serviceAccountEmail := record.Template.ServiceAccount
	attributes := cloudResourceAttributes(settings, "cloud_run_service", firstNonEmpty(record.Name, record.UID), lastPathSegment(record.Name), "cloud_run_service", location, record.Labels)
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["ingress"] = record.Ingress
	attributes["uri"] = record.URI
	attributes["public_endpoint"] = record.URI
	attributes["public"] = boolString(publicEndpoint)
	attributes["internet_exposed"] = boolString(publicEndpoint)
	attributes["external_exposure"] = boolString(publicEndpoint)
	attributes["container_images"] = strings.Join(cloudRunImages(record), ",")
	attributes["vpc_connector"] = record.Template.VpcAccess.Connector
	attributes["vpc_egress"] = record.Template.VpcAccess.Egress
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-run-service-"+firstNonEmpty(record.Name, record.UID), "gcp.cloud_run_service", "gcp/cloud_run_service/v1", payload, attributes)
}

func CloudRunRevisionEvent(settings Settings, record CloudRunRevisionRecord) (*primitives.Event, error) {
	location := firstNonEmpty(locationFromResourceName(record.Name), record.ServiceLocation, locationFromResourceName(record.ServiceName))
	serviceName := firstNonEmpty(record.Service, record.ServiceName)
	serviceAccountEmail := record.ServiceAccount
	images := cloudRunRevisionImages(record)
	attributes := cloudResourceAttributes(settings, "cloud_run_revision", firstNonEmpty(record.Name, record.UID), lastPathSegment(record.Name), "cloud_run_revision", location, record.Labels)
	attributes["service"] = serviceName
	attributes["service_name"] = lastPathSegment(serviceName)
	attributes["revision_name"] = lastPathSegment(record.Name)
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["container_images"] = strings.Join(images, ",")
	attributes["image_uri"] = firstString(images)
	attributes["image_digest"] = artifactImageDigest(firstString(images))
	attributes["digest"] = artifactImageDigest(firstString(images))
	attributes["vpc_connector"] = record.VpcAccess.Connector
	attributes["vpc_egress"] = record.VpcAccess.Egress
	attributes["kms_key_name"] = record.EncryptionKey
	attributes["encryption_enabled"] = boolString(record.EncryptionKey != "")
	attributes["reconciling"] = boolString(record.Reconciling)
	attributes["generation"] = record.Generation
	attributes["observed_generation"] = record.ObservedGeneration
	attributes["max_instance_request_concurrency"] = strconv.Itoa(record.MaxInstanceRequestConcurrency)
	attributes["timeout"] = record.Timeout
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	attributes["delete_time"] = record.DeleteTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "service": serviceName})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-run-revision-"+firstNonEmpty(record.Name, record.UID), "gcp.cloud_run_revision", "gcp/cloud_run_revision/v1", payload, attributes)
}

func CloudFunctionEvent(settings Settings, record CloudFunctionRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	publicEndpoint := strings.EqualFold(record.ServiceConfig.IngressSettings, "ALLOW_ALL") && record.ServiceConfig.URI != ""
	serviceAccountEmail := record.ServiceConfig.ServiceAccountEmail
	attributes := cloudResourceAttributes(settings, "cloud_function", record.Name, lastPathSegment(record.Name), "cloud_function", location, record.Labels)
	attributes["description"] = record.Description
	attributes["state"] = record.State
	attributes["environment"] = record.Environment
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["ingress"] = record.ServiceConfig.IngressSettings
	attributes["uri"] = record.ServiceConfig.URI
	attributes["public_endpoint"] = record.ServiceConfig.URI
	attributes["public"] = boolString(publicEndpoint)
	attributes["internet_exposed"] = boolString(publicEndpoint)
	attributes["external_exposure"] = boolString(publicEndpoint)
	attributes["vpc_connector"] = record.ServiceConfig.VpcConnector
	attributes["vpc_egress"] = record.ServiceConfig.VpcConnectorEgressSettings
	attributes["kms_key_name"] = record.ServiceConfig.KMSKeyName
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-function-"+record.Name, "gcp.cloud_function", "gcp/cloud_function/v1", payload, attributes)
}

func CloudSQLInstanceEvent(settings Settings, record CloudSQLInstanceRecord) (*primitives.Event, error) {
	publicIP, privateIP := cloudSQLIPs(record)
	publicAuthorized := cloudSQLPublicAuthorizedNetwork(record)
	attributes := cloudResourceAttributes(settings, "cloud_sql_instance", firstNonEmpty(record.SelfLink, record.Name), record.Name, "cloud_sql_instance", record.Region, record.Settings.UserLabels)
	attributes["zone"] = record.GCEZone
	attributes["database_version"] = record.DatabaseVersion
	attributes["state"] = record.State
	attributes["instance_type"] = record.InstanceType
	attributes["backend_type"] = record.BackendType
	attributes["service_account_email"] = record.ServiceAccountEmailAddress
	attributes["runtime_identity"] = record.ServiceAccountEmailAddress
	attributes["public_ip"] = publicIP
	attributes["private_ip"] = privateIP
	attributes["public"] = boolString(publicIP != "")
	attributes["internet_exposed"] = boolString(publicAuthorized)
	attributes["external_exposure"] = boolString(publicAuthorized)
	attributes["authorized_networks"] = strings.Join(cloudSQLAuthorizedNetworks(record), ",")
	attributes["private_network"] = record.Settings.IPConfiguration.PrivateNetwork
	attributes["ssl_required"] = boolString(record.Settings.IPConfiguration.RequireSSL)
	attributes["backup_enabled"] = boolString(record.Settings.BackupConfiguration.Enabled)
	attributes["point_in_time_recovery"] = boolString(record.Settings.BackupConfiguration.PointInTimeRecoveryEnabled)
	attributes["backup_start_time"] = record.Settings.BackupConfiguration.StartTime
	attributes["storage_auto_resize"] = boolString(record.Settings.StorageAutoResize)
	attributes["deletion_protection"] = boolString(record.Settings.DeletionProtection)
	attributes["kms_key_name"] = record.DiskEncryptionConfig.KMSKeyName
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-sql-instance-"+firstNonEmpty(record.SelfLink, record.Name), "gcp.cloud_sql_instance", "gcp/cloud_sql_instance/v1", payload, attributes)
}

func GKENodePoolEvent(settings Settings, record GKENodePoolRecord) (*primitives.Event, error) {
	location := firstNonEmpty(record.ClusterLocation, locationFromResourceName(record.SelfLink), locationFromResourceName(record.Name))
	resourceID := firstNonEmpty(record.SelfLink, record.Name)
	resourceName := lastPathSegment(firstNonEmpty(record.Name, record.SelfLink))
	serviceAccountEmail := record.Config.ServiceAccount
	attributes := cloudResourceAttributes(settings, "gke_node_pool", resourceID, resourceName, "gke_node_pool", location, record.Config.Labels)
	attributes["cluster"] = record.ClusterName
	attributes["cluster_name"] = record.ClusterName
	attributes["status"] = record.Status
	attributes["version"] = record.Version
	attributes["node_locations"] = strings.Join(record.Locations, ",")
	attributes["machine_type"] = record.Config.MachineType
	attributes["disk_type"] = record.Config.DiskType
	attributes["disk_size_gb"] = strconv.Itoa(record.Config.DiskSizeGB)
	attributes["image_type"] = record.Config.ImageType
	attributes["config.image_type"] = record.Config.ImageType
	attributes["service_account_email"] = serviceAccountEmail
	attributes["runtime_identity"] = serviceAccountEmail
	attributes["network_tags"] = strings.Join(record.Config.Tags, ",")
	attributes["security_tags"] = strings.Join(record.Config.Tags, ",")
	attributes["workload_metadata_mode"] = record.Config.WorkloadMetadataConfig.Mode
	attributes["config.workload_metadata_config.mode"] = record.Config.WorkloadMetadataConfig.Mode
	attributes["secure_boot"] = boolString(record.Config.ShieldedInstanceConfig.EnableSecureBoot)
	attributes["integrity_monitoring"] = boolString(record.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring)
	attributes["auto_repair"] = boolString(record.Management.AutoRepair)
	attributes["auto_upgrade"] = boolString(record.Management.AutoUpgrade)
	attributes["management.auto_repair"] = boolString(record.Management.AutoRepair)
	attributes["management.auto_upgrade"] = boolString(record.Management.AutoUpgrade)
	attributes["autoscaling_enabled"] = boolString(record.Autoscaling.Enabled)
	attributes["autoscaling_min_nodes"] = strconv.Itoa(record.Autoscaling.MinNodeCount)
	attributes["autoscaling_max_nodes"] = strconv.Itoa(record.Autoscaling.MaxNodeCount)
	attributes["initial_node_count"] = strconv.Itoa(record.InitialNodeCount)
	attributes["kms_key_name"] = record.Config.BootDiskKMSCryptoKeyName
	payload, err := payloadWithRaw(record.Raw, map[string]any{"cluster": record.ClusterName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gke-node-pool-"+resourceID, "gcp.gke_node_pool", "gcp/gke_node_pool/v1", payload, attributes)
}

func GCSBucketEvent(settings Settings, record GCSBucketRecord) (*primitives.Event, error) {
	attributes := cloudResourceAttributes(settings, "gcs_bucket", firstNonEmpty(record.ID, record.Name), record.Name, "gcs_bucket", record.Location, record.Labels)
	attributes["storage_class"] = record.StorageClass
	attributes["kms_key_name"] = record.Encryption.DefaultKMSKeyName
	attributes["encryption_enabled"] = boolString(record.Encryption.DefaultKMSKeyName != "")
	attributes["versioning_enabled"] = boolString(record.Versioning.Enabled)
	attributes["uniform_bucket_level_access"] = boolString(record.IAMConfiguration.UniformBucketLevelAccess.Enabled)
	attributes["public_access_prevention"] = record.IAMConfiguration.PublicAccessPrevention
	if strings.EqualFold(record.IAMConfiguration.PublicAccessPrevention, "enforced") {
		attributes["public"] = "false"
		attributes["internet_exposed"] = "false"
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gcs-bucket-"+firstNonEmpty(record.ID, record.Name), "gcp.gcs_bucket", "gcp/gcs_bucket/v1", payload, attributes)
}

func SecretEvent(settings Settings, record SecretRecord) (*primitives.Event, error) {
	kmsKey := secretKMSKey(record)
	attributes := cloudResourceAttributes(settings, "secret_manager_secret", record.Name, lastPathSegment(record.Name), "secret_manager_secret", secretLocation(record), record.Labels)
	attributes["replication"] = secretReplicationMode(record)
	attributes["kms_key_name"] = kmsKey
	attributes["encryption_enabled"] = boolString(kmsKey != "")
	attributes["rotation_next_time"] = record.Rotation.NextRotationTime
	attributes["rotation_period"] = record.Rotation.RotationPeriod
	attributes["rotation_enabled"] = boolString(record.Rotation.RotationPeriod != "" || record.Rotation.NextRotationTime != "")
	attributes["expire_time"] = record.ExpireTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-secret-manager-secret-"+record.Name, "gcp.secret_manager_secret", "gcp/secret_manager_secret/v1", payload, attributes)
}

func KMSKeyEvent(settings Settings, record KMSKeyRecord, keyRing string) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "kms_key", record.Name, lastPathSegment(record.Name), "kms_key", location, record.Labels)
	attributes["purpose"] = record.Purpose
	attributes["kms_key_name"] = record.Name
	attributes["rotation_next_time"] = record.NextRotationTime
	attributes["rotation_period"] = record.RotationPeriod
	attributes["rotation_enabled"] = boolString(record.RotationPeriod != "" || record.NextRotationTime != "")
	attributes["protection_level"] = firstNonEmpty(record.Primary.ProtectionLevel, record.VersionTemplate.ProtectionLevel)
	attributes["algorithm"] = firstNonEmpty(record.Primary.Algorithm, record.VersionTemplate.Algorithm)
	attributes["primary_version"] = record.Primary.Name
	attributes["primary_version_state"] = record.Primary.State
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "location": settings.Location, "key_ring": keyRing})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-kms-key-"+record.Name, "gcp.kms_key", "gcp/kms_key/v1", payload, attributes)
}

func ArtifactRepositoryEvent(settings Settings, record ArtifactRepositoryRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	attributes := cloudResourceAttributes(settings, "artifact_registry_repository", record.Name, lastPathSegment(record.Name), "artifact_registry_repository", location, record.Labels)
	attributes["format"] = record.Format
	attributes["mode"] = record.Mode
	attributes["description"] = record.Description
	attributes["kms_key_name"] = record.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.KMSKeyName != "")
	attributes["immutable_tags"] = boolString(record.DockerConfig.ImmutableTags)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-artifact-registry-repository-"+record.Name, "gcp.artifact_registry_repository", "gcp/artifact_registry_repository/v1", payload, attributes)
}

func ArtifactImageEvent(settings Settings, record ArtifactImageRecord, artifactRepository string) (*primitives.Event, error) {
	imageURI := firstNonEmpty(record.URI, record.Name)
	location := locationFromResourceName(artifactRepository)
	attributes := cloudResourceAttributes(settings, "artifact_registry_image", imageURI, lastPathSegment(imageURI), "artifact_registry_image", location, nil)
	attributes["artifact_repository"] = artifactRepository
	attributes["image_uri"] = imageURI
	attributes["image_name"] = lastPathSegment(imageURI)
	attributes["registry"] = artifactRegistryHost(imageURI)
	attributes["repository"] = artifactRepositoryName(artifactRepository)
	attributes["digest"] = artifactImageDigest(imageURI)
	attributes["tags"] = strings.Join(record.Tags, ",")
	attributes["media_type"] = record.MediaType
	attributes["image_size_bytes"] = record.ImageSizeBytes
	attributes["uploaded_at"] = record.UploadTime
	attributes["built_at"] = record.BuildTime
	attributes["updated_at"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "artifact_repository": artifactRepository})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-artifact-registry-image-"+imageURI, "gcp.artifact_registry_image", "gcp/artifact_registry_image/v1", payload, attributes)
}

func LoggingSinkEvent(settings Settings, record LoggingSinkRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ResourceName, "projects/"+settings.ProjectID+"/sinks/"+record.Name)
	exclusionNames, exclusionFilters, activeExclusions := loggingSinkExclusions(record.Exclusions)
	attributes := cloudResourceAttributes(settings, "logging_project_sink", resourceID, lastPathSegment(resourceID), "logging_project_sink", "global", nil)
	attributes["description"] = record.Description
	attributes["destination"] = record.Destination
	attributes["destination_type"] = loggingSinkDestinationType(record.Destination)
	attributes["filter"] = record.Filter
	attributes["disabled"] = boolString(record.Disabled)
	attributes["writer_identity"] = record.WriterIdentity
	attributes["include_children"] = boolString(record.IncludeChildren)
	attributes["intercept_children"] = boolString(record.InterceptChildren)
	attributes["exclusions"] = strings.Join(exclusionNames, ",")
	attributes["exclusion_filters"] = strings.Join(exclusionFilters, " | ")
	attributes["exclusions_count"] = strconv.Itoa(len(record.Exclusions))
	attributes["active_exclusions_count"] = strconv.Itoa(activeExclusions)
	attributes["bigquery_use_partitioned_tables"] = boolString(record.BigQueryOptions.UsePartitionedTables)
	attributes["bigquery_uses_timestamp_column_partitioning"] = boolString(record.BigQueryOptions.UsesTimestampColumnPartitioning)
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-logging-project-sink-"+resourceID, "gcp.logging_project_sink", "gcp/logging_project_sink/v1", payload, attributes)
}

func BigQueryDatasetEvent(settings Settings, record BigQueryDatasetRecord) (*primitives.Event, error) {
	datasetID := firstNonEmpty(record.DatasetReference.DatasetID, lastPathSegment(record.ID))
	resourceID := firstNonEmpty(record.ID, settings.ProjectID+":"+datasetID)
	access := bigQueryAccessSummary(record.Access)
	attributes := cloudResourceAttributes(settings, "bigquery_dataset", resourceID, datasetID, "bigquery_dataset", record.Location, record.Labels)
	attributes["dataset_id"] = datasetID
	attributes["friendly_name"] = record.FriendlyName
	attributes["description"] = record.Description
	attributes["self_link"] = record.SelfLink
	attributes["kms_key_name"] = record.DefaultEncryptionConfiguration.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.DefaultEncryptionConfiguration.KMSKeyName != "")
	attributes["access_entries_count"] = strconv.Itoa(len(record.Access))
	attributes["authorized_views_count"] = strconv.Itoa(access.AuthorizedViews)
	attributes["authorized_datasets_count"] = strconv.Itoa(access.AuthorizedDatasets)
	attributes["readers"] = strings.Join(access.Readers, ",")
	attributes["writers"] = strings.Join(access.Writers, ",")
	attributes["owners"] = strings.Join(access.Owners, ",")
	attributes["public"] = boolString(access.Public)
	attributes["internet_exposed"] = boolString(access.Public)
	attributes["external_exposure"] = boolString(access.Public)
	attributes["created_at"] = unixMillisTime(record.CreationTime)
	attributes["updated_at"] = unixMillisTime(record.LastModifiedTime)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-bigquery-dataset-"+resourceID, "gcp.bigquery_dataset", "gcp/bigquery_dataset/v1", payload, attributes)
}

func ContainerVulnerabilityEvent(settings Settings, record ContainerVulnerabilityRecord) (*primitives.Event, error) {
	issue := firstContainerPackageIssue(record.Vulnerability.PackageIssue)
	vulnerabilityID := vulnerabilityIDFromNote(record.NoteName)
	imageURI := record.ResourceURI
	fixedVersion := versionName(issue.FixedVersion)
	affectedVersion := versionName(issue.AffectedVersion)
	attributes := map[string]string{
		"cve_id":                 cveID(vulnerabilityID),
		"description":            firstNonEmpty(record.Vulnerability.ShortDescription, record.Vulnerability.LongDescription),
		"digest":                 artifactImageDigest(imageURI),
		"discovered_at":          record.CreateTime,
		"domain":                 settings.TenantID,
		"effective_severity":     firstNonEmpty(issue.EffectiveSeverity, record.Vulnerability.EffectiveSeverity),
		"family":                 "container_vulnerability",
		"fix_available":          boolString(issue.FixAvailable || fixedVersion != ""),
		"fixed_package":          issue.FixedPackage,
		"fixed_package_versions": fixedVersion,
		"fixed_version":          fixedVersion,
		"image_name":             containerImageName(imageURI),
		"image_registry":         containerImageRegistry(imageURI),
		"image_repository":       containerImageRepository(imageURI),
		"image_uri":              imageURI,
		"installed_version":      affectedVersion,
		"package":                issue.AffectedPackage,
		"package_name":           issue.AffectedPackage,
		"package_type":           issue.PackageType,
		"project_id":             settings.ProjectID,
		"registry":               containerImageRegistry(imageURI),
		"remediation":            record.Remediation,
		"repository":             containerImageRepository(imageURI),
		"resource_id":            imageURI,
		"resource_name":          containerImageName(imageURI),
		"resource_provider":      "gcp",
		"resource_type":          "container_image",
		"resource_uri":           imageURI,
		"scanner":                "artifact_analysis",
		"severity":               firstNonEmpty(issue.EffectiveSeverity, record.Vulnerability.EffectiveSeverity, record.Vulnerability.Severity),
		"source_provider":        "gcp",
		"status":                 "active",
		"updated_at":             record.UpdateTime,
		"version":                affectedVersion,
		"vulnerability_id":       vulnerabilityID,
		"vulnerability_source":   "gcp_artifact_analysis",
		"vulnerability_type":     "container",
	}
	if record.Vulnerability.CVSSScore != 0 {
		attributes["cvss_score"] = strconv.FormatFloat(record.Vulnerability.CVSSScore, 'f', -1, 64)
	}
	attributes["cvss_version"] = record.Vulnerability.CVSSVersion
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	idParts := []string{record.Name, imageURI, vulnerabilityID, issue.AffectedPackage, affectedVersion}
	return sourceEvent(settings, "gcp-container-vulnerability-"+strings.Join(idParts, "-"), "gcp.container_vulnerability", "gcp/container_vulnerability/v1", payload, attributes)
}

func ResourceManagerProjectEvent(settings Settings, record ResourceManagerProjectRecord) (*primitives.Event, error) {
	projectID := firstNonEmpty(record.ProjectID, settings.ProjectID)
	attributes := cloudResourceAttributes(settings, "resourcemanager_project", projectID, firstNonEmpty(record.Name, projectID), "resourcemanager_project", "global", record.Labels)
	attributes["project_number"] = record.ProjectNumber
	attributes["project_id"] = projectID
	attributes["name"] = record.Name
	attributes["lifecycle_state"] = record.LifecycleState
	attributes["status"] = record.LifecycleState
	attributes["parent_type"] = record.Parent.Type
	attributes["parent_id"] = record.Parent.ID
	attributes["parent"] = strings.Trim(strings.Join([]string{record.Parent.Type, record.Parent.ID}, "/"), "/")
	attributes["create_time"] = record.CreateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-resourcemanager-project-"+projectID, "gcp.resourcemanager_project", "gcp/resourcemanager_project/v1", payload, attributes)
}

func dnsManagedZoneNetworks(record DNSManagedZoneRecord) []string {
	networks := make([]string, 0, len(record.PrivateVisibilityConfig.Networks))
	for _, network := range record.PrivateVisibilityConfig.Networks {
		if strings.TrimSpace(network.NetworkURL) == "" {
			continue
		}
		networks = append(networks, network.NetworkURL)
	}
	return networks
}

func cloudRunImages(record CloudRunServiceRecord) []string {
	images := make([]string, 0, len(record.Template.Containers))
	for _, container := range record.Template.Containers {
		if strings.TrimSpace(container.Image) != "" {
			images = append(images, container.Image)
		}
	}
	return images
}

func cloudRunAllowsAllIngress(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return normalized == "INGRESS_TRAFFIC_ALL" || normalized == "ALLOW_ALL" || normalized == "ALL"
}

func artifactRepositoryName(value string) string {
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for index, part := range parts {
		if part == "repositories" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return lastPathSegment(value)
}

func artifactRegistryHost(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) != 0 && strings.Contains(parts[0], ".pkg.dev") {
		return parts[0]
	}
	return ""
}

func artifactImageDigest(value string) string {
	if index := strings.LastIndex(value, "@"); index >= 0 && index+1 < len(value) {
		return value[index+1:]
	}
	return ""
}

func loggingSinkExclusions(exclusions []LoggingSinkExclusion) ([]string, []string, int) {
	names := make([]string, 0, len(exclusions))
	filters := make([]string, 0, len(exclusions))
	active := 0
	for _, exclusion := range exclusions {
		if strings.TrimSpace(exclusion.Name) != "" {
			names = append(names, exclusion.Name)
		}
		if strings.TrimSpace(exclusion.Filter) != "" {
			filters = append(filters, exclusion.Filter)
		}
		if !exclusion.Disabled {
			active++
		}
	}
	return names, filters, active
}

func loggingSinkDestinationType(destination string) string {
	normalized := strings.ToLower(strings.TrimSpace(destination))
	switch {
	case strings.HasPrefix(normalized, "storage.googleapis.com/"):
		return "storage"
	case strings.HasPrefix(normalized, "bigquery.googleapis.com/"):
		return "bigquery"
	case strings.HasPrefix(normalized, "pubsub.googleapis.com/"):
		return "pubsub"
	case strings.HasPrefix(normalized, "logging.googleapis.com/"):
		return "logging"
	default:
		return ""
	}
}

func dnsRecordMayExpose(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT":
		return true
	default:
		return false
	}
}

func cloudRunRevisionImages(record CloudRunRevisionRecord) []string {
	images := make([]string, 0, len(record.Containers))
	for _, container := range record.Containers {
		if strings.TrimSpace(container.Image) != "" {
			images = append(images, container.Image)
		}
	}
	return images
}

type bigQueryAccess struct {
	Public             bool
	Readers            []string
	Writers            []string
	Owners             []string
	AuthorizedViews    int
	AuthorizedDatasets int
}

func bigQueryAccessSummary(entries []BigQueryDatasetAccess) bigQueryAccess {
	summary := bigQueryAccess{}
	for _, entry := range entries {
		principal := bigQueryAccessPrincipal(entry)
		if bigQueryPublicPrincipal(principal) {
			summary.Public = true
		}
		switch strings.ToUpper(strings.TrimSpace(entry.Role)) {
		case "READER":
			if principal != "" {
				summary.Readers = append(summary.Readers, principal)
			}
		case "WRITER":
			if principal != "" {
				summary.Writers = append(summary.Writers, principal)
			}
		case "OWNER":
			if principal != "" {
				summary.Owners = append(summary.Owners, principal)
			}
		}
		if len(entry.View) != 0 {
			summary.AuthorizedViews++
		}
		if len(entry.Dataset) != 0 {
			summary.AuthorizedDatasets++
		}
	}
	return summary
}

func bigQueryAccessPrincipal(entry BigQueryDatasetAccess) string {
	switch {
	case strings.TrimSpace(entry.UserByEmail) != "":
		return "user:" + strings.TrimSpace(entry.UserByEmail)
	case strings.TrimSpace(entry.GroupByEmail) != "":
		return "group:" + strings.TrimSpace(entry.GroupByEmail)
	case strings.TrimSpace(entry.Domain) != "":
		return "domain:" + strings.TrimSpace(entry.Domain)
	case strings.TrimSpace(entry.SpecialGroup) != "":
		return strings.TrimSpace(entry.SpecialGroup)
	case strings.TrimSpace(entry.IAMMember) != "":
		return strings.TrimSpace(entry.IAMMember)
	case len(entry.View) != 0:
		return "authorized_view"
	case len(entry.Routine) != 0:
		return "authorized_routine"
	case len(entry.Dataset) != 0:
		return "authorized_dataset"
	default:
		return ""
	}
}

func bigQueryPublicPrincipal(principal string) bool {
	normalized := strings.ToLower(strings.TrimSpace(principal))
	return normalized == "allusers" || normalized == "allauthenticatedusers" || normalized == "all_users" || normalized == "all_authenticated_users"
}

func unixMillisTime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	millis, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return time.UnixMilli(millis).UTC().Format(time.RFC3339)
}

func firstContainerPackageIssue(issues []ContainerVulnerabilityPackageIssue) ContainerVulnerabilityPackageIssue {
	if len(issues) == 0 {
		return ContainerVulnerabilityPackageIssue{}
	}
	return issues[0]
}

func vulnerabilityIDFromNote(noteName string) string {
	value := lastPathSegment(noteName)
	if value == "" {
		return strings.TrimSpace(noteName)
	}
	return value
}

func versionName(version ContainerVulnerabilityVersion) string {
	return firstNonEmpty(version.FullName, version.Name, version.Revision)
}

func cveID(value string) string {
	upper := strings.ToUpper(strings.TrimSpace(value))
	if strings.HasPrefix(upper, "CVE-") {
		return upper
	}
	return ""
}

func containerImageRegistry(imageURI string) string {
	parts := strings.Split(strings.TrimSpace(imageURI), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func containerImageRepository(imageURI string) string {
	withoutDigest := imageWithoutDigest(imageURI)
	parts := strings.Split(strings.Trim(withoutDigest, "/"), "/")
	if len(parts) >= 3 && strings.Contains(parts[0], ".pkg.dev") {
		return strings.Join(parts[1:3], "/")
	}
	if len(parts) >= 2 {
		return strings.Join(parts[1:len(parts)-1], "/")
	}
	return ""
}

func containerImageName(imageURI string) string {
	return lastPathSegment(imageWithoutDigest(imageURI))
}

func imageWithoutDigest(imageURI string) string {
	if index := strings.LastIndex(imageURI, "@"); index >= 0 {
		return imageURI[:index]
	}
	return imageURI
}

func firstString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cloudSQLIPs(record CloudSQLInstanceRecord) (string, string) {
	publicIP := ""
	privateIP := ""
	for _, ip := range record.IPAddresses {
		switch strings.ToUpper(strings.TrimSpace(ip.Type)) {
		case "PRIVATE":
			privateIP = firstNonEmpty(privateIP, ip.IPAddress)
		default:
			publicIP = firstNonEmpty(publicIP, ip.IPAddress)
		}
	}
	return publicIP, privateIP
}

func cloudSQLAuthorizedNetworks(record CloudSQLInstanceRecord) []string {
	networks := make([]string, 0, len(record.Settings.IPConfiguration.AuthorizedNetworks))
	for _, network := range record.Settings.IPConfiguration.AuthorizedNetworks {
		if value := strings.TrimSpace(network.Value); value != "" {
			networks = append(networks, value)
		}
	}
	return networks
}

func cloudSQLPublicAuthorizedNetwork(record CloudSQLInstanceRecord) bool {
	for _, network := range record.Settings.IPConfiguration.AuthorizedNetworks {
		if publicCIDR(network.Value) {
			return true
		}
	}
	return false
}

func publicCIDR(value string) bool {
	value = strings.TrimSpace(value)
	return value == "0.0.0.0/0" || value == "::/0"
}

func secretReplicationMode(record SecretRecord) string {
	if len(record.Replication.UserManaged.Replicas) != 0 {
		return "user_managed"
	}
	if record.Replication.Automatic.CustomerManagedEncryption.KMSKeyName != "" {
		return "automatic"
	}
	return ""
}

func secretLocation(record SecretRecord) string {
	if len(record.Replication.UserManaged.Replicas) != 0 {
		return record.Replication.UserManaged.Replicas[0].Location
	}
	return "global"
}

func secretKMSKey(record SecretRecord) string {
	if key := strings.TrimSpace(record.Replication.Automatic.CustomerManagedEncryption.KMSKeyName); key != "" {
		return key
	}
	for _, replica := range record.Replication.UserManaged.Replicas {
		if key := strings.TrimSpace(replica.CustomerManagedEncryption.KMSKeyName); key != "" {
			return key
		}
	}
	return ""
}

func cloudResourceAttributes(settings Settings, family string, resourceID string, resourceName string, resourceType string, location string, labels map[string]string) map[string]string {
	attributes := map[string]string{
		"domain":            settings.TenantID,
		"family":            family,
		"gcp_project_id":    settings.ProjectID,
		"location":          location,
		"project_id":        settings.ProjectID,
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

func sourceEvent(settings Settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.TenantID,
		SourceId:   "gcp",
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Now().UTC()),
		SchemaRef:  schemaRef,
		Payload:    payload,
		Attributes: attributes,
	}, nil
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

func boolString(value bool) string {
	return strconv.FormatBool(value)
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
