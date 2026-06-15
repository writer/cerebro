package gcpcloud

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

var cloudIDSResourceLabelIDFilterRE = regexp.MustCompile(`resource\.labels\.id\s*(?:=|:)\s*"?([^"\s)]+)"?`)
var gcsContentEmailRE = regexp.MustCompile(`[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
var gcsContentClassificationRE = regexp.MustCompile(`\b(restricted|confidential|internal|public)\b`)
var gcsContentSecretRE = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*["']?[a-z0-9_./+=\-]{12,}`)
var gcsContentSSNRE = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

type Settings struct {
	ProjectID           string
	TenantID            string
	Location            string
	CustomerID          string
	GroupKey            string
	ServiceAccountEmail string
}

type ServiceAccountRecord struct {
	Name           string          `json:"name"`
	ProjectID      string          `json:"projectId"`
	UniqueID       string          `json:"uniqueId"`
	Email          string          `json:"email"`
	DisplayName    string          `json:"displayName"`
	Description    string          `json:"description"`
	Disabled       bool            `json:"disabled"`
	OAuth2ClientID string          `json:"oauth2ClientId"`
	Raw            json.RawMessage `json:"-"`
}

type ServiceAccountKeyRecord struct {
	Name            string          `json:"name"`
	PrivateKeyType  string          `json:"privateKeyType"`
	KeyAlgorithm    string          `json:"keyAlgorithm"`
	ValidAfterTime  string          `json:"validAfterTime"`
	ValidBeforeTime string          `json:"validBeforeTime"`
	KeyOrigin       string          `json:"keyOrigin"`
	KeyType         string          `json:"keyType"`
	Disabled        bool            `json:"disabled"`
	Raw             json.RawMessage `json:"-"`
}

type EntityKey struct {
	ID string `json:"id"`
}

type GroupRecord struct {
	Name        string          `json:"name"`
	GroupKey    EntityKey       `json:"groupKey"`
	DisplayName string          `json:"displayName"`
	Description string          `json:"description"`
	Raw         json.RawMessage `json:"-"`
}

type MembershipRecord struct {
	Name               string           `json:"name"`
	PreferredMemberKey EntityKey        `json:"preferredMemberKey"`
	Roles              []MembershipRole `json:"roles"`
	Type               string           `json:"type"`
	Raw                json.RawMessage  `json:"-"`
}

type MembershipRole struct {
	Name string `json:"name"`
}

type RoleAssignmentRecord struct {
	Role   string
	Member string
	Raw    json.RawMessage
}

type ServiceAccountImpersonationRecord struct {
	Role   string
	Member string
	Raw    json.RawMessage
}

type AuditRecord struct {
	InsertID     string        `json:"insertId"`
	Timestamp    string        `json:"timestamp"`
	ProtoPayload AuditProto    `json:"protoPayload"`
	Resource     AuditResource `json:"resource"`
	Raw          json.RawMessage
}

type AuditProto struct {
	MethodName         string                  `json:"methodName"`
	ServiceName        string                  `json:"serviceName"`
	ResourceName       string                  `json:"resourceName"`
	AuthenticationInfo AuditAuthenticationInfo `json:"authenticationInfo"`
}

type AuditAuthenticationInfo struct {
	PrincipalEmail   string `json:"principalEmail"`
	PrincipalSubject string `json:"principalSubject"`
}

type AuditResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type IAMPolicy struct {
	Bindings []IAMBinding `json:"bindings"`
	Etag     string       `json:"etag"`
	Version  int          `json:"version"`
}

type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type AIDatasetRecord struct {
	Name              string            `json:"name"`
	DisplayName       string            `json:"displayName"`
	Description       string            `json:"description"`
	MetadataSchemaURI string            `json:"metadataSchemaUri"`
	Metadata          json.RawMessage   `json:"metadata"`
	Labels            map[string]string `json:"labels"`
	CreateTime        string            `json:"createTime"`
	UpdateTime        string            `json:"updateTime"`
	EncryptionSpec    AIEncryptionSpec  `json:"encryptionSpec"`
	ETag              string            `json:"etag"`
	IAMPolicy         IAMPolicy         `json:"-"`
	Raw               json.RawMessage   `json:"-"`
}

type AIEndpointRecord struct {
	Name                        string                        `json:"name"`
	DisplayName                 string                        `json:"displayName"`
	Description                 string                        `json:"description"`
	Labels                      map[string]string             `json:"labels"`
	CreateTime                  string                        `json:"createTime"`
	UpdateTime                  string                        `json:"updateTime"`
	EncryptionSpec              AIEncryptionSpec              `json:"encryptionSpec"`
	DeployedModels              []AIDeployedModel             `json:"deployedModels"`
	TrafficSplit                map[string]int                `json:"trafficSplit"`
	Network                     string                        `json:"network"`
	PrivateServiceConnectConfig AIPrivateServiceConnectConfig `json:"privateServiceConnectConfig"`
	ETag                        string                        `json:"etag"`
	IAMPolicy                   IAMPolicy                     `json:"-"`
	Raw                         json.RawMessage               `json:"-"`
}

type AIEncryptionSpec struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type AIDeployedModel struct {
	ID                 string        `json:"id"`
	Model              string        `json:"model"`
	DisplayName        string        `json:"displayName"`
	ServiceAccount     string        `json:"serviceAccount"`
	CreateTime         string        `json:"createTime"`
	EnableAccessLog    bool          `json:"enableAccessLogging"`
	EnableContainerLog bool          `json:"enableContainerLogging"`
	MachineSpec        AIMachineSpec `json:"machineSpec"`
}

type AIMachineSpec struct {
	MachineType      string `json:"machineType"`
	AcceleratorType  string `json:"acceleratorType"`
	AcceleratorCount int    `json:"acceleratorCount"`
}

type AIPrivateServiceConnectConfig struct {
	EnablePrivateServiceConnect bool     `json:"enablePrivateServiceConnect"`
	ProjectAllowlist            []string `json:"projectAllowlist"`
}

type CloudIDSEndpointRecord struct {
	Name                   string              `json:"name"`
	CreateTime             string              `json:"createTime"`
	UpdateTime             string              `json:"updateTime"`
	Labels                 map[string]string   `json:"labels"`
	Network                string              `json:"network"`
	EndpointForwardingRule string              `json:"endpointForwardingRule"`
	EndpointIP             string              `json:"endpointIp"`
	Description            string              `json:"description"`
	Severity               string              `json:"severity"`
	ThreatExceptions       []string            `json:"threatExceptions"`
	State                  string              `json:"state"`
	TrafficLogs            bool                `json:"trafficLogs"`
	LoggingSinks           []LoggingSinkRecord `json:"-"`
	Raw                    json.RawMessage     `json:"-"`
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

type CloudSchedulerJobRecord struct {
	Name                string                            `json:"name"`
	Description         string                            `json:"description"`
	Schedule            string                            `json:"schedule"`
	TimeZone            string                            `json:"timeZone"`
	UserUpdateTime      string                            `json:"userUpdateTime"`
	State               string                            `json:"state"`
	Status              CloudSchedulerStatus              `json:"status"`
	ScheduleTime        string                            `json:"scheduleTime"`
	LastAttemptTime     string                            `json:"lastAttemptTime"`
	RetryConfig         CloudSchedulerRetryConfig         `json:"retryConfig"`
	AttemptDeadline     string                            `json:"attemptDeadline"`
	SatisfiesPzs        bool                              `json:"satisfiesPzs"`
	PubsubTarget        CloudSchedulerPubsubTarget        `json:"pubsubTarget"`
	AppEngineHTTPTarget CloudSchedulerAppEngineHTTPTarget `json:"appEngineHttpTarget"`
	HTTPTarget          CloudSchedulerHTTPTarget          `json:"httpTarget"`
	Raw                 json.RawMessage                   `json:"-"`
}

type CloudSchedulerStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CloudSchedulerRetryConfig struct {
	RetryCount         int    `json:"retryCount"`
	MaxRetryDuration   string `json:"maxRetryDuration"`
	MinBackoffDuration string `json:"minBackoffDuration"`
	MaxBackoffDuration string `json:"maxBackoffDuration"`
	MaxDoublings       int    `json:"maxDoublings"`
}

type CloudSchedulerPubsubTarget struct {
	TopicName  string            `json:"topicName"`
	Attributes map[string]string `json:"attributes"`
	Data       string            `json:"data"`
}

type CloudSchedulerAppEngineHTTPTarget struct {
	HTTPMethod       string                   `json:"httpMethod"`
	AppEngineRouting CloudSchedulerAppRouting `json:"appEngineRouting"`
	RelativeURI      string                   `json:"relativeUri"`
	Headers          map[string]string        `json:"headers"`
	Body             string                   `json:"body"`
}

type CloudSchedulerAppRouting struct {
	Service  string `json:"service"`
	Version  string `json:"version"`
	Instance string `json:"instance"`
	Host     string `json:"host"`
}

type CloudSchedulerHTTPTarget struct {
	URI        string                   `json:"uri"`
	HTTPMethod string                   `json:"httpMethod"`
	Headers    map[string]string        `json:"headers"`
	Body       string                   `json:"body"`
	OAuthToken CloudSchedulerOAuthToken `json:"oauthToken"`
	OIDCToken  CloudSchedulerOIDCToken  `json:"oidcToken"`
}

type CloudSchedulerOAuthToken struct {
	ServiceAccountEmail string `json:"serviceAccountEmail"`
	Scope               string `json:"scope"`
}

type CloudSchedulerOIDCToken struct {
	ServiceAccountEmail string `json:"serviceAccountEmail"`
	Audience            string `json:"audience"`
}

type CloudSchedulerJobsResponse struct {
	Jobs          []json.RawMessage `json:"jobs"`
	NextPageToken string            `json:"nextPageToken"`
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

type ComputeNetworkRecord struct {
	ID                    string                      `json:"id"`
	Name                  string                      `json:"name"`
	SelfLink              string                      `json:"selfLink"`
	Description           string                      `json:"description"`
	AutoCreateSubnetworks bool                        `json:"autoCreateSubnetworks"`
	RoutingConfig         ComputeNetworkRoutingConfig `json:"routingConfig"`
	Labels                map[string]string           `json:"labels"`
	Raw                   json.RawMessage             `json:"-"`
}

type ComputeNetworkRoutingConfig struct {
	RoutingMode string `json:"routingMode"`
}

type ComputeDiskRecord struct {
	ID                string                   `json:"id"`
	Name              string                   `json:"name"`
	SelfLink          string                   `json:"selfLink"`
	Zone              string                   `json:"zone"`
	Region            string                   `json:"region"`
	Type              string                   `json:"type"`
	Status            string                   `json:"status"`
	SizeGB            string                   `json:"sizeGb"`
	Users             []string                 `json:"users"`
	Labels            map[string]string        `json:"labels"`
	DiskEncryptionKey ComputeDiskEncryptionKey `json:"diskEncryptionKey"`
	Raw               json.RawMessage          `json:"-"`
}

type ComputeDiskEncryptionKey struct {
	KMSKeyName string `json:"kmsKeyName"`
}

type GKEClusterRecord struct {
	Name                           string                            `json:"name"`
	SelfLink                       string                            `json:"selfLink"`
	Location                       string                            `json:"location"`
	Endpoint                       string                            `json:"endpoint"`
	Status                         string                            `json:"status"`
	Network                        string                            `json:"network"`
	Subnetwork                     string                            `json:"subnetwork"`
	CurrentMasterVersion           string                            `json:"currentMasterVersion"`
	ResourceLabels                 map[string]string                 `json:"resourceLabels"`
	NodeConfig                     GKEClusterNodeConfig              `json:"nodeConfig"`
	PrivateClusterConfig           GKEPrivateClusterConfig           `json:"privateClusterConfig"`
	MasterAuthorizedNetworksConfig GKEMasterAuthorizedNetworksConfig `json:"masterAuthorizedNetworksConfig"`
	DatabaseEncryption             GKEDatabaseEncryption             `json:"databaseEncryption"`
	Raw                            json.RawMessage                   `json:"-"`
}

type GKEClusterNodeConfig struct {
	ServiceAccount string            `json:"serviceAccount"`
	Tags           []string          `json:"tags"`
	Labels         map[string]string `json:"labels"`
}

type GKEPrivateClusterConfig struct {
	EnablePrivateNodes    bool   `json:"enablePrivateNodes"`
	EnablePrivateEndpoint bool   `json:"enablePrivateEndpoint"`
	MasterIpv4CidrBlock   string `json:"masterIpv4CidrBlock"`
}

type GKEMasterAuthorizedNetworksConfig struct {
	Enabled    bool           `json:"enabled"`
	CidrBlocks []GKECIDRBlock `json:"cidrBlocks"`
}

type GKECIDRBlock struct {
	CidrBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName"`
}

type GKEDatabaseEncryption struct {
	State   string `json:"state"`
	KeyName string `json:"keyName"`
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

type GCSObjectRecord struct {
	ID                      string                `json:"id"`
	Name                    string                `json:"name"`
	Bucket                  string                `json:"bucket"`
	Generation              string                `json:"generation"`
	Metageneration          string                `json:"metageneration"`
	ContentType             string                `json:"contentType"`
	StorageClass            string                `json:"storageClass"`
	Size                    string                `json:"size"`
	MD5Hash                 string                `json:"md5Hash"`
	CRC32C                  string                `json:"crc32c"`
	KMSKeyName              string                `json:"kmsKeyName"`
	CustomerEncryption      GCSCustomerEncryption `json:"customerEncryption"`
	EventBasedHold          bool                  `json:"eventBasedHold"`
	TemporaryHold           bool                  `json:"temporaryHold"`
	RetentionExpirationTime string                `json:"retentionExpirationTime"`
	TimeCreated             string                `json:"timeCreated"`
	Updated                 string                `json:"updated"`
	Metadata                map[string]string     `json:"metadata"`
	ACL                     []GCSObjectACL        `json:"acl"`
	BucketLocation          string
	ContentInspection       GCSObjectContentInspection `json:"-"`
	Raw                     json.RawMessage            `json:"-"`
}

type GCSObjectContentInspection struct {
	Inspected          bool     `json:"inspected"`
	BytesScanned       int      `json:"bytes_scanned"`
	Truncated          bool     `json:"truncated"`
	Findings           []string `json:"findings"`
	DataClassification string   `json:"data_classification"`
	ContainsPII        bool     `json:"contains_pii"`
	ContainsSecrets    bool     `json:"contains_secrets"`
	Error              string   `json:"error,omitempty"`
}

type GCSCustomerEncryption struct {
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
	KeySHA256           string `json:"keySha256"`
}

type GCSObjectACL struct {
	Entity string `json:"entity"`
	Role   string `json:"role"`
	Email  string `json:"email"`
	Domain string `json:"domain"`
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

type PubSubTopicRecord struct {
	Name                     string                     `json:"name"`
	Labels                   map[string]string          `json:"labels"`
	KMSKeyName               string                     `json:"kmsKeyName"`
	MessageStoragePolicy     PubSubMessageStoragePolicy `json:"messageStoragePolicy"`
	SchemaSettings           PubSubSchemaSettings       `json:"schemaSettings"`
	MessageRetentionDuration string                     `json:"messageRetentionDuration"`
	State                    string                     `json:"state"`
	SatisfiesPZS             bool                       `json:"satisfiesPzs"`
	IAMPolicy                IAMPolicy                  `json:"-"`
	Raw                      json.RawMessage            `json:"-"`
}

type PubSubMessageStoragePolicy struct {
	AllowedPersistenceRegions []string `json:"allowedPersistenceRegions"`
}

type PubSubSchemaSettings struct {
	Schema          string `json:"schema"`
	Encoding        string `json:"encoding"`
	FirstRevisionID string `json:"firstRevisionId"`
	LastRevisionID  string `json:"lastRevisionId"`
}

type PubSubSubscriptionRecord struct {
	Name                          string                   `json:"name"`
	Topic                         string                   `json:"topic"`
	Labels                        map[string]string        `json:"labels"`
	PushConfig                    PubSubPushConfig         `json:"pushConfig"`
	BigQueryConfig                PubSubBigQueryConfig     `json:"bigqueryConfig"`
	CloudStorageConfig            PubSubCloudStorageConfig `json:"cloudStorageConfig"`
	DeadLetterPolicy              PubSubDeadLetterPolicy   `json:"deadLetterPolicy"`
	RetryPolicy                   PubSubRetryPolicy        `json:"retryPolicy"`
	ExpirationPolicy              PubSubExpirationPolicy   `json:"expirationPolicy"`
	MessageRetentionDuration      string                   `json:"messageRetentionDuration"`
	TopicMessageRetentionDuration string                   `json:"topicMessageRetentionDuration"`
	AckDeadlineSeconds            int                      `json:"ackDeadlineSeconds"`
	RetainAckedMessages           bool                     `json:"retainAckedMessages"`
	EnableMessageOrdering         bool                     `json:"enableMessageOrdering"`
	Detached                      bool                     `json:"detached"`
	Filter                        string                   `json:"filter"`
	State                         string                   `json:"state"`
	IAMPolicy                     IAMPolicy                `json:"-"`
	Raw                           json.RawMessage          `json:"-"`
}

type PubSubPushConfig struct {
	PushEndpoint  string              `json:"pushEndpoint"`
	Attributes    map[string]string   `json:"attributes"`
	OIDCToken     PubSubOIDCToken     `json:"oidcToken"`
	PubsubWrapper PubSubWrapperConfig `json:"pubsubWrapper"`
}

type PubSubWrapperConfig struct{}

type PubSubOIDCToken struct {
	ServiceAccountEmail string `json:"serviceAccountEmail"`
	Audience            string `json:"audience"`
}

type PubSubBigQueryConfig struct {
	Table               string `json:"table"`
	UseTopicSchema      bool   `json:"useTopicSchema"`
	WriteMetadata       bool   `json:"writeMetadata"`
	DropUnknownFields   bool   `json:"dropUnknownFields"`
	ServiceAccountEmail string `json:"serviceAccountEmail"`
}

type PubSubCloudStorageConfig struct {
	Bucket         string `json:"bucket"`
	FilenamePrefix string `json:"filenamePrefix"`
	FilenameSuffix string `json:"filenameSuffix"`
	MaxBytes       string `json:"maxBytes"`
	MaxDuration    string `json:"maxDuration"`
}

type PubSubDeadLetterPolicy struct {
	DeadLetterTopic     string `json:"deadLetterTopic"`
	MaxDeliveryAttempts int    `json:"maxDeliveryAttempts"`
}

type PubSubRetryPolicy struct {
	MinimumBackoff string `json:"minimumBackoff"`
	MaximumBackoff string `json:"maximumBackoff"`
}

type PubSubExpirationPolicy struct {
	TTL string `json:"ttl"`
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
	ProjectNumber   string                       `json:"projectNumber"`
	ProjectID       string                       `json:"projectId"`
	LifecycleState  string                       `json:"lifecycleState"`
	Name            string                       `json:"name"`
	Labels          map[string]string            `json:"labels"`
	CreateTime      string                       `json:"createTime"`
	Parent          ResourceManagerProjectParent `json:"parent"`
	EnabledServices []ServiceUsageServiceRecord
	OrgPolicies     []OrgPolicyRecord
	Raw             json.RawMessage `json:"-"`
}

type ResourceManagerProjectParent struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ServiceUsageServiceRecord struct {
	Name   string             `json:"name"`
	Parent string             `json:"parent"`
	State  string             `json:"state"`
	Config ServiceUsageConfig `json:"config"`
	Raw    json.RawMessage    `json:"-"`
}

type ServiceUsageConfig struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

type OrgPolicyRecord struct {
	Name       string          `json:"name"`
	Spec       OrgPolicySpec   `json:"spec"`
	DryRunSpec OrgPolicySpec   `json:"dryRunSpec"`
	Etag       string          `json:"etag"`
	Raw        json.RawMessage `json:"-"`
}

type OrgPolicySpec struct {
	Rules             []OrgPolicyRule `json:"rules"`
	InheritFromParent bool            `json:"inheritFromParent"`
	Reset             bool            `json:"reset"`
	Etag              string          `json:"etag"`
	UpdateTime        string          `json:"updateTime"`
}

type OrgPolicyRule struct {
	Values    OrgPolicyValues `json:"values"`
	AllowAll  bool            `json:"allowAll"`
	DenyAll   bool            `json:"denyAll"`
	Enforce   *bool           `json:"enforce"`
	Condition json.RawMessage `json:"condition"`
}

type OrgPolicyValues struct {
	AllowedValues []string `json:"allowedValues"`
	DeniedValues  []string `json:"deniedValues"`
}

func ServiceAccountEvent(settings Settings, record ServiceAccountRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"display_name":   firstNonEmpty(record.DisplayName, record.Email),
		"domain":         settings.TenantID,
		"email":          record.Email,
		"family":         "service_account",
		"mfa_enrolled":   "false",
		"principal_type": "service_account",
		"status":         disabledStatus(record.Disabled),
		"unique_id":      record.UniqueID,
		"user_id":        firstNonEmpty(record.Email, record.UniqueID, record.Name),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-service-account-"+firstNonEmpty(record.UniqueID, record.Email), "gcp.service_account", "gcp/service_account/v1", payload, attributes)
}

func ServiceAccountKeyEvent(settings Settings, record ServiceAccountKeyRecord) (*primitives.Event, error) {
	attributes := map[string]string{ // #nosec G101 -- service-account key attributes are inventory identifiers, not key material.
		"credential_id":   firstNonEmpty(record.Name, settings.ServiceAccountEmail),
		"credential_type": "gcp_service_account_key",
		"domain":          settings.TenantID,
		"event_type":      "gcp_service_account_key_present",
		"family":          "service_account_key",
		"resource_id":     firstNonEmpty(record.Name, settings.ServiceAccountEmail),
		"resource_type":   "service_account_key",
		"status":          disabledStatus(record.Disabled),
		"subject_email":   settings.ServiceAccountEmail,
		"subject_id":      settings.ServiceAccountEmail,
		"subject_type":    "service_account",
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "service_account_email": settings.ServiceAccountEmail})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.ValidAfterTime != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.ValidAfterTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEventAt(settings, "gcp-service-account-key-"+firstNonEmpty(record.Name, settings.ServiceAccountEmail), "gcp.service_account_key", "gcp/service_account_key/v1", payload, attributes, occurredAt)
}

func GroupEvent(settings Settings, record GroupRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":      settings.TenantID,
		"family":      "group",
		"group_email": emailLike(record.GroupKey.ID),
		"group_id":    firstNonEmpty(record.GroupKey.ID, record.Name),
		"group_name":  firstNonEmpty(record.DisplayName, record.GroupKey.ID),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"customer_id": settings.CustomerID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-group-"+firstNonEmpty(record.GroupKey.ID, record.Name), "gcp.group", "gcp/group/v1", payload, attributes)
}

func GroupMembershipEvent(settings Settings, record MembershipRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.PreferredMemberKey.ID)
	attributes := map[string]string{
		"domain":       settings.TenantID,
		"family":       "group_membership",
		"group_email":  emailLike(settings.GroupKey),
		"group_id":     settings.GroupKey,
		"member_email": memberEmail,
		"member_id":    memberID,
		"member_type":  memberType,
		"role":         membershipRoleName(record.Roles),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"group_key": settings.GroupKey})
	if err != nil {
		return nil, err
	}
	id := "gcp-group-membership-" + settings.GroupKey + "-" + firstNonEmpty(memberID, record.Name)
	return sourceEvent(settings, id, "gcp.group_membership", "gcp/group_membership/v1", payload, attributes)
}

func RoleAssignmentEvent(settings Settings, record RoleAssignmentRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	attributes := map[string]string{
		"domain":         settings.TenantID,
		"family":         "iam_role_assignment",
		"is_admin":       boolString(iamAdminRole(record.Role)),
		"principal_type": memberType,
		"role_id":        record.Role,
		"role_name":      record.Role,
		"role_type":      "gcp_iam_role",
		"subject_email":  memberEmail,
		"subject_id":     memberID,
		"subject_type":   memberType,
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	id := "gcp-iam-role-assignment-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.iam_role_assignment", "gcp/iam_role_assignment/v1", payload, attributes)
}

func EffectivePermissionEvent(settings Settings, record RoleAssignmentRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	projectResource := "projects/" + settings.ProjectID
	admin := iamAdminRole(record.Role)
	attributes := map[string]string{
		"actions":         record.Role,
		"domain":          settings.TenantID,
		"effect":          "allow",
		"family":          "effective_permission",
		"is_admin":        boolString(admin),
		"permission":      record.Role,
		"privilege_level": privilegeLevel(admin),
		"project_id":      settings.ProjectID,
		"resource_id":     projectResource,
		"resource_name":   settings.ProjectID,
		"resource_type":   "project",
		"role_id":         record.Role,
		"role_name":       record.Role,
		"role_type":       "gcp_iam_role",
		"scope":           projectResource,
		"subject_email":   memberEmail,
		"subject_id":      memberID,
		"subject_type":    memberType,
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	id := "gcp-effective-permission-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.effective_permission", "gcp/effective_permission/v1", payload, attributes)
}

func ServiceAccountImpersonationEvent(settings Settings, record ServiceAccountImpersonationRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	attributes := map[string]string{
		"domain":        settings.TenantID,
		"family":        "service_account_impersonation",
		"is_admin":      "true",
		"member":        record.Member,
		"path_type":     "service_account_impersonation",
		"relationship":  "can_impersonate",
		"role_id":       record.Role,
		"role_name":     record.Role,
		"role_type":     "gcp_service_account_iam_role",
		"subject_email": memberEmail,
		"subject_id":    memberID,
		"subject_type":  memberType,
		"target_email":  settings.ServiceAccountEmail,
		"target_id":     settings.ServiceAccountEmail,
		"target_name":   settings.ServiceAccountEmail,
		"target_type":   "service_account",
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "service_account_email": settings.ServiceAccountEmail})
	if err != nil {
		return nil, err
	}
	id := "gcp-service-account-impersonation-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.service_account_impersonation", "gcp/service_account_impersonation/v1", payload, attributes)
}

func AuditEvent(settings Settings, record AuditRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ProtoPayload.ResourceName, record.Resource.Labels["project_id"], settings.ProjectID)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalEmail, record.ProtoPayload.AuthenticationInfo.PrincipalSubject),
		"actor_email":        emailLike(record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"actor_id":           firstNonEmpty(record.ProtoPayload.AuthenticationInfo.PrincipalSubject, record.ProtoPayload.AuthenticationInfo.PrincipalEmail),
		"domain":             settings.TenantID,
		"event_name":         record.ProtoPayload.MethodName,
		"event_type":         record.ProtoPayload.MethodName,
		"family":             "audit",
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_type":      firstNonEmpty(record.Resource.Type, record.ProtoPayload.ServiceName, "resource"),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.Timestamp); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEventAt(settings, "gcp-audit-"+firstNonEmpty(record.InsertID, record.ProtoPayload.MethodName), "gcp.audit", "gcp/audit/v1", payload, attributes, occurredAt)
}

func AIDatasetEvent(settings Settings, record AIDatasetRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	resourceID := record.Name
	policy := iamPolicySummary(record.IAMPolicy)
	attributes := cloudResourceAttributes(settings, "aiplatform_dataset", resourceID, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "aiplatform_dataset", location, record.Labels)
	attributes["dataset_id"] = lastPathSegment(record.Name)
	attributes["display_name"] = record.DisplayName
	attributes["description"] = record.Description
	attributes["metadata_schema_uri"] = record.MetadataSchemaURI
	attributes["kms_key_name"] = record.EncryptionSpec.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.EncryptionSpec.KMSKeyName != "")
	attributes["iam_bindings_count"] = strconv.Itoa(len(record.IAMPolicy.Bindings))
	attributes["iam_members"] = strings.Join(policy.Members, ",")
	attributes["admin_members"] = strings.Join(policy.AdminMembers, ",")
	attributes["public"] = boolString(policy.Public)
	attributes["internet_exposed"] = boolString(policy.Public)
	attributes["external_exposure"] = boolString(policy.Public)
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"iam_policy": record.IAMPolicy, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-aiplatform-dataset-"+resourceID, "gcp.aiplatform_dataset", "gcp/aiplatform_dataset/v1", payload, attributes)
}

func AIEndpointEvent(settings Settings, record AIEndpointRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	resourceID := record.Name
	policy := iamPolicySummary(record.IAMPolicy)
	deployed := aiDeployedModelSummary(record.DeployedModels)
	privateEndpoint := strings.TrimSpace(record.Network) != "" || record.PrivateServiceConnectConfig.EnablePrivateServiceConnect
	publicEndpoint := !privateEndpoint
	attributes := cloudResourceAttributes(settings, "aiplatform_endpoint", resourceID, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "aiplatform_endpoint", location, record.Labels)
	attributes["endpoint_id"] = lastPathSegment(record.Name)
	attributes["display_name"] = record.DisplayName
	attributes["description"] = record.Description
	attributes["deployed_models_count"] = strconv.Itoa(len(record.DeployedModels))
	attributes["deployed_models"] = strings.Join(deployed.Models, ",")
	attributes["deployed_model_ids"] = strings.Join(deployed.IDs, ",")
	attributes["runtime_identities"] = strings.Join(deployed.ServiceAccounts, ",")
	attributes["service_account_email"] = firstString(deployed.ServiceAccounts)
	attributes["runtime_identity"] = firstString(deployed.ServiceAccounts)
	attributes["machine_types"] = strings.Join(deployed.MachineTypes, ",")
	attributes["access_logging_enabled"] = boolString(deployed.AccessLogging)
	attributes["container_logging_enabled"] = boolString(deployed.ContainerLogging)
	attributes["traffic_split_count"] = strconv.Itoa(len(record.TrafficSplit))
	attributes["network"] = record.Network
	attributes["private_service_connect_enabled"] = boolString(record.PrivateServiceConnectConfig.EnablePrivateServiceConnect)
	attributes["private_service_connect_projects"] = strings.Join(record.PrivateServiceConnectConfig.ProjectAllowlist, ",")
	attributes["private_endpoint"] = boolString(privateEndpoint)
	attributes["public"] = boolString(publicEndpoint || policy.Public)
	attributes["internet_exposed"] = boolString(publicEndpoint || policy.Public)
	attributes["external_exposure"] = boolString(publicEndpoint || policy.Public)
	attributes["kms_key_name"] = record.EncryptionSpec.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.EncryptionSpec.KMSKeyName != "")
	attributes["iam_bindings_count"] = strconv.Itoa(len(record.IAMPolicy.Bindings))
	attributes["iam_members"] = strings.Join(policy.Members, ",")
	attributes["admin_members"] = strings.Join(policy.AdminMembers, ",")
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"iam_policy": record.IAMPolicy, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-aiplatform-endpoint-"+resourceID, "gcp.aiplatform_endpoint", "gcp/aiplatform_endpoint/v1", payload, attributes)
}

func CloudIDSEndpointEvent(settings Settings, record CloudIDSEndpointRecord) (*primitives.Event, error) {
	location := firstNonEmpty(locationFromResourceName(record.Name), settings.Location)
	resourceID := firstNonEmpty(record.Name, record.EndpointForwardingRule)
	resourceName := lastPathSegment(resourceID)
	endpointIP := record.EndpointIP
	logs := cloudIDSLogSinkSummary(record.LoggingSinks)
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
	attributes["threat_log_name"] = cloudIDSLogName(settings.ProjectID, "threat")
	attributes["traffic_log_name"] = cloudIDSLogName(settings.ProjectID, "traffic")
	attributes["threat_log_routed"] = boolString(logs.Threat)
	attributes["traffic_log_routed"] = boolString(logs.Traffic)
	attributes["log_sinks_count"] = strconv.Itoa(len(record.LoggingSinks))
	attributes["log_sink_names"] = strings.Join(logs.Names, ",")
	attributes["log_sink_destinations"] = strings.Join(logs.Destinations, ",")
	attributes["log_sink_destination_types"] = strings.Join(logs.DestinationTypes, ",")
	attributes["notification_configured"] = boolString(len(logs.NotificationDestinations) != 0)
	attributes["notification_destinations"] = strings.Join(logs.NotificationDestinations, ",")
	attributes["private_endpoint"] = boolString(endpointIP != "")
	attributes["create_time"] = record.CreateTime
	attributes["update_time"] = record.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"logging_sinks": record.LoggingSinks, "project_id": settings.ProjectID})
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

func CloudSchedulerJobEvent(settings Settings, record CloudSchedulerJobRecord) (*primitives.Event, error) {
	location := locationFromResourceName(record.Name)
	target := cloudSchedulerTarget(record)
	attributes := cloudResourceAttributes(settings, "cloud_scheduler_job", record.Name, lastPathSegment(record.Name), "cloud_scheduler_job", location, nil)
	attributes["description"] = record.Description
	attributes["schedule"] = record.Schedule
	attributes["time_zone"] = record.TimeZone
	attributes["state"] = record.State
	attributes["status"] = record.State
	if record.Status.Code != 0 || record.Status.Message != "" {
		attributes["status_code"] = strconv.Itoa(record.Status.Code)
		attributes["status_message"] = record.Status.Message
	}
	attributes["target_type"] = target.Type
	attributes["target"] = target.Target
	attributes["target_uri"] = target.URI
	attributes["target_topic"] = target.Topic
	attributes["http_method"] = target.Method
	attributes["service_account_email"] = target.ServiceAccountEmail
	attributes["runtime_identity"] = target.ServiceAccountEmail
	attributes["oauth_scope"] = target.OAuthScope
	attributes["oidc_audience"] = target.OIDCAudience
	attributes["attempt_deadline"] = record.AttemptDeadline
	attributes["retry_count"] = strconv.Itoa(record.RetryConfig.RetryCount)
	attributes["max_retry_duration"] = record.RetryConfig.MaxRetryDuration
	attributes["min_backoff_duration"] = record.RetryConfig.MinBackoffDuration
	attributes["max_backoff_duration"] = record.RetryConfig.MaxBackoffDuration
	attributes["max_doublings"] = strconv.Itoa(record.RetryConfig.MaxDoublings)
	attributes["schedule_time"] = record.ScheduleTime
	attributes["last_attempt_time"] = record.LastAttemptTime
	attributes["user_update_time"] = record.UserUpdateTime
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPzs)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-cloud-scheduler-job-"+record.Name, "gcp.cloud_scheduler_job", "gcp/cloud_scheduler_job/v1", payload, attributes)
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

func ComputeNetworkEvent(settings Settings, record ComputeNetworkRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_network", resourceID, record.Name, "compute_network", "global", record.Labels)
	attributes["description"] = record.Description
	attributes["auto_create_subnetworks"] = boolString(record.AutoCreateSubnetworks)
	attributes["routing_mode"] = record.RoutingConfig.RoutingMode
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-network-"+resourceID, "gcp.compute_network", "gcp/compute_network/v1", payload, attributes)
}

func ComputeDiskEvent(settings Settings, record ComputeDiskRecord) (*primitives.Event, error) {
	location := lastPathSegment(firstNonEmpty(record.Zone, record.Region))
	resourceID := firstNonEmpty(record.SelfLink, record.ID, record.Name)
	attributes := cloudResourceAttributes(settings, "compute_disk", resourceID, record.Name, "compute_disk", location, record.Labels)
	attributes["zone"] = lastPathSegment(record.Zone)
	attributes["region"] = firstNonEmpty(lastPathSegment(record.Region), attributes["region"])
	attributes["disk_type"] = lastPathSegment(record.Type)
	attributes["status"] = record.Status
	attributes["size_gb"] = record.SizeGB
	attributes["attached_to"] = strings.Join(record.Users, ",")
	attributes["kms_key_name"] = record.DiskEncryptionKey.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.DiskEncryptionKey.KMSKeyName != "")
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-compute-disk-"+resourceID, "gcp.compute_disk", "gcp/compute_disk/v1", payload, attributes)
}

func GKEClusterEvent(settings Settings, record GKEClusterRecord) (*primitives.Event, error) {
	location := firstNonEmpty(record.Location, locationFromResourceName(record.Name))
	serviceAccountEmail := record.NodeConfig.ServiceAccount
	publicEndpoint := record.Endpoint != "" && !record.PrivateClusterConfig.EnablePrivateEndpoint
	attributes := cloudResourceAttributes(settings, "gke_cluster", firstNonEmpty(record.SelfLink, record.Name), record.Name, "gke_cluster", location, record.ResourceLabels)
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
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gke-cluster-"+firstNonEmpty(record.SelfLink, record.Name), "gcp.gke_cluster", "gcp/gke_cluster/v1", payload, attributes)
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

func gkeAuthorizedCIDRs(record GKEClusterRecord) []string {
	cidrs := make([]string, 0, len(record.MasterAuthorizedNetworksConfig.CidrBlocks))
	for _, block := range record.MasterAuthorizedNetworksConfig.CidrBlocks {
		if cidr := strings.TrimSpace(block.CidrBlock); cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
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

func GCSObjectEvent(settings Settings, record GCSObjectRecord) (*primitives.Event, error) {
	acl := gcsObjectACLSummary(record.ACL)
	metadataClass := labelLookup(record.Metadata, "data_classification", "data-classification", "classification", "sensitivity", "data_sensitivity")
	inspection := record.ContentInspection
	resourceID := firstNonEmpty(record.ID, record.Bucket+"/"+record.Name)
	location := firstNonEmpty(record.BucketLocation, "global")
	attributes := cloudResourceAttributes(settings, "gcs_object", resourceID, record.Name, "gcs_object", location, record.Metadata)
	attributes["bucket"] = record.Bucket
	attributes["object_name"] = record.Name
	attributes["generation"] = record.Generation
	attributes["metageneration"] = record.Metageneration
	attributes["content_type"] = record.ContentType
	attributes["storage_class"] = record.StorageClass
	attributes["size_bytes"] = record.Size
	attributes["md5_hash"] = record.MD5Hash
	attributes["crc32c"] = record.CRC32C
	attributes["kms_key_name"] = record.KMSKeyName
	attributes["customer_encryption_algorithm"] = record.CustomerEncryption.EncryptionAlgorithm
	attributes["customer_encryption_key_sha256"] = record.CustomerEncryption.KeySHA256
	attributes["encryption_enabled"] = boolString(record.KMSKeyName != "" || record.CustomerEncryption.EncryptionAlgorithm != "")
	attributes["event_based_hold"] = boolString(record.EventBasedHold)
	attributes["temporary_hold"] = boolString(record.TemporaryHold)
	attributes["retention_expiration_time"] = record.RetentionExpirationTime
	attributes["created_at"] = record.TimeCreated
	attributes["updated_at"] = record.Updated
	attributes["acl_entries_count"] = strconv.Itoa(len(record.ACL))
	attributes["acl_readers"] = strings.Join(acl.Readers, ",")
	attributes["acl_owners"] = strings.Join(acl.Owners, ",")
	attributes["public"] = boolString(acl.Public)
	attributes["internet_exposed"] = boolString(acl.Public)
	attributes["external_exposure"] = boolString(acl.Public)
	contentBytesScanned := ""
	contentInspectionTruncated := ""
	contentContainsPII := ""
	contentContainsSecrets := ""
	if inspection.Inspected {
		contentBytesScanned = strconv.Itoa(inspection.BytesScanned)
		contentInspectionTruncated = boolString(inspection.Truncated)
		contentContainsPII = boolString(inspection.ContainsPII)
		contentContainsSecrets = boolString(inspection.ContainsSecrets)
	}
	attributes["content_inspected"] = boolString(inspection.Inspected)
	attributes["content_bytes_scanned"] = contentBytesScanned
	attributes["content_inspection_truncated"] = contentInspectionTruncated
	attributes["content_findings"] = strings.Join(inspection.Findings, ",")
	attributes["content_contains_pii"] = contentContainsPII
	attributes["content_contains_secrets"] = contentContainsSecrets
	attributes["content_inspection_error"] = inspection.Error
	attributes["data_classification"] = strongestDataClassification(metadataClass, inspection.DataClassification)
	attributes["contains_pii"] = mergeContainsIndicator(labelLookup(record.Metadata, "contains_pii", "pii"), contentContainsPII)
	attributes["contains_secrets"] = contentContainsSecrets
	payload, err := payloadWithRaw(record.Raw, map[string]any{"bucket": record.Bucket, "content_inspection": inspection, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-gcs-object-"+resourceID, "gcp.gcs_object", "gcp/gcs_object/v1", payload, attributes)
}

func GCSObjectContentInspectable(record GCSObjectRecord) bool {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(record.ContentType, ";")[0]))
	switch {
	case strings.HasPrefix(contentType, "text/"):
		return true
	case contentType == "application/json", contentType == "application/xml", contentType == "application/yaml", contentType == "application/x-yaml", contentType == "application/javascript", contentType == "application/x-www-form-urlencoded":
		return true
	case strings.HasSuffix(contentType, "+json"), strings.HasSuffix(contentType, "+xml"):
		return true
	}
	name := strings.ToLower(record.Name)
	for _, suffix := range []string{".csv", ".env", ".ini", ".json", ".log", ".md", ".sql", ".tf", ".txt", ".xml", ".yaml", ".yml"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

type GCSObjectContentFetcher func(GCSObjectRecord) ([]byte, bool, error)

func EnrichGCSObjectContentInspections(records []GCSObjectRecord, fetch GCSObjectContentFetcher) {
	for index := range records {
		if !GCSObjectContentInspectable(records[index]) {
			continue
		}
		inspection, err := inspectGCSObjectContent(records[index], fetch)
		if err != nil {
			inspection = GCSObjectContentInspection{Error: err.Error()}
		}
		records[index].ContentInspection = inspection
	}
}

func inspectGCSObjectContent(record GCSObjectRecord, fetch GCSObjectContentFetcher) (GCSObjectContentInspection, error) {
	content, truncated, err := fetch(record)
	if err != nil {
		return GCSObjectContentInspection{}, err
	}
	return InspectGCSObjectContentSample(content, truncated), nil
}

func GCSObjectContentMediaRequest(record GCSObjectRecord) (string, url.Values) {
	query := url.Values{"alt": {"media"}}
	if strings.TrimSpace(record.Generation) != "" {
		query.Set("generation", record.Generation)
	}
	return "/storage/v1/b/" + url.PathEscape(record.Bucket) + "/o/" + url.PathEscape(record.Name), query
}

func InspectGCSObjectContentSample(sample []byte, truncated bool) GCSObjectContentInspection {
	inspection := GCSObjectContentInspection{Inspected: true, BytesScanned: len(sample), Truncated: truncated}
	normalized := strings.ToLower(string(sample))
	if gcsContentEmailRE.MatchString(normalized) || gcsContentSSNRE.MatchString(normalized) {
		inspection.ContainsPII = true
		inspection.Findings = appendUnique(inspection.Findings, "pii")
	}
	if gcsContentSecretRE.MatchString(normalized) || (strings.Contains(normalized, "-----begin ") && strings.Contains(normalized, " private key-----")) {
		inspection.ContainsSecrets = true
		inspection.Findings = appendUnique(inspection.Findings, "secret")
	}
	contentClass := gcsContentClassificationRE.FindString(normalized)
	switch {
	case inspection.ContainsSecrets || inspection.ContainsPII || contentClass == "restricted":
		inspection.DataClassification = "restricted"
	case contentClass == "confidential":
		inspection.DataClassification = "confidential"
	case contentClass == "internal":
		inspection.DataClassification = "internal"
	case contentClass == "public":
		inspection.DataClassification = "public"
	}
	return inspection
}

func strongestDataClassification(metadataClass string, contentClass string) string {
	metadataClass = strings.TrimSpace(metadataClass)
	contentClass = strings.TrimSpace(contentClass)
	if metadataClass == "" {
		return contentClass
	}
	if contentClass == "" {
		return metadataClass
	}
	metadataRank := dataClassificationRank(metadataClass)
	if metadataRank == 0 {
		return metadataClass
	}
	if dataClassificationRank(contentClass) > metadataRank {
		return contentClass
	}
	return metadataClass
}

func dataClassificationRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "public":
		return 1
	case "internal":
		return 2
	case "confidential":
		return 3
	case "restricted":
		return 4
	default:
		return 0
	}
}

func mergeContainsIndicator(metadataValue string, contentValue string) string {
	if truthyIndicator(contentValue) || truthyIndicator(metadataValue) {
		return "true"
	}
	return firstNonEmpty(metadataValue, contentValue)
}

func truthyIndicator(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "y":
		return true
	default:
		return false
	}
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

func ContainerRegistryEvent(settings Settings, record ContainerRegistryRecord) (*primitives.Event, error) {
	iam := iamPolicySummary(record.IAMPolicy)
	resourceID := record.Host + "/" + settings.ProjectID
	attributes := cloudResourceAttributes(settings, "container_registry", resourceID, record.Host, "container_registry", record.Location, record.Labels)
	attributes["registry"] = record.Host
	attributes["registry_host"] = record.Host
	attributes["bucket"] = record.Bucket
	attributes["storage_bucket"] = record.Bucket
	attributes["storage_class"] = record.StorageClass
	attributes["kms_key_name"] = record.Encryption.DefaultKMSKeyName
	attributes["encryption_enabled"] = boolString(record.Encryption.DefaultKMSKeyName != "")
	attributes["versioning_enabled"] = boolString(record.Versioning.Enabled)
	attributes["uniform_bucket_level_access"] = boolString(record.IAMConfiguration.UniformBucketLevelAccess.Enabled)
	attributes["public_access_prevention"] = record.IAMConfiguration.PublicAccessPrevention
	attributes["legacy_container_registry"] = "true"
	attributes["uses_cloud_storage"] = "true"
	attributes["iam_bindings_count"] = strconv.Itoa(len(record.IAMPolicy.Bindings))
	attributes["iam_roles"] = strings.Join(iamPolicyRoles(record.IAMPolicy), ",")
	attributes["iam_members"] = strings.Join(iam.Members, ",")
	attributes["iam_admin_members"] = strings.Join(iam.AdminMembers, ",")
	attributes["public"] = boolString(iam.Public)
	attributes["internet_exposed"] = boolString(iam.Public)
	attributes["external_exposure"] = boolString(iam.Public)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"bucket": record.Bucket, "host": record.Host, "iam_policy": record.IAMPolicy, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-container-registry-"+resourceID, "gcp.container_registry", "gcp/container_registry/v1", payload, attributes)
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

func PubSubTopicEvent(settings Settings, record PubSubTopicRecord) (*primitives.Event, error) {
	iam := iamPolicySummary(record.IAMPolicy)
	attributes := cloudResourceAttributes(settings, "pubsub_topic", record.Name, lastPathSegment(record.Name), "pubsub_topic", "global", record.Labels)
	attributes["topic_name"] = lastPathSegment(record.Name)
	attributes["kms_key_name"] = record.KMSKeyName
	attributes["encryption_enabled"] = boolString(record.KMSKeyName != "")
	attributes["message_retention_duration"] = record.MessageRetentionDuration
	attributes["allowed_persistence_regions"] = strings.Join(record.MessageStoragePolicy.AllowedPersistenceRegions, ",")
	attributes["allowed_persistence_regions_count"] = strconv.Itoa(len(record.MessageStoragePolicy.AllowedPersistenceRegions))
	attributes["schema"] = record.SchemaSettings.Schema
	attributes["schema_encoding"] = record.SchemaSettings.Encoding
	attributes["schema_first_revision_id"] = record.SchemaSettings.FirstRevisionID
	attributes["schema_last_revision_id"] = record.SchemaSettings.LastRevisionID
	attributes["state"] = record.State
	attributes["satisfies_pzs"] = boolString(record.SatisfiesPZS)
	attributes["iam_bindings_count"] = strconv.Itoa(len(record.IAMPolicy.Bindings))
	attributes["iam_roles"] = strings.Join(iamPolicyRoles(record.IAMPolicy), ",")
	attributes["iam_members"] = strings.Join(iam.Members, ",")
	attributes["iam_admin_members"] = strings.Join(iam.AdminMembers, ",")
	attributes["public"] = boolString(iam.Public)
	attributes["internet_exposed"] = boolString(iam.Public)
	attributes["external_exposure"] = boolString(iam.Public)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"iam_policy": record.IAMPolicy, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-pubsub-topic-"+record.Name, "gcp.pubsub_topic", "gcp/pubsub_topic/v1", payload, attributes)
}

func PubSubSubscriptionEvent(settings Settings, record PubSubSubscriptionRecord) (*primitives.Event, error) {
	iam := iamPolicySummary(record.IAMPolicy)
	attributes := cloudResourceAttributes(settings, "pubsub_subscription", record.Name, lastPathSegment(record.Name), "pubsub_subscription", "global", record.Labels)
	attributes["subscription_name"] = lastPathSegment(record.Name)
	attributes["topic"] = record.Topic
	attributes["topic_name"] = lastPathSegment(record.Topic)
	attributes["state"] = record.State
	attributes["filter"] = record.Filter
	attributes["detached"] = boolString(record.Detached)
	attributes["message_ordering_enabled"] = boolString(record.EnableMessageOrdering)
	attributes["retain_acked_messages"] = boolString(record.RetainAckedMessages)
	attributes["ack_deadline_seconds"] = strconv.Itoa(record.AckDeadlineSeconds)
	attributes["message_retention_duration"] = record.MessageRetentionDuration
	attributes["topic_message_retention_duration"] = record.TopicMessageRetentionDuration
	attributes["expiration_ttl"] = record.ExpirationPolicy.TTL
	attributes["push_configured"] = boolString(record.PushConfig.PushEndpoint != "")
	attributes["push_endpoint"] = record.PushConfig.PushEndpoint
	attributes["push_oidc_service_account_email"] = record.PushConfig.OIDCToken.ServiceAccountEmail
	attributes["push_oidc_audience"] = record.PushConfig.OIDCToken.Audience
	attributes["bigquery_table"] = record.BigQueryConfig.Table
	attributes["bigquery_use_topic_schema"] = boolString(record.BigQueryConfig.UseTopicSchema)
	attributes["bigquery_write_metadata"] = boolString(record.BigQueryConfig.WriteMetadata)
	attributes["bigquery_drop_unknown_fields"] = boolString(record.BigQueryConfig.DropUnknownFields)
	attributes["bigquery_service_account_email"] = record.BigQueryConfig.ServiceAccountEmail
	attributes["cloud_storage_bucket"] = record.CloudStorageConfig.Bucket
	attributes["cloud_storage_filename_prefix"] = record.CloudStorageConfig.FilenamePrefix
	attributes["cloud_storage_filename_suffix"] = record.CloudStorageConfig.FilenameSuffix
	attributes["dead_letter_topic"] = record.DeadLetterPolicy.DeadLetterTopic
	attributes["dead_letter_topic_name"] = lastPathSegment(record.DeadLetterPolicy.DeadLetterTopic)
	attributes["max_delivery_attempts"] = strconv.Itoa(record.DeadLetterPolicy.MaxDeliveryAttempts)
	attributes["retry_minimum_backoff"] = record.RetryPolicy.MinimumBackoff
	attributes["retry_maximum_backoff"] = record.RetryPolicy.MaximumBackoff
	attributes["iam_bindings_count"] = strconv.Itoa(len(record.IAMPolicy.Bindings))
	attributes["iam_roles"] = strings.Join(iamPolicyRoles(record.IAMPolicy), ",")
	attributes["iam_members"] = strings.Join(iam.Members, ",")
	attributes["iam_admin_members"] = strings.Join(iam.AdminMembers, ",")
	attributes["public"] = boolString(iam.Public)
	attributes["internet_exposed"] = boolString(iam.Public)
	attributes["external_exposure"] = boolString(iam.Public)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"iam_policy": record.IAMPolicy, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-pubsub-subscription-"+record.Name, "gcp.pubsub_subscription", "gcp/pubsub_subscription/v1", payload, attributes)
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
	enabledServices := serviceUsageNames(record.EnabledServices)
	orgPolicies := orgPolicyConstraints(record.OrgPolicies)
	enforcedPolicies := enforcedOrgPolicyConstraints(record.OrgPolicies)
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
	attributes["enabled_services"] = strings.Join(enabledServices, ",")
	attributes["enabled_services_count"] = strconv.Itoa(len(enabledServices))
	attributes["org_policies"] = strings.Join(orgPolicies, ",")
	attributes["org_policies_count"] = strconv.Itoa(len(orgPolicies))
	attributes["enforced_org_policies"] = strings.Join(enforcedPolicies, ",")
	attributes["enforced_org_policies_count"] = strconv.Itoa(len(enforcedPolicies))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"enabled_services": record.EnabledServices, "org_policies": record.OrgPolicies, "project_id": projectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-resourcemanager-project-"+projectID, "gcp.resourcemanager_project", "gcp/resourcemanager_project/v1", payload, attributes)
}

func ServiceUsageServiceEvent(settings Settings, record ServiceUsageServiceRecord) (*primitives.Event, error) {
	serviceName := firstNonEmpty(record.Config.Name, lastPathSegment(record.Name), record.Name)
	resourceID := firstNonEmpty(record.Name, settings.ProjectID+"/services/"+serviceName)
	attributes := cloudResourceAttributes(settings, "service_usage_service", resourceID, firstNonEmpty(record.Config.Title, serviceName), "service_usage_service", "global", nil)
	attributes["parent"] = record.Parent
	attributes["service_name"] = serviceName
	attributes["service_title"] = record.Config.Title
	attributes["state"] = record.State
	attributes["status"] = record.State
	attributes["enabled"] = boolString(strings.EqualFold(record.State, "ENABLED"))
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-service-usage-service-"+resourceID, "gcp.service_usage_service", "gcp/service_usage_service/v1", payload, attributes)
}

func OrgPolicyEvent(settings Settings, record OrgPolicyRecord) (*primitives.Event, error) {
	constraint := orgPolicyConstraint(record.Name)
	allowedValues, deniedValues := orgPolicyRuleValues(record.Spec.Rules)
	resourceID := firstNonEmpty(record.Name, settings.ProjectID+"/policies/"+constraint)
	attributes := cloudResourceAttributes(settings, "org_policy", resourceID, constraint, "org_policy", "global", nil)
	attributes["constraint"] = constraint
	attributes["etag"] = firstNonEmpty(record.Spec.Etag, record.Etag)
	attributes["inherit_from_parent"] = boolString(record.Spec.InheritFromParent)
	attributes["enforced"] = boolString(orgPolicyEnforced(record))
	attributes["policy_name"] = record.Name
	attributes["reset"] = boolString(record.Spec.Reset)
	attributes["rules_count"] = strconv.Itoa(len(record.Spec.Rules))
	attributes["allowed_values"] = strings.Join(allowedValues, ",")
	attributes["denied_values"] = strings.Join(deniedValues, ",")
	attributes["updated_at"] = record.Spec.UpdateTime
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-org-policy-"+resourceID, "gcp.org_policy", "gcp/org_policy/v1", payload, attributes)
}

type cloudSchedulerTargetSummary struct {
	Type                string
	Target              string
	URI                 string
	Topic               string
	Method              string
	ServiceAccountEmail string
	OAuthScope          string
	OIDCAudience        string
}

func cloudSchedulerTarget(record CloudSchedulerJobRecord) cloudSchedulerTargetSummary {
	if record.PubsubTarget.TopicName != "" {
		return cloudSchedulerTargetSummary{Type: "pubsub", Target: record.PubsubTarget.TopicName, Topic: record.PubsubTarget.TopicName}
	}
	if record.HTTPTarget.URI != "" || record.HTTPTarget.HTTPMethod != "" {
		serviceAccount := firstNonEmpty(record.HTTPTarget.OAuthToken.ServiceAccountEmail, record.HTTPTarget.OIDCToken.ServiceAccountEmail)
		return cloudSchedulerTargetSummary{Type: "http", Target: record.HTTPTarget.URI, URI: record.HTTPTarget.URI, Method: record.HTTPTarget.HTTPMethod, ServiceAccountEmail: serviceAccount, OAuthScope: record.HTTPTarget.OAuthToken.Scope, OIDCAudience: record.HTTPTarget.OIDCToken.Audience}
	}
	if record.AppEngineHTTPTarget.RelativeURI != "" || record.AppEngineHTTPTarget.HTTPMethod != "" {
		target := firstNonEmpty(record.AppEngineHTTPTarget.AppEngineRouting.Host, record.AppEngineHTTPTarget.RelativeURI)
		return cloudSchedulerTargetSummary{Type: "app_engine", Target: target, URI: record.AppEngineHTTPTarget.RelativeURI, Method: record.AppEngineHTTPTarget.HTTPMethod}
	}
	return cloudSchedulerTargetSummary{}
}

type iamSummary struct {
	Public       bool
	Members      []string
	AdminMembers []string
}

func iamPolicySummary(policy IAMPolicy) iamSummary {
	summary := iamSummary{}
	for _, binding := range policy.Bindings {
		admin := iamAdminRole(binding.Role)
		for _, member := range binding.Members {
			trimmed := strings.TrimSpace(member)
			if trimmed == "" {
				continue
			}
			summary.Members = appendUnique(summary.Members, trimmed)
			if admin {
				summary.AdminMembers = appendUnique(summary.AdminMembers, trimmed)
			}
			if publicPrincipal(trimmed) {
				summary.Public = true
			}
		}
	}
	return summary
}

func iamPolicyRoles(policy IAMPolicy) []string {
	roles := make([]string, 0, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		roles = appendUnique(roles, binding.Role)
	}
	return roles
}

func iamAdminRole(role string) bool {
	normalized := strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(normalized, "admin") || strings.Contains(normalized, "owner") || strings.Contains(normalized, "editor")
}

type deployedModelSummary struct {
	IDs              []string
	Models           []string
	ServiceAccounts  []string
	MachineTypes     []string
	AccessLogging    bool
	ContainerLogging bool
}

func aiDeployedModelSummary(models []AIDeployedModel) deployedModelSummary {
	summary := deployedModelSummary{}
	for _, model := range models {
		summary.IDs = appendUnique(summary.IDs, model.ID)
		summary.Models = appendUnique(summary.Models, model.Model)
		summary.ServiceAccounts = appendUnique(summary.ServiceAccounts, model.ServiceAccount)
		summary.MachineTypes = appendUnique(summary.MachineTypes, model.MachineSpec.MachineType)
		summary.AccessLogging = summary.AccessLogging || model.EnableAccessLog
		summary.ContainerLogging = summary.ContainerLogging || model.EnableContainerLog
	}
	return summary
}

type cloudIDSLoggingSummary struct {
	Names                    []string
	Destinations             []string
	DestinationTypes         []string
	NotificationDestinations []string
	Threat                   bool
	Traffic                  bool
}

func AttachCloudIDSLoggingSinks(records []CloudIDSEndpointRecord, sinks []LoggingSinkRecord) {
	for index := range records {
		records[index].LoggingSinks = cloudIDSLoggingSinks(records[index], sinks)
	}
}

func cloudIDSLoggingSinks(record CloudIDSEndpointRecord, sinks []LoggingSinkRecord) []LoggingSinkRecord {
	matched := make([]LoggingSinkRecord, 0)
	endpointName := strings.ToLower(lastPathSegment(record.Name))
	for _, sink := range sinks {
		if sink.Disabled || !cloudIDSFilterMatches(sink.Filter, endpointName) {
			continue
		}
		matched = append(matched, sink)
	}
	return matched
}

func cloudIDSLogSinkSummary(sinks []LoggingSinkRecord) cloudIDSLoggingSummary {
	summary := cloudIDSLoggingSummary{}
	for _, sink := range sinks {
		destinationType := loggingSinkDestinationType(sink.Destination)
		summary.Names = appendUnique(summary.Names, sink.Name)
		summary.Destinations = appendUnique(summary.Destinations, sink.Destination)
		summary.DestinationTypes = appendUnique(summary.DestinationTypes, destinationType)
		if destinationType == "pubsub" {
			summary.NotificationDestinations = appendUnique(summary.NotificationDestinations, sink.Destination)
		}
		filter := strings.ToLower(strings.TrimSpace(sink.Filter))
		if filter == "" {
			summary.Threat = true
			summary.Traffic = true
			continue
		}
		genericIDS := strings.Contains(filter, "ids.googleapis.com/endpoint") || strings.Contains(filter, "ids_googleapis_com_endpoint")
		summary.Threat = summary.Threat || genericIDS || strings.Contains(filter, "ids.googleapis.com%2fthreat") || strings.Contains(filter, "ids.googleapis.com/threat")
		summary.Traffic = summary.Traffic || genericIDS || strings.Contains(filter, "ids.googleapis.com%2ftraffic") || strings.Contains(filter, "ids.googleapis.com/traffic")
	}
	return summary
}

func cloudIDSFilterMatches(filter string, endpointName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(filter))
	if normalized == "" {
		return true
	}
	if endpointName != "" && strings.Contains(normalized, "resource.labels.id") && !cloudIDSResourceIDFilterMatches(normalized, endpointName) {
		return false
	}
	return strings.Contains(normalized, "ids.googleapis.com%2f") ||
		strings.Contains(normalized, "ids.googleapis.com/") ||
		strings.Contains(normalized, "ids.googleapis.com/endpoint") ||
		strings.Contains(normalized, "ids_googleapis_com_endpoint")
}

func cloudIDSResourceIDFilterMatches(normalized string, endpointName string) bool {
	matches := cloudIDSResourceLabelIDFilterRE.FindAllStringSubmatch(normalized, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if len(match) > 1 && strings.Trim(match[1], `"'`) == endpointName {
			return true
		}
	}
	return false
}

func cloudIDSLogName(projectID string, logID string) string {
	return "projects/" + projectID + "/logs/ids.googleapis.com%2F" + logID
}

type objectACLSummary struct {
	Public  bool
	Readers []string
	Owners  []string
}

func gcsObjectACLSummary(entries []GCSObjectACL) objectACLSummary {
	summary := objectACLSummary{}
	for _, entry := range entries {
		principal := firstNonEmpty(entry.Email, entry.Entity, entry.Domain)
		if publicPrincipal(principal) {
			summary.Public = true
		}
		switch strings.ToUpper(strings.TrimSpace(entry.Role)) {
		case "OWNER":
			summary.Owners = appendUnique(summary.Owners, principal)
		case "READER":
			summary.Readers = appendUnique(summary.Readers, principal)
		}
	}
	return summary
}

func publicPrincipal(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "allusers" || normalized == "allauthenticatedusers" || normalized == "all_users" || normalized == "all_authenticated_users"
}

func serviceUsageNames(services []ServiceUsageServiceRecord) []string {
	names := make([]string, 0, len(services))
	for _, service := range services {
		name := firstNonEmpty(service.Config.Name, lastPathSegment(service.Name), service.Name)
		names = appendUnique(names, name)
	}
	return names
}

func orgPolicyConstraints(policies []OrgPolicyRecord) []string {
	constraints := make([]string, 0, len(policies))
	for _, policy := range policies {
		constraints = appendUnique(constraints, orgPolicyConstraint(policy.Name))
	}
	return constraints
}

func orgPolicyRuleValues(rules []OrgPolicyRule) ([]string, []string) {
	allowed := []string{}
	denied := []string{}
	for _, rule := range rules {
		for _, value := range rule.Values.AllowedValues {
			allowed = appendUnique(allowed, value)
		}
		for _, value := range rule.Values.DeniedValues {
			denied = appendUnique(denied, value)
		}
	}
	return allowed, denied
}

func enforcedOrgPolicyConstraints(policies []OrgPolicyRecord) []string {
	constraints := make([]string, 0, len(policies))
	for _, policy := range policies {
		if orgPolicyEnforced(policy) {
			constraints = appendUnique(constraints, orgPolicyConstraint(policy.Name))
		}
	}
	return constraints
}

func orgPolicyConstraint(name string) string {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	for index, part := range parts {
		if part == "policies" && index+1 < len(parts) {
			return parts[index+1]
		}
	}
	return lastPathSegment(name)
}

func orgPolicyEnforced(policy OrgPolicyRecord) bool {
	for _, rule := range policy.Spec.Rules {
		if rule.Enforce != nil && *rule.Enforce {
			return true
		}
		if rule.DenyAll || len(rule.Values.DeniedValues) != 0 {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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
	return sourceEventAt(settings, id, kind, schemaRef, payload, attributes, time.Now().UTC())
}

func sourceEventAt(settings Settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{
		Id:         sanitizeEventID(id),
		TenantId:   settings.TenantID,
		SourceId:   "gcp",
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt.UTC()),
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

func disabledStatus(disabled bool) string {
	if disabled {
		return "DISABLED"
	}
	return "ACTIVE"
}

func parseMember(value string) (string, string, string) {
	trimmed := strings.TrimSpace(value)
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		if publicPrincipal(trimmed) {
			return "public", trimmed, ""
		}
		return "user", trimmed, emailLike(trimmed)
	}
	memberType := strings.ToLower(strings.ReplaceAll(parts[0], "serviceAccount", "service_account"))
	if publicPrincipal(memberType) {
		memberType = "public"
	}
	return memberType, parts[1], emailLike(parts[1])
}

func membershipRoleName(roles []MembershipRole) string {
	if len(roles) == 0 {
		return "member"
	}
	return firstNonEmpty(roles[0].Name, "member")
}

func privilegeLevel(admin bool) string {
	if admin {
		return "admin"
	}
	return "standard"
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
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
